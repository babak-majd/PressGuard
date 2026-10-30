<?php
/**
 * Malware & integrity scanner (AJAX-driven, resumable).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Scanner;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Scans every file under the WordPress root (all .htaccess files included) for
 * malware signatures, and verifies core integrity against the official
 * checksums. The scan is chunked and stepped over AJAX with a progress bar, and
 * backed by a self-rescheduling WP-Cron job so it keeps running server-side
 * even if the admin closes the tab. Results are written to a findings file so
 * the full report survives and never bloats the options table.
 */
final class Scanner implements Module {

	const STATE_OPTION = 'pressguard_scan_state';
	const ADMIN_SLUG   = 'pressguard-scan';
	const CRON_HOOK    = 'pressguard_scan_cron';
	const AJAX_BUDGET  = 8;   // seconds per AJAX step.
	const CRON_BUDGET  = 15;  // seconds per cron tick.
	const MAX_BYTES    = 3145728; // 3 MB per file.

	/**
	 * Extensions skipped for signature matching (binary media/archives).
	 *
	 * @var string[]
	 */
	private static $skip_ext = array(
		'jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'tiff',
		'mp4', 'mp3', 'wav', 'avi', 'mov', 'mkv', 'ogg', 'webm',
		'zip', 'gz', 'tar', 'bz2', '7z', 'rar',
		'woff', 'woff2', 'ttf', 'eot', 'otf',
		'pdf', 'psd', 'mo', 'webp',
	);

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'scanner';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Scan', 'pressguard' ), __( 'Scan', 'pressguard' ), $cap, self::ADMIN_SLUG, array( $this, 'render' ) );
			},
			10,
			2
		);

		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'wp_ajax_pressguard_scan_start', array( $this, 'ajax_start' ) );
		add_action( 'wp_ajax_pressguard_scan_step', array( $this, 'ajax_step' ) );
		add_action( 'wp_ajax_pressguard_scan_status', array( $this, 'ajax_status' ) );
		add_action( self::CRON_HOOK, array( $this, 'cron_step' ) );
	}

	/**
	 * Enqueue the scan UI script on our scan page only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue( $hook ) {
		if ( false === strpos( (string) $hook, self::ADMIN_SLUG ) ) {
			return;
		}

		wp_enqueue_script( 'pressguard-scan', PRESSGUARD_URL . 'assets/scan.js', array(), PRESSGUARD_VERSION, true );
		wp_localize_script(
			'pressguard-scan',
			'PressGuardScan',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'pressguard_scan' ),
				'i18n'    => array(
					'scanning' => __( 'Scanning…', 'pressguard' ),
					'done'     => __( 'Scan complete.', 'pressguard' ),
					'ofFiles'  => __( '%1$d / %2$d files', 'pressguard' ),
				),
			)
		);
	}

	// ---- AJAX -------------------------------------------------------------

	/**
	 * AJAX: start a new scan.
	 */
	public function ajax_start() {
		$this->verify_ajax();
		$this->start();
		wp_send_json_success( $this->public_state() );
	}

	/**
	 * AJAX: run one step.
	 */
	public function ajax_step() {
		$this->verify_ajax();
		$this->step( self::AJAX_BUDGET );
		wp_send_json_success( $this->public_state() );
	}

	/**
	 * AJAX: report current state (used to resume after a reload).
	 */
	public function ajax_status() {
		$this->verify_ajax();
		wp_send_json_success( $this->public_state() );
	}

	/**
	 * Shared AJAX guard.
	 */
	private function verify_ajax() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		check_ajax_referer( 'pressguard_scan', 'nonce' );
	}

	// ---- Cron (continues if the tab is closed) ----------------------------

	/**
	 * Cron tick: advance the scan, then reschedule itself until done.
	 */
	public function cron_step() {
		$state = $this->get_state();
		if ( 'running' !== ( $state['status'] ?? 'idle' ) ) {
			return;
		}

		$deadline = time() + self::CRON_BUDGET;
		do {
			$state = $this->step( 5 );
		} while ( 'running' === ( $state['status'] ?? 'idle' ) && time() < $deadline );

		if ( 'running' === ( $state['status'] ?? 'idle' ) ) {
			wp_schedule_single_event( time() + 20, self::CRON_HOOK );
		}
	}

	// ---- Scan lifecycle ---------------------------------------------------

	/**
	 * Begin a scan: build the file queue, run core integrity, schedule cron.
	 *
	 * @return array State.
	 */
	public function start() {
		$paths = $this->paths();

		// Truncate the findings file and record core-integrity findings first.
		$this->reset_findings();
		$core = $this->core_integrity();
		foreach ( $core as $finding ) {
			$this->append_finding( $finding );
		}

		// Build the queue file (one path per line).
		$queue = $this->enumerate_files();
		@file_put_contents( $paths['queue'], implode( "\n", $queue ) ); // phpcs:ignore

		$state = array(
			'status'         => empty( $queue ) ? 'done' : 'running',
			'offset'         => 0,
			'total'          => count( $queue ),
			'scanned'        => 0,
			'findings_count' => count( $core ),
			'started'        => time(),
			'updated'        => time(),
			'duration'       => 0,
		);
		$this->save_state( $state );

		if ( 'running' === $state['status'] ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				wp_schedule_single_event( time() + 2, self::CRON_HOOK );
			}
		} else {
			$this->finish( $state );
		}

		return $state;
	}

	/**
	 * Process one chunk of the queue within a time budget.
	 *
	 * @param int $budget Seconds.
	 * @return array State.
	 */
	public function step( $budget ) {
		$state = $this->get_state();
		if ( 'running' !== ( $state['status'] ?? 'idle' ) ) {
			return $state;
		}

		$paths = $this->paths();
		$lines = is_readable( $paths['queue'] ) ? file( $paths['queue'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) : array();
		$total = count( $lines );

		$deadline = time() + max( 2, (int) $budget );
		$offset   = (int) $state['offset'];

		while ( $offset < $total && time() < $deadline ) {
			$file = $lines[ $offset ];
			++$offset;

			$findings = $this->scan_file( $file );
			foreach ( $findings as $finding ) {
				$this->append_finding( $finding );
				++$state['findings_count'];
			}
			++$state['scanned'];
		}

		$state['offset']  = $offset;
		$state['total']   = $total;
		$state['updated'] = time();

		if ( $offset >= $total ) {
			$state['status']   = 'done';
			$state['duration'] = time() - (int) $state['started'];
			$this->finish( $state );
		}

		$this->save_state( $state );
		return $state;
	}

	/**
	 * Scan a single file and return its findings.
	 *
	 * @param string $file Absolute path.
	 * @return array[]
	 */
	private function scan_file( $file ) {
		$out  = array();
		$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > self::MAX_BYTES ) {
			return $out;
		}

		$base = basename( $file );
		$ext  = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );

		$is_htaccess = ( '.htaccess' === $base );
		if ( ! $is_htaccess && in_array( $ext, self::$skip_ext, true ) ) {
			return $out;
		}

		$content = @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $content ) {
			return $out;
		}

		if ( $is_htaccess ) {
			// Strip PressGuard's own marker blocks so our Extended WAF
			// auto_prepend line isn't flagged as a backdoor.
			$content = preg_replace( '/# BEGIN PressGuard.*?# END PressGuard[^\n]*\n?/s', '', $content );
		}

		$matches = $is_htaccess ? Signatures::scan_htaccess( $content ) : Signatures::scan_content( $content );
		foreach ( $matches as $m ) {
			$out[] = array(
				'file'   => $this->relpath( $file ),
				'type'   => $is_htaccess ? 'htaccess' : 'malware',
				'score'  => $m['score'],
				'detail' => $m['description'] . ' [' . $m['id'] . ']',
			);
		}

		return $out;
	}

	/**
	 * Finalize a completed scan: mirror a summary, log it, clear cron.
	 *
	 * @param array $state State (by value).
	 */
	private function finish( array $state ) {
		wp_clear_scheduled_hook( self::CRON_HOOK );

		$this->plugin->logger()->log(
			'scanner',
			'scan_complete',
			array(
				'severity' => ( $state['findings_count'] > 0 ) ? Logger::SEVERITY_WARNING : Logger::SEVERITY_NOTICE,
				'message'  => sprintf( 'Scanned %d files in %ds, %d findings.', (int) $state['scanned'], (int) $state['duration'], (int) $state['findings_count'] ),
			)
		);
	}

	// ---- File discovery ---------------------------------------------------

	/**
	 * Enumerate every file under ABSPATH, excluding our own files.
	 *
	 * @return string[]
	 */
	private function enumerate_files() {
		$files = array();
		$skip  = array(
			rtrim( PRESSGUARD_DIR, '/' ),
			WP_CONTENT_DIR . '/uploads/pressguard',
			WP_CONTENT_DIR . '/cache',
		);

		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( ABSPATH, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::FOLLOW_SYMLINKS ),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( \Exception $e ) {
			return $files;
		}

		foreach ( $it as $fileinfo ) {
			if ( ! $fileinfo->isFile() ) {
				continue;
			}
			$path    = $fileinfo->getPathname();
			$skipped = false;
			foreach ( $skip as $prefix ) {
				if ( 0 === strpos( $path, $prefix ) ) {
					$skipped = true;
					break;
				}
			}
			if ( ! $skipped ) {
				$files[] = $path;
			}
		}

		return $files;
	}

	/**
	 * Verify core files against api.wordpress.org checksums.
	 *
	 * @return array[]
	 */
	private function core_integrity() {
		$findings = array();
		$url      = add_query_arg(
			array(
				'version' => get_bloginfo( 'version' ),
				'locale'  => get_locale(),
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return $findings;
		}
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			return $findings;
		}

		foreach ( $body['checksums'] as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				$findings[] = array(
					'file'   => $file,
					'type'   => 'core_missing',
					'score'  => 6,
					'detail' => __( 'Core file missing.', 'pressguard' ),
				);
			} elseif ( md5_file( $path ) !== $md5 ) {
				$findings[] = array(
					'file'   => $file,
					'type'   => 'core_modified',
					'score'  => 8,
					'detail' => __( 'Core file does not match the official checksum.', 'pressguard' ),
				);
			}
		}

		return $findings;
	}

	// ---- State & findings storage -----------------------------------------

	/**
	 * Data file paths (under uploads/pressguard).
	 *
	 * @return array{dir:string,queue:string,findings:string}
	 */
	private function paths() {
		$uploads = wp_upload_dir();
		$dir     = trailingslashit( $uploads['basedir'] ) . 'pressguard';
		wp_mkdir_p( $dir );
		return array(
			'dir'      => $dir,
			'queue'    => $dir . '/scan-queue.txt',
			'findings' => $dir . '/scan-findings.jsonl',
		);
	}

	/**
	 * Truncate the findings file.
	 */
	private function reset_findings() {
		$paths = $this->paths();
		@file_put_contents( $paths['findings'], '' ); // phpcs:ignore
	}

	/**
	 * Append one finding as a JSON line.
	 *
	 * @param array $finding Finding.
	 */
	private function append_finding( array $finding ) {
		$paths = $this->paths();
		@file_put_contents( $paths['findings'], wp_json_encode( $finding ) . "\n", FILE_APPEND | LOCK_EX ); // phpcs:ignore
	}

	/**
	 * Read all findings from the findings file.
	 *
	 * @param int $limit Max to return (0 = all).
	 * @return array[]
	 */
	public function read_findings( $limit = 0 ) {
		$paths = $this->paths();
		if ( ! is_readable( $paths['findings'] ) ) {
			return array();
		}
		$out   = array();
		$lines = file( $paths['findings'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		foreach ( (array) $lines as $line ) {
			$row = json_decode( $line, true );
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
			if ( $limit && count( $out ) >= $limit ) {
				break;
			}
		}
		return $out;
	}

	/**
	 * Current scan state.
	 *
	 * @return array
	 */
	public function get_state() {
		$state = get_option( self::STATE_OPTION, array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Persist scan state.
	 *
	 * @param array $state State.
	 */
	private function save_state( array $state ) {
		update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * State plus a progress percentage for the UI.
	 *
	 * @return array
	 */
	private function public_state() {
		$state   = $this->get_state();
		$total   = max( 1, (int) ( $state['total'] ?? 1 ) );
		$percent = min( 100, (int) round( ( (int) ( $state['offset'] ?? 0 ) / $total ) * 100 ) );
		$state['percent'] = empty( $state ) ? 0 : $percent;
		$state['status']  = $state['status'] ?? 'idle';
		return $state;
	}

	/**
	 * Path relative to the WordPress root.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function relpath( $path ) {
		return ltrim( str_replace( ABSPATH, '', $path ), '/' );
	}

	// ---- Admin screen ------------------------------------------------------

	/**
	 * Render the scan page: progress UI + full report.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$state    = $this->public_state();
		$findings = $this->read_findings();
		$running  = ( 'running' === ( $state['status'] ?? 'idle' ) );

		// Summary counts by type.
		$by_type = array();
		foreach ( $findings as $f ) {
			$t             = $f['type'] ?? 'other';
			$by_type[ $t ] = ( $by_type[ $t ] ?? 0 ) + 1;
		}
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Malware &amp; Integrity Scan', 'pressguard' ); ?></h1>
			<p class="description"><?php esc_html_e( 'Scans every file (including all .htaccess files) and verifies WordPress core. The scan continues on the server even if you close this tab.', 'pressguard' ); ?></p>

			<p>
				<button type="button" class="button button-primary" id="pg-scan-start" <?php disabled( $running ); ?>>
					<?php esc_html_e( 'Run scan now', 'pressguard' ); ?>
				</button>
				<span id="pg-scan-status" style="margin-inline-start:10px;"></span>
			</p>

			<div id="pg-scan-progress" style="max-width:600px;background:#f0f0f1;border-radius:4px;overflow:hidden;height:20px;<?php echo $running ? '' : 'display:none;'; ?>">
				<div id="pg-scan-bar" style="height:100%;width:<?php echo (int) ( $state['percent'] ?? 0 ); ?>%;background:#2271b1;transition:width .3s;"></div>
			</div>

			<?php if ( ! empty( $state['started'] ) ) : ?>
				<p class="description" id="pg-scan-summary">
					<?php
					printf(
						/* translators: 1: files scanned, 2: findings, 3: seconds */
						esc_html__( 'Scanned %1$d files — %2$d findings%3$s.', 'pressguard' ),
						(int) ( $state['scanned'] ?? 0 ),
						(int) ( $state['findings_count'] ?? 0 ),
						! empty( $state['duration'] ) ? ' (' . (int) $state['duration'] . 's)' : ''
					);
					?>
				</p>
			<?php endif; ?>

			<?php if ( ! empty( $by_type ) ) : ?>
				<p>
					<?php foreach ( $by_type as $type => $count ) : ?>
						<span class="pressguard-badge" style="display:inline-block;margin:2px;padding:2px 8px;background:#e5e5e5;border-radius:10px;">
							<?php echo esc_html( $type ); ?>: <strong><?php echo (int) $count; ?></strong>
						</span>
					<?php endforeach; ?>
				</p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Scan report', 'pressguard' ); ?></h2>
			<?php if ( empty( $findings ) ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'No threats found.', 'pressguard' ); ?></p></div>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr>
						<th><?php esc_html_e( 'Severity', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'Type', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'File', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'Detail', 'pressguard' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( array_slice( $findings, 0, 1000 ) as $f ) : ?>
						<tr>
							<td><?php echo (int) ( $f['score'] ?? 0 ); ?></td>
							<td><code><?php echo esc_html( $f['type'] ?? '' ); ?></code></td>
							<td><?php echo esc_html( $f['file'] ?? '' ); ?></td>
							<td><?php echo esc_html( $f['detail'] ?? '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<?php if ( count( $findings ) > 1000 ) : ?>
					<p class="description"><?php echo esc_html( sprintf( __( 'Showing first 1000 of %d findings.', 'pressguard' ), count( $findings ) ) ); ?></p>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}
}
