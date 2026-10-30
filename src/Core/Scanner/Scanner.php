<?php
/**
 * Malware & integrity scanner.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Scanner;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Scans the site for malware signatures (in wp-content PHP files) and verifies
 * WordPress core integrity against the official checksums API. Work is
 * time-boxed so it never exhausts a shared host; results are stored for the
 * admin screen. Nothing is auto-deleted — findings are reported for review.
 */
final class Scanner implements Module {

	const RESULTS_OPTION = 'pressguard_scan_results';
	const ADMIN_SLUG     = 'pressguard-scan';
	const TIME_BUDGET    = 20; // seconds per run.
	const MAX_FILE_BYTES = 3145728; // 3 MB — skip larger files.

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
				add_submenu_page(
					$parent,
					__( 'Scan', 'pressguard' ),
					__( 'Scan', 'pressguard' ),
					$cap,
					self::ADMIN_SLUG,
					array( $this, 'render' )
				);
			},
			10,
			2
		);

		add_action( 'admin_post_pressguard_run_scan', array( $this, 'handle_run' ) );
	}

	/**
	 * Handle the "Run scan" form submission.
	 */
	public function handle_run() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_run_scan' );

		$results = $this->scan();
		update_option( self::RESULTS_OPTION, $results, false );

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&scanned=1' ) );
		exit;
	}

	/**
	 * Run a full (time-boxed) scan: malware signatures + core integrity.
	 *
	 * @return array Results payload.
	 */
	public function scan() {
		$start    = time();
		$findings = array();
		$scanned  = 0;

		// 1) Core integrity against the official checksums.
		foreach ( $this->core_integrity() as $finding ) {
			$findings[] = $finding;
		}

		// 2) Malware signature scan of wp-content PHP files.
		foreach ( $this->iterate_php_files() as $file ) {
			if ( time() - $start > self::TIME_BUDGET ) {
				$findings[] = array(
					'file'     => '',
					'type'     => 'notice',
					'score'    => 0,
					'detail'   => __( 'Scan time budget reached; run again to continue.', 'pressguard' ),
				);
				break;
			}

			$size = @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $size || $size > self::MAX_FILE_BYTES ) {
				continue;
			}

			$content = @file_get_contents( $file ); // phpcs:ignore
			if ( false === $content ) {
				continue;
			}
			++$scanned;

			$matches = Signatures::scan_content( $content );
			foreach ( $matches as $m ) {
				$findings[] = array(
					'file'   => $this->relpath( $file ),
					'type'   => 'malware',
					'score'  => $m['score'],
					'detail' => $m['description'] . ' [' . $m['id'] . ']',
				);
			}
		}

		$results = array(
			'time'          => time(),
			'files_scanned' => $scanned,
			'findings'      => $findings,
		);

		$this->plugin->logger()->log(
			'scanner',
			'scan_complete',
			array(
				'severity' => empty( $findings ) ? Logger::SEVERITY_NOTICE : Logger::SEVERITY_WARNING,
				'message'  => sprintf( 'Scanned %d files, %d findings.', $scanned, count( $findings ) ),
			)
		);

		return $results;
	}

	/**
	 * Verify core files against api.wordpress.org checksums.
	 *
	 * @return array[] Findings for modified/missing core files.
	 */
	private function core_integrity() {
		$findings = array();
		$version  = get_bloginfo( 'version' );
		$locale   = get_locale();

		$url      = add_query_arg(
			array(
				'version' => $version,
				'locale'  => $locale,
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return $findings;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			// Try the en_US fallback (locale checksums can be absent).
			return $findings;
		}

		foreach ( $body['checksums'] as $file => $md5 ) {
			// Only verify core; wp-content is covered by the malware scan.
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
				continue;
			}
			if ( md5_file( $path ) !== $md5 ) {
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

	/**
	 * Yield PHP files under wp-content, excluding PressGuard's own files.
	 *
	 * @return \Generator<string>
	 */
	private function iterate_php_files() {
		$root = WP_CONTENT_DIR;
		if ( ! is_dir( $root ) ) {
			return;
		}

		$skip = array(
			rtrim( PRESSGUARD_DIR, '/' ),              // our plugin.
			WP_CONTENT_DIR . '/uploads/pressguard',    // our snapshot/data.
			WP_CONTENT_DIR . '/cache',                 // cache plugins.
		);

		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( \Exception $e ) {
			return;
		}

		foreach ( $it as $fileinfo ) {
			$path = $fileinfo->getPathname();

			$skipped = false;
			foreach ( $skip as $prefix ) {
				if ( 0 === strpos( $path, $prefix ) ) {
					$skipped = true;
					break;
				}
			}
			if ( $skipped ) {
				continue;
			}

			$ext = strtolower( $fileinfo->getExtension() );
			if ( in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'inc' ), true ) ) {
				yield $path;
			}
		}
	}

	/**
	 * Path relative to the WordPress root, for display.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function relpath( $path ) {
		return ltrim( str_replace( ABSPATH, '', $path ), '/' );
	}

	/**
	 * Render the scan admin page.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$results = get_option( self::RESULTS_OPTION, array() );
		$findings = isset( $results['findings'] ) ? $results['findings'] : array();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Malware &amp; Integrity Scan', 'pressguard' ); ?></h1>

			<?php if ( isset( $_GET['scanned'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Scan finished.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="pressguard_run_scan" />
				<?php wp_nonce_field( 'pressguard_run_scan' ); ?>
				<?php submit_button( __( 'Run scan now', 'pressguard' ), 'primary' ); ?>
			</form>

			<?php if ( ! empty( $results['time'] ) ) : ?>
				<p class="description">
					<?php
					printf(
						/* translators: 1: date, 2: file count */
						esc_html__( 'Last scan: %1$s — %2$d files scanned.', 'pressguard' ),
						esc_html( wp_date( 'Y-m-d H:i', (int) $results['time'] ) ),
						(int) ( $results['files_scanned'] ?? 0 )
					);
					?>
				</p>
			<?php endif; ?>

			<?php if ( empty( $findings ) ) : ?>
				<?php if ( ! empty( $results['time'] ) ) : ?>
					<div class="notice notice-success inline"><p><?php esc_html_e( 'No threats found.', 'pressguard' ); ?></p></div>
				<?php endif; ?>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr>
						<th><?php esc_html_e( 'Severity', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'Type', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'File', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'Detail', 'pressguard' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $findings as $f ) : ?>
						<tr>
							<td><?php echo (int) ( $f['score'] ?? 0 ); ?></td>
							<td><code><?php echo esc_html( $f['type'] ?? '' ); ?></code></td>
							<td><?php echo esc_html( $f['file'] ?? '' ); ?></td>
							<td><?php echo esc_html( $f['detail'] ?? '' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}
}
