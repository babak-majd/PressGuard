<?php
/**
 * Full settings import / export.
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Exports every setting as a versioned JSON file and imports it back, with two
 * safety rules: secrets (encrypted keys/tokens) are never exported, and
 * environment-dependent keys that don't fit the target site (e.g. per-plugin
 * access for plugins that aren't installed) are skipped with a clear report —
 * so importing a config can't break the destination site.
 */
final class ImportExport {

	const SLUG = 'pressguard-tools';

	/**
	 * Keys never exported (sensitive) — dot-paths.
	 *
	 * @var string[]
	 */
	private static $sensitive = array(
		'ssl.acme.account_key',
		'ssl.cert.key',
		'ssl.cloudflare_token',
		'cloudflare.token',
		'alerts.telegram.token',
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
	 * Register the page + handlers.
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Tools (Import / Export)', 'pressguard' ), __( 'Tools', 'pressguard' ), $cap, self::SLUG, array( $this, 'render' ) );
			},
			10,
			2
		);
		add_action( 'admin_post_pressguard_export', array( $this, 'handle_export' ) );
		add_action( 'admin_post_pressguard_import', array( $this, 'handle_import' ) );
	}

	/**
	 * Stream the export file.
	 */
	public function handle_export() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_export' );

		$data = $this->plugin->config()->all();
		foreach ( self::$sensitive as $path ) {
			$data = $this->forget_path( $data, $path );
		}
		$payload = array(
			'_pressguard' => true,
			'_version'    => PRESSGUARD_VERSION,
			'_exported'   => gmdate( 'c' ),
			'settings'    => $data,
		);

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=pressguard-settings-' . gmdate( 'Ymd-His' ) . '.json' );
		echo wp_json_encode( $payload, JSON_PRETTY_PRINT ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Handle an uploaded import file.
	 */
	public function handle_import() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_import' );

		if ( empty( $_FILES['file']['tmp_name'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$this->redirect( 'error', __( 'No file uploaded.', 'pressguard' ) );
		}
		$raw  = file_get_contents( $_FILES['file']['tmp_name'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$json = json_decode( (string) $raw, true );
		if ( ! is_array( $json ) || empty( $json['_pressguard'] ) || ! isset( $json['settings'] ) ) {
			$this->redirect( 'error', __( 'Not a valid PressGuard export file.', 'pressguard' ) );
		}

		$incoming = (array) $json['settings'];
		$mode     = ( isset( $_POST['mode'] ) && 'replace' === $_POST['mode'] ) ? 'replace' : 'merge';

		$report = $this->sanitize_for_environment( $incoming );

		// Preserve existing secrets regardless of import mode.
		$current = $this->plugin->config()->all();
		foreach ( self::$sensitive as $path ) {
			$val = $this->get_path( $current, $path );
			if ( null !== $val ) {
				$report['data'] = $this->set_path( $report['data'], $path, $val );
			}
		}

		if ( 'merge' === $mode ) {
			$merged = array_replace_recursive( $current, $report['data'] );
		} else {
			$merged = $report['data'];
		}
		$this->plugin->config()->replace( $merged );

		set_transient( 'pressguard_import_report', $report['skipped'], 60 );
		$this->redirect( 'imported', '' );
	}

	/**
	 * Strip/adjust environment-dependent keys; returns ['data'=>..,'skipped'=>[]].
	 *
	 * @param array $incoming Imported settings.
	 * @return array
	 */
	private function sanitize_for_environment( array $incoming ) {
		$skipped = array();

		// Per-plugin access entries for plugins that aren't installed here.
		if ( ! empty( $incoming['access']['plugin_roles'] ) && is_array( $incoming['access']['plugin_roles'] ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$installed = array_keys( get_plugins() );
			foreach ( array_keys( $incoming['access']['plugin_roles'] ) as $file ) {
				if ( ! in_array( $file, $installed, true ) ) {
					unset( $incoming['access']['plugin_roles'][ $file ] );
					$skipped[] = sprintf( 'access.plugin_roles: %s (plugin not installed)', $file );
				}
			}
		}

		// Drop any sensitive keys that slipped into the file.
		foreach ( self::$sensitive as $path ) {
			if ( null !== $this->get_path( $incoming, $path ) ) {
				$incoming  = $this->forget_path( $incoming, $path );
				$skipped[] = $path . ' (sensitive — not imported)';
			}
		}

		return array( 'data' => $incoming, 'skipped' => $skipped );
	}

	/**
	 * Render the Tools page.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$post   = admin_url( 'admin-post.php' );
		$notice = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$report = get_transient( 'pressguard_import_report' );
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Import / Export', 'pressguard' ); ?></h1>
			<?php if ( 'imported' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings imported.', 'pressguard' ); ?></p></div>
				<?php if ( is_array( $report ) && ! empty( $report ) ) : ?>
					<div class="notice notice-warning"><p><strong><?php esc_html_e( 'Skipped (environment-dependent or sensitive):', 'pressguard' ); ?></strong></p>
						<ul style="list-style:disc;margin-inline-start:20px;"><?php foreach ( $report as $line ) : ?><li><?php echo esc_html( $line ); ?></li><?php endforeach; ?></ul>
					</div>
					<?php delete_transient( 'pressguard_import_report' ); ?>
				<?php endif; ?>
			<?php elseif ( 'error' === $notice ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php echo esc_html( isset( $_GET['msg'] ) ? rawurldecode( sanitize_text_field( wp_unslash( $_GET['msg'] ) ) ) : __( 'Import failed.', 'pressguard' ) ); ?></p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Export', 'pressguard' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Download all settings as JSON (secrets and API tokens are excluded).', 'pressguard' ); ?></p>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_export" />
				<?php wp_nonce_field( 'pressguard_export' ); ?>
				<?php submit_button( __( 'Export settings', 'pressguard' ), 'secondary' ); ?>
			</form>

			<h2><?php esc_html_e( 'Import', 'pressguard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( $post ); ?>" enctype="multipart/form-data">
				<input type="hidden" name="action" value="pressguard_import" />
				<?php wp_nonce_field( 'pressguard_import' ); ?>
				<p><input type="file" name="file" accept="application/json,.json" required /></p>
				<p>
					<label><input type="radio" name="mode" value="merge" checked /> <?php esc_html_e( 'Merge with current settings', 'pressguard' ); ?></label>
					&nbsp;
					<label><input type="radio" name="mode" value="replace" /> <?php esc_html_e( 'Replace all settings', 'pressguard' ); ?></label>
				</p>
				<?php submit_button( __( 'Import settings', 'pressguard' ), 'primary' ); ?>
			</form>
		</div>
		<?php
	}

	// ---- dot-path helpers -------------------------------------------------

	/**
	 * Get a value by dot-path.
	 *
	 * @param array  $data Data.
	 * @param string $path Path.
	 * @return mixed|null
	 */
	private function get_path( $data, $path ) {
		foreach ( explode( '.', $path ) as $seg ) {
			if ( is_array( $data ) && array_key_exists( $seg, $data ) ) {
				$data = $data[ $seg ];
			} else {
				return null;
			}
		}
		return $data;
	}

	/**
	 * Set a value by dot-path (returns modified array).
	 *
	 * @param array  $data  Data.
	 * @param string $path  Path.
	 * @param mixed  $value Value.
	 * @return array
	 */
	private function set_path( $data, $path, $value ) {
		$segs = explode( '.', $path );
		$ref  = &$data;
		foreach ( $segs as $i => $seg ) {
			if ( count( $segs ) - 1 === $i ) {
				$ref[ $seg ] = $value;
			} else {
				if ( ! isset( $ref[ $seg ] ) || ! is_array( $ref[ $seg ] ) ) {
					$ref[ $seg ] = array();
				}
				$ref = &$ref[ $seg ];
			}
		}
		unset( $ref );
		return $data;
	}

	/**
	 * Remove a value by dot-path.
	 *
	 * @param array  $data Data.
	 * @param string $path Path.
	 * @return array
	 */
	private function forget_path( $data, $path ) {
		$segs = explode( '.', $path );
		$ref  = &$data;
		foreach ( $segs as $i => $seg ) {
			if ( count( $segs ) - 1 === $i ) {
				unset( $ref[ $seg ] );
			} else {
				if ( ! isset( $ref[ $seg ] ) || ! is_array( $ref[ $seg ] ) ) {
					return $data;
				}
				$ref = &$ref[ $seg ];
			}
		}
		unset( $ref );
		return $data;
	}

	/**
	 * Redirect back with a notice.
	 *
	 * @param string $notice Notice code.
	 * @param string $msg    Optional message.
	 */
	private function redirect( $notice, $msg ) {
		$url = admin_url( 'admin.php?page=' . self::SLUG . '&notice=' . $notice );
		if ( '' !== $msg ) {
			$url .= '&msg=' . rawurlencode( $msg );
		}
		wp_safe_redirect( $url );
		exit;
	}
}
