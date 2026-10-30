<?php
/**
 * Third-party compatibility (WooCommerce, Elementor, Gutenberg, caches, PressPilot).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Compat;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps PressGuard out of the way of legitimate first-party flows. Rather than
 * disabling the firewall, it marks known-safe contexts as "trusted" so only the
 * POST-body rule matching is skipped (IP/UA/rate/geo still apply), exempts
 * critical endpoints from the Under Attack challenge, and widens the REST
 * public allowlist. Each integration can be toggled.
 */
final class Compatibility implements Module {

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
		return 'compat';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_filter( 'pressguard_firewall_trusted_context', array( $this, 'is_trusted' ) );
		add_filter( 'pressguard_under_attack_exempt', array( $this, 'is_exempt' ) );
		add_filter( 'pressguard_rest_public_prefixes', array( $this, 'rest_prefixes' ) );

		add_action( 'pressguard_admin_menu', array( $this, 'menu' ), 10, 2 );
	}

	/**
	 * Whether a compatibility integration is enabled (default on).
	 *
	 * @param string $key Integration key.
	 * @return bool
	 */
	private function on( $key ) {
		return (bool) $this->plugin->config()->get( 'compat.' . $key, true );
	}

	/**
	 * The current request's REST route (from pretty or query-string form), or ''.
	 *
	 * @return string
	 */
	private function rest_route() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		$prefix = '/' . ltrim( rest_get_url_prefix(), '/' ) . '/';
		if ( false !== strpos( $path, $prefix ) ) {
			return '/' . ltrim( substr( $path, strpos( $path, $prefix ) + strlen( $prefix ) ), '/' );
		}
		// Plain-permalink form: ?rest_route=/wc/store/...
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['rest_route'] ) ) {
			return '/' . ltrim( (string) wp_unslash( $_GET['rest_route'] ), '/' );
		}
		return '';
	}

	/**
	 * Is there a logged-in cookie on this request?
	 *
	 * @return bool
	 */
	private function has_login_cookie() {
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Mark trusted first-party contexts (skips POST-body rule matching only).
	 *
	 * @param bool $trusted Current value.
	 * @return bool
	 */
	public function is_trusted( $trusted ) {
		if ( $trusted ) {
			return true;
		}
		$route = $this->rest_route();
		// phpcs:disable WordPress.Security.NonceVerification
		$action = isset( $_REQUEST['action'] ) ? (string) wp_unslash( $_REQUEST['action'] ) : '';
		$get    = wp_unslash( $_GET );
		// phpcs:enable

		// WooCommerce: AJAX + its REST namespaces + webhooks.
		if ( $this->on( 'woocommerce' ) ) {
			if ( isset( $get['wc-ajax'] ) ) {
				return true;
			}
			if ( '' !== $route && preg_match( '#^/(wc|wc-analytics|wc-admin)/#', $route ) ) {
				return true;
			}
		}

		// Elementor: editor AJAX + preview + its REST namespace (logged-in).
		if ( $this->on( 'elementor' ) && $this->has_login_cookie() ) {
			if ( 0 === strpos( $action, 'elementor' ) || isset( $get['elementor-preview'] ) || isset( $get['elementor_library'] ) ) {
				return true;
			}
			if ( '' !== $route && 0 === strpos( $route, '/elementor/' ) ) {
				return true;
			}
		}

		// Gutenberg / block editor: core REST writes by a logged-in user.
		if ( $this->on( 'gutenberg' ) && $this->has_login_cookie() ) {
			if ( '' !== $route && preg_match( '#^/wp/v2/#', $route ) ) {
				return true;
			}
		}

		// PressPilot: its REST namespace when an auth attempt is present
		// (logged-in cookie or its API key header). Anonymous callers without
		// credentials are still inspected + rate-limited.
		if ( $this->on( 'presspilot' ) && '' !== $route && 0 === strpos( $route, '/presspilot/' ) ) {
			if ( $this->has_login_cookie() || ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) || ! empty( $_SERVER['HTTP_X_PRESSPILOT_KEY'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Exempt critical endpoints from the Under Attack challenge.
	 *
	 * @param bool $exempt Current value.
	 * @return bool
	 */
	public function is_exempt( $exempt ) {
		if ( $exempt ) {
			return true;
		}
		$route = $this->rest_route();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $this->on( 'woocommerce' ) && isset( $_GET['wc-ajax'] ) ) {
			return true;
		}
		if ( '' !== $route ) {
			if ( $this->on( 'woocommerce' ) && preg_match( '#^/(wc|wc-analytics)/#', $route ) ) {
				return true;
			}
			if ( $this->on( 'presspilot' ) && 0 === strpos( $route, '/presspilot/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Widen the REST public allowlist used by REST hardening.
	 *
	 * @param string[] $prefixes Existing prefixes.
	 * @return string[]
	 */
	public function rest_prefixes( $prefixes ) {
		if ( $this->on( 'woocommerce' ) ) {
			$prefixes[] = '/wc/store/'; // Public Store API (cart/products).
		}
		return $prefixes;
	}

	/**
	 * Register the Compatibility submenu.
	 *
	 * @param string $parent Parent slug.
	 * @param string $cap    Capability.
	 */
	public function menu( $parent, $cap ) {
		add_submenu_page( $parent, __( 'Compatibility', 'pressguard' ), __( 'Compatibility', 'pressguard' ), $cap, 'pressguard-compat', array( $this, 'render' ) );
	}

	/**
	 * Detected integrations for the status screen.
	 *
	 * @return array<string,array{label:string,active:bool}>
	 */
	private function detected() {
		$cache = defined( 'WP_ROCKET_VERSION' ) || defined( 'W3TC' ) || defined( 'LSCWP_V' ) || defined( 'WPCACHEHOME' ) || function_exists( 'wp_cache_is_enabled' );
		return array(
			'woocommerce' => array( 'label' => 'WooCommerce', 'active' => class_exists( 'WooCommerce' ) ),
			'elementor'   => array( 'label' => 'Elementor', 'active' => defined( 'ELEMENTOR_VERSION' ) ),
			'gutenberg'   => array( 'label' => 'Gutenberg / Block editor', 'active' => true ),
			'presspilot'  => array( 'label' => 'PressPilot', 'active' => defined( 'PRESSPILOT_VERSION' ) || in_array( 'presspilot/presspilot.php', (array) get_option( 'active_plugins', array() ), true ) ),
			'cache'       => array( 'label' => __( 'Page cache plugin', 'pressguard' ), 'active' => (bool) $cache ),
		);
	}

	/**
	 * Render the Compatibility screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$config = $this->plugin->config();

		if ( isset( $_POST['pressguard_compat_save'] ) ) {
			check_admin_referer( 'pressguard_compat' );
			foreach ( array( 'woocommerce', 'elementor', 'gutenberg', 'presspilot' ) as $k ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$config->set( 'compat.' . $k, ! empty( $_POST[ 'compat_' . $k ] ) );
			}
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'pressguard' ) . '</p></div>';
		}

		$rows = $this->detected();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Compatibility', 'pressguard' ); ?></h1>
			<p class="description"><?php esc_html_e( 'PressGuard auto-detects these and skips body rule-matching on their legitimate endpoints (IP, rate and geo protection still apply). Toggle an integration off only if you need to.', 'pressguard' ); ?></p>
			<form method="post">
				<?php wp_nonce_field( 'pressguard_compat' ); ?>
				<table class="widefat striped" style="max-width:640px;">
					<thead><tr><th><?php esc_html_e( 'Integration', 'pressguard' ); ?></th><th><?php esc_html_e( 'Detected', 'pressguard' ); ?></th><th><?php esc_html_e( 'Compatibility', 'pressguard' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $rows as $key => $row ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $row['label'] ); ?></strong></td>
							<td><?php echo $row['active'] ? '<span style="color:#00a32a;">&#10003; ' . esc_html__( 'Active', 'pressguard' ) . '</span>' : '<span style="color:#646970;">&mdash;</span>'; ?></td>
							<td>
								<?php if ( 'cache' === $key ) : ?>
									<span class="description"><?php esc_html_e( 'Handled automatically (no cache busting; challenges set DONOTCACHEPAGE).', 'pressguard' ); ?></span>
								<?php else : ?>
									<label><input type="checkbox" name="compat_<?php echo esc_attr( $key ); ?>" value="1" <?php checked( $this->on( $key ) ); ?> /> <?php esc_html_e( 'Enabled', 'pressguard' ); ?></label>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<?php submit_button( __( 'Save', 'pressguard' ), 'primary', 'pressguard_compat_save' ); ?>
			</form>
		</div>
		<?php
	}
}
