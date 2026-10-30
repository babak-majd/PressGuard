<?php
/**
 * Cloudflare integration module.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Integrations\Cloudflare;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * Optional Cloudflare integration: connect with a scoped token, apply the
 * free-plan security settings in one click, toggle Under Attack mode (manually
 * or automatically when the anomaly core detects a surge), and trust
 * CF-Connecting-IP only from Cloudflare's own ranges. Edge protection only
 * applies when DNS is proxied — we detect that and say so.
 */
final class Cloudflare implements Module {

	const ADMIN_SLUG = 'pressguard-cloudflare';
	const REVERT_HOOK = 'pressguard_cf_revert_attack';

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
		return 'cloudflare';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action( 'pressguard_admin_menu', array( $this, 'menu' ), 10, 2 );
		add_action( 'admin_post_pressguard_cf', array( $this, 'handle' ) );

		// Trust Cloudflare edge IPs for forwarded-header resolution when proxied.
		add_filter( 'pressguard_trusted_proxies', array( $this, 'trusted_proxies' ) );

		// Smart Under Attack: react to the anomaly core's detection.
		add_action( 'pressguard_under_attack_detected', array( $this, 'on_attack_detected' ) );
		add_action( self::REVERT_HOOK, array( $this, 'revert_attack' ) );
	}

	/**
	 * The decrypted API token, or ''.
	 *
	 * @return string
	 */
	private function token() {
		return Crypto::decrypt( (string) $this->plugin->config()->get( 'cloudflare.token', '' ) );
	}

	/**
	 * Add Cloudflare's cached IP ranges to the trusted-proxy list when connected
	 * and proxied.
	 *
	 * @param string[] $ranges Existing ranges.
	 * @return string[]
	 */
	public function trusted_proxies( $ranges ) {
		$config = $this->plugin->config();
		if ( ! $config->get( 'cloudflare.proxied', false ) ) {
			return $ranges;
		}
		$cf = (array) $config->get( 'cloudflare.ip_ranges', array() );
		return array_merge( $ranges, $cf );
	}

	/**
	 * Register the submenu.
	 *
	 * @param string $parent Parent slug.
	 * @param string $cap    Capability.
	 */
	public function menu( $parent, $cap ) {
		add_submenu_page( $parent, __( 'Cloudflare', 'pressguard' ), __( 'Cloudflare', 'pressguard' ), $cap, self::ADMIN_SLUG, array( $this, 'render' ) );
	}

	/**
	 * Handle Cloudflare form actions.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_cf' );

		$config = $this->plugin->config();
		$do     = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$notice = 'saved';

		if ( 'connect' === $do ) {
			$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
			$notice = $this->connect( $token ) ? 'connected' : 'error';
		} elseif ( 'disconnect' === $do ) {
			$config->set( 'cloudflare.token', '' );
			$config->set( 'cloudflare.zone', '' );
			$config->set( 'cloudflare.proxied', false );
			$config->set( 'cloudflare.connected', false );
		} elseif ( 'apply_free' === $do ) {
			$notice = $this->apply_free_settings() ? 'applied' : 'error';
		} elseif ( 'under_attack_on' === $do ) {
			$this->set_under_attack( true );
			$notice = 'ua_on';
		} elseif ( 'under_attack_off' === $do ) {
			$this->set_under_attack( false );
			$notice = 'ua_off';
		} elseif ( 'save_auto' === $do ) {
			$config->set( 'cloudflare.smart_under_attack', ! empty( $_POST['smart'] ) );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&notice=' . $notice ) );
		exit;
	}

	/**
	 * Connect: verify token, detect zone + proxied, cache IP ranges.
	 *
	 * @param string $token API token.
	 * @return bool
	 */
	private function connect( $token ) {
		if ( '' === $token ) {
			return false;
		}
		$api = new Api( $token );
		if ( ! $api->verify() ) {
			return false;
		}

		$config = $this->plugin->config();
		$config->set( 'cloudflare.token', Crypto::encrypt( $token ) );
		$config->set( 'cloudflare.connected', true );

		$zone = $api->zone_for( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( $zone ) {
			$config->set( 'cloudflare.zone', $zone );
			$config->set( 'cloudflare.proxied', $api->is_proxied( $zone['id'] ) );
		}
		$config->set( 'cloudflare.ip_ranges', $api->ip_ranges() );

		$this->plugin->logger()->log( 'cloudflare', 'connected', array( 'severity' => 2, 'message' => 'Cloudflare connected.' ) );
		return true;
	}

	/**
	 * Apply the free-plan security settings.
	 *
	 * @return bool
	 */
	private function apply_free_settings() {
		$zone = (array) $this->plugin->config()->get( 'cloudflare.zone', array() );
		$token = $this->token();
		if ( empty( $zone['id'] ) || '' === $token ) {
			return false;
		}
		$api = new Api( $token );
		$ok  = true;
		$ok  = $api->set_setting( $zone['id'], 'always_use_https', 'on' ) && $ok;
		$ok  = $api->set_setting( $zone['id'], 'automatic_https_rewrites', 'on' ) && $ok;
		$ok  = $api->set_setting( $zone['id'], 'ssl', 'full' ) && $ok;
		$ok  = $api->set_setting( $zone['id'], 'min_tls_version', '1.2' ) && $ok;
		$ok  = $api->set_setting( $zone['id'], 'browser_check', 'on' ) && $ok;
		$ok  = $api->set_setting( $zone['id'], 'security_level', 'medium' ) && $ok;

		$this->plugin->logger()->log( 'cloudflare', 'free_settings', array( 'severity' => 2, 'message' => 'Applied free security settings.' ) );
		return $ok;
	}

	/**
	 * Enable/disable edge Under Attack mode.
	 *
	 * @param bool $on Enable.
	 * @return bool
	 */
	public function set_under_attack( $on ) {
		$zone  = (array) $this->plugin->config()->get( 'cloudflare.zone', array() );
		$token = $this->token();
		if ( empty( $zone['id'] ) || '' === $token ) {
			return false;
		}
		$api = new Api( $token );
		$ok  = $api->set_setting( $zone['id'], 'security_level', $on ? 'under_attack' : 'medium' );
		$this->plugin->config()->set( 'cloudflare.under_attack_active', (bool) $on );
		return $ok;
	}

	/**
	 * React to anomaly-detected attacks: enable edge Under Attack + schedule revert.
	 *
	 * @param int $until Unix timestamp the attack window lasts until.
	 */
	public function on_attack_detected( $until ) {
		$config = $this->plugin->config();
		if ( ! $config->get( 'cloudflare.connected', false ) || ! $config->get( 'cloudflare.smart_under_attack', false ) ) {
			return;
		}
		if ( $config->get( 'cloudflare.under_attack_active', false ) ) {
			return;
		}
		$this->set_under_attack( true );
		$this->plugin->logger()->log( 'cloudflare', 'auto_under_attack', array( 'severity' => 4, 'message' => 'Auto-enabled Cloudflare Under Attack.' ) );
		wp_schedule_single_event( max( $until, time() + 300 ), self::REVERT_HOOK );
	}

	/**
	 * Revert edge Under Attack mode after the window.
	 */
	public function revert_attack() {
		if ( $this->plugin->config()->get( 'cloudflare.under_attack_active', false ) ) {
			$this->set_under_attack( false );
			$this->plugin->logger()->log( 'cloudflare', 'under_attack_revert', array( 'severity' => 2, 'message' => 'Reverted Cloudflare Under Attack.' ) );
		}
	}

	/**
	 * Render the Cloudflare screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$config    = $this->plugin->config();
		$connected = (bool) $config->get( 'cloudflare.connected', false );
		$zone      = (array) $config->get( 'cloudflare.zone', array() );
		$proxied   = (bool) $config->get( 'cloudflare.proxied', false );
		$post      = admin_url( 'admin-post.php' );
		$notice    = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Cloudflare', 'pressguard' ); ?></h1>
			<?php if ( 'connected' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Connected to Cloudflare.', 'pressguard' ); ?></p></div>
			<?php elseif ( 'applied' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Free security settings applied.', 'pressguard' ); ?></p></div>
			<?php elseif ( 'error' === $notice ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Cloudflare request failed. Check the API token and its permissions.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<?php if ( ! $connected ) : ?>
				<p class="description"><?php esc_html_e( 'Connect with a scoped API token (Zone → DNS + Zone Settings edit). Edge protection only applies when your DNS is proxied through Cloudflare (orange cloud).', 'pressguard' ); ?></p>
				<form method="post" action="<?php echo esc_url( $post ); ?>">
					<input type="hidden" name="action" value="pressguard_cf" />
					<input type="hidden" name="do" value="connect" />
					<?php wp_nonce_field( 'pressguard_cf' ); ?>
					<table class="form-table"><tr>
						<th><?php esc_html_e( 'API token', 'pressguard' ); ?></th>
						<td><input type="password" name="token" class="regular-text" autocomplete="new-password" /></td>
					</tr></table>
					<?php submit_button( __( 'Connect', 'pressguard' ), 'primary' ); ?>
				</form>
			<?php else : ?>
				<div class="pressguard-cards">
					<div class="pressguard-card pressguard-card--ok">
						<span class="pressguard-card__label"><?php esc_html_e( 'Zone', 'pressguard' ); ?></span>
						<span class="pressguard-card__value" style="font-size:15px;"><?php echo esc_html( $zone['name'] ?? '—' ); ?></span>
					</div>
					<div class="pressguard-card pressguard-card--<?php echo $proxied ? 'ok' : 'warn'; ?>">
						<span class="pressguard-card__label"><?php esc_html_e( 'Proxied (orange cloud)', 'pressguard' ); ?></span>
						<span class="pressguard-card__value"><?php echo $proxied ? esc_html__( 'Yes', 'pressguard' ) : esc_html__( 'No', 'pressguard' ); ?></span>
					</div>
				</div>
				<?php if ( ! $proxied ) : ?>
					<div class="notice notice-warning inline"><p><?php esc_html_e( 'DNS is not proxied — settings will apply but edge filtering/Under Attack have no effect until you enable the orange cloud.', 'pressguard' ); ?></p></div>
				<?php endif; ?>

				<p>
					<?php $this->mini_form( $post, 'apply_free', __( 'Apply free security settings', 'pressguard' ), 'primary' ); ?>
					<?php $this->mini_form( $post, 'under_attack_on', __( 'Enable Under Attack', 'pressguard' ), 'secondary' ); ?>
					<?php $this->mini_form( $post, 'under_attack_off', __( 'Disable Under Attack', 'pressguard' ), 'secondary' ); ?>
				</p>

				<form method="post" action="<?php echo esc_url( $post ); ?>">
					<input type="hidden" name="action" value="pressguard_cf" />
					<input type="hidden" name="do" value="save_auto" />
					<?php wp_nonce_field( 'pressguard_cf' ); ?>
					<label><input type="checkbox" name="smart" value="1" <?php checked( (bool) $config->get( 'cloudflare.smart_under_attack', false ) ); ?> />
						<?php esc_html_e( 'Automatically enable Under Attack when PressGuard detects an attack surge (auto-reverts after the window).', 'pressguard' ); ?></label>
					<?php submit_button( __( 'Save', 'pressguard' ) ); ?>
				</form>

				<?php $this->mini_form( $post, 'disconnect', __( 'Disconnect', 'pressguard' ), 'delete' ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render a tiny single-action form.
	 *
	 * @param string $post   admin-post URL.
	 * @param string $action do value.
	 * @param string $label  Button label.
	 * @param string $type   Button type.
	 */
	private function mini_form( $post, $action, $label, $type ) {
		?>
		<form method="post" action="<?php echo esc_url( $post ); ?>" style="display:inline;margin-inline-end:6px;">
			<input type="hidden" name="action" value="pressguard_cf" />
			<input type="hidden" name="do" value="<?php echo esc_attr( $action ); ?>" />
			<?php wp_nonce_field( 'pressguard_cf' ); ?>
			<?php submit_button( $label, $type, 'submit', false ); ?>
		</form>
		<?php
	}
}
