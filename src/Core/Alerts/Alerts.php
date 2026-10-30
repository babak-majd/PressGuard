<?php
/**
 * Security alerts (email / webhook / Telegram).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Alerts;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Dispatches notifications when noteworthy events are logged. Channels: email
 * (wp_mail), a generic webhook (JSON POST), and Telegram (bot API). Only events
 * at or above a configured severity are sent, with light rate-limiting so an
 * attack burst can't flood the channel.
 */
final class Alerts implements Module {

	const ADMIN_SLUG = 'pressguard-alerts';

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
		return 'alerts';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action( 'pressguard_event_logged', array( $this, 'maybe_alert' ), 10, 4 );
		add_action( 'pressguard_admin_menu', array( $this, 'menu' ), 10, 2 );
		add_action( 'admin_post_pressguard_alerts', array( $this, 'handle' ) );
	}

	/**
	 * Decide whether to alert, then dispatch.
	 *
	 * @param string $module   Module id.
	 * @param string $type     Event type.
	 * @param int    $severity Severity.
	 * @param array  $args     Event args.
	 */
	public function maybe_alert( $module, $type, $severity, $args ) {
		$config = $this->plugin->config();
		if ( ! (bool) $config->get( 'alerts.enabled', false ) ) {
			return;
		}
		$min = (int) $config->get( 'alerts.min_severity', 4 );
		if ( (int) $severity < $min ) {
			return;
		}

		// Rate-limit: at most one alert per type per 5 minutes.
		$rl = 'pressguard_alert_' . md5( $module . $type );
		if ( get_transient( $rl ) ) {
			return;
		}
		set_transient( $rl, 1, 5 * MINUTE_IN_SECONDS );

		$site    = wp_parse_url( home_url(), PHP_URL_HOST );
		$subject = sprintf( '[PressGuard] %s: %s', $site, $type );
		$message = sprintf(
			"Site: %s\nEvent: %s / %s\nSeverity: %d\nIP: %s\nUser: %d\nMessage: %s\nTime: %s",
			$site,
			$module,
			$type,
			$severity,
			isset( $args['ip'] ) ? $args['ip'] : '',
			isset( $args['user_id'] ) ? (int) $args['user_id'] : 0,
			isset( $args['message'] ) ? $args['message'] : '',
			current_time( 'mysql' )
		);

		if ( (bool) $config->get( 'alerts.email.enabled', false ) ) {
			$to = $config->get( 'alerts.email.to', get_option( 'admin_email' ) );
			wp_mail( $to, $subject, $message );
		}
		if ( (bool) $config->get( 'alerts.webhook.enabled', false ) ) {
			$this->send_webhook( (string) $config->get( 'alerts.webhook.url', '' ), $module, $type, $severity, $args );
		}
		if ( (bool) $config->get( 'alerts.telegram.enabled', false ) ) {
			$this->send_telegram( $config, $message );
		}
	}

	/**
	 * POST a JSON payload to a webhook.
	 *
	 * @param string $url      Webhook URL.
	 * @param string $module   Module.
	 * @param string $type     Type.
	 * @param int    $severity Severity.
	 * @param array  $args     Args.
	 */
	private function send_webhook( $url, $module, $type, $severity, $args ) {
		if ( '' === $url ) {
			return;
		}
		wp_remote_post(
			$url,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'site'     => home_url(),
						'module'   => $module,
						'type'     => $type,
						'severity' => $severity,
						'ip'       => $args['ip'] ?? '',
						'message'  => $args['message'] ?? '',
						'time'     => current_time( 'mysql' ),
					)
				),
			)
		);
	}

	/**
	 * Send a Telegram message via the bot API.
	 *
	 * @param \PressGuard\Support\Config $config  Config.
	 * @param string                    $message Message.
	 */
	private function send_telegram( $config, $message ) {
		$token = (string) $config->get( 'alerts.telegram.token', '' );
		$chat  = (string) $config->get( 'alerts.telegram.chat_id', '' );
		if ( '' === $token || '' === $chat ) {
			return;
		}
		wp_remote_post(
			'https://api.telegram.org/bot' . $token . '/sendMessage',
			array(
				'timeout' => 10,
				'body'    => array(
					'chat_id' => $chat,
					'text'    => $message,
				),
			)
		);
	}

	/**
	 * Register the submenu.
	 *
	 * @param string $parent Parent slug.
	 * @param string $cap    Capability.
	 */
	public function menu( $parent, $cap ) {
		add_submenu_page( $parent, __( 'Alerts', 'pressguard' ), __( 'Alerts', 'pressguard' ), $cap, self::ADMIN_SLUG, array( $this, 'render' ) );
	}

	/**
	 * Handle the settings form.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_alerts' );
		$c = $this->plugin->config();

		$c->set( 'alerts.enabled', ! empty( $_POST['enabled'] ) );
		$c->set( 'alerts.min_severity', isset( $_POST['min_severity'] ) ? (int) $_POST['min_severity'] : 4 );
		$c->set( 'alerts.email.enabled', ! empty( $_POST['email_enabled'] ) );
		$c->set( 'alerts.email.to', isset( $_POST['email_to'] ) ? sanitize_email( wp_unslash( $_POST['email_to'] ) ) : '' );
		$c->set( 'alerts.webhook.enabled', ! empty( $_POST['webhook_enabled'] ) );
		$c->set( 'alerts.webhook.url', isset( $_POST['webhook_url'] ) ? esc_url_raw( wp_unslash( $_POST['webhook_url'] ) ) : '' );
		$c->set( 'alerts.telegram.enabled', ! empty( $_POST['telegram_enabled'] ) );
		$c->set( 'alerts.telegram.token', isset( $_POST['telegram_token'] ) ? sanitize_text_field( wp_unslash( $_POST['telegram_token'] ) ) : '' );
		$c->set( 'alerts.telegram.chat_id', isset( $_POST['telegram_chat'] ) ? sanitize_text_field( wp_unslash( $_POST['telegram_chat'] ) ) : '' );

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&updated=1' ) );
		exit;
	}

	/**
	 * Render the Alerts screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$c   = $this->plugin->config();
		$post = admin_url( 'admin-post.php' );
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Security Alerts', 'pressguard' ); ?></h1>
			<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Saved.', 'pressguard' ); ?></p></div>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_alerts" />
				<?php wp_nonce_field( 'pressguard_alerts' ); ?>
				<table class="form-table" role="presentation">
					<tr><th><?php esc_html_e( 'Enable alerts', 'pressguard' ); ?></th><td><label><input type="checkbox" name="enabled" value="1" <?php checked( (bool) $c->get( 'alerts.enabled', false ) ); ?> /> <?php esc_html_e( 'On', 'pressguard' ); ?></label></td></tr>
					<tr><th><?php esc_html_e( 'Minimum severity', 'pressguard' ); ?></th><td>
						<select name="min_severity">
							<?php foreach ( array( 2 => 'Notice', 3 => 'Warning', 4 => 'Error', 5 => 'Critical' ) as $lvl => $lbl ) : ?>
								<option value="<?php echo (int) $lvl; ?>" <?php selected( (int) $c->get( 'alerts.min_severity', 4 ), $lvl ); ?>><?php echo esc_html( $lbl ); ?></option>
							<?php endforeach; ?>
						</select>
					</td></tr>
					<tr><th><?php esc_html_e( 'Email', 'pressguard' ); ?></th><td>
						<label><input type="checkbox" name="email_enabled" value="1" <?php checked( (bool) $c->get( 'alerts.email.enabled', false ) ); ?> /> <?php esc_html_e( 'Send email to', 'pressguard' ); ?></label>
						<input type="email" name="email_to" class="regular-text" value="<?php echo esc_attr( (string) $c->get( 'alerts.email.to', get_option( 'admin_email' ) ) ); ?>" />
					</td></tr>
					<tr><th><?php esc_html_e( 'Webhook', 'pressguard' ); ?></th><td>
						<label><input type="checkbox" name="webhook_enabled" value="1" <?php checked( (bool) $c->get( 'alerts.webhook.enabled', false ) ); ?> /> <?php esc_html_e( 'POST JSON to', 'pressguard' ); ?></label>
						<input type="url" name="webhook_url" class="regular-text" value="<?php echo esc_attr( (string) $c->get( 'alerts.webhook.url', '' ) ); ?>" placeholder="https://" />
					</td></tr>
					<tr><th><?php esc_html_e( 'Telegram', 'pressguard' ); ?></th><td>
						<label><input type="checkbox" name="telegram_enabled" value="1" <?php checked( (bool) $c->get( 'alerts.telegram.enabled', false ) ); ?> /> <?php esc_html_e( 'Bot token / chat ID', 'pressguard' ); ?></label><br/>
						<input type="text" name="telegram_token" class="regular-text" value="<?php echo esc_attr( (string) $c->get( 'alerts.telegram.token', '' ) ); ?>" placeholder="bot token" />
						<input type="text" name="telegram_chat" class="regular-text" value="<?php echo esc_attr( (string) $c->get( 'alerts.telegram.chat_id', '' ) ); ?>" placeholder="chat id" />
					</td></tr>
				</table>
				<?php submit_button( __( 'Save', 'pressguard' ) ); ?>
			</form>
		</div>
		<?php
	}
}
