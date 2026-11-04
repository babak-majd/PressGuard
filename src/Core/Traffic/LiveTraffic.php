<?php
/**
 * Live Traffic — optional per-request logging + viewer.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Traffic;

use PressGuard\Admin\EventsTable;
use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Ip;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * When enabled, logs WordPress-handled front-end requests (not static assets —
 * those never reach PHP) to the event log under the "traffic" module, so you
 * can watch who is hitting the site. Off by default; capped + purged like all
 * event logging to avoid DB bloat. The viewer reuses the native list table.
 */
final class LiveTraffic implements Module {

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * IP resolver.
	 *
	 * @var Ip
	 */
	private $ip;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
		$this->ip     = new Ip( $plugin->config() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'traffic';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Live Traffic', 'pressguard' ), __( 'Live Traffic', 'pressguard' ), $cap, 'pressguard-traffic', array( $this, 'render' ) );
			},
			10,
			2
		);

		if ( (bool) $this->plugin->config()->get( 'traffic.enabled', false ) ) {
			add_action( 'template_redirect', array( $this, 'log_request' ), 99 );
		}
	}

	/**
	 * Log the current front-end request.
	 */
	public function log_request() {
		if ( is_admin() || wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		$type = is_404() ? 'visit_404' : 'visit';
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';

		$this->plugin->logger()->log(
			'traffic',
			$type,
			array(
				'severity' => Logger::SEVERITY_DEBUG,
				'ip'       => $this->ip->client_ip(),
				'message'  => ( is_user_logged_in() ? '[auth] ' : '' ) . substr( $uri, 0, 255 ),
				'context'  => array( 'ua' => substr( $ua, 0, 200 ) ),
			)
		);
	}

	/**
	 * Render the Live Traffic screen (events filtered to the traffic module).
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// Force the module filter to "traffic" for this screen.
		$_REQUEST['module'] = 'traffic';

		$enabled = (bool) $this->plugin->config()->get( 'traffic.enabled', false );
		$table   = new EventsTable();
		$table->prepare_items();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Live Traffic', 'pressguard' ); ?></h1>
			<?php if ( ! $enabled ) : ?>
				<div class="notice notice-info inline"><p>
					<?php
					printf(
						/* translators: %s: settings URL */
						wp_kses_post( __( 'Request logging is off. Enable it under <a href="%s">Settings → General</a> to record traffic here.', 'pressguard' ) ),
						esc_url( admin_url( 'admin.php?page=pressguard-settings&tab=general' ) )
					);
					?>
				</p></div>
			<?php endif; ?>
			<form method="get">
				<input type="hidden" name="page" value="pressguard-traffic" />
				<input type="hidden" name="module" value="traffic" />
				<?php $table->display(); ?>
			</form>
		</div>
		<?php
	}
}
