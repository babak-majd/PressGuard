<?php
/**
 * First-run setup wizard.
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Core\Audit\Audit;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * A guided onboarding shown after activation. It runs the security audit and
 * lets the admin apply a recommended baseline in one click: full hardening
 * (including .htaccess PHP-block in uploads and sensitive-file protection), the
 * firewall, login protections, and a reminder to set up 2FA. Every step is
 * reversible from Settings; the wizard never changes anything until the admin
 * clicks Apply.
 */
final class Wizard {

	const SLUG = 'pressguard-wizard';

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
	 * Register the page, handler, and first-run notice.
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Setup Wizard', 'pressguard' ), __( 'Setup Wizard', 'pressguard' ), $cap, self::SLUG, array( $this, 'render' ) );
			},
			10,
			2
		);
		add_action( 'admin_post_pressguard_wizard', array( $this, 'handle' ) );
		add_action( 'admin_notices', array( $this, 'first_run_notice' ) );
	}

	/**
	 * Show a one-time notice pointing to the wizard after activation.
	 */
	public function first_run_notice() {
		if ( ! current_user_can( 'manage_options' ) || ! get_option( 'pressguard_wizard_pending' ) ) {
			return;
		}
		$url = admin_url( 'admin.php?page=' . self::SLUG );
		echo '<div class="notice notice-info"><p>';
		printf(
			/* translators: %s: wizard URL */
			wp_kses_post( __( 'PressGuard is active. <a href="%s">Run the setup wizard</a> to harden your site in one click.', 'pressguard' ) ),
			esc_url( $url )
		);
		echo '</p></div>';
	}

	/**
	 * Apply the recommended baseline / dismiss.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_wizard' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';

		if ( 'apply' === $do ) {
			$this->apply_recommended();
		}

		update_option( 'pressguard_wizard_done', 1, false );
		delete_option( 'pressguard_wizard_pending' );

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SLUG . '&notice=' . ( 'apply' === $do ? 'applied' : 'dismissed' ) ) );
		exit;
	}

	/**
	 * Apply the recommended secure baseline. Setting hardening keys triggers the
	 * .htaccess sync (PHP-block in uploads + sensitive-file protection).
	 */
	private function apply_recommended() {
		$c = $this->plugin->config();

		$c->set( 'hardening.enabled', true );
		foreach ( array( 'disable_file_edit', 'disable_xmlrpc', 'hide_wp_version', 'block_user_enumeration', 'security_headers', 'block_php_uploads', 'protect_sensitive_files' ) as $sw ) {
			$c->set( 'hardening.' . $sw, true );
		}

		$c->set( 'login.enabled', true );
		$c->set( 'login.lockout.enabled', true );
		$c->set( 'login.two_factor.enabled', true );
		$c->set( 'login.generic_errors', true );

		$c->set( 'firewall.enabled', true );
		$c->set( 'firewall.mode', 'enabled' );

		$c->set( 'activity.enabled', true );

		$this->plugin->logger()->log( 'wizard', 'applied', array( 'severity' => 2, 'message' => 'Recommended baseline applied via setup wizard.' ) );
	}

	/**
	 * Render the wizard.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$audit  = ( new Audit( $this->plugin ) )->run();
		$post   = admin_url( 'admin-post.php' );
		$notice = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'PressGuard Setup Wizard', 'pressguard' ); ?></h1>
			<?php if ( 'applied' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Recommended security baseline applied.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<div class="pressguard-cards">
				<div class="pressguard-card pressguard-card--<?php echo $audit['score'] >= 85 ? 'ok' : 'warn'; ?>">
					<span class="pressguard-card__label"><?php esc_html_e( 'Current security score', 'pressguard' ); ?></span>
					<span class="pressguard-card__value"><?php echo (int) $audit['score']; ?>/100</span>
				</div>
			</div>

			<h2><?php esc_html_e( 'One-click recommended setup', 'pressguard' ); ?></h2>
			<p class="description"><?php esc_html_e( 'This enables:', 'pressguard' ); ?></p>
			<ul style="list-style:disc;margin-inline-start:20px;">
				<li><?php esc_html_e( 'Hardening: disable file editor & XML-RPC, hide version, block user enumeration, security headers', 'pressguard' ); ?></li>
				<li><?php esc_html_e( 'Block PHP execution in uploads + deny access to sensitive files (.htaccess)', 'pressguard' ); ?></li>
				<li><?php esc_html_e( 'Firewall in blocking mode', 'pressguard' ); ?></li>
				<li><?php esc_html_e( 'Login lockout, generic errors, and two-factor availability', 'pressguard' ); ?></li>
				<li><?php esc_html_e( 'Activity logging', 'pressguard' ); ?></li>
			</ul>
			<p class="description"><?php esc_html_e( 'After applying, set up two-factor on your profile and enable the custom login URL under Settings → Login.', 'pressguard' ); ?></p>

			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_wizard" />
				<input type="hidden" name="do" value="apply" />
				<?php wp_nonce_field( 'pressguard_wizard' ); ?>
				<?php submit_button( __( 'Apply recommended settings', 'pressguard' ), 'primary' ); ?>
			</form>

			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_wizard" />
				<input type="hidden" name="do" value="dismiss" />
				<?php wp_nonce_field( 'pressguard_wizard' ); ?>
				<?php submit_button( __( 'Dismiss (I’ll configure manually)', 'pressguard' ), 'secondary' ); ?>
			</form>
		</div>
		<?php
	}
}
