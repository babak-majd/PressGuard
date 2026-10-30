<?php
/**
 * Admin UI: menu, dashboard, and chrome.
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the top-level PressGuard admin menu and renders a native-looking
 * WordPress dashboard. Submenus for each feature area are added as their
 * modules land; for now the dashboard gives an at-a-glance status.
 */
final class Admin implements Module {

	const MENU_SLUG  = 'pressguard';
	const CAPABILITY = 'manage_options';
	const COFFEE_URL = 'https://bobclub.ir/coffee';

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
		return 'admin';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		if ( ! is_admin() ) {
			return;
		}

		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_filter( 'admin_footer_text', array( $this, 'footer_text' ) );
		add_filter(
			'plugin_action_links_' . PRESSGUARD_BASENAME,
			array( $this, 'action_links' )
		);
	}

	/**
	 * Register the top-level menu and the Dashboard subpage.
	 */
	public function register_menu() {
		$hook = add_menu_page(
			__( 'PressGuard', 'pressguard' ),
			__( 'PressGuard', 'pressguard' ),
			self::CAPABILITY,
			self::MENU_SLUG,
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			81
		);

		add_submenu_page(
			self::MENU_SLUG,
			__( 'Dashboard', 'pressguard' ),
			__( 'Dashboard', 'pressguard' ),
			self::CAPABILITY,
			self::MENU_SLUG,
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			self::MENU_SLUG,
			__( 'Activity Log', 'pressguard' ),
			__( 'Activity Log', 'pressguard' ),
			self::CAPABILITY,
			self::MENU_SLUG . '-activity',
			array( $this, 'render_activity' )
		);

		/**
		 * Let feature modules add their own submenus under PressGuard.
		 *
		 * @param string $parent_slug The PressGuard menu slug.
		 * @param string $capability  Capability required to view pages.
		 */
		do_action( 'pressguard_admin_menu', self::MENU_SLUG, self::CAPABILITY );

		unset( $hook );
	}

	/**
	 * Enqueue admin styles on PressGuard screens only.
	 *
	 * @param string $hook_suffix Current admin page hook.
	 */
	public function enqueue_assets( $hook_suffix ) {
		if ( false === strpos( (string) $hook_suffix, self::MENU_SLUG ) ) {
			return;
		}

		wp_enqueue_style(
			'pressguard-admin',
			PRESSGUARD_URL . 'assets/admin.css',
			array(),
			PRESSGUARD_VERSION
		);
	}

	/**
	 * Render the dashboard using native WP admin markup.
	 */
	public function render_dashboard() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$config   = $this->plugin->config();
		$firewall = $config->get( 'firewall.mode', 'learning' );

		$cards = array(
			array(
				'label'  => __( 'Firewall', 'pressguard' ),
				'value'  => $this->firewall_mode_label( $firewall ),
				'state'  => 'enabled' === $firewall ? 'ok' : 'warn',
			),
			array(
				'label' => __( 'Login protection', 'pressguard' ),
				'value' => $config->is_enabled( 'login' ) ? __( 'On', 'pressguard' ) : __( 'Off', 'pressguard' ),
				'state' => $config->is_enabled( 'login' ) ? 'ok' : 'warn',
			),
			array(
				'label' => __( 'Hardening', 'pressguard' ),
				'value' => $config->is_enabled( 'hardening' ) ? __( 'On', 'pressguard' ) : __( 'Off', 'pressguard' ),
				'state' => $config->is_enabled( 'hardening' ) ? 'ok' : 'warn',
			),
		);
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'PressGuard', 'pressguard' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Complete, free WordPress security. More modules arrive as you enable them.', 'pressguard' ); ?>
			</p>

			<div class="pressguard-cards">
				<?php foreach ( $cards as $card ) : ?>
					<div class="pressguard-card pressguard-card--<?php echo esc_attr( $card['state'] ); ?>">
						<span class="pressguard-card__label"><?php echo esc_html( $card['label'] ); ?></span>
						<span class="pressguard-card__value"><?php echo esc_html( $card['value'] ); ?></span>
					</div>
				<?php endforeach; ?>
			</div>

			<div class="pressguard-coffee notice notice-info is-dismissible">
				<p>
					<?php esc_html_e( 'If PressGuard saves you time:', 'pressguard' ); ?>
					<a href="<?php echo esc_url( self::COFFEE_URL ); ?>" target="_blank" rel="noopener noreferrer">
						<?php esc_html_e( 'buy me a coffee', 'pressguard' ); ?> &#9749;
					</a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Activity Log screen.
	 */
	public function render_activity() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}

		$table = new EventsTable();
		$table->prepare_items();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Activity Log', 'pressguard' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Security events and user activity. Older rows are purged automatically to keep the database lean.', 'pressguard' ); ?>
			</p>
			<form method="get">
				<input type="hidden" name="page" value="<?php echo esc_attr( self::MENU_SLUG . '-activity' ); ?>" />
				<?php
				$table->search_box( __( 'Search', 'pressguard' ), 'pressguard-events' );
				$table->display();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Human-readable firewall mode label.
	 *
	 * @param string $mode Stored mode.
	 * @return string
	 */
	private function firewall_mode_label( $mode ) {
		switch ( $mode ) {
			case 'enabled':
				return __( 'Enabled', 'pressguard' );
			case 'detect':
				return __( 'Detection only', 'pressguard' );
			default:
				return __( 'Learning', 'pressguard' );
		}
	}

	/**
	 * Add a coffee link to the admin footer on PressGuard screens.
	 *
	 * @param string $text Existing footer text.
	 * @return string
	 */
	public function footer_text( $text ) {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( (string) $screen->id, self::MENU_SLUG ) ) {
			return sprintf(
				/* translators: %s: coffee link */
				esc_html__( 'Thanks for using PressGuard. %s', 'pressguard' ),
				'<a href="' . esc_url( self::COFFEE_URL ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Buy me a coffee', 'pressguard' ) . ' &#9749;</a>'
			);
		}

		return $text;
	}

	/**
	 * Add a Dashboard shortcut to the plugins list row.
	 *
	 * @param array $links Existing action links.
	 * @return array
	 */
	public function action_links( $links ) {
		$url      = admin_url( 'admin.php?page=' . self::MENU_SLUG );
		$shortcut = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Dashboard', 'pressguard' ) . '</a>';
		array_unshift( $links, $shortcut );

		return $links;
	}
}
