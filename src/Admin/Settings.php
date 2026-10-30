<?php
/**
 * Settings screen (tabbed, native WP admin).
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * A native, data-driven settings page. Field definitions map directly to
 * dot-notation Config keys, so adding a toggle is a one-line change. This is
 * the usable core; the full Expert Mode UI (custom rules, IP lists) comes
 * later, but every value here is also round-tripped by import/export.
 */
final class Settings {

	const SLUG = 'pressguard-settings';

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
	 * Tab + field definitions.
	 *
	 * @return array
	 */
	private function schema() {
		return array(
			'general'   => array(
				'label'  => __( 'General', 'pressguard' ),
				'fields' => array(
					array( 'key' => 'firewall.mode', 'type' => 'select', 'label' => __( 'Firewall mode', 'pressguard' ), 'options' => array( 'learning' => __( 'Learning (log only)', 'pressguard' ), 'detect' => __( 'Detection only', 'pressguard' ), 'enabled' => __( 'Enabled (block)', 'pressguard' ) ), 'default' => 'learning' ),
				),
			),
			'firewall'  => array(
				'label'  => __( 'Firewall', 'pressguard' ),
				'fields' => array(
					array( 'key' => 'firewall.enabled', 'type' => 'checkbox', 'label' => __( 'Enable firewall', 'pressguard' ), 'default' => true ),
					array( 'key' => 'firewall.threshold', 'type' => 'number', 'label' => __( 'Anomaly score threshold', 'pressguard' ), 'default' => 5 ),
					array( 'key' => 'firewall.rate_limit.enabled', 'type' => 'checkbox', 'label' => __( 'Enable rate limiting', 'pressguard' ), 'default' => false ),
					array( 'key' => 'firewall.rate_limit.max', 'type' => 'number', 'label' => __( 'Max requests / window', 'pressguard' ), 'default' => 240 ),
					array( 'key' => 'firewall.rate_limit.window', 'type' => 'number', 'label' => __( 'Window (seconds)', 'pressguard' ), 'default' => 60 ),
					array( 'key' => 'firewall.ua.block_empty', 'type' => 'checkbox', 'label' => __( 'Block empty User-Agents', 'pressguard' ), 'default' => false ),
					array( 'key' => 'firewall.under_attack.manual', 'type' => 'checkbox', 'label' => __( 'Under Attack mode (manual)', 'pressguard' ), 'default' => false ),
					array( 'key' => 'firewall.under_attack.auto', 'type' => 'checkbox', 'label' => __( 'Auto Under Attack on detected surge', 'pressguard' ), 'default' => true ),
					array( 'key' => 'firewall.extended.enabled', 'type' => 'checkbox', 'label' => __( 'Extended WAF (run before WordPress via auto_prepend_file)', 'pressguard' ), 'default' => false ),
					array( 'key' => 'geo.enabled', 'type' => 'checkbox', 'label' => __( 'Country blocking', 'pressguard' ), 'default' => false ),
					array( 'key' => 'geo.mode', 'type' => 'select', 'label' => __( 'Country mode', 'pressguard' ), 'options' => array( 'block' => __( 'Block listed countries', 'pressguard' ), 'allow' => __( 'Allow only listed countries', 'pressguard' ) ), 'default' => 'block' ),
					array( 'key' => 'geo.countries', 'type' => 'csv', 'label' => __( 'Country codes (e.g. RU, CN, KP)', 'pressguard' ), 'default' => array() ),
					array( 'key' => 'geo.http_lookup', 'type' => 'checkbox', 'label' => __( 'Use external geolocation lookup (no local GeoIP DB)', 'pressguard' ), 'default' => false ),
				),
			),
			'login'     => array(
				'label'  => __( 'Login', 'pressguard' ),
				'fields' => array(
					array( 'key' => 'login.enabled', 'type' => 'checkbox', 'label' => __( 'Enable login protection', 'pressguard' ), 'default' => true ),
					array( 'key' => 'login.lockout.enabled', 'type' => 'checkbox', 'label' => __( 'Lockout after failed logins', 'pressguard' ), 'default' => true ),
					array( 'key' => 'login.lockout.max_attempts', 'type' => 'number', 'label' => __( 'Max attempts', 'pressguard' ), 'default' => 5 ),
					array( 'key' => 'login.lockout.window', 'type' => 'number', 'label' => __( 'Counting window (seconds)', 'pressguard' ), 'default' => 900 ),
					array( 'key' => 'login.two_factor.enabled', 'type' => 'checkbox', 'label' => __( 'Enable two-factor (TOTP)', 'pressguard' ), 'default' => true ),
					array( 'key' => 'login.custom_url.enabled', 'type' => 'checkbox', 'label' => __( 'Custom login URL', 'pressguard' ), 'default' => false ),
					array( 'key' => 'login.custom_url.slug', 'type' => 'text', 'label' => __( 'Login slug', 'pressguard' ), 'default' => $this->default_login_slug() ),
					array( 'key' => 'login.generic_errors', 'type' => 'checkbox', 'label' => __( 'Generic login errors', 'pressguard' ), 'default' => true ),
					array( 'key' => 'login.breached.enabled', 'type' => 'checkbox', 'label' => __( 'Breached-password screening (HaveIBeenPwned)', 'pressguard' ), 'default' => false ),
					array( 'key' => 'login.breached.block_login', 'type' => 'checkbox', 'label' => __( 'Block login when the password is breached', 'pressguard' ), 'default' => false ),
				),
			),
			'hardening' => array(
				'label'  => __( 'Hardening', 'pressguard' ),
				'fields' => array(
					array( 'key' => 'hardening.enabled', 'type' => 'checkbox', 'label' => __( 'Enable hardening', 'pressguard' ), 'default' => true ),
					array( 'key' => 'hardening.disable_file_edit', 'type' => 'checkbox', 'label' => __( 'Disable theme/plugin file editor', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.disable_xmlrpc', 'type' => 'checkbox', 'label' => __( 'Disable XML-RPC', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.hide_wp_version', 'type' => 'checkbox', 'label' => __( 'Hide WordPress version', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.block_php_uploads', 'type' => 'checkbox', 'label' => __( 'Block PHP execution in uploads (.htaccess)', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.protect_sensitive_files', 'type' => 'checkbox', 'label' => __( 'Deny access to sensitive files (.htaccess)', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.block_user_enumeration', 'type' => 'checkbox', 'label' => __( 'Block user enumeration', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.restrict_rest_anonymous', 'type' => 'checkbox', 'label' => __( 'Restrict REST API for anonymous', 'pressguard' ), 'default' => false ),
					array( 'key' => 'hardening.security_headers', 'type' => 'checkbox', 'label' => __( 'Send security headers', 'pressguard' ), 'default' => false ),
				),
			),
		);
	}

	/**
	 * Default login slug: the stored value, or a freshly generated and
	 * persisted 6-character random slug if none is set yet. This gives the
	 * custom-login field a sensible, non-guessable default out of the box.
	 *
	 * @return string
	 */
	private function default_login_slug() {
		$slug = (string) $this->plugin->config()->get( 'login.custom_url.slug', '' );
		if ( '' === $slug ) {
			$slug = self::generate_slug();
			$this->plugin->config()->set( 'login.custom_url.slug', $slug );
		}
		return $slug;
	}

	/**
	 * Generate a 6-character lowercase alphanumeric slug.
	 *
	 * @return string
	 */
	public static function generate_slug() {
		return strtolower( wp_generate_password( 6, false, false ) );
	}

	/**
	 * Register the submenu.
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page(
					$parent,
					__( 'Settings', 'pressguard' ),
					__( 'Settings', 'pressguard' ),
					$cap,
					self::SLUG,
					array( $this, 'render' )
				);
			},
			10,
			2
		);
	}

	/**
	 * Render the settings page and handle saves.
	 */
	public function render() {
		if ( ! current_user_can( Admin::CAPABILITY ) ) {
			return;
		}

		$schema = $this->schema();
		$saved  = false;

		if ( isset( $_POST['pressguard_settings_submit'] ) ) {
			check_admin_referer( 'pressguard_settings' );
			$this->save( $schema );
			$saved = true;
		}

		$active = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $schema[ $active ] ) ) {
			$active = 'general';
		}

		$config = $this->plugin->config();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'PressGuard Settings', 'pressguard' ); ?></h1>
			<?php if ( $saved ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<h2 class="nav-tab-wrapper">
				<?php foreach ( $schema as $tab_id => $tab ) : ?>
					<a class="nav-tab <?php echo $tab_id === $active ? 'nav-tab-active' : ''; ?>"
						href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::SLUG . '&tab=' . $tab_id ) ); ?>">
						<?php echo esc_html( $tab['label'] ); ?>
					</a>
				<?php endforeach; ?>
			</h2>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=' . self::SLUG . '&tab=' . $active ) ); ?>">
				<?php wp_nonce_field( 'pressguard_settings' ); ?>
				<input type="hidden" name="pressguard_active_tab" value="<?php echo esc_attr( $active ); ?>" />
				<table class="form-table" role="presentation">
					<?php foreach ( $schema[ $active ]['fields'] as $field ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( $field['label'] ); ?></th>
							<td><?php $this->render_field( $field, $config->get( $field['key'], $field['default'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</table>
				<?php submit_button( __( 'Save Changes', 'pressguard' ), 'primary', 'pressguard_settings_submit' ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Render one field control.
	 *
	 * @param array $field Field def.
	 * @param mixed $value Current value.
	 */
	private function render_field( $field, $value ) {
		// Wrap in pg[...] so PHP doesn't mangle the dots in the key name
		// (PHP rewrites "." to "_" in top-level POST keys, but preserves them
		// inside an array sub-key).
		$name = 'pg[' . esc_attr( $field['key'] ) . ']';

		switch ( $field['type'] ) {
			case 'checkbox':
				printf(
					'<label><input type="checkbox" name="%s" value="1" %s /> %s</label>',
					$name,
					checked( (bool) $value, true, false ),
					esc_html__( 'Enabled', 'pressguard' )
				);
				break;
			case 'number':
				printf( '<input type="number" name="%s" value="%s" class="small-text" />', $name, esc_attr( (string) $value ) );
				break;
			case 'csv':
				$joined = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
				printf( '<input type="text" name="%s" value="%s" class="regular-text" />', $name, esc_attr( $joined ) );
				break;
			case 'select':
				echo '<select name="' . $name . '">';
				foreach ( $field['options'] as $opt_val => $opt_label ) {
					printf(
						'<option value="%s" %s>%s</option>',
						esc_attr( $opt_val ),
						selected( (string) $value, (string) $opt_val, false ),
						esc_html( $opt_label )
					);
				}
				echo '</select>';
				break;
			default:
				printf( '<input type="text" name="%s" value="%s" class="regular-text" />', $name, esc_attr( (string) $value ) );
		}
	}

	/**
	 * Persist the submitted values for the active tab.
	 *
	 * @param array $schema Full schema.
	 */
	private function save( $schema ) {
		$active = isset( $_POST['pressguard_active_tab'] ) ? sanitize_key( wp_unslash( $_POST['pressguard_active_tab'] ) ) : 'general';
		if ( ! isset( $schema[ $active ] ) ) {
			return;
		}

		$config = $this->plugin->config();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce checked by caller.
		$data = isset( $_POST['pg'] ) && is_array( $_POST['pg'] ) ? wp_unslash( $_POST['pg'] ) : array();
		// phpcs:enable

		foreach ( $schema[ $active ]['fields'] as $field ) {
			$key = $field['key'];
			switch ( $field['type'] ) {
				case 'checkbox':
					$config->set( $key, ! empty( $data[ $key ] ) );
					break;
				case 'number':
					$config->set( $key, isset( $data[ $key ] ) ? (int) $data[ $key ] : 0 );
					break;
				case 'select':
					$val = isset( $data[ $key ] ) ? sanitize_text_field( $data[ $key ] ) : '';
					if ( isset( $field['options'][ $val ] ) ) {
						$config->set( $key, $val );
					}
					break;
				case 'text':
					$raw = isset( $data[ $key ] ) ? sanitize_text_field( $data[ $key ] ) : '';
					if ( 'login.custom_url.slug' === $key ) {
						$raw = sanitize_title( $raw );
					}
					$config->set( $key, $raw );
					break;
				case 'csv':
					$raw   = isset( $data[ $key ] ) ? sanitize_text_field( $data[ $key ] ) : '';
					$items = array_filter( array_map( 'trim', explode( ',', $raw ) ) );
					$config->set( $key, array_values( $items ) );
					break;
			}
		}
	}
}
