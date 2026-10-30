<?php
/**
 * Plugin Name:       PressGuard
 * Plugin URI:        https://github.com/babak-majd/PressGuard
 * Description:       Complete, free WordPress security — firewall, login protection, hardening, malware & security scanning, roles & activity, SSL and more. Nothing less than the big paid plugins, fully free.
 * Version:           0.1.0-dev
 * Requires at least: 5.6
 * Requires PHP:      7.4
 * Author:            Babak Majd
 * Author URI:        https://bobclub.ir
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       pressguard
 * Domain Path:       /languages
 *
 * @package PressGuard
 */

defined( 'ABSPATH' ) || exit;

if ( defined( 'PRESSGUARD_VERSION' ) ) {
	// Already loaded (e.g. the plugin file was included twice).
	return;
}

define( 'PRESSGUARD_VERSION', '0.1.0-dev' );
define( 'PRESSGUARD_FILE', __FILE__ );
define( 'PRESSGUARD_DIR', plugin_dir_path( __FILE__ ) );
define( 'PRESSGUARD_URL', plugin_dir_url( __FILE__ ) );
define( 'PRESSGUARD_BASENAME', plugin_basename( __FILE__ ) );
define( 'PRESSGUARD_MIN_PHP', '7.4' );
define( 'PRESSGUARD_MIN_WP', '5.6' );

/**
 * Environment guard: bail gracefully (never fatal) on unsupported PHP/WP.
 *
 * @return bool True when the environment is supported.
 */
function pressguard_requirements_met() {
	if ( version_compare( PHP_VERSION, PRESSGUARD_MIN_PHP, '<' ) ) {
		return false;
	}

	global $wp_version;
	if ( isset( $wp_version ) && version_compare( $wp_version, PRESSGUARD_MIN_WP, '<' ) ) {
		return false;
	}

	return true;
}

/**
 * Show an admin notice when requirements are not met.
 */
function pressguard_requirements_notice() {
	echo '<div class="notice notice-error"><p>';
	echo esc_html(
		sprintf(
			/* translators: 1: required PHP version, 2: required WordPress version */
			__( 'PressGuard requires PHP %1$s+ and WordPress %2$s+. The plugin is inactive until the environment is updated.', 'pressguard' ),
			PRESSGUARD_MIN_PHP,
			PRESSGUARD_MIN_WP
		)
	);
	echo '</p></div>';
}

// Prefer Composer's autoloader when present; otherwise fall back to a bundled
// PSR-4 autoloader so the plugin runs without `composer install`.
if ( is_readable( PRESSGUARD_DIR . 'vendor/autoload.php' ) ) {
	require PRESSGUARD_DIR . 'vendor/autoload.php';
} else {
	require PRESSGUARD_DIR . 'src/autoload.php';
}

if ( ! pressguard_requirements_met() ) {
	add_action( 'admin_notices', 'pressguard_requirements_notice' );
	return;
}

// Activation / deactivation hooks are registered against the main file.
register_activation_hook( __FILE__, array( \PressGuard\Support\Installer::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \PressGuard\Support\Installer::class, 'deactivate' ) );

// Boot the plugin once all plugins are loaded. The firewall hooks into an early
// action from inside Plugin::boot(); booting here keeps ordering predictable.
add_action(
	'plugins_loaded',
	static function () {
		\PressGuard\Plugin::instance()->boot();
	},
	5
);
