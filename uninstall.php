<?php
/**
 * Uninstall routine.
 *
 * Only removes PressGuard data when the user has explicitly opted in via the
 * `pressguard_delete_data_on_uninstall` setting. Security logs and config are
 * otherwise preserved so an accidental delete/reinstall keeps history.
 *
 * @package PressGuard
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

require_once __DIR__ . '/src/autoload.php';

$settings = get_option( \PressGuard\Support\Config::OPTION, array() );
$delete   = is_array( $settings ) && ! empty( $settings['delete_data_on_uninstall'] );

if ( $delete ) {
	\PressGuard\Support\Db::drop();

	delete_option( \PressGuard\Support\Config::OPTION );
	delete_option( 'pressguard_wizard_done' );
	delete_option( 'pressguard_wizard_pending' );

	wp_clear_scheduled_hook( \PressGuard\Support\Installer::CRON_PURGE );
}
