<?php
/**
 * Activation / deactivation lifecycle.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Handles setup on activation (tables, defaults, scheduled jobs) and teardown
 * on deactivation (clear schedules). Data is preserved on deactivation; actual
 * data removal lives in uninstall.php and only runs when the user opts in.
 */
final class Installer {

	const CRON_PURGE = 'pressguard_daily_maintenance';

	/**
	 * Fired on plugin activation.
	 */
	public static function activate() {
		Db::migrate();

		self::seed_defaults();

		// Generate the Extended WAF snapshot so the prepend has data to read
		// if/when the user installs it.
		( new \PressGuard\Core\Firewall\Extended( \PressGuard\Plugin::instance() ) )->generate_snapshot();

		if ( ! wp_next_scheduled( self::CRON_PURGE ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_PURGE );
		}

		// Mark that the setup wizard should run on first admin visit.
		if ( false === get_option( 'pressguard_wizard_done', false ) ) {
			update_option( 'pressguard_wizard_pending', 1, false );
		}
	}

	/**
	 * Fired on plugin deactivation. Clears schedules but keeps data.
	 */
	public static function deactivate() {
		$timestamp = wp_next_scheduled( self::CRON_PURGE );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_PURGE );
		}
		wp_clear_scheduled_hook( self::CRON_PURGE );
	}

	/**
	 * Write conservative default settings on first activation only.
	 */
	private static function seed_defaults() {
		$config = new Config();
		if ( ! empty( $config->all() ) ) {
			return; // Respect existing settings on reactivation.
		}

		$config->replace(
			array(
				'_schema'   => 1,
				'login'     => array(
					'enabled'    => true,
					'custom_url' => array(
						'enabled' => false,
						'slug'    => strtolower( wp_generate_password( 6, false, false ) ),
					),
				),
				'hardening' => array(
					'enabled' => true,
				),
				'firewall'  => array(
					'enabled' => true,
					'mode'    => 'learning', // learning | detect | enabled.
				),
				'activity'  => array(
					'enabled'        => true,
					'retention_days' => 90,
					'max_rows'       => 100000,
				),
			)
		);
	}
}
