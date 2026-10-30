<?php
/**
 * Database schema and retention.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Owns PressGuard's custom tables. Creating dedicated tables (instead of the
 * options table) keeps high-volume logs out of autoloaded options, and every
 * log table is capped + purged to avoid the DB bloat that plagues other
 * security plugins.
 */
final class Db {

	const SCHEMA_VERSION = 1;
	const SCHEMA_OPTION  = 'pressguard_schema_version';

	/**
	 * Fully-qualified name of the activity/event log table.
	 *
	 * @return string
	 */
	public static function events_table() {
		global $wpdb;
		return $wpdb->prefix . 'pressguard_events';
	}

	/**
	 * Create or upgrade tables via dbDelta. Safe to call repeatedly.
	 */
	public static function migrate() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$events          = self::events_table();

		$sql = "CREATE TABLE {$events} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			module VARCHAR(40) NOT NULL DEFAULT '',
			type VARCHAR(60) NOT NULL DEFAULT '',
			severity TINYINT UNSIGNED NOT NULL DEFAULT 2,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			ip VARCHAR(45) NOT NULL DEFAULT '',
			message TEXT NULL,
			context LONGTEXT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY module_type (module, type),
			KEY ip (ip)
		) {$charset_collate};";

		dbDelta( $sql );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * Run migrate() only when the stored schema version is behind.
	 */
	public static function maybe_migrate() {
		$current = (int) get_option( self::SCHEMA_OPTION, 0 );
		if ( $current < self::SCHEMA_VERSION ) {
			self::migrate();
		}
	}

	/**
	 * Purge events older than the retention window, then enforce a hard row cap.
	 *
	 * @param int $retention_days Days to keep.
	 * @param int $max_rows       Absolute row ceiling.
	 */
	public static function purge_events( $retention_days = 90, $max_rows = 100000 ) {
		global $wpdb;

		$events         = self::events_table();
		$retention_days = max( 1, (int) $retention_days );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$events} WHERE created_at < ( NOW() - INTERVAL %d DAY )",
				$retention_days
			)
		);

		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$events}" );
		if ( $count > $max_rows ) {
			$overflow = $count - $max_rows;
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$events} ORDER BY id ASC LIMIT %d",
					$overflow
				)
			);
		}
		// phpcs:enable
	}

	/**
	 * Drop PressGuard tables. Called only from uninstall when the user opts in.
	 */
	public static function drop() {
		global $wpdb;
		$events = self::events_table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "DROP TABLE IF EXISTS {$events}" );
		delete_option( self::SCHEMA_OPTION );
	}
}
