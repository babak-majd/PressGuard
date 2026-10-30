<?php
/**
 * Event logger.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Writes structured events to the custom events table. Used by every module for
 * the Activity Log, Live Traffic, firewall hits, etc. Designed to be cheap on
 * the request path; heavy purging happens on a scheduled job.
 */
final class Logger {

	const SEVERITY_DEBUG   = 1;
	const SEVERITY_NOTICE  = 2;
	const SEVERITY_WARNING = 3;
	const SEVERITY_ERROR   = 4;
	const SEVERITY_CRITICAL = 5;

	/**
	 * Config service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Constructor.
	 *
	 * @param Config $config Config service.
	 */
	public function __construct( Config $config ) {
		$this->config = $config;
	}

	/**
	 * Record an event.
	 *
	 * @param string $module   Module id (e.g. "firewall").
	 * @param string $type     Event type (e.g. "login_failed").
	 * @param array  $args     Optional: message, severity, user_id, ip, context.
	 * @return int|false Inserted row id, or false on failure.
	 */
	public function log( $module, $type, array $args = array() ) {
		global $wpdb;

		$severity = isset( $args['severity'] ) ? (int) $args['severity'] : self::SEVERITY_NOTICE;
		$user_id  = isset( $args['user_id'] ) ? (int) $args['user_id'] : get_current_user_id();
		$ip       = isset( $args['ip'] ) ? (string) $args['ip'] : '';
		$message  = isset( $args['message'] ) ? (string) $args['message'] : '';
		$context  = isset( $args['context'] ) ? wp_json_encode( $args['context'] ) : null;

		$result = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Db::events_table(),
			array(
				'created_at' => current_time( 'mysql' ),
				'module'     => substr( $module, 0, 40 ),
				'type'       => substr( $type, 0, 60 ),
				'severity'   => $severity,
				'user_id'    => $user_id,
				'ip'         => substr( $ip, 0, 45 ),
				'message'    => $message,
				'context'    => $context,
			),
			array( '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%s' )
		);

		return $result ? (int) $wpdb->insert_id : false;
	}
}
