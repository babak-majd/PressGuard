<?php
/**
 * Activity / Live Traffic list table.
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Support\Db;

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Renders PressGuard events using the native WP_List_Table so the Activity Log
 * looks and behaves like core admin screens (sorting, pagination, search).
 */
final class EventsTable extends \WP_List_Table {

	/**
	 * Map severity levels to labels.
	 *
	 * @var array<int,string>
	 */
	private $severity_labels;

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct(
			array(
				'singular' => 'pressguard_event',
				'plural'   => 'pressguard_events',
				'ajax'     => false,
			)
		);

		$this->severity_labels = array(
			1 => __( 'Debug', 'pressguard' ),
			2 => __( 'Notice', 'pressguard' ),
			3 => __( 'Warning', 'pressguard' ),
			4 => __( 'Error', 'pressguard' ),
			5 => __( 'Critical', 'pressguard' ),
		);
	}

	/**
	 * Define columns.
	 *
	 * @return array<string,string>
	 */
	public function get_columns() {
		return array(
			'created_at' => __( 'Time', 'pressguard' ),
			'module'     => __( 'Module', 'pressguard' ),
			'type'       => __( 'Event', 'pressguard' ),
			'severity'   => __( 'Severity', 'pressguard' ),
			'user'       => __( 'User', 'pressguard' ),
			'ip'         => __( 'IP', 'pressguard' ),
			'message'    => __( 'Details', 'pressguard' ),
		);
	}

	/**
	 * Load items (with search + pagination).
	 */
	public function prepare_items() {
		global $wpdb;

		$this->_column_headers = array( $this->get_columns(), array(), array() );

		$per_page = 50;
		$page     = $this->get_pagenum();
		$offset   = ( $page - 1 ) * $per_page;
		$table    = Db::events_table();

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$where  = '1=1';
		$params = array();

		$search = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $search ) {
			$like   = '%' . $wpdb->esc_like( $search ) . '%';
			$where .= ' AND ( type LIKE %s OR module LIKE %s OR ip LIKE %s OR message LIKE %s )';
			array_push( $params, $like, $like, $like, $like );
		}

		$module = isset( $_REQUEST['module'] ) ? sanitize_key( wp_unslash( $_REQUEST['module'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $module ) {
			$where   .= ' AND module = %s';
			$params[] = $module;
		}

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where}";
		$total     = $params
			? (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) )
			: (int) $wpdb->get_var( $count_sql );

		$data_sql     = "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT %d OFFSET %d";
		$data_params  = array_merge( $params, array( $per_page, $offset ) );
		$this->items  = $wpdb->get_results( $wpdb->prepare( $data_sql, $data_params ), ARRAY_A );
		// phpcs:enable

		$this->set_pagination_args(
			array(
				'total_items' => $total,
				'per_page'    => $per_page,
				'total_pages' => (int) ceil( $total / $per_page ),
			)
		);
	}

	/**
	 * Default column renderer.
	 *
	 * @param array  $item        Row.
	 * @param string $column_name Column id.
	 * @return string
	 */
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'created_at':
				return esc_html( $item['created_at'] );
			case 'module':
				return esc_html( $item['module'] );
			case 'type':
				return '<code>' . esc_html( $item['type'] ) . '</code>';
			case 'severity':
				$level = (int) $item['severity'];
				return esc_html( isset( $this->severity_labels[ $level ] ) ? $this->severity_labels[ $level ] : (string) $level );
			case 'user':
				$uid = (int) $item['user_id'];
				if ( ! $uid ) {
					return '&mdash;';
				}
				$user = get_userdata( $uid );
				return $user ? esc_html( $user->user_login ) : (string) $uid;
			case 'ip':
				return esc_html( $item['ip'] );
			case 'message':
				$msg = (string) $item['message'];
				if ( '' === $msg && ! empty( $item['context'] ) ) {
					$msg = (string) $item['context'];
				}
				return esc_html( $msg );
			default:
				return '';
		}
	}

	/**
	 * Empty-state text.
	 */
	public function no_items() {
		esc_html_e( 'No activity recorded yet.', 'pressguard' );
	}
}
