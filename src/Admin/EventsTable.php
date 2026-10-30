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
			$like    = '%' . $wpdb->esc_like( $search ) . '%';
			$clauses = array( 'type LIKE %s', 'module LIKE %s', 'ip LIKE %s', 'message LIKE %s' );
			$args    = array( $like, $like, $like, $like );

			// Severity: match by number (1-5) or by label ("warning", …).
			$sev = $this->severity_from_search( $search );
			if ( $sev > 0 ) {
				$clauses[] = 'severity = %d';
				$args[]    = $sev;
			}

			// User: resolve the term against login/display name/email, then
			// match the stored user_id (the table only stores the id).
			$user_ids = get_users(
				array(
					'search'         => '*' . $search . '*',
					'search_columns' => array( 'user_login', 'display_name', 'user_email', 'user_nicename' ),
					'fields'         => 'ID',
					'number'         => 50,
				)
			);
			if ( ! empty( $user_ids ) ) {
				$placeholders = implode( ',', array_fill( 0, count( $user_ids ), '%d' ) );
				$clauses[]    = "user_id IN ( {$placeholders} )";
				foreach ( $user_ids as $uid ) {
					$args[] = (int) $uid;
				}
			}

			$where .= ' AND ( ' . implode( ' OR ', $clauses ) . ' )';
			$params = array_merge( $params, $args );
		}

		$module = isset( $_REQUEST['module'] ) ? sanitize_key( wp_unslash( $_REQUEST['module'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' !== $module ) {
			$where   .= ' AND module = %s';
			$params[] = $module;
		}

		$severity = isset( $_REQUEST['severity'] ) ? (int) $_REQUEST['severity'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $severity > 0 ) {
			$where   .= ' AND severity = %d';
			$params[] = $severity;
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
	 * Resolve a search term to a severity level (0 if not a severity).
	 *
	 * @param string $search Search term.
	 * @return int 1–5, or 0.
	 */
	private function severity_from_search( $search ) {
		$search = strtolower( trim( $search ) );

		if ( is_numeric( $search ) ) {
			$n = (int) $search;
			return ( $n >= 1 && $n <= 5 ) ? $n : 0;
		}

		foreach ( $this->severity_labels as $level => $label ) {
			if ( strtolower( $label ) === $search ) {
				return (int) $level;
			}
		}

		return 0;
	}

	/**
	 * Module + severity filter controls in the table nav.
	 *
	 * @param string $which Which nav ("top" or "bottom").
	 */
	public function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}

		global $wpdb;
		$table = Db::events_table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$modules = $wpdb->get_col( "SELECT DISTINCT module FROM {$table} WHERE module <> '' ORDER BY module ASC" );

		$cur_module = isset( $_REQUEST['module'] ) ? sanitize_key( wp_unslash( $_REQUEST['module'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$cur_sev    = isset( $_REQUEST['severity'] ) ? (int) $_REQUEST['severity'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		?>
		<div class="alignleft actions">
			<label class="screen-reader-text" for="pg-filter-module"><?php esc_html_e( 'Filter by module', 'pressguard' ); ?></label>
			<select name="module" id="pg-filter-module">
				<option value=""><?php esc_html_e( 'All modules', 'pressguard' ); ?></option>
				<?php foreach ( (array) $modules as $m ) : ?>
					<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $cur_module, $m ); ?>><?php echo esc_html( $m ); ?></option>
				<?php endforeach; ?>
			</select>

			<label class="screen-reader-text" for="pg-filter-severity"><?php esc_html_e( 'Filter by severity', 'pressguard' ); ?></label>
			<select name="severity" id="pg-filter-severity">
				<option value="0"><?php esc_html_e( 'All severities', 'pressguard' ); ?></option>
				<?php foreach ( $this->severity_labels as $level => $label ) : ?>
					<option value="<?php echo (int) $level; ?>" <?php selected( $cur_sev, $level ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>

			<?php submit_button( __( 'Filter', 'pressguard' ), '', 'filter_action', false, array( 'id' => 'pg-event-filter' ) ); ?>
		</div>
		<?php
	}

	/**
	 * Empty-state text.
	 */
	public function no_items() {
		esc_html_e( 'No activity recorded yet.', 'pressguard' );
	}
}
