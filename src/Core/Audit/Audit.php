<?php
/**
 * Security audit / health score.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Audit;

use PressGuard\Core\Permissions\Permissions;
use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Audits configuration and posture (distinct from the malware scanner, which
 * inspects file content). Produces a 0–100 security score plus actionable
 * findings — outdated software, weak settings, exposed files, risky
 * permissions — each with a short "how to fix".
 */
final class Audit implements Module {

	const ADMIN_SLUG = 'pressguard-audit';

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
		return 'audit';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page(
					$parent,
					__( 'Security Audit', 'pressguard' ),
					__( 'Audit', 'pressguard' ),
					$cap,
					self::ADMIN_SLUG,
					array( $this, 'render' )
				);
			},
			10,
			2
		);
	}

	/**
	 * Run all checks and return findings + score.
	 *
	 * @return array{score:int,findings:array[]}
	 */
	public function run() {
		global $wpdb;
		$findings = array();

		// Outdated software.
		if ( function_exists( 'wp_get_update_data' ) ) {
			$counts = wp_get_update_data()['counts'];
			if ( ! empty( $counts['wordpress'] ) ) {
				$findings[] = $this->f( 'core_update', 3, __( 'WordPress core is out of date.', 'pressguard' ), __( 'Update WordPress from Dashboard → Updates.', 'pressguard' ) );
			}
			if ( ! empty( $counts['plugins'] ) ) {
				$findings[] = $this->f( 'plugin_updates', 2, sprintf( /* translators: %d: count */ __( '%d plugin update(s) available.', 'pressguard' ), (int) $counts['plugins'] ), __( 'Update plugins — outdated plugins are the #1 attack vector.', 'pressguard' ) );
			}
			if ( ! empty( $counts['themes'] ) ) {
				$findings[] = $this->f( 'theme_updates', 1, sprintf( /* translators: %d: count */ __( '%d theme update(s) available.', 'pressguard' ), (int) $counts['themes'] ), __( 'Update your themes.', 'pressguard' ) );
			}
		}

		// Debug mode in production.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$findings[] = $this->f( 'debug_on', 2, __( 'WP_DEBUG is enabled.', 'pressguard' ), __( 'Disable WP_DEBUG on production sites.', 'pressguard' ) );
		}

		// Default table prefix.
		if ( 'wp_' === $wpdb->prefix ) {
			$findings[] = $this->f( 'default_prefix', 1, __( 'Database uses the default "wp_" table prefix.', 'pressguard' ), __( 'A non-default prefix adds a small layer of obscurity.', 'pressguard' ) );
		}

		// "admin" username.
		if ( username_exists( 'admin' ) ) {
			$findings[] = $this->f( 'admin_user', 2, __( 'A user named "admin" exists.', 'pressguard' ), __( 'Create a new admin with a unique name and remove "admin".', 'pressguard' ) );
		}

		// File editor.
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$findings[] = $this->f( 'file_editor', 2, __( 'The theme/plugin file editor is enabled.', 'pressguard' ), __( 'Enable “Disable file editor” in PressGuard → Settings → Hardening.', 'pressguard' ) );
		}

		// XML-RPC reachable.
		if ( apply_filters( 'xmlrpc_enabled', true ) && ! (bool) $this->plugin->config()->get( 'hardening.disable_xmlrpc', false ) ) {
			$findings[] = $this->f( 'xmlrpc', 1, __( 'XML-RPC is enabled.', 'pressguard' ), __( 'Disable XML-RPC if you do not use it (Hardening).', 'pressguard' ) );
		}

		// HTTPS.
		if ( 'https' !== wp_parse_url( home_url(), PHP_URL_SCHEME ) ) {
			$findings[] = $this->f( 'no_https', 3, __( 'The site is not using HTTPS.', 'pressguard' ), __( 'Install an SSL certificate and force HTTPS.', 'pressguard' ) );
		}

		// Exposed files.
		foreach ( array( 'readme.html', 'wp-config.php.bak', 'wp-config.bak' ) as $exposed ) {
			if ( file_exists( ABSPATH . $exposed ) ) {
				$findings[] = $this->f( 'exposed_' . $exposed, 1, sprintf( /* translators: %s: filename */ __( 'Exposed file: %s', 'pressguard' ), $exposed ), __( 'Delete or block access to this file.', 'pressguard' ) );
			}
		}
		if ( file_exists( WP_CONTENT_DIR . '/debug.log' ) ) {
			$findings[] = $this->f( 'debug_log', 2, __( 'A debug.log file is present in wp-content.', 'pressguard' ), __( 'Remove debug.log or block public access to it.', 'pressguard' ) );
		}

		// Risky permissions.
		$risky = 0;
		foreach ( ( new Permissions( $this->plugin ) )->scan() as $row ) {
			if ( ! empty( $row['risky'] ) ) {
				++$risky;
			}
		}
		if ( $risky > 0 ) {
			$findings[] = $this->f( 'perms', 2, sprintf( /* translators: %d: count */ __( '%d path(s) have risky permissions.', 'pressguard' ), $risky ), __( 'Review PressGuard → Permissions and fix the flagged entries.', 'pressguard' ) );
		}

		// Score: deduct by severity.
		$weights = array( 1 => 4, 2 => 8, 3 => 14 );
		$score   = 100;
		foreach ( $findings as $finding ) {
			$score -= isset( $weights[ $finding['severity'] ] ) ? $weights[ $finding['severity'] ] : 5;
		}
		$score = max( 0, min( 100, $score ) );

		return array(
			'score'    => $score,
			'findings' => $findings,
		);
	}

	/**
	 * Build a finding row.
	 *
	 * @param string $id       Finding id.
	 * @param int    $severity 1–3.
	 * @param string $label    Short label.
	 * @param string $fix      How to fix.
	 * @return array
	 */
	private function f( $id, $severity, $label, $fix ) {
		return array(
			'id'       => $id,
			'severity' => $severity,
			'label'    => $label,
			'fix'      => $fix,
		);
	}

	/**
	 * Render the audit screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$result = $this->run();
		$score  = $result['score'];
		$color  = $score >= 85 ? '#00a32a' : ( $score >= 60 ? '#dba617' : '#d63638' );
		$sev    = array( 1 => __( 'Low', 'pressguard' ), 2 => __( 'Medium', 'pressguard' ), 3 => __( 'High', 'pressguard' ) );
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Security Audit', 'pressguard' ); ?></h1>

			<div class="pressguard-cards">
				<div class="pressguard-card" style="border-left-color:<?php echo esc_attr( $color ); ?>;">
					<span class="pressguard-card__label"><?php esc_html_e( 'Security score', 'pressguard' ); ?></span>
					<span class="pressguard-card__value" style="color:<?php echo esc_attr( $color ); ?>;"><?php echo (int) $score; ?>/100</span>
				</div>
			</div>

			<?php if ( empty( $result['findings'] ) ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'No issues found. Nicely locked down!', 'pressguard' ); ?></p></div>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr>
						<th><?php esc_html_e( 'Severity', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'Finding', 'pressguard' ); ?></th>
						<th><?php esc_html_e( 'How to fix', 'pressguard' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $result['findings'] as $f ) : ?>
						<tr>
							<td><?php echo esc_html( $sev[ $f['severity'] ] ?? '' ); ?></td>
							<td><?php echo esc_html( $f['label'] ); ?></td>
							<td class="description"><?php echo esc_html( $f['fix'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}
}
