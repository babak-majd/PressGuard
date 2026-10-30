<?php
/**
 * Expert mode: IP lists, per-rule overrides, custom rules.
 *
 * @package PressGuard
 */

namespace PressGuard\Admin;

use PressGuard\Core\Firewall\RuleSet;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Fine-grained control for advanced users: absolute IP allow/deny lists,
 * per-rule enable/disable + score overrides, and fully custom WAF rules. Custom
 * rules and overrides live in settings (no file writes) and are picked up by
 * the firewall engine on the next request. Nothing here is a hard lock.
 */
final class Expert {

	const SLUG = 'pressguard-expert';

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
	 * Register page + handler.
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Expert (Rules & IPs)', 'pressguard' ), __( 'Expert', 'pressguard' ), $cap, self::SLUG, array( $this, 'render' ) );
			},
			10,
			2
		);
		add_action( 'admin_post_pressguard_expert', array( $this, 'handle' ) );
	}

	/**
	 * Handle form actions.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_expert' );

		$c  = $this->plugin->config();
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';

		if ( 'save_ips' === $do ) {
			$c->set( 'ip.whitelist', $this->lines( 'whitelist' ) );
			$c->set( 'ip.blacklist', $this->lines( 'blacklist' ) );
		} elseif ( 'save_overrides' === $do ) {
			$this->save_overrides();
		} elseif ( 'add_custom' === $do ) {
			$this->add_custom();
		} elseif ( 'remove_custom' === $do ) {
			$id      = isset( $_POST['rule_id'] ) ? sanitize_text_field( wp_unslash( $_POST['rule_id'] ) ) : '';
			$custom  = (array) $c->get( 'firewall.custom_rules', array() );
			$custom  = array_values( array_filter( $custom, static function ( $r ) use ( $id ) {
				return ( $r['id'] ?? '' ) !== $id;
			} ) );
			$c->set( 'firewall.custom_rules', $custom );
		}

		RuleSet::flush_cache();
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SLUG . '&updated=1' ) );
		exit;
	}

	/**
	 * Sanitize a textarea of IPs/CIDRs (one per line).
	 *
	 * @param string $field Field name.
	 * @return string[]
	 */
	private function lines( $field ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked by caller.
		$raw = isset( $_POST[ $field ] ) ? (string) wp_unslash( $_POST[ $field ] ) : '';
		$out = array();
		foreach ( preg_split( '/\r\n|\n|\r/', $raw ) as $line ) {
			$line = trim( $line );
			if ( '' !== $line ) {
				$out[] = sanitize_text_field( $line );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Save per-rule enable/score overrides.
	 */
	private function save_overrides() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce checked by caller.
		$enabled = isset( $_POST['rule_enabled'] ) && is_array( $_POST['rule_enabled'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['rule_enabled'] ) ) : array();
		$scores  = isset( $_POST['rule_score'] ) && is_array( $_POST['rule_score'] ) ? wp_unslash( $_POST['rule_score'] ) : array();
		// phpcs:enable

		$overrides = array();
		foreach ( RuleSet::load( $this->plugin->config() ) as $rule ) {
			// Skip custom rules here (managed separately).
			$overrides[ $rule->id ] = array(
				'enabled' => isset( $enabled[ $rule->id ] ),
				'score'   => isset( $scores[ $rule->id ] ) ? max( 0, (int) $scores[ $rule->id ] ) : $rule->score,
			);
		}
		$this->plugin->config()->set( 'firewall.rule_overrides', $overrides );
	}

	/**
	 * Add a custom rule.
	 */
	private function add_custom() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce checked by caller.
		$id      = isset( $_POST['c_id'] ) ? sanitize_key( wp_unslash( $_POST['c_id'] ) ) : '';
		$pattern = isset( $_POST['c_pattern'] ) ? (string) wp_unslash( $_POST['c_pattern'] ) : '';
		$score   = isset( $_POST['c_score'] ) ? max( 1, (int) $_POST['c_score'] ) : 5;
		$cat     = isset( $_POST['c_category'] ) ? sanitize_key( wp_unslash( $_POST['c_category'] ) ) : 'custom';
		$targets = isset( $_POST['c_targets'] ) ? array_filter( array_map( 'sanitize_key', array_map( 'trim', explode( ',', (string) wp_unslash( $_POST['c_targets'] ) ) ) ) ) : array();
		// phpcs:enable

		if ( '' === $id || '' === $pattern || @preg_match( '#' . str_replace( '#', '\#', $pattern ) . '#iu', '' ) === false ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return; // Invalid id or pattern — ignore.
		}

		$custom   = (array) $this->plugin->config()->get( 'firewall.custom_rules', array() );
		$custom[] = array(
			'id'       => $id,
			'category' => '' !== $cat ? $cat : 'custom',
			'pattern'  => $pattern,
			'score'    => $score,
			'targets'  => ! empty( $targets ) ? array_values( $targets ) : array( 'uri', 'query', 'body' ),
			'enabled'  => true,
		);
		$this->plugin->config()->set( 'firewall.custom_rules', $custom );
	}

	/**
	 * Render the Expert screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$c    = $this->plugin->config();
		$post = admin_url( 'admin-post.php' );
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Expert — Rules & IPs', 'pressguard' ); ?></h1>
			<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Saved.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'IP access lists', 'pressguard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_expert" />
				<input type="hidden" name="do" value="save_ips" />
				<?php wp_nonce_field( 'pressguard_expert' ); ?>
				<p><strong><?php esc_html_e( 'Whitelist (bypass everything)', 'pressguard' ); ?></strong> — <?php esc_html_e( 'one IP or CIDR per line', 'pressguard' ); ?><br/>
					<textarea name="whitelist" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $c->get( 'ip.whitelist', array() ) ) ); ?></textarea></p>
				<p><strong><?php esc_html_e( 'Blacklist (always block)', 'pressguard' ); ?></strong><br/>
					<textarea name="blacklist" rows="4" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $c->get( 'ip.blacklist', array() ) ) ); ?></textarea></p>
				<?php submit_button( __( 'Save IP lists', 'pressguard' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Firewall rules', 'pressguard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_expert" />
				<input type="hidden" name="do" value="save_overrides" />
				<?php wp_nonce_field( 'pressguard_expert' ); ?>
				<table class="widefat striped"><thead><tr>
					<th><?php esc_html_e( 'Enabled', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Rule', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Category', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Score', 'pressguard' ); ?></th>
				</tr></thead><tbody>
				<?php foreach ( RuleSet::load( $c ) as $rule ) : ?>
					<tr>
						<td><input type="checkbox" name="rule_enabled[<?php echo esc_attr( $rule->id ); ?>]" value="1" <?php checked( $rule->enabled ); ?> /></td>
						<td><code><?php echo esc_html( $rule->id ); ?></code><br/><span class="description"><?php echo esc_html( $rule->description ); ?></span></td>
						<td><?php echo esc_html( $rule->category ); ?></td>
						<td><input type="number" name="rule_score[<?php echo esc_attr( $rule->id ); ?>]" value="<?php echo (int) $rule->score; ?>" class="small-text" /></td>
					</tr>
				<?php endforeach; ?>
				</tbody></table>
				<?php submit_button( __( 'Save rule overrides', 'pressguard' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Add a custom rule', 'pressguard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_expert" />
				<input type="hidden" name="do" value="add_custom" />
				<?php wp_nonce_field( 'pressguard_expert' ); ?>
				<table class="form-table">
					<tr><th><?php esc_html_e( 'ID', 'pressguard' ); ?></th><td><input type="text" name="c_id" class="regular-text" required /></td></tr>
					<tr><th><?php esc_html_e( 'Regex pattern', 'pressguard' ); ?></th><td><input type="text" name="c_pattern" class="large-text code" required /> <span class="description"><?php esc_html_e( 'Without delimiters; matched case-insensitively.', 'pressguard' ); ?></span></td></tr>
					<tr><th><?php esc_html_e( 'Score', 'pressguard' ); ?></th><td><input type="number" name="c_score" value="5" class="small-text" /></td></tr>
					<tr><th><?php esc_html_e( 'Category', 'pressguard' ); ?></th><td><input type="text" name="c_category" value="custom" class="regular-text" /></td></tr>
					<tr><th><?php esc_html_e( 'Targets', 'pressguard' ); ?></th><td><input type="text" name="c_targets" value="uri, query, body" class="regular-text" /> <span class="description">uri, query, body, cookie, ua, referer</span></td></tr>
				</table>
				<?php submit_button( __( 'Add custom rule', 'pressguard' ) ); ?>
			</form>

			<?php $custom = (array) $c->get( 'firewall.custom_rules', array() ); ?>
			<?php if ( ! empty( $custom ) ) : ?>
				<h3><?php esc_html_e( 'Your custom rules', 'pressguard' ); ?></h3>
				<table class="widefat striped"><thead><tr><th>ID</th><th><?php esc_html_e( 'Pattern', 'pressguard' ); ?></th><th><?php esc_html_e( 'Score', 'pressguard' ); ?></th><th></th></tr></thead><tbody>
				<?php foreach ( $custom as $r ) : ?>
					<tr>
						<td><code><?php echo esc_html( $r['id'] ?? '' ); ?></code></td>
						<td><code><?php echo esc_html( $r['pattern'] ?? '' ); ?></code></td>
						<td><?php echo (int) ( $r['score'] ?? 0 ); ?></td>
						<td>
							<form method="post" action="<?php echo esc_url( $post ); ?>" style="margin:0;">
								<input type="hidden" name="action" value="pressguard_expert" />
								<input type="hidden" name="do" value="remove_custom" />
								<input type="hidden" name="rule_id" value="<?php echo esc_attr( $r['id'] ?? '' ); ?>" />
								<?php wp_nonce_field( 'pressguard_expert' ); ?>
								<button class="button button-small button-link-delete"><?php esc_html_e( 'Remove', 'pressguard' ); ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody></table>
			<?php endif; ?>
		</div>
		<?php
	}
}
