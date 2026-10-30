<?php
/**
 * Roles, capabilities & per-plugin access control.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Access;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Lets an admin build custom roles, edit any capability, and control which
 * roles may see/manage specific plugins. Restriction hides a plugin from the
 * Plugins screen for non-privileged roles; "opening" access is done by granting
 * capabilities. Users with manage_options are never locked out of their own
 * tools (so you can't fence yourself out).
 */
final class Access implements Module {

	const ADMIN_SLUG = 'pressguard-access';

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
		return 'access';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_action(
			'pressguard_admin_menu',
			function ( $parent, $cap ) {
				add_submenu_page( $parent, __( 'Roles & Access', 'pressguard' ), __( 'Roles & Access', 'pressguard' ), $cap, self::ADMIN_SLUG, array( $this, 'render' ) );
			},
			10,
			2
		);

		add_action( 'admin_post_pressguard_access', array( $this, 'handle' ) );

		// Enforce per-plugin visibility on the Plugins screen.
		add_filter( 'all_plugins', array( $this, 'filter_plugins' ) );
	}

	/**
	 * Hide restricted plugins from users whose roles aren't allowed.
	 *
	 * @param array $plugins Plugins keyed by file.
	 * @return array
	 */
	public function filter_plugins( $plugins ) {
		// Never hide anything from a full admin — avoids self-lockout.
		if ( current_user_can( 'manage_options' ) ) {
			return $plugins;
		}

		$map  = (array) $this->plugin->config()->get( 'access.plugin_roles', array() );
		$user = wp_get_current_user();
		$mine = (array) $user->roles;

		foreach ( $map as $file => $allowed ) {
			$allowed = (array) $allowed;
			if ( empty( $allowed ) ) {
				continue;
			}
			if ( ! array_intersect( $mine, $allowed ) && isset( $plugins[ $file ] ) ) {
				unset( $plugins[ $file ] );
			}
		}

		return $plugins;
	}

	/**
	 * Handle role / access form actions.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_access' );

		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';

		switch ( $do ) {
			case 'create_role':
				$this->create_role();
				break;
			case 'update_caps':
				$this->update_caps();
				break;
			case 'delete_role':
				$this->delete_role();
				break;
			case 'save_plugins':
				$this->save_plugin_access();
				break;
		}

		$back = isset( $_POST['role'] ) ? '&role=' . rawurlencode( sanitize_key( wp_unslash( $_POST['role'] ) ) ) : '';
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&updated=1' . $back ) );
		exit;
	}

	/**
	 * Create a custom role, optionally cloning another's capabilities.
	 */
	private function create_role() {
		$slug = isset( $_POST['role_slug'] ) ? sanitize_key( wp_unslash( $_POST['role_slug'] ) ) : '';
		$name = isset( $_POST['role_name'] ) ? sanitize_text_field( wp_unslash( $_POST['role_name'] ) ) : '';
		$from = isset( $_POST['clone_from'] ) ? sanitize_key( wp_unslash( $_POST['clone_from'] ) ) : '';
		if ( '' === $slug || '' === $name || get_role( $slug ) ) {
			return;
		}

		$caps = array();
		if ( '' !== $from ) {
			$src = get_role( $from );
			if ( $src ) {
				$caps = $src->capabilities;
			}
		}
		add_role( $slug, $name, $caps );

		$this->plugin->logger()->log( 'access', 'role_created', array( 'severity' => 3, 'message' => sprintf( 'Role "%s" created.', $slug ) ) );
	}

	/**
	 * Update a role's capabilities from the submitted checkbox grid.
	 */
	private function update_caps() {
		$slug = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
		$role = get_role( $slug );
		if ( ! $role ) {
			return;
		}

		$chosen = isset( $_POST['caps'] ) && is_array( $_POST['caps'] )
			? array_map( 'sanitize_key', array_keys( wp_unslash( $_POST['caps'] ) ) )
			: array();

		foreach ( array_keys( $this->all_caps() ) as $cap ) {
			if ( in_array( $cap, $chosen, true ) ) {
				$role->add_cap( $cap );
			} else {
				$role->remove_cap( $cap );
			}
		}

		$this->plugin->logger()->log( 'access', 'caps_updated', array( 'severity' => 3, 'message' => sprintf( 'Capabilities updated for "%s".', $slug ) ) );
	}

	/**
	 * Delete a custom role, reassigning its users to subscriber.
	 */
	private function delete_role() {
		$slug = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
		$protected = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );
		if ( '' === $slug || in_array( $slug, $protected, true ) || ! get_role( $slug ) ) {
			return;
		}

		foreach ( get_users( array( 'role' => $slug ) ) as $user ) {
			$user->set_role( 'subscriber' );
		}
		remove_role( $slug );

		$this->plugin->logger()->log( 'access', 'role_deleted', array( 'severity' => 3, 'message' => sprintf( 'Role "%s" deleted.', $slug ) ) );
	}

	/**
	 * Save per-plugin role access.
	 */
	private function save_plugin_access() {
		$input = isset( $_POST['plugin_roles'] ) && is_array( $_POST['plugin_roles'] )
			? wp_unslash( $_POST['plugin_roles'] )
			: array();

		$map = array();
		foreach ( $input as $file => $roles ) {
			$file = sanitize_text_field( $file );
			$map[ $file ] = array_map( 'sanitize_key', (array) $roles );
		}
		$this->plugin->config()->set( 'access.plugin_roles', $map );
	}

	/**
	 * All known capabilities across roles (plus a few common ones).
	 *
	 * @return array<string,bool>
	 */
	private function all_caps() {
		$caps = array();
		foreach ( wp_roles()->roles as $role ) {
			if ( ! empty( $role['capabilities'] ) ) {
				$caps += $role['capabilities'];
			}
		}
		ksort( $caps );
		return $caps;
	}

	/**
	 * Render the Roles & Access screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$roles   = wp_roles();
		$editing = isset( $_GET['role'] ) ? sanitize_key( wp_unslash( $_GET['role'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$post_url = admin_url( 'admin-post.php' );
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'Roles & Access', 'pressguard' ); ?></h1>
			<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Saved.', 'pressguard' ); ?></p></div>
			<?php endif; ?>

			<?php if ( $editing && isset( $roles->roles[ $editing ] ) ) : ?>
				<?php $this->render_cap_editor( $editing ); ?>
			<?php else : ?>
				<?php $this->render_roles_table(); ?>
				<?php $this->render_create_role(); ?>
				<?php $this->render_plugin_access(); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Roles overview table.
	 */
	private function render_roles_table() {
		$roles = wp_roles();
		echo '<h2>' . esc_html__( 'Roles', 'pressguard' ) . '</h2><table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Role', 'pressguard' ) . '</th><th>' . esc_html__( 'Capabilities', 'pressguard' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $roles->roles as $slug => $role ) {
			$edit = admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&role=' . rawurlencode( $slug ) );
			echo '<tr><td><strong>' . esc_html( $role['name'] ) . '</strong> <code>' . esc_html( $slug ) . '</code></td>';
			echo '<td>' . (int) count( $role['capabilities'] ) . '</td>';
			echo '<td><a class="button button-small" href="' . esc_url( $edit ) . '">' . esc_html__( 'Edit capabilities', 'pressguard' ) . '</a></td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * Capability editor for one role.
	 *
	 * @param string $slug Role slug.
	 */
	private function render_cap_editor( $slug ) {
		$role = get_role( $slug );
		$all  = $this->all_caps();
		?>
		<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::ADMIN_SLUG ) ); ?>">&larr; <?php esc_html_e( 'Back to roles', 'pressguard' ); ?></a></p>
		<h2><?php echo esc_html( sprintf( __( 'Capabilities — %s', 'pressguard' ), $slug ) ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pressguard_access" />
			<input type="hidden" name="do" value="update_caps" />
			<input type="hidden" name="role" value="<?php echo esc_attr( $slug ); ?>" />
			<?php wp_nonce_field( 'pressguard_access' ); ?>
			<div style="column-width:260px;">
				<?php foreach ( $all as $cap => $x ) : ?>
					<label style="display:block;">
						<input type="checkbox" name="caps[<?php echo esc_attr( $cap ); ?>]" value="1" <?php checked( $role->has_cap( $cap ) ); ?> />
						<?php echo esc_html( $cap ); ?>
					</label>
				<?php endforeach; ?>
			</div>
			<?php submit_button( __( 'Save capabilities', 'pressguard' ) ); ?>
		</form>

		<?php $protected = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' ); ?>
		<?php if ( ! in_array( $slug, $protected, true ) ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this role? Its users move to Subscriber.', 'pressguard' ) ); ?>');">
				<input type="hidden" name="action" value="pressguard_access" />
				<input type="hidden" name="do" value="delete_role" />
				<input type="hidden" name="role" value="<?php echo esc_attr( $slug ); ?>" />
				<?php wp_nonce_field( 'pressguard_access' ); ?>
				<?php submit_button( __( 'Delete role', 'pressguard' ), 'delete' ); ?>
			</form>
		<?php endif; ?>
		<?php
	}

	/**
	 * Create-role form.
	 */
	private function render_create_role() {
		?>
		<h2><?php esc_html_e( 'Create custom role', 'pressguard' ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pressguard_access" />
			<input type="hidden" name="do" value="create_role" />
			<?php wp_nonce_field( 'pressguard_access' ); ?>
			<table class="form-table"><tr>
				<th><?php esc_html_e( 'Name', 'pressguard' ); ?></th>
				<td><input type="text" name="role_name" class="regular-text" required /></td>
			</tr><tr>
				<th><?php esc_html_e( 'Slug', 'pressguard' ); ?></th>
				<td><input type="text" name="role_slug" class="regular-text" required /></td>
			</tr><tr>
				<th><?php esc_html_e( 'Clone capabilities from', 'pressguard' ); ?></th>
				<td><select name="clone_from">
					<option value=""><?php esc_html_e( '— none —', 'pressguard' ); ?></option>
					<?php foreach ( wp_roles()->roles as $slug => $role ) : ?>
						<option value="<?php echo esc_attr( $slug ); ?>"><?php echo esc_html( $role['name'] ); ?></option>
					<?php endforeach; ?>
				</select></td>
			</tr></table>
			<?php submit_button( __( 'Create role', 'pressguard' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Per-plugin access control.
	 */
	private function render_plugin_access() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		$map     = (array) $this->plugin->config()->get( 'access.plugin_roles', array() );
		$roles   = wp_roles()->roles;
		?>
		<h2><?php esc_html_e( 'Per-plugin access', 'pressguard' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Choose which roles may see a plugin on the Plugins screen. Leave all unchecked to allow everyone. Administrators always see every plugin.', 'pressguard' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pressguard_access" />
			<input type="hidden" name="do" value="save_plugins" />
			<?php wp_nonce_field( 'pressguard_access' ); ?>
			<table class="widefat striped"><thead><tr>
				<th><?php esc_html_e( 'Plugin', 'pressguard' ); ?></th>
				<th><?php esc_html_e( 'Allowed roles', 'pressguard' ); ?></th>
			</tr></thead><tbody>
			<?php foreach ( $plugins as $file => $data ) : ?>
				<tr>
					<td><?php echo esc_html( $data['Name'] ); ?></td>
					<td>
						<?php foreach ( $roles as $slug => $role ) : ?>
							<label style="margin-inline-end:10px;">
								<input type="checkbox" name="plugin_roles[<?php echo esc_attr( $file ); ?>][]" value="<?php echo esc_attr( $slug ); ?>"
									<?php checked( isset( $map[ $file ] ) && in_array( $slug, (array) $map[ $file ], true ) ); ?> />
								<?php echo esc_html( $role['name'] ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody></table>
			<?php submit_button( __( 'Save plugin access', 'pressguard' ) ); ?>
		</form>
		<?php
	}
}
