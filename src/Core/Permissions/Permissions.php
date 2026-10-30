<?php
/**
 * File permission check & repair.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Permissions;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Audits permissions on sensitive paths against recommended values and offers
 * a confirmed, reversible fix. Repairs use PHP chmod() only (no shell); when
 * chmod is unavailable or the path isn't owned, it reports manual guidance
 * instead. Default is report-only — a wrong chmod can break some hosts.
 */
final class Permissions implements Module {

	const ADMIN_SLUG = 'pressguard-permissions';

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
		return 'permissions';
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
					__( 'File Permissions', 'pressguard' ),
					__( 'Permissions', 'pressguard' ),
					$cap,
					self::ADMIN_SLUG,
					array( $this, 'render' )
				);
			},
			10,
			2
		);

		add_action( 'admin_post_pressguard_fix_perms', array( $this, 'handle_fix' ) );
	}

	/**
	 * Recommended permissions per path (octal).
	 *
	 * @return array<string,int> Absolute path => recommended mode.
	 */
	private function targets() {
		$targets = array(
			untrailingslashit( ABSPATH )          => 0755,
			ABSPATH . 'wp-admin'                   => 0755,
			ABSPATH . 'wp-includes'                => 0755,
			untrailingslashit( WP_CONTENT_DIR )    => 0755,
			WP_CONTENT_DIR . '/uploads'            => 0755,
			ABSPATH . 'wp-config.php'              => 0640,
			ABSPATH . '.htaccess'                  => 0644,
		);

		return array_filter(
			$targets,
			static function ( $mode, $path ) {
				unset( $mode );
				return file_exists( $path );
			},
			ARRAY_FILTER_USE_BOTH
		);
	}

	/**
	 * Scan the targets and return their status.
	 *
	 * @return array[] Each: path, current, recommended, risky, reason.
	 */
	public function scan() {
		$rows = array();
		foreach ( $this->targets() as $path => $recommended ) {
			$current = fileperms( $path ) & 0777;
			$risky   = false;
			$reason  = '';

			if ( $current & 0002 ) {
				$risky  = true;
				$reason = __( 'World-writable.', 'pressguard' );
			} elseif ( $current > $recommended ) {
				$risky  = true;
				$reason = __( 'More permissive than recommended.', 'pressguard' );
			}

			// wp-config.php should not be group/world readable.
			if ( 'wp-config.php' === basename( $path ) && ( $current & 0077 ) ) {
				$risky  = true;
				$reason = __( 'Readable by group/other.', 'pressguard' );
			}

			$rows[] = array(
				'path'        => $path,
				'display'     => $this->relpath( $path ),
				'current'     => $current,
				'recommended' => $recommended,
				'risky'       => $risky,
				'reason'      => $reason,
			);
		}

		return $rows;
	}

	/**
	 * Handle a confirmed fix request.
	 */
	public function handle_fix() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_fix_perms' );

		$status = 'none';
		$target = isset( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : '';

		foreach ( $this->scan() as $row ) {
			if ( $row['path'] !== $target || ! $row['risky'] ) {
				continue;
			}
			$status = $this->apply_fix( $row['path'], $row['recommended'] );
			break;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&fixed=' . rawurlencode( $status ) ) );
		exit;
	}

	/**
	 * Apply a chmod fix, logging the prior value for reversibility.
	 *
	 * @param string $path Absolute path.
	 * @param int    $mode Target mode.
	 * @return string Status: fixed|cannot|error.
	 */
	private function apply_fix( $path, $mode ) {
		if ( ! function_exists( 'chmod' ) || ! is_writable( $path ) ) {
			return 'cannot';
		}

		$before = fileperms( $path ) & 0777;
		$ok      = @chmod( $path, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$this->plugin->logger()->log(
			'permissions',
			$ok ? 'chmod' : 'chmod_failed',
			array(
				'severity' => 3,
				'message'  => sprintf( '%s: %o -> %o', $this->relpath( $path ), $before, $mode ),
			)
		);

		return $ok ? 'fixed' : 'error';
	}

	/**
	 * Path relative to the WordPress root.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function relpath( $path ) {
		$rel = ltrim( str_replace( untrailingslashit( ABSPATH ), '', $path ), '/' );
		return '' === $rel ? '/ (site root)' : $rel;
	}

	/**
	 * Render the permissions screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$rows = $this->scan();
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'File Permissions', 'pressguard' ); ?></h1>
			<p class="description"><?php esc_html_e( 'Recommended: directories 755, files 644, wp-config.php 640. Fixes use PHP chmod and are only offered for risky entries.', 'pressguard' ); ?></p>

			<?php if ( isset( $_GET['fixed'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<?php $st = sanitize_key( wp_unslash( $_GET['fixed'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-<?php echo 'fixed' === $st ? 'success' : 'warning'; ?> is-dismissible"><p>
					<?php
					echo esc_html(
						'fixed' === $st ? __( 'Permission updated.', 'pressguard' )
						: ( 'cannot' === $st ? __( 'Cannot change this permission on this host — fix it manually via your host/SFTP.', 'pressguard' )
						: __( 'No change made.', 'pressguard' ) )
					);
					?>
				</p></div>
			<?php endif; ?>

			<table class="widefat striped">
				<thead><tr>
					<th><?php esc_html_e( 'Path', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Current', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Recommended', 'pressguard' ); ?></th>
					<th><?php esc_html_e( 'Status', 'pressguard' ); ?></th>
					<th></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( $row['display'] ); ?></code></td>
						<td><?php echo esc_html( sprintf( '%o', $row['current'] ) ); ?></td>
						<td><?php echo esc_html( sprintf( '%o', $row['recommended'] ) ); ?></td>
						<td>
							<?php if ( $row['risky'] ) : ?>
								<span style="color:#d63638;">&#9888; <?php echo esc_html( $row['reason'] ); ?></span>
							<?php else : ?>
								<span style="color:#00a32a;">&#10003; <?php esc_html_e( 'OK', 'pressguard' ); ?></span>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( $row['risky'] ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
									<input type="hidden" name="action" value="pressguard_fix_perms" />
									<input type="hidden" name="path" value="<?php echo esc_attr( $row['path'] ); ?>" />
									<?php wp_nonce_field( 'pressguard_fix_perms' ); ?>
									<button type="submit" class="button button-small"
										onclick="return confirm('<?php echo esc_js( __( 'Change this permission? You can revert via your host if needed.', 'pressguard' ) ); ?>');">
										<?php echo esc_html( sprintf( __( 'Fix to %o', 'pressguard' ), $row['recommended'] ) ); ?>
									</button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}
}
