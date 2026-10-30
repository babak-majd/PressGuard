<?php
/**
 * User-activity logging & behaviour observation.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Activity;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Ip;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Records who did what (logins, content, plugins/themes, users/roles, settings)
 * into the shared event log, and flags unusual behaviour — e.g. a login from an
 * IP never seen before for that account — which also feeds the anomaly signal.
 * This is the "protect from the inside" layer (compromised/careless accounts).
 */
final class Activity implements Module {

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * IP resolver.
	 *
	 * @var Ip
	 */
	private $ip;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
		$this->ip     = new Ip( $plugin->config() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'activity';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		if ( ! $this->plugin->config()->is_enabled( 'activity' ) ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'on_logout' ) );

		add_action( 'activated_plugin', array( $this, 'on_plugin' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_off' ) );
		add_action( 'switch_theme', array( $this, 'on_theme' ) );

		add_action( 'user_register', array( $this, 'on_user_register' ) );
		add_action( 'deleted_user', array( $this, 'on_user_delete' ) );
		add_action( 'set_user_role', array( $this, 'on_role_change' ), 10, 3 );

		add_action( 'transition_post_status', array( $this, 'on_post_status' ), 10, 3 );
	}

	/**
	 * Log a successful login and flag logins from new IPs.
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       User.
	 */
	public function on_login( $user_login, $user = null ) {
		$ip  = $this->ip->client_ip();
		$uid = ( $user instanceof \WP_User ) ? $user->ID : 0;

		$this->log( 'login_success', Logger::SEVERITY_NOTICE, sprintf( 'User "%s" logged in.', $user_login ), $uid, $ip );

		// Observe: first time we've seen this IP for this user?
		if ( $uid && '' !== $ip ) {
			$key   = 'pressguard_known_ips';
			$known = (array) get_user_meta( $uid, $key, true );
			if ( ! in_array( $ip, $known, true ) ) {
				$known[] = $ip;
				update_user_meta( $uid, $key, array_slice( $known, -20 ) );
				if ( count( $known ) > 1 ) {
					$this->log( 'login_new_ip', Logger::SEVERITY_WARNING, sprintf( 'Login for "%s" from a new IP.', $user_login ), $uid, $ip );
					$this->feed_anomaly();
				}
			}
		}
	}

	/**
	 * Log a logout.
	 */
	public function on_logout() {
		$this->log( 'logout', Logger::SEVERITY_DEBUG, 'User logged out.' );
	}

	/**
	 * Log plugin activation.
	 *
	 * @param string $plugin Plugin file.
	 */
	public function on_plugin( $plugin ) {
		$this->log( 'plugin_activated', Logger::SEVERITY_WARNING, sprintf( 'Plugin activated: %s', $plugin ) );
	}

	/**
	 * Log plugin deactivation.
	 *
	 * @param string $plugin Plugin file.
	 */
	public function on_plugin_off( $plugin ) {
		$this->log( 'plugin_deactivated', Logger::SEVERITY_WARNING, sprintf( 'Plugin deactivated: %s', $plugin ) );
	}

	/**
	 * Log a theme switch.
	 *
	 * @param string $name New theme name.
	 */
	public function on_theme( $name ) {
		$this->log( 'theme_switched', Logger::SEVERITY_WARNING, sprintf( 'Theme switched to: %s', $name ) );
	}

	/**
	 * Log user creation.
	 *
	 * @param int $user_id New user id.
	 */
	public function on_user_register( $user_id ) {
		$this->log( 'user_created', Logger::SEVERITY_WARNING, sprintf( 'User #%d created.', $user_id ) );
	}

	/**
	 * Log user deletion.
	 *
	 * @param int $user_id Deleted user id.
	 */
	public function on_user_delete( $user_id ) {
		$this->log( 'user_deleted', Logger::SEVERITY_WARNING, sprintf( 'User #%d deleted.', $user_id ) );
	}

	/**
	 * Log a role change.
	 *
	 * @param int      $user_id   User id.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		$this->log( 'role_changed', Logger::SEVERITY_WARNING, sprintf( 'User #%d role set to "%s" (was %s).', $user_id, $role, implode( ',', (array) $old_roles ) ) );
	}

	/**
	 * Log publish/unpublish transitions (ignore autosaves/no-ops).
	 *
	 * @param string    $new New status.
	 * @param string    $old Old status.
	 * @param \WP_Post  $post Post.
	 */
	public function on_post_status( $new, $old, $post ) {
		if ( $new === $old || 'auto-draft' === $new || wp_is_post_revision( $post ) ) {
			return;
		}
		if ( ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return;
		}
		$this->log( 'content_' . $new, Logger::SEVERITY_NOTICE, sprintf( '%s "%s" (#%d): %s → %s', $post->post_type, get_the_title( $post ), $post->ID, $old, $new ) );
	}

	/**
	 * Write an activity row.
	 *
	 * @param string $type     Event type.
	 * @param int    $severity Severity.
	 * @param string $message  Message.
	 * @param int    $user_id  Optional user id.
	 * @param string $ip       Optional IP.
	 */
	private function log( $type, $severity, $message, $user_id = null, $ip = null ) {
		$this->plugin->logger()->log(
			'activity',
			$type,
			array(
				'severity' => $severity,
				'message'  => $message,
				'user_id'  => null === $user_id ? get_current_user_id() : $user_id,
				'ip'       => null === $ip ? $this->ip->client_ip() : $ip,
			)
		);
	}

	/**
	 * Feed the anomaly core when suspicious activity is observed.
	 */
	private function feed_anomaly() {
		if ( class_exists( \PressGuard\Core\Anomaly\Anomaly::class ) ) {
			( new \PressGuard\Core\Anomaly\Anomaly( $this->plugin ) )->record_hit( 'activity' );
		}
	}
}
