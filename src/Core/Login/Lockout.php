<?php
/**
 * Progressive login lockout.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

use PressGuard\Plugin;
use PressGuard\Support\Ip;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failed logins per IP and blocks further attempts with an escalating
 * (exponential) delay rather than a hard permanent lock — a hard lock enables
 * a denial-of-service against legitimate users. Successful logins do NOT reset
 * the counter window (so a correct guess mid-attack still leaves a trail).
 */
final class Lockout {

	const PREFIX = 'pressguard_lockout_';

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
	 * Wire authentication hooks.
	 */
	public function register() {
		add_filter( 'authenticate', array( $this, 'check_lock' ), 30 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ) );
		add_action( 'wp_login', array( $this, 'clear_on_success' ), 10, 2 );
	}

	/**
	 * Block authentication while an IP is locked out.
	 *
	 * @param \WP_User|\WP_Error|null $user Current auth result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_lock( $user ) {
		$ip = $this->ip->client_ip();
		if ( '' === $ip || $this->is_whitelisted( $ip ) ) {
			return $user;
		}

		$until = (int) get_transient( $this->lock_key( $ip ) );
		if ( $until > time() ) {
			$seconds = $until - time();
			return new \WP_Error(
				'pressguard_locked_out',
				sprintf(
					/* translators: %d: seconds remaining */
					__( 'Too many failed attempts. Try again in %d seconds.', 'pressguard' ),
					$seconds
				)
			);
		}

		return $user;
	}

	/**
	 * Record a failed attempt and, past the threshold, set an escalating lock.
	 *
	 * @param string $username Attempted username.
	 */
	public function record_failure( $username ) {
		$ip = $this->ip->client_ip();
		if ( '' === $ip || $this->is_whitelisted( $ip ) ) {
			return;
		}

		// If the IP is already locked, this failure is an attempt made *during*
		// the lock (WordPress fires wp_login_failed for our lockout WP_Error
		// too). Log it but don't re-increment, or the counter inflates forever.
		$until = (int) get_transient( $this->lock_key( $ip ) );
		if ( $until > time() ) {
			$this->plugin->logger()->log(
				'login',
				'blocked_attempt',
				array(
					'severity' => Logger::SEVERITY_NOTICE,
					'ip'       => $ip,
					'context'  => array( 'username' => (string) $username ),
				)
			);
			return;
		}

		$config    = $this->plugin->config();
		$max        = max( 1, (int) $config->get( 'login.lockout.max_attempts', 5 ) );
		$window     = max( 60, (int) $config->get( 'login.lockout.window', 900 ) );
		$base_delay = max( 60, (int) $config->get( 'login.lockout.base_delay', 300 ) );

		$count_key = $this->count_key( $ip );
		$count     = (int) get_transient( $count_key ) + 1;
		set_transient( $count_key, $count, $window );

		if ( $count >= $max ) {
			// Exponential backoff: base * 2^(extra lockouts), capped at 24h.
			$over     = intdiv( $count, $max ) - 1;
			$duration = min( DAY_IN_SECONDS, $base_delay * ( 2 ** max( 0, $over ) ) );
			set_transient( $this->lock_key( $ip ), time() + $duration, $duration );

			$this->plugin->logger()->log(
				'login',
				'lockout',
				array(
					'severity' => Logger::SEVERITY_WARNING,
					'ip'       => $ip,
					'message'  => sprintf( 'IP locked for %ds after %d failures.', $duration, $count ),
					'context'  => array(
						'username' => (string) $username,
						'count'    => $count,
					),
				)
			);
		} else {
			$this->plugin->logger()->log(
				'login',
				'login_failed',
				array(
					'severity' => Logger::SEVERITY_NOTICE,
					'ip'       => $ip,
					'context'  => array( 'username' => (string) $username ),
				)
			);
		}
	}

	/**
	 * Clear the failure counter after a successful login (keeps any active
	 * lock — a success does not unlock an already-locked window).
	 *
	 * @param string   $user_login Username.
	 * @param \WP_User $user       User object.
	 */
	public function clear_on_success( $user_login, $user = null ) {
		unset( $user_login, $user );
		$ip = $this->ip->client_ip();
		if ( '' !== $ip ) {
			delete_transient( $this->count_key( $ip ) );
		}
	}

	/**
	 * Is the IP on the absolute allowlist?
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function is_whitelisted( $ip ) {
		$list = (array) $this->plugin->config()->get( 'ip.whitelist', array() );
		foreach ( $list as $cidr ) {
			if ( Ip::ip_in_cidr( $ip, (string) $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Transient key for the lock expiry of an IP.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private function lock_key( $ip ) {
		return self::PREFIX . 'until_' . md5( $ip );
	}

	/**
	 * Transient key for the failure count of an IP.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private function count_key( $ip ) {
		return self::PREFIX . 'count_' . md5( $ip );
	}
}
