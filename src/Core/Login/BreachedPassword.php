<?php
/**
 * Breached-password screening via HaveIBeenPwned (k-anonymity).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

use PressGuard\Plugin;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Checks passwords against the HaveIBeenPwned Pwned Passwords range API using
 * k-anonymity: only the first 5 chars of the SHA-1 hash are ever sent, so the
 * password itself never leaves the site. Blocks setting a breached password and
 * flags logins made with one (which can feed an alert).
 */
final class BreachedPassword {

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
	 * Wire hooks.
	 */
	public function register() {
		add_action( 'user_profile_update_errors', array( $this, 'block_on_set' ), 10, 3 );
		add_filter( 'wp_authenticate_user', array( $this, 'flag_on_login' ), 20, 2 );
	}

	/**
	 * How many times a password appears in breaches (0 = not found).
	 *
	 * @param string $password Plaintext password.
	 * @return int
	 */
	public static function pwned_count( $password ) {
		$sha1   = strtoupper( sha1( $password ) );
		$prefix = substr( $sha1, 0, 5 );
		$suffix = substr( $sha1, 5 );

		$res = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout' => 8,
				'headers' => array( 'Add-Padding' => 'true' ),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return 0; // Fail open: never block on a lookup error.
		}

		foreach ( preg_split( '/\r\n|\n/', wp_remote_retrieve_body( $res ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( isset( $parts[0] ) && strtoupper( $parts[0] ) === $suffix ) {
				return (int) ( $parts[1] ?? 1 );
			}
		}
		return 0;
	}

	/**
	 * Reject a breached password when a user sets/changes it.
	 *
	 * @param \WP_Error $errors Errors.
	 * @param bool      $update Whether this is an update.
	 * @param \stdClass $user   User data (pass1 lives in $_POST).
	 */
	public function block_on_set( $errors, $update, $user ) {
		unset( $update, $user );
		if ( ! (bool) $this->plugin->config()->get( 'login.breached.block_on_set', true ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core profile form nonce already checked by WP.
		$pass = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		if ( '' === $pass ) {
			return;
		}
		if ( self::pwned_count( $pass ) > 0 ) {
			$errors->add( 'pressguard_breached', __( 'This password has appeared in a known data breach. Please choose a different one.', 'pressguard' ) );
		}
	}

	/**
	 * Flag (and optionally block) a login made with a breached password.
	 *
	 * @param \WP_User|\WP_Error $user     Auth result.
	 * @param string             $password Submitted password.
	 * @return \WP_User|\WP_Error
	 */
	public function flag_on_login( $user, $password ) {
		if ( ! $user instanceof \WP_User || '' === $password ) {
			return $user;
		}
		if ( ! (bool) $this->plugin->config()->get( 'login.breached.check_login', true ) ) {
			return $user;
		}

		if ( self::pwned_count( $password ) > 0 ) {
			$this->plugin->logger()->log(
				'login',
				'breached_password_login',
				array(
					'severity' => Logger::SEVERITY_WARNING,
					'user_id'  => $user->ID,
					'message'  => sprintf( 'User "%s" logged in with a breached password.', $user->user_login ),
				)
			);
			set_transient( 'pressguard_breached_notice_' . $user->ID, 1, DAY_IN_SECONDS );

			if ( (bool) $this->plugin->config()->get( 'login.breached.block_login', false ) ) {
				return new \WP_Error( 'pressguard_breached_login', __( 'Your password appears in a known breach and must be reset before you can sign in.', 'pressguard' ) );
			}
		}
		return $user;
	}
}
