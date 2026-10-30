<?php
/**
 * ACME HTTP-01 challenge responder.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Ssl;

defined( 'ABSPATH' ) || exit;

/**
 * Stores pending HTTP-01 challenge tokens and serves them at
 * /.well-known/acme-challenge/<token> before WordPress routing kicks in. Tokens
 * are short-lived and kept in an option (no files needed, works on any host).
 */
final class Challenge {

	const OPTION = 'pressguard_acme_challenges';
	const PREFIX = '/.well-known/acme-challenge/';

	/**
	 * Register the responder.
	 */
	public function register() {
		add_action( 'init', array( $this, 'maybe_serve' ), 0 );
	}

	/**
	 * Store a token → key-authorization pair.
	 *
	 * @param string $token Challenge token.
	 * @param string $value Key authorization.
	 */
	public static function put( $token, $value ) {
		$all = get_option( self::OPTION, array() );
		if ( ! is_array( $all ) ) {
			$all = array();
		}
		$all[ $token ] = array(
			'value'   => $value,
			'expires' => time() + HOUR_IN_SECONDS,
		);
		update_option( self::OPTION, $all, false );
	}

	/**
	 * Remove a token.
	 *
	 * @param string $token Challenge token.
	 */
	public static function forget( $token ) {
		$all = get_option( self::OPTION, array() );
		if ( is_array( $all ) && isset( $all[ $token ] ) ) {
			unset( $all[ $token ] );
			update_option( self::OPTION, $all, false );
		}
	}

	/**
	 * Serve the key authorization when the request matches a stored token.
	 */
	public function maybe_serve() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		if ( 0 !== strpos( $path, self::PREFIX ) ) {
			return;
		}

		$token = sanitize_text_field( substr( $path, strlen( self::PREFIX ) ) );
		$all   = get_option( self::OPTION, array() );

		if ( is_array( $all ) && isset( $all[ $token ] ) && $all[ $token ]['expires'] > time() ) {
			header( 'Content-Type: text/plain' );
			echo $all[ $token ]['value']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain ACME token.
			exit;
		}

		status_header( 404 );
		exit;
	}
}
