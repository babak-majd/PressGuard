<?php
/**
 * TOTP (RFC 6238) helper.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

defined( 'ABSPATH' ) || exit;

/**
 * Self-contained TOTP implementation: base32 secrets, HMAC-SHA1 codes, and a
 * small asymmetric verification window. Compatible with Google Authenticator,
 * Authy, and other RFC 6238 apps. No external dependencies.
 */
final class Totp {

	const PERIOD  = 30;
	const DIGITS  = 6;
	const B32_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new random base32 secret.
	 *
	 * @param int $length Number of base32 characters (default 32 ≈ 160 bits).
	 * @return string
	 */
	public static function generate_secret( $length = 32 ) {
		$secret = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= self::B32_MAP[ random_int( 0, 31 ) ];
		}
		return $secret;
	}

	/**
	 * Build the otpauth:// URI for QR provisioning.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label (e.g. user email).
	 * @param string $issuer  Issuer label (e.g. site name).
	 * @return string
	 */
	public static function provisioning_uri( $secret, $account, $issuer ) {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d&digits=%d&algorithm=SHA1',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			$secret,
			rawurlencode( $issuer ),
			self::PERIOD,
			self::DIGITS
		);
	}

	/**
	 * Verify a submitted code against the secret, allowing a small clock-skew
	 * window. Returns the matched time-step on success, or false on failure.
	 *
	 * The caller must enforce replay protection by rejecting a step that is not
	 * strictly greater than the last accepted step for that user.
	 *
	 * @param string $secret        Base32 secret.
	 * @param string $code          Submitted 6-digit code.
	 * @param int    $back          Steps into the past to accept (default 1).
	 * @param int    $forward       Steps into the future to accept (default 1).
	 * @param int    $min_step      Reject any step <= this (replay guard). 0 = off.
	 * @return int|false Matched time-step, or false.
	 */
	public static function verify( $secret, $code, $back = 1, $forward = 1, $min_step = 0 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$now = (int) floor( time() / self::PERIOD );

		for ( $offset = -$back; $offset <= $forward; $offset++ ) {
			$step = $now + $offset;
			if ( $step <= $min_step ) {
				continue;
			}
			if ( hash_equals( self::code_at( $secret, $step ), $code ) ) {
				return $step;
			}
		}

		return false;
	}

	/**
	 * Compute the TOTP code for a specific time-step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time-step counter.
	 * @return string Zero-padded code.
	 */
	public static function code_at( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return str_repeat( '0', self::DIGITS );
		}

		$binary = pack( 'N*', 0 ) . pack( 'N*', $step ); // 64-bit big-endian counter.
		$hash   = hash_hmac( 'sha1', $binary, $key, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;
		$part   = substr( $hash, $offset, 4 );
		$value  = unpack( 'N', $part )[1] & 0x7fffffff;

		$code = $value % ( 10 ** self::DIGITS );
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Decode a base32 (RFC 4648) string to raw bytes.
	 *
	 * @param string $input Base32 string.
	 * @return string Raw bytes, or '' when invalid.
	 */
	public static function base32_decode( $input ) {
		$input = strtoupper( rtrim( (string) $input, '=' ) );
		if ( '' === $input ) {
			return '';
		}

		$buffer = 0;
		$bits   = 0;
		$output = '';

		$len = strlen( $input );
		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( self::B32_MAP, $input[ $i ] );
			if ( false === $pos ) {
				return '';
			}
			$buffer = ( $buffer << 5 ) | $pos;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits   -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xff );
			}
		}

		return $output;
	}
}
