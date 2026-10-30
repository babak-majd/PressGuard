<?php
/**
 * Symmetric encryption for stored secrets.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Encrypts/decrypts small secrets (2FA seeds, API tokens) at rest.
 *
 * A random 32-byte key is generated once per install and stored in its own
 * option. Because the key is per-install, encrypted values are not portable
 * between sites — which is intentional: import/export treats these as sensitive
 * and does not carry them across unless the user supplies a passphrase.
 *
 * Prefers libsodium; falls back to OpenSSL AES-256-GCM.
 */
final class Crypto {

	const KEY_OPTION = 'pressguard_crypto_key';

	/**
	 * Get (or lazily create) the raw 32-byte install key.
	 *
	 * @return string Raw binary key.
	 */
	private static function key() {
		$stored = get_option( self::KEY_OPTION, '' );
		if ( is_string( $stored ) && '' !== $stored ) {
			$raw = base64_decode( $stored, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false !== $raw && 32 === strlen( $raw ) ) {
				return $raw;
			}
		}

		$raw = self::random_bytes( 32 );
		update_option( self::KEY_OPTION, base64_encode( $raw ), false ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return $raw;
	}

	/**
	 * Encrypt a plaintext string. Returns a base64 token, or '' on failure.
	 *
	 * @param string $plaintext Plaintext.
	 * @return string
	 */
	public static function encrypt( $plaintext ) {
		$plaintext = (string) $plaintext;
		$key       = self::key();

		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce  = self::random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $plaintext, $nonce, $key );
			return 'v1s:' . base64_encode( $nonce . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		}

		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv     = self::random_bytes( 12 );
			$tag    = '';
			$cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false === $cipher ) {
				return '';
			}
			return 'v1o:' . base64_encode( $iv . $tag . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		}

		return '';
	}

	/**
	 * Decrypt a token produced by encrypt(). Returns '' on failure.
	 *
	 * @param string $token Base64 token with a version prefix.
	 * @return string
	 */
	public static function decrypt( $token ) {
		$token = (string) $token;
		$key   = self::key();

		if ( 0 === strpos( $token, 'v1s:' ) && function_exists( 'sodium_crypto_secretbox_open' ) ) {
			$raw = base64_decode( substr( $token, 4 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				return '';
			}
			$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plain  = sodium_crypto_secretbox_open( $cipher, $nonce, $key );
			return false === $plain ? '' : $plain;
		}

		if ( 0 === strpos( $token, 'v1o:' ) && function_exists( 'openssl_decrypt' ) ) {
			$raw = base64_decode( substr( $token, 4 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $raw || strlen( $raw ) <= 28 ) {
				return '';
			}
			$iv     = substr( $raw, 0, 12 );
			$tag    = substr( $raw, 12, 16 );
			$cipher = substr( $raw, 28 );
			$plain  = openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			return false === $plain ? '' : $plain;
		}

		return '';
	}

	/**
	 * Cryptographically secure random bytes.
	 *
	 * @param int $length Number of bytes.
	 * @return string
	 */
	private static function random_bytes( $length ) {
		try {
			return random_bytes( $length );
		} catch ( \Exception $e ) {
			// Extremely unlikely; fall back to WP's generator.
			return wp_generate_password( $length, true, true );
		}
	}
}
