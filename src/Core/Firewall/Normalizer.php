<?php
/**
 * Request value normalization.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

// Loadable both inside WordPress and from the pre-WordPress Extended WAF
// (prepend.php defines PRESSGUARD_WAF); still blocks direct web access.
defined( 'ABSPATH' ) || defined( 'PRESSGUARD_WAF' ) || exit;

/**
 * Normalizes request values before rule matching. Most WAF evasion hides in
 * encoding, so decoding/canonicalizing consistently is where detection
 * strength actually lives — not in the regexes themselves.
 */
final class Normalizer {

	/**
	 * Canonicalize a single scalar value for matching.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	public static function canonicalize( $value ) {
		$value = (string) $value;

		// Repeated URL-decoding to unwrap multi-encoded payloads (bounded).
		for ( $i = 0; $i < 3; $i++ ) {
			$decoded = rawurldecode( $value );
			if ( $decoded === $value ) {
				break;
			}
			$value = $decoded;
		}

		// HTML entity decode (e.g. &#x3c;script&#x3e;).
		$value = html_entity_decode( $value, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

		// Collapse null bytes and normalize whitespace runs.
		$value = str_replace( "\0", '', $value );
		$value = preg_replace( '/\s+/', ' ', $value );

		return strtolower( $value );
	}

	/**
	 * Flatten a request array (possibly nested) into a list of canonical
	 * scalar strings, so deeply nested params can't hide a payload.
	 *
	 * @param mixed $data Array or scalar.
	 * @param int   $depth Current recursion depth.
	 * @return string[]
	 */
	public static function flatten( $data, $depth = 0 ) {
		$out = array();

		if ( $depth > 10 ) {
			return $out;
		}

		if ( is_array( $data ) ) {
			foreach ( $data as $key => $value ) {
				// Keys can carry payloads too (e.g. param-name injection).
				if ( is_string( $key ) ) {
					$out[] = self::canonicalize( $key );
				}
				$out = array_merge( $out, self::flatten( $value, $depth + 1 ) );
			}
		} elseif ( is_scalar( $data ) ) {
			$out[] = self::canonicalize( (string) $data );
		}

		return $out;
	}
}
