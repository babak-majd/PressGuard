<?php
/**
 * Client IP resolution.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Single source of truth for the visitor's IP.
 *
 * Forwarded headers (X-Forwarded-For, CF-Connecting-IP, …) are only trusted
 * when the direct peer (REMOTE_ADDR) is inside a configured trusted-proxy
 * range. Otherwise an attacker could spoof a header to bypass an IP blocklist
 * or frame an innocent address, so we fall back to REMOTE_ADDR.
 */
final class Ip {

	/**
	 * Config service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Cached resolved IP for this request.
	 *
	 * @var string|null
	 */
	private $resolved = null;

	/**
	 * Constructor.
	 *
	 * @param Config $config Config service.
	 */
	public function __construct( Config $config ) {
		$this->config = $config;
	}

	/**
	 * Resolve the client IP for the current request.
	 *
	 * @return string Valid IP, or empty string when none could be determined.
	 */
	public function client_ip() {
		if ( null !== $this->resolved ) {
			return $this->resolved;
		}

		$remote = isset( $_SERVER['REMOTE_ADDR'] )
			? $this->clean( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		$this->resolved = $remote;

		if ( '' !== $remote && $this->is_trusted_proxy( $remote ) ) {
			$forwarded = $this->from_forwarded_headers();
			if ( '' !== $forwarded ) {
				$this->resolved = $forwarded;
			}
		}

		return $this->resolved;
	}

	/**
	 * Read the first valid IP from configured forwarded headers.
	 *
	 * @return string
	 */
	private function from_forwarded_headers() {
		$headers = $this->config->get(
			'ip.forwarded_headers',
			array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' )
		);

		foreach ( (array) $headers as $header ) {
			if ( empty( $_SERVER[ $header ] ) ) {
				continue;
			}
			$raw = $this->clean( wp_unslash( $_SERVER[ $header ] ) );
			// X-Forwarded-For can be a comma list; the left-most is the client.
			foreach ( array_map( 'trim', explode( ',', $raw ) ) as $candidate ) {
				$valid = filter_var( $candidate, FILTER_VALIDATE_IP );
				if ( $valid ) {
					return $valid;
				}
			}
		}

		return '';
	}

	/**
	 * Is the direct peer a trusted reverse proxy / load balancer?
	 *
	 * @param string $ip Direct peer IP (REMOTE_ADDR).
	 * @return bool
	 */
	private function is_trusted_proxy( $ip ) {
		$ranges = (array) $this->config->get( 'ip.trusted_proxies', array() );

		/**
		 * Filter the trusted-proxy CIDR list. The Cloudflare integration adds
		 * Cloudflare's published ranges here when the site is proxied.
		 *
		 * @param string[] $ranges CIDR strings.
		 */
		$ranges = apply_filters( 'pressguard_trusted_proxies', $ranges );

		foreach ( $ranges as $cidr ) {
			if ( self::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Sanitize a candidate IP string.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private function clean( $value ) {
		$value = trim( (string) $value );
		$valid = filter_var( $value, FILTER_VALIDATE_IP );
		return $valid ? $valid : '';
	}

	/**
	 * Test whether an IP falls within a CIDR range (IPv4 and IPv6).
	 *
	 * @param string $ip   IP address.
	 * @param string $cidr CIDR notation, or a plain IP.
	 * @return bool
	 */
	public static function ip_in_cidr( $ip, $cidr ) {
		if ( false === strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}

		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$bits                  = (int) $bits;

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;

		if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $bytes ) ) {
			return false;
		}

		if ( 0 === $rem ) {
			return true;
		}

		$mask = ~( ( 1 << ( 8 - $rem ) ) - 1 ) & 0xff;
		return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $subnet_bin[ $bytes ] ) & $mask );
	}
}
