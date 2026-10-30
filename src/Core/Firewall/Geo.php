<?php
/**
 * Country resolution & blocking.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Support\Config;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves an IP to a country and decides whether to block it. Resolution is
 * pluggable (filter first, so a MaxMind GeoLite2 reader or any provider can be
 * attached), with an optional opt-in HTTP lookup as a fallback. Results are
 * cached per IP. Country data (GeoLite2 / an API) must be provided by the host;
 * with no resolver available, nothing is blocked (fail-open).
 */
final class Geo {

	/**
	 * Config service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Constructor.
	 *
	 * @param Config $config Config.
	 */
	public function __construct( Config $config ) {
		$this->config = $config;
	}

	/**
	 * Should this IP be blocked by country policy?
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public function is_blocked( $ip ) {
		if ( ! (bool) $this->config->get( 'geo.enabled', false ) || '' === $ip ) {
			return false;
		}

		$country = $this->country( $ip );
		if ( '' === $country ) {
			return false; // Unknown — never block.
		}

		$list = array_map( 'strtoupper', (array) $this->config->get( 'geo.countries', array() ) );
		$mode = (string) $this->config->get( 'geo.mode', 'block' );

		if ( 'allow' === $mode ) {
			// Allow-list: block anything NOT listed.
			return ! in_array( $country, $list, true );
		}
		// Block-list: block anything listed.
		return in_array( $country, $list, true );
	}

	/**
	 * Resolve an IP to a 2-letter country code ('' if unknown). Cached per IP.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	public function country( $ip ) {
		/**
		 * Short-circuit country resolution. Return a 2-letter code to use a
		 * custom provider (e.g. a MaxMind GeoLite2 reader), or null to continue.
		 *
		 * @param string|null $country Country code or null.
		 * @param string      $ip      Client IP.
		 */
		$pre = apply_filters( 'pressguard_geo_country', null, $ip );
		if ( is_string( $pre ) && 2 === strlen( $pre ) ) {
			return strtoupper( $pre );
		}

		$cache_key = 'pressguard_geo_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return (string) $cached;
		}

		$country = '';
		if ( (bool) $this->config->get( 'geo.http_lookup', false ) ) {
			$country = $this->http_lookup( $ip );
		}

		set_transient( $cache_key, $country, DAY_IN_SECONDS );
		return $country;
	}

	/**
	 * Opt-in HTTP geolocation fallback (ip-api.com).
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private function http_lookup( $ip ) {
		$res = wp_remote_get( 'http://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=countryCode', array( 'timeout' => 5 ) );
		if ( is_wp_error( $res ) ) {
			return '';
		}
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		return isset( $data['countryCode'] ) ? strtoupper( substr( (string) $data['countryCode'], 0, 2 ) ) : '';
	}
}
