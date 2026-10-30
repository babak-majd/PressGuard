<?php
/**
 * Cloudflare API client (zones, settings, IPs).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Integrations\Cloudflare;

defined( 'ABSPATH' ) || exit;

/**
 * Thin Cloudflare v4 API wrapper using a scoped API token. Covers the calls the
 * integration needs: verify the token, find a zone, read/patch zone settings,
 * inspect DNS proxy status, and fetch Cloudflare's IP ranges.
 */
final class Api {

	const BASE = 'https://api.cloudflare.com/client/v4';

	/**
	 * API token.
	 *
	 * @var string
	 */
	private $token;

	/**
	 * Constructor.
	 *
	 * @param string $token Scoped API token.
	 */
	public function __construct( $token ) {
		$this->token = $token;
	}

	/**
	 * Verify the token is valid.
	 *
	 * @return bool
	 */
	public function verify() {
		$res = $this->request( 'GET', '/user/tokens/verify' );
		return ! empty( $res['success'] );
	}

	/**
	 * Find the zone for a domain (longest matching suffix).
	 *
	 * @param string $domain Domain.
	 * @return array{id:string,name:string}|null
	 */
	public function zone_for( $domain ) {
		$domain = ltrim( (string) $domain, '*.' );
		$parts  = explode( '.', $domain );
		while ( count( $parts ) >= 2 ) {
			$name = implode( '.', $parts );
			$res  = $this->request( 'GET', '/zones?name=' . rawurlencode( $name ) );
			if ( ! empty( $res['result'][0]['id'] ) ) {
				return array(
					'id'   => $res['result'][0]['id'],
					'name' => $res['result'][0]['name'],
				);
			}
			array_shift( $parts );
		}
		return null;
	}

	/**
	 * Is the zone proxied (orange cloud) for at least one root/www record?
	 *
	 * @param string $zone_id Zone id.
	 * @return bool
	 */
	public function is_proxied( $zone_id ) {
		$res = $this->request( 'GET', '/zones/' . $zone_id . '/dns_records?per_page=100' );
		foreach ( (array) ( $res['result'] ?? array() ) as $rec ) {
			if ( in_array( $rec['type'] ?? '', array( 'A', 'AAAA', 'CNAME' ), true ) && ! empty( $rec['proxied'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Patch a zone setting.
	 *
	 * @param string $zone_id Zone id.
	 * @param string $key     Setting key.
	 * @param mixed  $value   Value.
	 * @return bool
	 */
	public function set_setting( $zone_id, $key, $value ) {
		$res = $this->request( 'PATCH', '/zones/' . $zone_id . '/settings/' . $key, array( 'value' => $value ) );
		return ! empty( $res['success'] );
	}

	/**
	 * Read a zone setting value.
	 *
	 * @param string $zone_id Zone id.
	 * @param string $key     Setting key.
	 * @return mixed|null
	 */
	public function get_setting( $zone_id, $key ) {
		$res = $this->request( 'GET', '/zones/' . $zone_id . '/settings/' . $key );
		return $res['result']['value'] ?? null;
	}

	/**
	 * Cloudflare's published edge IP ranges (IPv4 + IPv6).
	 *
	 * @return string[]
	 */
	public function ip_ranges() {
		$res  = $this->request( 'GET', '/ips' );
		$v4   = (array) ( $res['result']['ipv4_cidrs'] ?? array() );
		$v6   = (array) ( $res['result']['ipv6_cidrs'] ?? array() );
		return array_merge( $v4, $v6 );
	}

	/**
	 * Perform a request; returns the decoded JSON array.
	 *
	 * @param string     $method HTTP method.
	 * @param string     $path   API path.
	 * @param array|null $body   Body.
	 * @return array
	 */
	private function request( $method, $path, $body = null ) {
		$args = array(
			'method'  => $method,
			'timeout' => 20,
			'headers' => array(
				'Authorization' => 'Bearer ' . $this->token,
				'Content-Type'  => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}
		$res = wp_remote_request( self::BASE . $path, $args );
		if ( is_wp_error( $res ) ) {
			return array( 'success' => false, 'errors' => array( $res->get_error_message() ) );
		}
		$decoded = json_decode( wp_remote_retrieve_body( $res ), true );
		return is_array( $decoded ) ? $decoded : array( 'success' => false );
	}
}
