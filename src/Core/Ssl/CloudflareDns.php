<?php
/**
 * Cloudflare DNS-01 provider.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Ssl;

defined( 'ABSPATH' ) || exit;

/**
 * Creates/removes the _acme-challenge TXT record via the Cloudflare API for the
 * DNS-01 challenge (needed for wildcard certs or when HTTP-01 isn't possible).
 * Requires a scoped API token with DNS edit permission on the zone.
 */
final class CloudflareDns {

	const API = 'https://api.cloudflare.com/client/v4';

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
	 * Resolve the zone id for a domain (matches the longest zone suffix).
	 *
	 * @param string $domain Domain.
	 * @return string Zone id.
	 */
	public function zone_id( $domain ) {
		$domain = ltrim( $domain, '*.' );
		$parts  = explode( '.', $domain );
		// Try progressively shorter suffixes (sub.example.com → example.com).
		while ( count( $parts ) >= 2 ) {
			$candidate = implode( '.', $parts );
			$res       = $this->get( '/zones?name=' . rawurlencode( $candidate ) );
			if ( ! empty( $res['result'][0]['id'] ) ) {
				return $res['result'][0]['id'];
			}
			array_shift( $parts );
		}
		throw new \RuntimeException( 'Cloudflare zone not found for ' . $domain );
	}

	/**
	 * Add a TXT record; returns the record id.
	 *
	 * @param string $name  Record name (e.g. _acme-challenge.example.com).
	 * @param string $value TXT value.
	 * @return string Record id.
	 */
	public function add_txt( $name, $value ) {
		$zone = $this->zone_id( $name );
		$res  = $this->post(
			'/zones/' . $zone . '/dns_records',
			array(
				'type'    => 'TXT',
				'name'    => $name,
				'content' => $value,
				'ttl'     => 120,
			)
		);
		if ( empty( $res['success'] ) ) {
			throw new \RuntimeException( 'Cloudflare TXT create failed.' );
		}
		return array(
			'zone'   => $zone,
			'record' => $res['result']['id'],
		);
	}

	/**
	 * Delete a TXT record.
	 *
	 * @param string $zone   Zone id.
	 * @param string $record Record id.
	 */
	public function delete_txt( $zone, $record ) {
		$this->request( 'DELETE', '/zones/' . $zone . '/dns_records/' . $record, null );
	}

	/**
	 * GET helper.
	 *
	 * @param string $path API path.
	 * @return array
	 */
	private function get( $path ) {
		return $this->request( 'GET', $path, null );
	}

	/**
	 * POST helper.
	 *
	 * @param string $path API path.
	 * @param array  $body Body.
	 * @return array
	 */
	private function post( $path, $body ) {
		return $this->request( 'POST', $path, $body );
	}

	/**
	 * Perform an authenticated request.
	 *
	 * @param string     $method HTTP method.
	 * @param string     $path   API path.
	 * @param array|null $body   Body.
	 * @return array
	 */
	private function request( $method, $path, $body ) {
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

		$res = wp_remote_request( self::API . $path, $args );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( 'Cloudflare API error: ' . $res->get_error_message() );
		}
		return json_decode( wp_remote_retrieve_body( $res ), true );
	}
}
