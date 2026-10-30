<?php
/**
 * User-Agent evaluation.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Support\Config;

defined( 'ABSPATH' ) || exit;

/**
 * Evaluates the request User-Agent: blocks a user-defined list and (optionally)
 * empty UAs, and confirms "good" crawlers by forward-confirmed reverse DNS so a
 * spoofed `Googlebot` string can't earn an allowlist bypass.
 */
final class UserAgent {

	/**
	 * Config service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Constructor.
	 *
	 * @param Config $config Config service.
	 */
	public function __construct( Config $config ) {
		$this->config = $config;
	}

	/**
	 * The raw request User-Agent.
	 *
	 * @return string
	 */
	public function current() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
	}

	/**
	 * Should the request be blocked purely on its User-Agent?
	 *
	 * @return bool
	 */
	public function is_blocked() {
		$ua = $this->current();

		if ( '' === trim( $ua ) ) {
			return (bool) $this->config->get( 'firewall.ua.block_empty', false );
		}

		$patterns = (array) $this->config->get( 'firewall.ua.blocklist', array() );
		foreach ( $patterns as $pattern ) {
			$pattern = (string) $pattern;
			if ( '' === $pattern ) {
				continue;
			}
			if ( @preg_match( '#' . str_replace( '#', '\#', $pattern ) . '#i', $ua ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return true;
			}
		}

		return false;
	}

	/**
	 * Is this request from a verified good crawler? Used to exempt such bots
	 * from rate limiting and Under Attack challenges (never from rule matching).
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public function is_verified_good_bot( $ip ) {
		$ua = strtolower( $this->current() );
		if ( '' === $ua || '' === $ip ) {
			return false;
		}

		$map = array(
			'googlebot'    => array( '.googlebot.com', '.google.com' ),
			'bingbot'      => array( '.search.msn.com' ),
			'applebot'     => array( '.applebot.apple.com' ),
			'duckduckbot'  => array( '.duckduckgo.com' ),
			'yandex'       => array( '.yandex.com', '.yandex.net', '.yandex.ru' ),
		);

		$suffixes = array();
		foreach ( $map as $token => $domains ) {
			if ( false !== strpos( $ua, $token ) ) {
				$suffixes = $domains;
				break;
			}
		}
		if ( empty( $suffixes ) ) {
			return false;
		}

		// Forward-confirmed reverse DNS: PTR must end with an allowed suffix and
		// resolve back to the same IP.
		$host = @gethostbyaddr( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! $host || $host === $ip ) {
			return false;
		}

		$host_matches = false;
		foreach ( $suffixes as $suffix ) {
			if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
				$host_matches = true;
				break;
			}
		}
		if ( ! $host_matches ) {
			return false;
		}

		$forward = @gethostbyname( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return $forward === $ip;
	}
}
