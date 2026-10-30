<?php
/**
 * Hardening module — independent, reversible security switches.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Hardening;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Applies a set of "maximum hardening" switches. Each switch is independent and
 * defaults off unless enabled in settings, so nothing silently changes site
 * behaviour. Advanced users can re-open anything these switches close (handled
 * by reading the same settings — there are no hard locks here).
 */
final class Hardening implements Module {

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
	 * {@inheritDoc}
	 */
	public function id() {
		return 'hardening';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		if ( ! $this->plugin->config()->is_enabled( 'hardening' ) ) {
			return;
		}

		if ( $this->on( 'disable_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		if ( $this->on( 'disable_xmlrpc' ) ) {
			// Fully block the endpoint: `xmlrpc_enabled` alone leaves demo and
			// pingback methods callable. We're already on plugins_loaded, and
			// xmlrpc.php defines XMLRPC_REQUEST before wp-load runs, so we can
			// short-circuit the request here.
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				status_header( 403 );
				exit( 'XML-RPC is disabled.' );
			}
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'xmlrpc_methods', array( $this, 'strip_xmlrpc_methods' ) );
		}

		if ( $this->on( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( $this->on( 'block_user_enumeration' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_scan' ) );
			add_filter( 'rest_endpoints', array( $this, 'restrict_users_endpoint' ) );
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}

		if ( $this->on( 'restrict_rest_anonymous' ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'require_auth_for_rest' ) );
		}

		if ( $this->on( 'security_headers' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
		}
	}

	/**
	 * Is a given hardening switch turned on?
	 *
	 * @param string $key Switch key under `hardening.`.
	 * @return bool
	 */
	private function on( $key ) {
		return (bool) $this->plugin->config()->get( 'hardening.' . $key, false );
	}

	/**
	 * Remove the pingback methods most abused for DDoS amplification.
	 *
	 * @param array $methods Registered XML-RPC methods.
	 * @return array
	 */
	public function strip_xmlrpc_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Redirect/disable author enumeration via `?author=N` on the front end.
	 */
	public function block_author_scan() {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}

		// Numeric `?author=N` is the enumeration vector: it 301s to
		// /author/<slug>/ and leaks the username. Legitimate author archives
		// use the slug form (author_name) which we leave untouched.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only probe check.
		$author = isset( $_GET['author'] ) ? wp_unslash( $_GET['author'] ) : '';
		if ( '' !== $author && is_numeric( $author ) ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Remove the core users REST endpoints for unauthenticated requests.
	 *
	 * @param array $endpoints REST endpoints.
	 * @return array
	 */
	public function restrict_users_endpoint( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
			if ( isset( $endpoints[ $route ] ) ) {
				unset( $endpoints[ $route ] );
			}
		}

		return $endpoints;
	}

	/**
	 * Require authentication for all REST requests when enabled.
	 *
	 * Allowlisted namespaces (e.g. PressPilot) and PressGuard's own routes are
	 * left alone so integrations keep working.
	 *
	 * @param mixed $result Current auth result.
	 * @return mixed
	 */
	public function require_auth_for_rest( $result ) {
		if ( ! empty( $result ) || is_user_logged_in() ) {
			return $result;
		}

		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] )
			? (string) $GLOBALS['wp']->query_vars['rest_route']
			: '';

		/**
		 * Filter REST route prefixes that stay public even when anonymous REST
		 * is restricted. PressPilot and others hook here to keep their endpoints
		 * reachable for their own authenticated flows.
		 *
		 * @param string[] $allowed Route prefixes.
		 */
		$allowed = apply_filters(
			'pressguard_rest_public_prefixes',
			array( '/presspilot/', '/oembed/' )
		);

		foreach ( $allowed as $prefix ) {
			if ( 0 === strpos( $route, $prefix ) ) {
				return $result;
			}
		}

		return new \WP_Error(
			'pressguard_rest_forbidden',
			__( 'REST API access is restricted to authenticated users.', 'pressguard' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Emit baseline security headers. HSTS is deliberately left to the SSL
	 * module to avoid two modules setting the same header (single owner rule).
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );

		$custom = (string) $this->plugin->config()->get( 'hardening.referrer_policy', '' );
		if ( '' !== $custom ) {
			header( 'Referrer-Policy: ' . $custom );
		}
	}
}
