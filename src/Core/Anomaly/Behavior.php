<?php
/**
 * Behavioural signal collection (404 scanning, login failures).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Anomaly;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Ip;

defined( 'ABSPATH' ) || exit;

/**
 * Feeds the per-IP RiskEngine from signals the firewall doesn't see directly:
 * 404 responses (recon/scanning), probes of sensitive paths, and failed logins.
 * This is the data side of the advanced anomaly layer; the firewall reads the
 * resulting score to decide whether to escalate.
 */
final class Behavior implements Module {

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * IP resolver.
	 *
	 * @var Ip
	 */
	private $ip;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
		$this->ip     = new Ip( $plugin->config() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'behavior';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		if ( ! (bool) $this->plugin->config()->get( 'anomaly.risk_scoring', true ) ) {
			return;
		}
		add_action( 'template_redirect', array( $this, 'on_template' ) );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
	}

	/**
	 * Record 404s and sensitive-path probes.
	 */
	public function on_template() {
		if ( ! is_404() ) {
			return;
		}
		$ip = $this->ip->client_ip();
		if ( '' === $ip ) {
			return;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( (string) wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// A 404 that targets a known recon/sensitive path scores higher.
		$probe = ( false !== strpos( $uri, 'readme' ) )
			|| ( false !== strpos( $uri, '.sql' ) )
			|| ( false !== strpos( $uri, 'wp-config' ) )
			|| ( false !== strpos( $uri, '.env' ) )
			|| ( false !== strpos( $uri, '.git' ) )
			|| preg_match( '#/wp-content/(plugins|themes)/[^/]+/.*\.(txt|md|log)$#', $uri );

		RiskEngine::record( $ip, $probe ? 'probe' : '404' );
	}

	/**
	 * Record a failed login.
	 */
	public function on_login_failed() {
		RiskEngine::record( $this->ip->client_ip(), 'login_failed' );
	}
}
