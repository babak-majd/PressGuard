<?php
/**
 * Login security module.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Orchestrates login-security sub-features: custom login URL, progressive
 * lockout, and generic error messages. Each is toggled from settings.
 */
final class Login implements Module {

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Lockout sub-feature.
	 *
	 * @var Lockout|null
	 */
	private $lockout = null;

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
		return 'login';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		$config = $this->plugin->config();
		if ( ! $config->is_enabled( 'login' ) ) {
			return;
		}

		if ( (bool) $config->get( 'login.lockout.enabled', true ) ) {
			$this->lockout = new Lockout( $this->plugin );
			$this->lockout->register();
		}

		if ( (bool) $config->get( 'login.two_factor.enabled', true ) ) {
			( new TwoFactor( $this->plugin ) )->register();
		}

		$slug = (string) $config->get( 'login.custom_url.slug', '' );
		if ( (bool) $config->get( 'login.custom_url.enabled', false ) && '' !== $slug ) {
			( new LoginUrl( $slug ) )->register();
		}

		if ( (bool) $config->get( 'login.generic_errors', true ) ) {
			add_filter( 'login_errors', array( $this, 'generic_error' ) );
		}
	}

	/**
	 * Replace login error output with a single generic message so a failed
	 * attempt never reveals whether the username existed.
	 *
	 * @param string $error Original error HTML.
	 * @return string
	 */
	public function generic_error( $error ) {
		unset( $error );
		return __( 'Invalid login details.', 'pressguard' );
	}
}
