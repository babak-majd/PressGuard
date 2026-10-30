<?php
/**
 * Plugin container and bootstrapper.
 *
 * @package PressGuard
 */

namespace PressGuard;

use PressGuard\Support\Config;
use PressGuard\Support\Db;
use PressGuard\Support\Installer;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Central service container. Holds shared services (config, logger) and the
 * registry of feature modules, then boots them on `plugins_loaded`.
 */
final class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Shared config service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Shared logger service.
	 *
	 * @var Logger
	 */
	private $logger;

	/**
	 * Registered feature modules, keyed by id.
	 *
	 * @var Module[]
	 */
	private $modules = array();

	/**
	 * Whether boot() has already run.
	 *
	 * @var bool
	 */
	private $booted = false;

	/**
	 * Private constructor — use instance().
	 */
	private function __construct() {
		$this->config = new Config();
		$this->logger = new Logger( $this->config );
	}

	/**
	 * Get the singleton instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Boot the plugin: register modules and wire admin UI. Idempotent.
	 */
	public function boot() {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		load_plugin_textdomain( 'pressguard', false, dirname( PRESSGUARD_BASENAME ) . '/languages' );

		// Keep the schema current after plugin updates that skip reactivation.
		Db::maybe_migrate();

		// Daily maintenance: purge/cap the event log.
		add_action( Installer::CRON_PURGE, array( $this, 'run_maintenance' ) );

		/**
		 * Filter the list of module class names before they are instantiated.
		 *
		 * @param string[] $classes Fully-qualified module class names.
		 */
		$classes = apply_filters( 'pressguard_modules', $this->default_modules() );

		foreach ( $classes as $class ) {
			if ( ! class_exists( $class ) ) {
				continue;
			}
			$module = new $class( $this );
			if ( $module instanceof Module ) {
				$this->modules[ $module->id() ] = $module;
				$module->register();
			}
		}

		/**
		 * Fires after all PressGuard modules have registered their hooks.
		 *
		 * @param Plugin $plugin The plugin container.
		 */
		do_action( 'pressguard_booted', $this );
	}

	/**
	 * Default module class list. Grows as phases are implemented.
	 *
	 * @return string[]
	 */
	private function default_modules() {
		return array(
			// Compatibility first: it only attaches exemption filters, which the
			// firewall consults when it inspects during its own registration.
			\PressGuard\Core\Compat\Compatibility::class,
			\PressGuard\Core\Firewall\Firewall::class,
			\PressGuard\Core\Hardening\Hardening::class,
			\PressGuard\Core\Login\Login::class,
			\PressGuard\Core\Scanner\Scanner::class,
			\PressGuard\Core\Audit\Audit::class,
			\PressGuard\Core\Permissions\Permissions::class,
			\PressGuard\Core\Access\Access::class,
			\PressGuard\Core\Activity\Activity::class,
			\PressGuard\Core\Ssl\Ssl::class,
			\PressGuard\Core\Integrations\Cloudflare\Cloudflare::class,
			\PressGuard\Core\Alerts\Alerts::class,
			\PressGuard\Admin\Admin::class,
		);
	}

	/**
	 * Scheduled daily maintenance callback: enforce log retention and row caps.
	 */
	public function run_maintenance() {
		$retention = (int) $this->config->get( 'activity.retention_days', 90 );
		$max_rows  = (int) $this->config->get( 'activity.max_rows', 100000 );
		Db::purge_events( $retention, $max_rows );
	}

	/**
	 * Config service accessor.
	 *
	 * @return Config
	 */
	public function config() {
		return $this->config;
	}

	/**
	 * Logger service accessor.
	 *
	 * @return Logger
	 */
	public function logger() {
		return $this->logger;
	}

	/**
	 * Get a registered module by id.
	 *
	 * @param string $id Module id.
	 * @return Module|null
	 */
	public function module( $id ) {
		return isset( $this->modules[ $id ] ) ? $this->modules[ $id ] : null;
	}

	/**
	 * All registered modules.
	 *
	 * @return Module[]
	 */
	public function modules() {
		return $this->modules;
	}
}
