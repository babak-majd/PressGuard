<?php
/**
 * Module contract.
 *
 * @package PressGuard
 */

namespace PressGuard;

defined( 'ABSPATH' ) || exit;

/**
 * Every feature area (firewall, login, hardening, …) implements this so the
 * Plugin container can boot them uniformly.
 */
interface Module {

	/**
	 * Stable machine id for the module (used in settings keys, menus, logs).
	 *
	 * @return string
	 */
	public function id();

	/**
	 * Register the module's WordPress hooks. Called once during boot.
	 */
	public function register();
}
