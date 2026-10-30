<?php
/**
 * Settings store.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Thin wrapper over a single WordPress option holding all PressGuard settings.
 *
 * Keeping everything in one option makes full import/export trivial and avoids
 * scattering rows across the options table. Supports dot-notation for nested
 * module settings (e.g. `login.two_factor.enabled`).
 */
final class Config {

	const OPTION = 'pressguard_settings';

	/**
	 * In-memory copy of the settings array.
	 *
	 * @var array|null
	 */
	private $data = null;

	/**
	 * Load settings from the database (once).
	 *
	 * @return array
	 */
	private function load() {
		if ( null === $this->data ) {
			$stored     = get_option( self::OPTION, array() );
			$this->data = is_array( $stored ) ? $stored : array();
		}

		return $this->data;
	}

	/**
	 * Get a setting by dot-path.
	 *
	 * @param string $path    Dot-notation key, e.g. "login.lockout.max".
	 * @param mixed  $default Value returned when the key is absent.
	 * @return mixed
	 */
	public function get( $path, $default = null ) {
		$data = $this->load();
		$node = $data;

		foreach ( explode( '.', $path ) as $segment ) {
			if ( is_array( $node ) && array_key_exists( $segment, $node ) ) {
				$node = $node[ $segment ];
			} else {
				return $default;
			}
		}

		return $node;
	}

	/**
	 * Set a setting by dot-path and persist.
	 *
	 * @param string $path  Dot-notation key.
	 * @param mixed  $value Value to store.
	 */
	public function set( $path, $value ) {
		$data     = $this->load();
		$segments = explode( '.', $path );
		$node     = &$data;

		foreach ( $segments as $i => $segment ) {
			if ( count( $segments ) - 1 === $i ) {
				$node[ $segment ] = $value;
				break;
			}
			if ( ! isset( $node[ $segment ] ) || ! is_array( $node[ $segment ] ) ) {
				$node[ $segment ] = array();
			}
			$node = &$node[ $segment ];
		}
		unset( $node );

		$this->data = $data;
		update_option( self::OPTION, $this->data, false );
	}

	/**
	 * Whether a module is enabled. Modules default to enabled unless a stored
	 * `<module>.enabled` flag says otherwise.
	 *
	 * @param string $module  Module id.
	 * @param bool   $default Default when unset.
	 * @return bool
	 */
	public function is_enabled( $module, $default = true ) {
		return (bool) $this->get( $module . '.enabled', $default );
	}

	/**
	 * Get the entire settings array (for export).
	 *
	 * @return array
	 */
	public function all() {
		return $this->load();
	}

	/**
	 * Replace the entire settings array (for import) and persist.
	 *
	 * @param array $data New settings.
	 */
	public function replace( array $data ) {
		$this->data = $data;
		update_option( self::OPTION, $this->data, false );
	}
}
