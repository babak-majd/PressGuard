<?php
/**
 * Rule loading and overrides.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Support\Config;

defined( 'ABSPATH' ) || exit;

/**
 * Loads built-in rule JSON files plus the user's custom rules, applies per-rule
 * overrides from settings (enable/disable, score), and caches the compiled
 * list so the hot path doesn't re-parse JSON on every request.
 */
final class RuleSet {

	const CACHE_KEY = 'pressguard_compiled_rules';

	/**
	 * Built-in rule file basenames (without extension).
	 *
	 * @var string[]
	 */
	private static $builtin = array( 'sqli', 'xss', 'traversal', 'rce' );

	/**
	 * Load the active rules.
	 *
	 * @param Config $config Config service.
	 * @return Rule[]
	 */
	public static function load( Config $config ) {
		$raw = self::read_definitions();

		// Merge the user's own custom rules (stored in settings so no file write
		// is needed on read-only plugin dirs).
		foreach ( (array) $config->get( 'firewall.custom_rules', array() ) as $custom ) {
			if ( is_array( $custom ) && ! empty( $custom['id'] ) && ! empty( $custom['pattern'] ) ) {
				$raw[] = $custom;
			}
		}

		$overrides = (array) $config->get( 'firewall.rule_overrides', array() );

		$rules = array();
		foreach ( $raw as $def ) {
			if ( ! isset( $def['id'] ) ) {
				continue;
			}
			$id = (string) $def['id'];

			if ( isset( $overrides[ $id ] ) && is_array( $overrides[ $id ] ) ) {
				$def = array_merge( $def, $overrides[ $id ] );
			}

			$rules[] = new Rule( $def );
		}

		return $rules;
	}

	/**
	 * Read and merge all rule definitions (cached in the object cache).
	 *
	 * @return array[]
	 */
	private static function read_definitions() {
		$cached = wp_cache_get( self::CACHE_KEY, 'pressguard' );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$defs = array();

		foreach ( self::$builtin as $name ) {
			$defs = array_merge( $defs, self::read_file( PRESSGUARD_DIR . 'rules/' . $name . '.json' ) );
		}

		// User custom rules live alongside the built-ins.
		$defs = array_merge( $defs, self::read_file( PRESSGUARD_DIR . 'rules/custom.json' ) );

		wp_cache_set( self::CACHE_KEY, $defs, 'pressguard', HOUR_IN_SECONDS );

		return $defs;
	}

	/**
	 * Read a single JSON rule file into an array of definitions.
	 *
	 * @param string $path Absolute path.
	 * @return array[]
	 */
	private static function read_file( $path ) {
		if ( ! is_readable( $path ) ) {
			return array();
		}

		$json = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $json ) {
			return array();
		}

		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * Clear the compiled-rule cache (call after editing custom rules).
	 */
	public static function flush_cache() {
		wp_cache_delete( self::CACHE_KEY, 'pressguard' );
	}
}
