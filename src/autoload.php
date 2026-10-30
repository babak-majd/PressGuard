<?php
/**
 * Lightweight PSR-4 autoloader for the `PressGuard\` namespace.
 *
 * Used as a fallback when Composer's autoloader is not present, so PressGuard
 * works on hosts where `composer install` was never run.
 *
 * @package PressGuard
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	static function ( $class ) {
		$prefix   = 'PressGuard\\';
		$base_dir = __DIR__ . '/';

		$len = strlen( $prefix );
		if ( 0 !== strncmp( $prefix, $class, $len ) ) {
			return;
		}

		$relative = substr( $class, $len );
		$file     = $base_dir . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_readable( $file ) ) {
			require $file;
		}
	}
);
