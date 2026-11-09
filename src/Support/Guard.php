<?php
/**
 * Error guard — records caught errors without ever throwing itself.
 *
 * @package PressGuard
 */

namespace PressGuard\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Tiny, dependency-free helper for the try/catch guards around critical paths
 * (authentication, the firewall). It records the most recent error to an option
 * and the PHP error log so a swallowed failure can still be diagnosed, and is
 * careful never to raise an error of its own.
 */
final class Guard {

	const OPTION = 'pressguard_last_fatal';

	/**
	 * Record a caught throwable.
	 *
	 * @param string     $context Where it happened (e.g. "lockout.check_lock").
	 * @param \Throwable $e       The error.
	 */
	public static function report( $context, $e ) {
		try {
			$data = array(
				'context' => (string) $context,
				'message' => $e->getMessage(),
				'file'    => $e->getFile(),
				'line'    => $e->getLine(),
				'class'   => get_class( $e ),
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				'uri'     => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				'time'    => time(),
			);
			if ( function_exists( 'update_option' ) ) {
				update_option( self::OPTION, $data, false );
			}
			if ( function_exists( 'error_log' ) ) {
				error_log( 'PressGuard caught error in ' . $context . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() ); // phpcs:ignore
			}
		} catch ( \Throwable $ignored ) {
			unset( $ignored );
		}
	}
}
