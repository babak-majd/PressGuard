<?php
/**
 * Malware signature definitions and matcher.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * A layered signature set for PHP malware: decoder-wrapped eval, dynamic code
 * from request input, command execution, deprecated /e preg_replace, known
 * webshell markers, and oversized base64 blobs. Signatures only flag (never
 * auto-delete), and matching is applied per file with a confidence score.
 */
final class Signatures {

	/**
	 * Return the signature definitions.
	 *
	 * @return array[] Each: id, pattern, score, description.
	 */
	public static function all() {
		return array(
			array(
				'id'          => 'eval-decoder',
				'pattern'     => '/\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(/i',
				'score'       => 9,
				'description' => 'eval() wrapping a decoder (classic obfuscated payload)',
			),
			array(
				'id'          => 'eval-request',
				'pattern'     => '/\b(eval|assert)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode\s*\(\s*\$_)/i',
				'score'       => 10,
				'description' => 'Dynamic code execution from request input',
			),
			array(
				'id'          => 'exec-request',
				'pattern'     => '/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
				'score'       => 10,
				'description' => 'OS command execution from request input',
			),
			array(
				'id'          => 'preg-replace-e',
				'pattern'     => '/preg_replace\s*\(\s*([\'"]).*?\1\s*[eismuxADSUXJ]*e[eismuxADSUXJ]*\1?\s*,/i',
				'score'       => 8,
				'description' => 'preg_replace with /e modifier (code execution)',
			),
			array(
				'id'          => 'create-function',
				'pattern'     => '/\bcreate_function\s*\(/i',
				'score'       => 5,
				'description' => 'create_function() (often used to hide eval)',
			),
			array(
				'id'          => 'webshell-marker',
				'pattern'     => '/(c99shell|r57shell|b374k|wso\s*shell|filesman|phpspy|\bweb\s*shell\b|\bbackdoor\b)/i',
				'score'       => 8,
				'description' => 'Known webshell / backdoor marker',
			),
			array(
				'id'          => 'callback-exec',
				'pattern'     => '/\b(call_user_func|call_user_func_array|array_map|array_filter)\s*\(\s*([\'"])(eval|assert|system|exec|shell_exec|passthru)\2/i',
				'score'       => 8,
				'description' => 'Callback used to invoke a dangerous function',
			),
			array(
				'id'          => 'obfuscated-chr',
				'pattern'     => '/(chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
				'score'       => 6,
				'description' => 'Long chr() concatenation (string obfuscation)',
			),
			array(
				'id'          => 'big-base64',
				'pattern'     => '/[\'"][A-Za-z0-9+\/]{300,}={0,2}[\'"]/',
				'score'       => 4,
				'description' => 'Oversized base64 blob (possible packed payload)',
			),
			array(
				'id'          => 'gzinflate-base64',
				'pattern'     => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
				'score'       => 7,
				'description' => 'gzinflate(base64_decode()) decoder chain',
			),
		);
	}

	/**
	 * Signatures specific to .htaccess files.
	 *
	 * @return array[]
	 */
	public static function htaccess_rules() {
		return array(
			array(
				'id'          => 'htaccess-auto-prepend',
				'pattern'     => '/php_value\s+auto_(prepend|append)_file/i',
				'score'       => 7,
				'description' => 'auto_prepend/append_file directive (can load a backdoor on every request)',
			),
			array(
				'id'          => 'htaccess-handler-php',
				'pattern'     => '/(AddType|AddHandler|SetHandler)\s+[^\n]*php/i',
				'score'       => 6,
				'description' => 'Directive mapping files to the PHP handler (risky in uploads)',
			),
			array(
				'id'          => 'htaccess-php-flag',
				'pattern'     => '/php_(value|flag)\s+(allow_url_include|auto_prepend_file|safe_mode|open_basedir)/i',
				'score'       => 6,
				'description' => 'Dangerous php_value/php_flag override',
			),
			array(
				'id'          => 'htaccess-base64',
				'pattern'     => '/(RewriteRule|RewriteCond)[^\n]*(base64|eval|%00)/i',
				'score'       => 7,
				'description' => 'Suspicious rewrite directive',
			),
		);
	}

	/**
	 * Scan .htaccess content for malicious directives.
	 *
	 * @param string $content File content.
	 * @return array[]
	 */
	public static function scan_htaccess( $content ) {
		$matches = array();
		foreach ( self::htaccess_rules() as $sig ) {
			if ( @preg_match( $sig['pattern'], $content ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$matches[] = array(
					'id'          => $sig['id'],
					'score'       => $sig['score'],
					'description' => $sig['description'],
				);
			}
		}
		return $matches;
	}

	/**
	 * Scan file content and return the matched signatures.
	 *
	 * @param string $content File content.
	 * @return array[] Matched signatures (id, score, description).
	 */
	public static function scan_content( $content ) {
		$matches = array();
		foreach ( self::all() as $sig ) {
			if ( @preg_match( $sig['pattern'], $content ) === 1 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$matches[] = array(
					'id'          => $sig['id'],
					'score'       => $sig['score'],
					'description' => $sig['description'],
				);
			}
		}
		return $matches;
	}
}
