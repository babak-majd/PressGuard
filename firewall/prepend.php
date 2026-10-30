<?php
/**
 * PressGuard Extended WAF — pre-WordPress firewall.
 *
 * Loaded via PHP's auto_prepend_file so it runs before WordPress (and before
 * cache plugins) on every PHP request. It is deliberately minimal: it loads a
 * generated snapshot plus the standalone Normalizer/Rule classes, and must
 * FAIL-OPEN on any error so a problem here can never take the site down.
 *
 * Because it runs before WordPress, it cannot see login state / nonces, so it
 * only performs context-free checks (IP lists, UA, size, rules) and skips POST
 * body rules on admin paths to avoid false positives on legitimate editing.
 *
 * @package PressGuard
 */

if ( defined( 'PRESSGUARD_WAF' ) ) {
	return;
}
define( 'PRESSGUARD_WAF', true );

( static function () {
	// Everything is wrapped so a failure just returns (fail-open).
	$base = __DIR__;

	$snapshot_file = $base . '/../../../uploads/pressguard/waf-snapshot.php';
	if ( ! is_readable( $snapshot_file ) ) {
		return;
	}

	$cfg = include $snapshot_file;
	if ( ! is_array( $cfg ) || empty( $cfg['enabled'] ) ) {
		return;
	}

	// Only act as a hard blocker in "enabled" mode; otherwise defer to Basic.
	if ( 'enabled' !== ( $cfg['mode'] ?? 'learning' ) ) {
		return;
	}

	$normalizer = $base . '/../src/Core/Firewall/Normalizer.php';
	$rule_class = $base . '/../src/Core/Firewall/Rule.php';
	if ( ! is_readable( $normalizer ) || ! is_readable( $rule_class ) ) {
		return;
	}
	require_once $normalizer;
	require_once $rule_class;

	// --- Resolve client IP (trust forwarded headers only from known proxies).
	$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
	$ip     = $remote;
	if ( '' !== $remote && ! empty( $cfg['trusted_proxies'] ) && pg_waf_ip_in_list( $remote, $cfg['trusted_proxies'] ) ) {
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $h ) {
			if ( ! empty( $_SERVER[ $h ] ) ) {
				$candidate = trim( explode( ',', (string) $_SERVER[ $h ] )[0] );
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					$ip = $candidate;
					break;
				}
			}
		}
	}

	// --- Absolute allowlist bypasses everything.
	if ( '' !== $ip && ! empty( $cfg['whitelist'] ) && pg_waf_ip_in_list( $ip, $cfg['whitelist'] ) ) {
		return;
	}

	// --- Permanent blocklist.
	if ( '' !== $ip && ! empty( $cfg['blacklist'] ) && pg_waf_ip_in_list( $ip, $cfg['blacklist'] ) ) {
		pg_waf_block();
	}

	// --- Request size cap.
	$max_body = (int) ( $cfg['max_body'] ?? 0 );
	if ( $max_body > 0 ) {
		$len = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
		if ( $len > $max_body ) {
			pg_waf_block();
		}
	}

	$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

	// --- User-Agent blocklist / empty UA.
	if ( '' === trim( $ua ) ) {
		if ( ! empty( $cfg['ua_block_empty'] ) ) {
			pg_waf_block();
		}
	} elseif ( ! empty( $cfg['ua_blocklist'] ) ) {
		foreach ( (array) $cfg['ua_blocklist'] as $pattern ) {
			if ( '' !== $pattern && @preg_match( '#' . str_replace( '#', '\#', (string) $pattern ) . '#i', $ua ) === 1 ) {
				pg_waf_block();
			}
		}
	}

	// --- Rule matching with anomaly scoring.
	if ( empty( $cfg['rules'] ) ) {
		return;
	}

	$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
	$path = (string) parse_url( $uri, PHP_URL_PATH );

	// Skip POST-body rules on admin paths: an admin legitimately saving content
	// with <script> must not be blocked by a layer that can't see login state.
	$is_admin_path = false;
	foreach ( (array) ( $cfg['admin_paths'] ?? array() ) as $ap ) {
		if ( '' !== $ap && false !== strpos( $path, $ap ) ) {
			$is_admin_path = true;
			break;
		}
	}

	$values = array(
		'uri'     => array( \PressGuard\Core\Firewall\Normalizer::canonicalize( $uri ) ),
		'query'   => isset( $_GET ) ? \PressGuard\Core\Firewall\Normalizer::flatten( $_GET ) : array(),
		'ua'      => array( \PressGuard\Core\Firewall\Normalizer::canonicalize( $ua ) ),
	);
	if ( ! $is_admin_path && ! empty( $_POST ) ) {
		$values['body'] = \PressGuard\Core\Firewall\Normalizer::flatten( $_POST );
	}

	$threshold = max( 1, (int) ( $cfg['threshold'] ?? 5 ) );
	$score     = 0;

	foreach ( (array) $cfg['rules'] as $def ) {
		$rule    = new \PressGuard\Core\Firewall\Rule( (array) $def );
		$subject = array();
		foreach ( $rule->targets as $t ) {
			if ( ! empty( $values[ $t ] ) ) {
				$subject = array_merge( $subject, $values[ $t ] );
			}
		}
		if ( ! empty( $subject ) && $rule->matches( $subject ) ) {
			$score += $rule->score;
			if ( $score >= $threshold ) {
				pg_waf_block();
			}
		}
	}
} )();

/**
 * Test an IP against a list of IPs/CIDRs (IPv4/IPv6).
 *
 * @param string $ip   IP address.
 * @param array  $list IPs/CIDRs.
 * @return bool
 */
function pg_waf_ip_in_list( $ip, $list ) {
	foreach ( (array) $list as $cidr ) {
		$cidr = (string) $cidr;
		if ( false === strpos( $cidr, '/' ) ) {
			if ( $ip === $cidr ) {
				return true;
			}
			continue;
		}
		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$ip_bin                = @inet_pton( $ip );
		$subnet_bin            = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			continue;
		}
		$bits  = (int) $bits;
		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( $bytes > 0 && 0 !== substr_compare( $ip_bin, $subnet_bin, 0, $bytes ) ) {
			continue;
		}
		if ( 0 === $rem ) {
			return true;
		}
		$mask = ~( ( 1 << ( 8 - $rem ) ) - 1 ) & 0xff;
		if ( ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $subnet_bin[ $bytes ] ) & $mask ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Emit a 403 and stop the request before WordPress loads.
 */
function pg_waf_block() {
	if ( ! headers_sent() ) {
		header( 'HTTP/1.1 403 Forbidden' );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Cache-Control: no-store' );
	}
	echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
	echo '<h1>403 Forbidden</h1><p>This request was blocked by PressGuard.</p>';
	echo '</body></html>';
	exit;
}
