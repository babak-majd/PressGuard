<?php
/**
 * Application firewall (Basic level).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Ip;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Inspects the current request with anomaly-scored rules. Matching rules add to
 * a per-request score; crossing the threshold triggers the mode's action:
 * learning/detect log only, enabled blocks with 403. Runs during plugins_loaded
 * (the earliest the plugin can act in Basic mode) with an early-exit fast path.
 */
final class Firewall implements Module {

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
		return 'firewall';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		$config = $this->plugin->config();
		if ( ! $config->is_enabled( 'firewall' ) ) {
			return;
		}

		// Never inspect CLI/cron; those are not attacker-controlled web input.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$this->inspect();
	}

	/**
	 * Inspect the current request and act according to the firewall mode.
	 */
	private function inspect() {
		$config = $this->plugin->config();
		$ip     = $this->ip->client_ip();

		// Absolute allowlist short-circuits everything (fast path first).
		if ( $this->ip_in_list( $ip, (array) $config->get( 'ip.whitelist', array() ) ) ) {
			return;
		}

		// Permanent blocklist.
		if ( $this->ip_in_list( $ip, (array) $config->get( 'ip.blacklist', array() ) ) ) {
			$this->block( $ip, array(), 0, 'ip_blocklist' );
			return;
		}

		/**
		 * Allow integrations (PressPilot authed requests, WooCommerce webhooks,
		 * …) to exempt the current request from inspection.
		 *
		 * @param bool $exempt Whether to skip firewall inspection.
		 */
		if ( apply_filters( 'pressguard_firewall_exempt_request', false ) ) {
			return;
		}

		$values = $this->collect_values();
		if ( empty( $values ) ) {
			return;
		}

		$rules     = RuleSet::load( $config );
		$threshold = max( 1, (int) $config->get( 'firewall.threshold', 5 ) );

		$score   = 0;
		$matched = array();

		foreach ( $rules as $rule ) {
			$subject = $this->values_for_targets( $values, $rule->targets );
			if ( empty( $subject ) ) {
				continue;
			}
			if ( $rule->matches( $subject ) ) {
				$score    += $rule->score;
				$matched[] = $rule->id;
				// Early exit once we're clearly over threshold in blocking mode.
				if ( $score >= $threshold && 'enabled' === $config->get( 'firewall.mode', 'learning' ) ) {
					break;
				}
			}
		}

		if ( $score < $threshold ) {
			return;
		}

		$mode = (string) $config->get( 'firewall.mode', 'learning' );

		if ( 'enabled' === $mode ) {
			$this->block( $ip, $matched, $score, 'rule_match' );
			return;
		}

		// learning / detect: record what *would* have been blocked.
		$this->plugin->logger()->log(
			'firewall',
			'detected',
			array(
				'severity' => Logger::SEVERITY_WARNING,
				'ip'       => $ip,
				'message'  => sprintf( 'Score %d (threshold %d) in %s mode.', $score, $threshold, $mode ),
				'context'  => array(
					'rules' => $matched,
					'uri'   => $this->request_uri(),
				),
			)
		);
	}

	/**
	 * Build the canonical value lists for each request part, once.
	 *
	 * @return array<string,string[]>
	 */
	private function collect_values() {
		$values = array();

		$values['uri'] = array( Normalizer::canonicalize( $this->request_uri() ) );

		// phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET ) ) {
			$values['query'] = Normalizer::flatten( wp_unslash( $_GET ) );
		}
		if ( ! empty( $_POST ) ) {
			$values['body'] = Normalizer::flatten( wp_unslash( $_POST ) );
		}
		if ( ! empty( $_COOKIE ) ) {
			$values['cookie'] = Normalizer::flatten( wp_unslash( $_COOKIE ) );
		}
		// phpcs:enable

		if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			$values['ua'] = array( Normalizer::canonicalize( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );
		}
		if ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			$values['referer'] = array( Normalizer::canonicalize( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) );
		}

		return $values;
	}

	/**
	 * Gather the canonical values for a rule's targets.
	 *
	 * @param array<string,string[]> $values  All collected values.
	 * @param string[]               $targets Rule targets.
	 * @return string[]
	 */
	private function values_for_targets( array $values, array $targets ) {
		$subject = array();
		foreach ( $targets as $target ) {
			if ( ! empty( $values[ $target ] ) ) {
				$subject = array_merge( $subject, $values[ $target ] );
			}
		}
		return $subject;
	}

	/**
	 * Block the request: log, send 403, and stop.
	 *
	 * @param string   $ip      Client IP.
	 * @param string[] $matched Matched rule ids.
	 * @param int      $score   Accumulated score.
	 * @param string   $reason  Short reason code.
	 */
	private function block( $ip, array $matched, $score, $reason ) {
		$this->plugin->logger()->log(
			'firewall',
			'blocked',
			array(
				'severity' => Logger::SEVERITY_CRITICAL,
				'ip'       => $ip,
				'message'  => sprintf( 'Blocked (%s), score %d.', $reason, $score ),
				'context'  => array(
					'rules' => $matched,
					'uri'   => $this->request_uri(),
				),
			)
		);

		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/html; charset=utf-8' );
		}

		echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
		echo '<h1>403 Forbidden</h1><p>This request was blocked by PressGuard.</p>';
		echo '</body></html>';
		exit;
	}

	/**
	 * The raw request URI.
	 *
	 * @return string
	 */
	private function request_uri() {
		return isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	}

	/**
	 * Is an IP contained in a list of IPs/CIDRs?
	 *
	 * @param string   $ip   Client IP.
	 * @param string[] $list IPs/CIDRs.
	 * @return bool
	 */
	private function ip_in_list( $ip, array $list ) {
		if ( '' === $ip ) {
			return false;
		}
		foreach ( $list as $cidr ) {
			if ( Ip::ip_in_cidr( $ip, (string) $cidr ) ) {
				return true;
			}
		}
		return false;
	}
}
