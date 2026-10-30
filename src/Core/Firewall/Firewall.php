<?php
/**
 * Application firewall (Basic level).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Core\Anomaly\Anomaly;
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
	 * User-Agent evaluator.
	 *
	 * @var UserAgent
	 */
	private $ua;

	/**
	 * Anomaly core.
	 *
	 * @var Anomaly
	 */
	private $anomaly;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin  = $plugin;
		$this->ip      = new Ip( $plugin->config() );
		$this->ua      = new UserAgent( $plugin->config() );
		$this->anomaly = new Anomaly( $plugin );
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

		// Extended WAF management (snapshot refresh + install toggle). Attach
		// this regardless of SAPI so the snapshot stays fresh even when settings
		// change via WP-CLI.
		( new Extended( $this->plugin ) )->register();

		// Never inspect CLI/cron; those are not attacker-controlled web input.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		// Local Under Attack challenge runs later (template_redirect); register
		// it before inspect() so the hook is in place even on clean requests.
		if ( (bool) $config->get( 'firewall.under_attack.enabled', true ) ) {
			( new UnderAttack( $this->plugin ) )->register();
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

		$mode = (string) $config->get( 'firewall.mode', 'learning' );

		// User-Agent blocklist (cheap, runs before rule matching).
		if ( $this->ua->is_blocked() ) {
			$this->anomaly->record_hit( 'ua' );
			if ( 'enabled' === $mode ) {
				$this->block( $ip, array(), 0, 'user_agent' );
				return;
			}
		}

		// Per-IP rate limiting.
		if ( $this->rate_limited( $ip ) ) {
			$this->anomaly->record_hit( 'rate' );
			if ( 'enabled' === $mode ) {
				$this->block( $ip, array(), 0, 'rate_limit' );
				return;
			}
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
				if ( $score >= $threshold && 'enabled' === $mode ) {
					break;
				}
			}
		}

		if ( $score < $threshold ) {
			return;
		}

		// A real attack signal — feed the anomaly core (drives Under Attack).
		$this->anomaly->record_hit( 'rule' );

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
		// Skip POST-body rules in a trusted admin context: an authenticated user
		// editing content legitimately posts markup/code that would otherwise
		// trip XSS/SQLi rules. Login state isn't loaded this early, so we use a
		// cheap logged-in-cookie-on-admin-path heuristic (matches the prepend).
		if ( ! empty( $_POST ) && ! $this->is_trusted_admin_context() ) {
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
	 * Whether this looks like an authenticated admin/editing request, where
	 * POST-body rule matching should be skipped to avoid false positives.
	 *
	 * @return bool
	 */
	private function is_trusted_admin_context() {
		$uri  = $this->request_uri();
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		$admin_path = ( false !== strpos( $path, '/wp-admin/' ) )
			|| ( false !== strpos( $path, 'wp-login.php' ) )
			|| ( false !== strpos( $path, '/wp-json/' ) );
		if ( ! $admin_path ) {
			return false;
		}

		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( 0 === strpos( (string) $cookie_name, 'wordpress_logged_in' ) ) {
				return true;
			}
		}

		return false;
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
	 * Per-IP rate limiting over a short sliding window. Logged-in users,
	 * whitelisted IPs, and verified good bots are exempt. The (slower)
	 * good-bot DNS check only runs once an IP is already over the limit.
	 *
	 * @param string $ip Client IP.
	 * @return bool True when the request should be rate-limited.
	 */
	private function rate_limited( $ip ) {
		$config = $this->plugin->config();
		if ( ! (bool) $config->get( 'firewall.rate_limit.enabled', false ) || '' === $ip ) {
			return false;
		}

		// Cheap logged-in exemption: the auth cookie is present before
		// pluggable functions load, so check its presence (not validity).
		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( 0 === strpos( (string) $cookie_name, 'wordpress_logged_in' ) ) {
				return false;
			}
		}

		$max    = max( 10, (int) $config->get( 'firewall.rate_limit.max', 240 ) );
		$window = max( 10, (int) $config->get( 'firewall.rate_limit.window', 60 ) );
		$bucket = (int) floor( time() / $window );
		$key    = 'pressguard_rl_' . md5( $ip ) . '_' . $bucket;

		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, $window );

		if ( $count <= $max ) {
			return false;
		}

		// Over the limit — exempt verified good crawlers before penalizing.
		if ( $this->ua->is_verified_good_bot( $ip ) ) {
			return false;
		}

		return true;
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
