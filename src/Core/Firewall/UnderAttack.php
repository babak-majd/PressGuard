<?php
/**
 * Local "Under Attack" challenge.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

use PressGuard\Core\Anomaly\Anomaly;
use PressGuard\Plugin;
use PressGuard\Support\Ip;

defined( 'ABSPATH' ) || exit;

/**
 * When active (manually, or automatically via the anomaly core), anonymous
 * front-end visitors must pass a lightweight JS/cookie challenge before the
 * page is served. Logged-in users, verified good bots, whitelisted IPs and
 * critical paths are exempt. Runs on template_redirect so login state and
 * conditional tags are available.
 */
final class UnderAttack {

	const COOKIE = 'pressguard_uac';

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Anomaly core.
	 *
	 * @var Anomaly
	 */
	private $anomaly;

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
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin  = $plugin;
		$this->anomaly = new Anomaly( $plugin );
		$this->ip      = new Ip( $plugin->config() );
		$this->ua      = new UserAgent( $plugin->config() );
	}

	/**
	 * Register the challenge hook when the feature could be active.
	 */
	public function register() {
		add_action( 'template_redirect', array( $this, 'maybe_challenge' ), 1 );
	}

	/**
	 * Is Under Attack mode currently active?
	 *
	 * @return bool
	 */
	public function is_active() {
		$config = $this->plugin->config();

		if ( (bool) $config->get( 'firewall.under_attack.manual', false ) ) {
			return true;
		}

		// If a proxy/edge (Cloudflare) is handling it, don't double-challenge.
		if ( (bool) $config->get( 'cloudflare.under_attack_active', false ) ) {
			return false;
		}

		return (bool) $config->get( 'firewall.under_attack.auto', true ) && $this->anomaly->is_under_attack();
	}

	/**
	 * Challenge the visitor if required.
	 */
	public function maybe_challenge() {
		if ( is_admin() || ! $this->is_active() ) {
			return;
		}
		if ( is_user_logged_in() ) {
			return;
		}

		// Never gate ACME validation or REST webhooks (payment, etc.).
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		if ( false !== strpos( $uri, '/.well-known/acme-challenge/' ) ) {
			return;
		}

		/**
		 * Allow integrations to exempt a request from the Under Attack gate
		 * (e.g. WooCommerce webhooks, PressPilot authed calls).
		 *
		 * @param bool $exempt Whether to skip the challenge.
		 */
		if ( apply_filters( 'pressguard_under_attack_exempt', false ) ) {
			return;
		}

		$client_ip = $this->ip->client_ip();

		if ( $this->is_whitelisted( $client_ip ) ) {
			return;
		}
		if ( $this->ua->is_verified_good_bot( $client_ip ) ) {
			return;
		}
		if ( $this->has_valid_cookie( $client_ip ) ) {
			return;
		}

		$this->render_challenge( $client_ip );
	}

	/**
	 * Render the interstitial challenge page and stop.
	 *
	 * @param string $client_ip Client IP.
	 */
	private function render_challenge( $client_ip ) {
		$token = $this->expected_token( $client_ip );

		if ( ! headers_sent() ) {
			status_header( 503 );
			header( 'Retry-After: 5' );
			nocache_headers();
			// Signal page-cache plugins not to store this interstitial.
			if ( ! defined( 'DONOTCACHEPAGE' ) ) {
				define( 'DONOTCACHEPAGE', true );
			}
			header( 'Content-Type: text/html; charset=utf-8' );
		}

		$cookie = self::COOKIE;
		$secure = is_ssl() ? '; Secure' : '';
		?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="robots" content="noindex" />
	<title><?php esc_html_e( 'Checking your browser…', 'pressguard' ); ?></title>
	<style>
		body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f7;color:#1d2327;
			display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
		.box{text-align:center;max-width:420px;padding:32px}
		.spin{width:36px;height:36px;border:3px solid #c3c4c7;border-top-color:#2271b1;border-radius:50%;
			margin:0 auto 16px;animation:s 1s linear infinite}
		@keyframes s{to{transform:rotate(360deg)}}
	</style>
	<script>
		document.cookie = "<?php echo esc_js( $cookie ); ?>=<?php echo esc_js( $token ); ?>; path=/; max-age=3600; SameSite=Lax<?php echo esc_js( $secure ); ?>";
		setTimeout(function(){ location.reload(); }, 1200);
	</script>
</head>
<body>
	<div class="box">
		<div class="spin"></div>
		<p><?php esc_html_e( 'Checking your browser before continuing…', 'pressguard' ); ?></p>
		<noscript><p><?php esc_html_e( 'Please enable JavaScript to continue.', 'pressguard' ); ?></p></noscript>
	</div>
</body>
</html>
		<?php
		exit;
	}

	/**
	 * Does the request carry a valid challenge cookie?
	 *
	 * @param string $client_ip Client IP.
	 * @return bool
	 */
	private function has_valid_cookie( $client_ip ) {
		if ( empty( $_COOKIE[ self::COOKIE ] ) ) {
			return false;
		}
		$provided = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) );
		return hash_equals( $this->expected_token( $client_ip ), $provided );
	}

	/**
	 * Expected cookie token, bound to IP + day + install salt.
	 *
	 * @param string $client_ip Client IP.
	 * @return string
	 */
	private function expected_token( $client_ip ) {
		$day = gmdate( 'Y-m-d' );
		return substr( hash_hmac( 'sha256', $client_ip . '|' . $day, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Is the IP absolutely whitelisted?
	 *
	 * @param string $client_ip Client IP.
	 * @return bool
	 */
	private function is_whitelisted( $client_ip ) {
		if ( '' === $client_ip ) {
			return false;
		}
		foreach ( (array) $this->plugin->config()->get( 'ip.whitelist', array() ) as $cidr ) {
			if ( Ip::ip_in_cidr( $client_ip, (string) $cidr ) ) {
				return true;
			}
		}
		return false;
	}
}
