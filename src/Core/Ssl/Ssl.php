<?php
/**
 * SSL / HTTPS module.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Ssl;

use PressGuard\Module;
use PressGuard\Plugin;
use PressGuard\Support\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * Two layers:
 *  1) Universal (works on any host): force HTTPS, fix mixed content, send HSTS.
 *  2) Optional Let's Encrypt issuance via ACME (HTTP-01, or DNS-01/Cloudflare
 *     for wildcards). Issuance obtains the cert + key; installing it into the
 *     web server is host-dependent, so where we can't install we store the cert
 *     and show manual instructions. Auto-renew runs on cron.
 *
 * HSTS is owned here (not Hardening) to avoid duplicate headers.
 */
final class Ssl implements Module {

	const ADMIN_SLUG = 'pressguard-ssl';
	const CRON_HOOK  = 'pressguard_ssl_renew';

	/**
	 * Plugin container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param Plugin $plugin Container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * {@inheritDoc}
	 */
	public function id() {
		return 'ssl';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		// ACME HTTP-01 responder is always available (needed during issuance).
		( new Challenge() )->register();

		$config = $this->plugin->config();

		if ( (bool) $config->get( 'ssl.force_https', false ) ) {
			add_action( 'init', array( $this, 'maybe_force_https' ), 1 );
		}
		if ( (bool) $config->get( 'ssl.hsts', false ) ) {
			add_action( 'send_headers', array( $this, 'send_hsts' ) );
		}
		if ( (bool) $config->get( 'ssl.fix_mixed_content', false ) ) {
			add_action( 'template_redirect', array( $this, 'start_mixed_content_buffer' ), 1 );
		}

		add_action( 'pressguard_admin_menu', array( $this, 'menu' ), 10, 2 );
		add_action( 'admin_post_pressguard_ssl', array( $this, 'handle' ) );
		add_action( self::CRON_HOOK, array( $this, 'maybe_renew' ) );
	}

	// ---- Universal layer --------------------------------------------------

	/**
	 * Is the current request already secure (direct or via a trusted proxy)?
	 *
	 * @return bool
	 */
	private function is_secure() {
		if ( is_ssl() ) {
			return true;
		}
		$proto = isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ? strtolower( (string) wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) : '';
		return 'https' === $proto;
	}

	/**
	 * Redirect to HTTPS when the request is insecure.
	 */
	public function maybe_force_https() {
		if ( $this->is_secure() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		// Never redirect the ACME challenge path (served over HTTP).
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		if ( 0 === strpos( (string) wp_parse_url( $uri, PHP_URL_PATH ), Challenge::PREFIX ) ) {
			return;
		}

		$host = isset( $_SERVER['HTTP_HOST'] ) ? (string) wp_unslash( $_SERVER['HTTP_HOST'] ) : '';
		if ( '' === $host ) {
			return;
		}
		wp_redirect( 'https://' . $host . $uri, 301 ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/**
	 * Send the HSTS header (only over HTTPS).
	 */
	public function send_hsts() {
		if ( ! $this->is_secure() || headers_sent() ) {
			return;
		}
		header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
	}

	/**
	 * Start an output buffer that rewrites insecure site URLs to HTTPS.
	 */
	public function start_mixed_content_buffer() {
		if ( is_admin() ) {
			return;
		}
		ob_start( array( $this, 'rewrite_mixed_content' ) );
	}

	/**
	 * Rewrite http:// → https:// for the site host only.
	 *
	 * @param string $html Buffered HTML.
	 * @return string
	 */
	public function rewrite_mixed_content( $html ) {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		if ( '' === $host ) {
			return $html;
		}
		return str_replace( 'http://' . $host, 'https://' . $host, $html );
	}

	// ---- Admin ------------------------------------------------------------

	/**
	 * Register the SSL submenu.
	 *
	 * @param string $parent Parent slug.
	 * @param string $cap    Capability.
	 */
	public function menu( $parent, $cap ) {
		add_submenu_page( $parent, __( 'SSL', 'pressguard' ), __( 'SSL', 'pressguard' ), $cap, self::ADMIN_SLUG, array( $this, 'render' ) );
	}

	/**
	 * Handle SSL form actions.
	 */
	public function handle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'pressguard' ) );
		}
		check_admin_referer( 'pressguard_ssl' );

		$config = $this->plugin->config();
		$do     = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$notice = 'saved';

		if ( 'save' === $do ) {
			$config->set( 'ssl.force_https', ! empty( $_POST['force_https'] ) );
			$config->set( 'ssl.hsts', ! empty( $_POST['hsts'] ) );
			$config->set( 'ssl.fix_mixed_content', ! empty( $_POST['fix_mixed_content'] ) );
		} elseif ( 'issue' === $do ) {
			$domains = array_filter( array_map( 'trim', explode( ',', isset( $_POST['domains'] ) ? sanitize_text_field( wp_unslash( $_POST['domains'] ) ) : '' ) ) );
			$email   = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
			$method  = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : 'http-01';
			$staging = ! empty( $_POST['staging'] );
			if ( ! empty( $_POST['cf_token'] ) ) {
				$config->set( 'ssl.cloudflare_token', Crypto::encrypt( sanitize_text_field( wp_unslash( $_POST['cf_token'] ) ) ) );
			}
			$config->set( 'ssl.acme.email', $email );
			$config->set( 'ssl.acme.domains', array_values( $domains ) );
			$config->set( 'ssl.acme.method', $method );
			$config->set( 'ssl.acme.staging', $staging );

			$result = $this->issue( $domains, $email, $method, $staging );
			$notice = $result['ok'] ? 'issued' : 'error:' . rawurlencode( $result['message'] );
			if ( $result['ok'] && ! wp_next_scheduled( self::CRON_HOOK ) ) {
				wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', self::CRON_HOOK );
			}
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::ADMIN_SLUG . '&notice=' . $notice ) );
		exit;
	}

	/**
	 * Run an issuance. Returns ['ok'=>bool,'message'=>string].
	 *
	 * @param string[] $domains Domains.
	 * @param string   $email   Contact email.
	 * @param string   $method  http-01 | dns-01.
	 * @param bool     $staging Use the staging directory.
	 * @return array
	 */
	public function issue( array $domains, $email, $method, $staging ) {
		if ( empty( $domains ) || '' === $email ) {
			return array( 'ok' => false, 'message' => 'Domains and email are required.' );
		}
		if ( ! function_exists( 'openssl_pkey_new' ) ) {
			return array( 'ok' => false, 'message' => 'OpenSSL is not available on this host.' );
		}

		$config = $this->plugin->config();
		$dir    = $staging
			? 'https://acme-staging-v02.api.letsencrypt.org/directory'
			: 'https://acme-v02.api.letsencrypt.org/directory';

		// Load or create the account key.
		$account_key = Crypto::decrypt( (string) $config->get( 'ssl.acme.account_key', '' ) );
		if ( '' === $account_key ) {
			$account_key = Acme::generate_rsa_key();
			$config->set( 'ssl.acme.account_key', Crypto::encrypt( $account_key ) );
		}

		try {
			$acme = new Acme( $account_key, $dir );
			$acme->register_account( $email );
			$ordered = $acme->new_order( $domains );
			$order   = $ordered['order'];

			$cf_cleanup = array();
			foreach ( (array) $order['authorizations'] as $authz_url ) {
				$authz = $acme->get_authorization( $authz_url );
				$this->solve_challenge( $acme, $authz, $method, $cf_cleanup );
				$status = $acme->poll_authorization( $authz_url );
				if ( 'valid' !== $status ) {
					$this->cleanup( $method, $authz, $cf_cleanup );
					return array( 'ok' => false, 'message' => 'Challenge failed (' . $status . ') for ' . ( $authz['identifier']['value'] ?? '' ) );
				}
			}

			$cert_key = Acme::generate_rsa_key();
			$chain    = $acme->finalize_and_download( $order, $cert_key, $domains );

			$config->set( 'ssl.cert.key', Crypto::encrypt( $cert_key ) );
			$config->set( 'ssl.cert.chain', $chain );
			$config->set( 'ssl.cert.issued', time() );
			$config->set( 'ssl.cert.expires', $this->cert_expiry( $chain ) );

			$this->plugin->logger()->log( 'ssl', 'cert_issued', array( 'severity' => 2, 'message' => 'Certificate issued for ' . implode( ', ', $domains ) ) );

			return array( 'ok' => true, 'message' => 'Certificate issued. Install it or follow the guidance below.' );
		} catch ( \Throwable $e ) {
			return array( 'ok' => false, 'message' => $e->getMessage() );
		}
	}

	/**
	 * Solve one authorization via the chosen method.
	 *
	 * @param Acme   $acme       ACME client.
	 * @param array  $authz      Authorization object.
	 * @param string $method     http-01 | dns-01.
	 * @param array  $cf_cleanup Collected Cloudflare records to remove later.
	 */
	private function solve_challenge( Acme $acme, $authz, $method, &$cf_cleanup ) {
		$want = ( 'dns-01' === $method ) ? 'dns-01' : 'http-01';
		$challenge = null;
		foreach ( (array) $authz['challenges'] as $c ) {
			if ( ( $c['type'] ?? '' ) === $want ) {
				$challenge = $c;
				break;
			}
		}
		if ( ! $challenge ) {
			throw new \RuntimeException( 'No ' . $want . ' challenge offered.' );
		}

		$token  = $challenge['token'];
		$domain = $authz['identifier']['value'] ?? '';

		if ( 'http-01' === $want ) {
			Challenge::put( $token, $acme->key_authorization( $token ) );
		} else {
			$token_val = $acme->dns_txt_value( $token );
			$cf_token  = Crypto::decrypt( (string) $this->plugin->config()->get( 'ssl.cloudflare_token', '' ) );
			if ( '' === $cf_token ) {
				throw new \RuntimeException( 'DNS-01 requires a Cloudflare API token.' );
			}
			$cf  = new CloudflareDns( $cf_token );
			$rec = $cf->add_txt( '_acme-challenge.' . ltrim( $domain, '*.' ), $token_val );
			$cf_cleanup[] = $rec;
			sleep( 10 ); // Allow propagation.
		}

		$acme->notify_ready( $challenge['url'] );
	}

	/**
	 * Clean up challenge artifacts.
	 *
	 * @param string $method     Method.
	 * @param array  $authz      Authorization.
	 * @param array  $cf_cleanup Cloudflare records.
	 */
	private function cleanup( $method, $authz, $cf_cleanup ) {
		if ( 'http-01' === $method ) {
			foreach ( (array) $authz['challenges'] as $c ) {
				if ( ! empty( $c['token'] ) ) {
					Challenge::forget( $c['token'] );
				}
			}
		} elseif ( ! empty( $cf_cleanup ) ) {
			$cf_token = Crypto::decrypt( (string) $this->plugin->config()->get( 'ssl.cloudflare_token', '' ) );
			if ( '' !== $cf_token ) {
				$cf = new CloudflareDns( $cf_token );
				foreach ( $cf_cleanup as $rec ) {
					try {
						$cf->delete_txt( $rec['zone'], $rec['record'] );
					} catch ( \Throwable $e ) {
						// best effort.
						unset( $e );
					}
				}
			}
		}
	}

	/**
	 * Extract the certificate expiry timestamp from a PEM chain.
	 *
	 * @param string $chain PEM.
	 * @return int
	 */
	private function cert_expiry( $chain ) {
		$info = @openssl_x509_parse( $chain ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return ( $info && ! empty( $info['validTo_time_t'] ) ) ? (int) $info['validTo_time_t'] : 0;
	}

	/**
	 * Cron: renew when within 30 days of expiry.
	 */
	public function maybe_renew() {
		$config  = $this->plugin->config();
		$expires = (int) $config->get( 'ssl.cert.expires', 0 );
		if ( $expires <= 0 || ( $expires - time() ) > 30 * DAY_IN_SECONDS ) {
			return;
		}
		$this->issue(
			(array) $config->get( 'ssl.acme.domains', array() ),
			(string) $config->get( 'ssl.acme.email', '' ),
			(string) $config->get( 'ssl.acme.method', 'http-01' ),
			(bool) $config->get( 'ssl.acme.staging', false )
		);
	}

	/**
	 * Render the SSL screen.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$config  = $this->plugin->config();
		$secure  = $this->is_secure();
		$expires = (int) $config->get( 'ssl.cert.expires', 0 );
		$post    = admin_url( 'admin-post.php' );

		$notice = isset( $_GET['notice'] ) ? sanitize_text_field( wp_unslash( $_GET['notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		?>
		<div class="wrap pressguard-wrap">
			<h1><?php esc_html_e( 'SSL / HTTPS', 'pressguard' ); ?></h1>

			<?php if ( 'issued' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Certificate issued.', 'pressguard' ); ?></p></div>
			<?php elseif ( 'saved' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'pressguard' ); ?></p></div>
			<?php elseif ( 0 === strpos( $notice, 'error:' ) ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php echo esc_html( rawurldecode( substr( $notice, 6 ) ) ); ?></p></div>
			<?php endif; ?>

			<div class="pressguard-cards">
				<div class="pressguard-card pressguard-card--<?php echo $secure ? 'ok' : 'warn'; ?>">
					<span class="pressguard-card__label"><?php esc_html_e( 'Connection', 'pressguard' ); ?></span>
					<span class="pressguard-card__value"><?php echo $secure ? esc_html__( 'HTTPS', 'pressguard' ) : esc_html__( 'Not secure', 'pressguard' ); ?></span>
				</div>
				<?php if ( $expires > 0 ) : ?>
					<div class="pressguard-card pressguard-card--ok">
						<span class="pressguard-card__label"><?php esc_html_e( 'Certificate expires', 'pressguard' ); ?></span>
						<span class="pressguard-card__value" style="font-size:15px;"><?php echo esc_html( wp_date( 'Y-m-d', $expires ) ); ?></span>
					</div>
				<?php endif; ?>
			</div>

			<h2><?php esc_html_e( 'HTTPS enforcement', 'pressguard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_ssl" />
				<input type="hidden" name="do" value="save" />
				<?php wp_nonce_field( 'pressguard_ssl' ); ?>
				<table class="form-table" role="presentation">
					<tr><th><?php esc_html_e( 'Force HTTPS', 'pressguard' ); ?></th><td><label><input type="checkbox" name="force_https" value="1" <?php checked( (bool) $config->get( 'ssl.force_https', false ) ); ?> /> <?php esc_html_e( 'Redirect all traffic to HTTPS', 'pressguard' ); ?></label></td></tr>
					<tr><th><?php esc_html_e( 'Fix mixed content', 'pressguard' ); ?></th><td><label><input type="checkbox" name="fix_mixed_content" value="1" <?php checked( (bool) $config->get( 'ssl.fix_mixed_content', false ) ); ?> /> <?php esc_html_e( 'Rewrite insecure site URLs on the front end', 'pressguard' ); ?></label></td></tr>
					<tr><th><?php esc_html_e( 'HSTS', 'pressguard' ); ?></th><td><label><input type="checkbox" name="hsts" value="1" <?php checked( (bool) $config->get( 'ssl.hsts', false ) ); ?> /> <?php esc_html_e( 'Send Strict-Transport-Security (only over HTTPS)', 'pressguard' ); ?></label></td></tr>
				</table>
				<?php submit_button( __( 'Save', 'pressguard' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Issue a free Let’s Encrypt certificate', 'pressguard' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Obtains a certificate via ACME. HTTP-01 works for normal domains; DNS-01 (Cloudflare) is for wildcards or when HTTP-01 is blocked. Installing the cert into the web server depends on your host — where we can’t install it, the cert and key are stored for manual installation.', 'pressguard' ); ?></p>
			<form method="post" action="<?php echo esc_url( $post ); ?>">
				<input type="hidden" name="action" value="pressguard_ssl" />
				<input type="hidden" name="do" value="issue" />
				<?php wp_nonce_field( 'pressguard_ssl' ); ?>
				<table class="form-table" role="presentation">
					<tr><th><?php esc_html_e( 'Domains', 'pressguard' ); ?></th><td><input type="text" name="domains" class="regular-text" placeholder="example.com, www.example.com" value="<?php echo esc_attr( implode( ', ', (array) $config->get( 'ssl.acme.domains', array() ) ) ); ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'Email', 'pressguard' ); ?></th><td><input type="email" name="email" class="regular-text" value="<?php echo esc_attr( (string) $config->get( 'ssl.acme.email', '' ) ); ?>" /></td></tr>
					<tr><th><?php esc_html_e( 'Method', 'pressguard' ); ?></th><td>
						<select name="method">
							<option value="http-01" <?php selected( (string) $config->get( 'ssl.acme.method', 'http-01' ), 'http-01' ); ?>>HTTP-01</option>
							<option value="dns-01" <?php selected( (string) $config->get( 'ssl.acme.method', 'http-01' ), 'dns-01' ); ?>>DNS-01 (Cloudflare)</option>
						</select>
					</td></tr>
					<tr><th><?php esc_html_e( 'Cloudflare API token', 'pressguard' ); ?></th><td><input type="password" name="cf_token" class="regular-text" autocomplete="new-password" placeholder="<?php echo esc_attr( $config->get( 'ssl.cloudflare_token', '' ) ? '••••••••' : '' ); ?>" /> <span class="description"><?php esc_html_e( 'Only for DNS-01.', 'pressguard' ); ?></span></td></tr>
					<tr><th><?php esc_html_e( 'Staging', 'pressguard' ); ?></th><td><label><input type="checkbox" name="staging" value="1" <?php checked( (bool) $config->get( 'ssl.acme.staging', false ) ); ?> /> <?php esc_html_e( 'Use the Let’s Encrypt staging environment (for testing)', 'pressguard' ); ?></label></td></tr>
				</table>
				<?php submit_button( __( 'Request certificate', 'pressguard' ), 'primary' ); ?>
			</form>
		</div>
		<?php
	}
}
