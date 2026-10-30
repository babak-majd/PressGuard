<?php
/**
 * Custom login URL (hide wp-login.php).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

defined( 'ABSPATH' ) || exit;

/**
 * Serves the login form from a custom slug and makes the default wp-login.php
 * path return 404 to anonymous visitors. Kept deliberately simple and
 * reversible; the slug is validated by the settings layer before it gets here.
 */
final class LoginUrl {

	/**
	 * Custom login slug (no slashes), e.g. "secure-login".
	 *
	 * @var string
	 */
	private $slug;

	/**
	 * Constructor.
	 *
	 * @param string $slug Custom login slug.
	 */
	public function __construct( $slug ) {
		$this->slug = trim( $slug, "/ \t\n\r\0\x0B" );
	}

	/**
	 * Wire the rewrite + interception hooks.
	 */
	public function register() {
		add_action( 'init', array( $this, 'maybe_handle_custom_slug' ) );
		add_action( 'init', array( $this, 'block_default_login' ), 20 );
		add_filter( 'site_url', array( $this, 'filter_login_url' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'filter_login_url' ), 10, 2 );
		add_filter( 'wp_redirect', array( $this, 'filter_login_url' ), 10, 1 );
	}

	/**
	 * When the request path matches the custom slug, load wp-login.php.
	 */
	public function maybe_handle_custom_slug() {
		$path = $this->request_path();
		if ( $path !== $this->slug ) {
			return;
		}

		// Hand off to core's login handler. wp-login.php expects to run in the
		// global scope (login_header() reads these as globals), so we promote
		// its top-level variables to globals before requiring it — otherwise
		// PHP 8 emits "undefined variable" warnings for $error/$user_login.
		global $error, $interim_login, $action, $user_login, $user_pass, $errors,
			$redirect_to, $customize_login, $rememberme, $pagenow;

		$pagenow                = 'wp-login.php';
		$_SERVER['SCRIPT_NAME'] = '/wp-login.php';

		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Return 404 for direct, unauthenticated hits on wp-login.php.
	 */
	public function block_default_login() {
		$path = $this->request_path();
		$is_login_file = ( 'wp-login.php' === $path )
			|| ( isset( $_SERVER['SCRIPT_NAME'] ) && false !== strpos( (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ), 'wp-login.php' ) );

		if ( ! $is_login_file ) {
			return;
		}

		// Allow legitimate logout/postpass and already-authenticated users.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		// phpcs:enable
		$allowed_actions = array( 'logout', 'postpass', 'rp', 'resetpass' );

		if ( is_user_logged_in() || in_array( $action, $allowed_actions, true ) ) {
			return;
		}

		// The custom-slug handler above already exited for valid logins, so a
		// request still hitting wp-login.php here is a direct probe: 404 it.
		if ( $this->request_path() === $this->slug ) {
			return;
		}

		status_header( 404 );
		nocache_headers();
		wp_die(
			esc_html__( 'Page not found.', 'pressguard' ),
			esc_html__( 'Not Found', 'pressguard' ),
			array( 'response' => 404 )
		);
	}

	/**
	 * Rewrite generated login URLs to the custom slug.
	 *
	 * @param string      $url  The complete URL.
	 * @param string|null $path The path relative to site root, when provided.
	 * @return string
	 */
	public function filter_login_url( $url, $path = null ) {
		unset( $path );
		if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
			$url = str_replace( 'wp-login.php', $this->slug, $url );
		}

		return $url;
	}

	/**
	 * The current request path, relative to the WordPress install root.
	 *
	 * @return string
	 */
	private function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$uri = wp_parse_url( $uri, PHP_URL_PATH );
		$uri = $uri ? $uri : '';

		$home = wp_parse_url( home_url(), PHP_URL_PATH );
		$home = $home ? rtrim( $home, '/' ) : '';
		if ( '' !== $home && 0 === strpos( $uri, $home ) ) {
			$uri = substr( $uri, strlen( $home ) );
		}

		return trim( $uri, '/' );
	}
}
