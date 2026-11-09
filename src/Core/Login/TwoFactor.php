<?php
/**
 * Two-factor authentication (TOTP) feature.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

use PressGuard\Plugin;
use PressGuard\Support\Crypto;
use PressGuard\Support\Guard;
use PressGuard\Support\Logger;

defined( 'ABSPATH' ) || exit;

/**
 * Adds optional TOTP two-factor auth, set up per user from their profile.
 *
 * Login is single-step: the code is entered alongside username/password. The
 * secret is stored encrypted; replay is prevented by tracking the last accepted
 * time-step; one-time backup codes are stored hashed.
 */
final class TwoFactor {

	const META_ENABLED = 'pressguard_2fa_enabled';
	const META_SECRET  = 'pressguard_2fa_secret';
	const META_PENDING = 'pressguard_2fa_pending_secret';
	const META_STEP    = 'pressguard_2fa_last_step';
	const META_BACKUP  = 'pressguard_2fa_backup';
	const FIELD        = 'pressguard_2fa';

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
	 * Wire hooks.
	 */
	public function register() {
		// Enforce on login (after core validates the password at priority 20).
		add_filter( 'authenticate', array( $this, 'enforce' ), 50, 1 );
		add_action( 'login_form', array( $this, 'render_login_field' ) );

		// Optional role-based enforcement (nag + redirect after a grace period).
		if ( ! empty( (array) $this->plugin->config()->get( 'login.two_factor.enforce_roles', array() ) ) ) {
			add_action( 'admin_init', array( $this, 'enforce_admin' ) );
			add_action( 'admin_notices', array( $this, 'enforce_notice' ) );
		}

		// Profile setup UI.
		add_action( 'show_user_profile', array( $this, 'render_profile' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile' ) );
		add_action( 'personal_options_update', array( $this, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );
	}

	/**
	 * Whether a user has 2FA active.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_enabled_for( $user_id ) {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * Does the current user fall under 2FA enforcement and still lack it?
	 *
	 * @return bool
	 */
	private function needs_enforcement() {
		$user = wp_get_current_user();
		if ( 0 === $user->ID || self::is_enabled_for( $user->ID ) ) {
			return false;
		}
		$roles = (array) $this->plugin->config()->get( 'login.two_factor.enforce_roles', array() );
		return (bool) array_intersect( (array) $user->roles, $roles );
	}

	/**
	 * Grace period in seconds before enforcement blocks admin access.
	 *
	 * @param int $user_id User id.
	 * @return int Seconds remaining (0 = grace over).
	 */
	private function grace_remaining( $user_id ) {
		$days  = max( 0, (int) $this->plugin->config()->get( 'login.two_factor.grace_days', 7 ) );
		$since = (int) get_user_meta( $user_id, 'pressguard_2fa_enforce_since', true );
		if ( ! $since ) {
			$since = time();
			update_user_meta( $user_id, 'pressguard_2fa_enforce_since', $since );
		}
		$deadline = $since + ( $days * DAY_IN_SECONDS );
		return max( 0, $deadline - time() );
	}

	/**
	 * After the grace period, confine an un-enrolled enforced user to their
	 * profile until they set up 2FA (logout always allowed).
	 */
	public function enforce_admin() {
		if ( ! $this->needs_enforcement() ) {
			return;
		}
		if ( $this->grace_remaining( get_current_user_id() ) > 0 ) {
			return; // Still in grace — just nag (see enforce_notice).
		}

		global $pagenow;
		$allowed_pages = array( 'profile.php', 'admin-ajax.php', 'admin-post.php', 'options.php' );
		if ( in_array( $pagenow, $allowed_pages, true ) ) {
			return;
		}
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		wp_safe_redirect( admin_url( 'profile.php#pressguard-2fa' ) );
		exit;
	}

	/**
	 * Nag enforced users to set up 2FA, showing the time left.
	 */
	public function enforce_notice() {
		if ( ! $this->needs_enforcement() ) {
			return;
		}
		$left = $this->grace_remaining( get_current_user_id() );
		$msg  = $left > 0
			? sprintf(
				/* translators: %d: days remaining */
				__( 'Two-factor authentication is required for your role. Please set it up within %d day(s) on your profile.', 'pressguard' ),
				(int) ceil( $left / DAY_IN_SECONDS )
			)
			: __( 'Two-factor authentication is required. Set it up on your profile to continue.', 'pressguard' );
		echo '<div class="notice notice-warning"><p><strong>PressGuard:</strong> ' . esc_html( $msg ) . '</p></div>';
	}

	/**
	 * Enforce 2FA during authentication.
	 *
	 * @param \WP_User|\WP_Error|null $user Current auth result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		try {
			if ( ! self::is_enabled_for( $user->ID ) ) {
				return $user;
			}

			// phpcs:disable WordPress.Security.NonceVerification.Missing -- this is the login POST itself.
			$code = isset( $_POST[ self::FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::FIELD ] ) ) : '';
			// phpcs:enable

			if ( '' === $code ) {
				return new \WP_Error(
					'pressguard_2fa_required',
					__( '<strong>Two-factor code required.</strong> Enter the code from your authenticator app.', 'pressguard' )
				);
			}

			if ( $this->validate_code( $user->ID, $code ) ) {
				return $user;
			}

			$this->plugin->logger()->log(
				'login',
				'2fa_failed',
				array(
					'severity' => Logger::SEVERITY_WARNING,
					'user_id'  => $user->ID,
				)
			);

			return new \WP_Error(
				'pressguard_2fa_invalid',
				__( '<strong>Invalid two-factor code.</strong> Please try again.', 'pressguard' )
			);
		} catch ( \Throwable $e ) {
			// Never lock a user out of login because of a 2FA error.
			Guard::report( 'twofactor.enforce', $e );
			return $user;
		}
	}

	/**
	 * Validate a TOTP or backup code for a user, with replay protection.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	private function validate_code( $user_id, $code ) {
		$secret = Crypto::decrypt( (string) get_user_meta( $user_id, self::META_SECRET, true ) );
		if ( '' !== $secret ) {
			$last = (int) get_user_meta( $user_id, self::META_STEP, true );
			$step = Totp::verify( $secret, $code, 1, 1, $last );
			if ( false !== $step ) {
				update_user_meta( $user_id, self::META_STEP, $step );
				return true;
			}
		}

		return $this->consume_backup_code( $user_id, $code );
	}

	/**
	 * Check and consume a one-time backup code.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	private function consume_backup_code( $user_id, $code ) {
		$codes = get_user_meta( $user_id, self::META_BACKUP, true );
		if ( ! is_array( $codes ) || empty( $codes ) ) {
			return false;
		}

		$normalized = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', $code ) );
		foreach ( $codes as $i => $hash ) {
			if ( wp_check_password( $normalized, $hash ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $codes ) );
				$this->plugin->logger()->log(
					'login',
					'2fa_backup_used',
					array(
						'severity' => Logger::SEVERITY_NOTICE,
						'user_id'  => $user_id,
					)
				);
				return true;
			}
		}

		return false;
	}

	/**
	 * Render the code input on the login form — but only after a username has
	 * been submitted for a user who actually has 2FA enabled. On the initial
	 * login page (and for users without 2FA) the field is not shown at all.
	 */
	public function render_login_field() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- this is the login form itself.
		$raw = isset( $_POST['log'] ) ? wp_unslash( $_POST['log'] ) : '';
		// A crafted login POST can send log[] as an array; coerce to string so
		// sanitize_user() never receives an array (which would be fatal).
		if ( is_array( $raw ) ) {
			$raw = reset( $raw );
		}
		$login = sanitize_user( (string) $raw );
		if ( '' === $login ) {
			return;
		}
		$user = get_user_by( 'login', $login );
		if ( ! $user ) {
			$user = get_user_by( 'email', $login );
		}
		if ( ! $user || ! self::is_enabled_for( $user->ID ) ) {
			return;
		}
		?>
		<p>
			<label for="pressguard_2fa"><?php esc_html_e( 'Two-factor code', 'pressguard' ); ?></label>
			<input type="text" name="<?php echo esc_attr( self::FIELD ); ?>" id="pressguard_2fa"
				class="input" value="" size="20" autocomplete="one-time-code"
				inputmode="numeric" pattern="[0-9A-Za-z]*" autofocus="autofocus" />
		</p>
		<?php
	}

	/**
	 * Generate a fresh set of backup codes and store them hashed.
	 *
	 * @param int $user_id User id.
	 * @param int $count   How many codes.
	 * @return string[] Plaintext codes (shown once).
	 */
	private function issue_backup_codes( $user_id, $count = 10 ) {
		$plain  = array();
		$hashed = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$code     = strtoupper( wp_generate_password( 10, false, false ) );
			$plain[]  = $code;
			$hashed[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashed );
		return $plain;
	}

	/**
	 * Render the 2FA section on the user profile screen.
	 *
	 * @param \WP_User $user Profile user.
	 */
	public function render_profile( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$enabled = self::is_enabled_for( $user->ID );

		// Ensure a pending secret exists to display when not yet enabled.
		$pending = Crypto::decrypt( (string) get_user_meta( $user->ID, self::META_PENDING, true ) );
		if ( ! $enabled && '' === $pending ) {
			$pending = Totp::generate_secret();
			update_user_meta( $user->ID, self::META_PENDING, Crypto::encrypt( $pending ) );
		}

		$issuer = get_bloginfo( 'name' );
		$uri    = $enabled ? '' : Totp::provisioning_uri( $pending, $user->user_email, $issuer );

		wp_nonce_field( 'pressguard_2fa_profile', 'pressguard_2fa_nonce' );
		?>
		<h2><?php esc_html_e( 'PressGuard — Two-Factor Authentication', 'pressguard' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'pressguard' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<p><strong style="color:#00a32a;"><?php esc_html_e( 'Enabled', 'pressguard' ); ?></strong></p>
						<label>
							<input type="checkbox" name="pressguard_2fa_disable" value="1" />
							<?php esc_html_e( 'Disable two-factor authentication', 'pressguard' ); ?>
						</label>
					<?php else : ?>
						<p>
							<?php esc_html_e( 'Scan this key in your authenticator app, then enter a code to confirm.', 'pressguard' ); ?>
						</p>
						<p>
							<code style="font-size:14px;letter-spacing:2px;"><?php echo esc_html( $pending ); ?></code>
						</p>
						<p class="description" style="word-break:break-all;"><?php echo esc_html( $uri ); ?></p>
						<p>
							<label for="pressguard_2fa_confirm"><?php esc_html_e( 'Verification code', 'pressguard' ); ?></label><br />
							<input type="text" id="pressguard_2fa_confirm" name="pressguard_2fa_confirm"
								class="regular-text" inputmode="numeric" autocomplete="one-time-code" />
						</p>
						<label>
							<input type="checkbox" name="pressguard_2fa_enable" value="1" />
							<?php esc_html_e( 'Enable two-factor authentication', 'pressguard' ); ?>
						</label>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Handle profile save: enable/disable 2FA.
	 *
	 * @param int $user_id User id being saved.
	 */
	public function save_profile( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		$nonce = isset( $_POST['pressguard_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['pressguard_2fa_nonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'pressguard_2fa_profile' ) ) {
			return;
		}

		// Disable path.
		if ( ! empty( $_POST['pressguard_2fa_disable'] ) ) {
			delete_user_meta( $user_id, self::META_ENABLED );
			delete_user_meta( $user_id, self::META_SECRET );
			delete_user_meta( $user_id, self::META_STEP );
			delete_user_meta( $user_id, self::META_BACKUP );
			return;
		}

		// Enable path: confirm a code against the pending secret first.
		if ( ! empty( $_POST['pressguard_2fa_enable'] ) ) {
			$pending = Crypto::decrypt( (string) get_user_meta( $user_id, self::META_PENDING, true ) );
			$code    = isset( $_POST['pressguard_2fa_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['pressguard_2fa_confirm'] ) ) : '';

			if ( '' === $pending ) {
				return;
			}

			$step = Totp::verify( $pending, $code, 1, 1, 0 );
			if ( false === $step ) {
				add_action(
					'user_profile_update_errors',
					static function ( $errors ) {
						$errors->add( 'pressguard_2fa', __( 'The two-factor code did not match. 2FA was not enabled.', 'pressguard' ) );
					}
				);
				return;
			}

			update_user_meta( $user_id, self::META_SECRET, Crypto::encrypt( $pending ) );
			update_user_meta( $user_id, self::META_STEP, $step );
			update_user_meta( $user_id, self::META_ENABLED, 1 );
			delete_user_meta( $user_id, self::META_PENDING );

			$this->issue_backup_codes( $user_id );

			$this->plugin->logger()->log(
				'login',
				'2fa_enabled',
				array(
					'severity' => Logger::SEVERITY_NOTICE,
					'user_id'  => $user_id,
				)
			);
		}
	}
}
