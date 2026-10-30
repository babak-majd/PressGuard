<?php
/**
 * Two-factor authentication (TOTP) feature.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Login;

use PressGuard\Plugin;
use PressGuard\Support\Crypto;
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
	 * Enforce 2FA during authentication.
	 *
	 * @param \WP_User|\WP_Error|null $user Current auth result.
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
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
	 * Render the code input on the login form.
	 */
	public function render_login_field() {
		?>
		<p>
			<label for="pressguard_2fa"><?php esc_html_e( 'Two-factor code (if enabled)', 'pressguard' ); ?></label>
			<input type="text" name="<?php echo esc_attr( self::FIELD ); ?>" id="pressguard_2fa"
				class="input" value="" size="20" autocomplete="one-time-code"
				inputmode="numeric" pattern="[0-9A-Za-z]*" />
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
