<?php
/**
 * @package PressGuard
 */

namespace PressGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PressGuard\Core\Login\Totp;

/**
 * TOTP (RFC 6238) tests.
 */
final class TotpTest extends TestCase {

	/**
	 * RFC 6238 SHA-1 test vector: seed "12345678901234567890" at T=59s (step 1)
	 * yields 8-digit 94287082 → 6-digit 287082.
	 */
	public function test_rfc6238_vector() {
		$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // base32 of the ASCII seed.
		$this->assertSame( '287082', Totp::code_at( $secret, 1 ) );
	}

	/**
	 * verify() accepts the current code and respects the replay floor.
	 */
	public function test_verify_and_replay_floor() {
		$secret = Totp::generate_secret();
		$step   = (int) floor( time() / Totp::PERIOD );
		$code   = Totp::code_at( $secret, $step );

		$this->assertSame( $step, Totp::verify( $secret, $code, 1, 1, 0 ) );
		// With the replay floor at the matched step, the same code is rejected.
		$this->assertFalse( Totp::verify( $secret, $code, 1, 1, $step ) );
	}

	/**
	 * A wrong code is rejected.
	 */
	public function test_wrong_code_rejected() {
		$secret = Totp::generate_secret();
		$this->assertFalse( Totp::verify( $secret, '000000', 1, 1, 0 ) );
	}

	/**
	 * base32_decode of "JBSWY3DP" is "Hello".
	 */
	public function test_base32_decode() {
		$this->assertSame( 'Hello', Totp::base32_decode( 'JBSWY3DP' ) );
	}
}
