<?php
/**
 * @package PressGuard
 */

namespace PressGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PressGuard\Support\Ip;

/**
 * IP / CIDR matching tests.
 */
final class IpTest extends TestCase {

	public function test_ipv4_cidr() {
		$this->assertTrue( Ip::ip_in_cidr( '192.168.1.5', '192.168.1.0/24' ) );
		$this->assertFalse( Ip::ip_in_cidr( '192.168.2.5', '192.168.1.0/24' ) );
	}

	public function test_exact_ip() {
		$this->assertTrue( Ip::ip_in_cidr( '10.0.0.1', '10.0.0.1' ) );
		$this->assertFalse( Ip::ip_in_cidr( '10.0.0.2', '10.0.0.1' ) );
	}

	public function test_ipv6_cidr() {
		$this->assertTrue( Ip::ip_in_cidr( '2001:db8::1', '2001:db8::/32' ) );
		$this->assertFalse( Ip::ip_in_cidr( '2001:dead::1', '2001:db8::/32' ) );
	}

	public function test_mixed_family_no_match() {
		$this->assertFalse( Ip::ip_in_cidr( '192.168.1.1', '2001:db8::/32' ) );
	}
}
