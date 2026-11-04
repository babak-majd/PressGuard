<?php
/**
 * @package PressGuard
 */

namespace PressGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PressGuard\Core\Firewall\Normalizer;

/**
 * Request normalizer tests.
 */
final class NormalizerTest extends TestCase {

	public function test_url_decode_and_lowercase() {
		$this->assertSame( '<script>', Normalizer::canonicalize( '%3CScript%3E' ) );
	}

	public function test_double_encoding_unwrapped() {
		$this->assertStringContainsString( '<script>', Normalizer::canonicalize( '%253Cscript%253E' ) );
	}

	public function test_html_entity_decode() {
		$this->assertStringContainsString( '<script>', Normalizer::canonicalize( '&#x3c;script&#x3e;' ) );
	}

	public function test_flatten_nested() {
		$values = Normalizer::flatten( array( 'a' => array( 'b' => 'PAYLOAD' ) ) );
		$this->assertContains( 'payload', $values );
	}
}
