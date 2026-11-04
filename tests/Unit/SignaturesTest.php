<?php
/**
 * @package PressGuard
 */

namespace PressGuard\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PressGuard\Core\Scanner\Signatures;
use PressGuard\Core\Firewall\Rule;

/**
 * Malware signature + rule-matching tests.
 */
final class SignaturesTest extends TestCase {

	public function test_detects_eval_request() {
		$ids = array_column( Signatures::scan_content( '<?php eval($_POST[1]);' ), 'id' );
		$this->assertContains( 'eval-request', $ids );
	}

	public function test_detects_webshell_marker() {
		$ids = array_column( Signatures::scan_content( '/* c99shell */' ), 'id' );
		$this->assertContains( 'webshell-marker', $ids );
	}

	public function test_clean_code_has_no_hits() {
		$this->assertSame( array(), Signatures::scan_content( '<?php echo "hello world";' ) );
	}

	public function test_htaccess_auto_prepend_flagged() {
		$ids = array_column( Signatures::scan_htaccess( 'php_value auto_prepend_file /tmp/x.php' ), 'id' );
		$this->assertContains( 'htaccess-auto-prepend', $ids );
	}

	public function test_rule_match_and_disable() {
		$rule = new Rule( array( 'id' => 't', 'pattern' => 'union\\s+select', 'score' => 5, 'targets' => array( 'query' ) ) );
		$this->assertTrue( $rule->matches( array( '1 union select 1' ) ) );
		$this->assertFalse( $rule->matches( array( 'nothing here' ) ) );

		$disabled = new Rule( array( 'id' => 't', 'pattern' => 'union\\s+select', 'score' => 5, 'enabled' => false ) );
		$this->assertFalse( $disabled->matches( array( '1 union select 1' ) ) );
	}
}
