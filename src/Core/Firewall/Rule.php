<?php
/**
 * A single firewall rule.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Firewall;

// Loadable both inside WordPress and from the pre-WordPress Extended WAF.
defined( 'ABSPATH' ) || defined( 'PRESSGUARD_WAF' ) || exit;

/**
 * Immutable value object for one detection rule. Rules add an anomaly score
 * when their pattern matches rather than blocking outright, so no single rule
 * is a hard decision (CRS-style anomaly scoring).
 */
final class Rule {

	/**
	 * Rule id.
	 *
	 * @var string
	 */
	public $id;

	/**
	 * Attack category (sqli, xss, …).
	 *
	 * @var string
	 */
	public $category;

	/**
	 * PCRE pattern (without delimiters).
	 *
	 * @var string
	 */
	public $pattern;

	/**
	 * Anomaly score contributed on match.
	 *
	 * @var int
	 */
	public $score;

	/**
	 * Which request parts to test: any of uri, query, body, cookie, ua, referer.
	 *
	 * @var string[]
	 */
	public $targets;

	/**
	 * Human description.
	 *
	 * @var string
	 */
	public $description;

	/**
	 * Whether the rule is enabled (user can toggle individually).
	 *
	 * @var bool
	 */
	public $enabled;

	/**
	 * Constructor.
	 *
	 * @param array $data Rule definition.
	 */
	public function __construct( array $data ) {
		$this->id          = isset( $data['id'] ) ? (string) $data['id'] : '';
		$this->category    = isset( $data['category'] ) ? (string) $data['category'] : 'generic';
		$this->pattern     = isset( $data['pattern'] ) ? (string) $data['pattern'] : '';
		$this->score       = isset( $data['score'] ) ? (int) $data['score'] : 5;
		$this->description = isset( $data['description'] ) ? (string) $data['description'] : '';
		$this->enabled     = isset( $data['enabled'] ) ? (bool) $data['enabled'] : true;
		$this->targets     = isset( $data['targets'] ) && is_array( $data['targets'] )
			? array_map( 'strval', $data['targets'] )
			: array( 'uri', 'query', 'body' );
	}

	/**
	 * Test the rule against a list of canonicalized values.
	 *
	 * @param string[] $values Canonical values for the targeted request parts.
	 * @return bool True on match.
	 */
	public function matches( array $values ) {
		if ( ! $this->enabled || '' === $this->pattern ) {
			return false;
		}

		$regex = '#' . str_replace( '#', '\#', $this->pattern ) . '#iu';

		foreach ( $values as $value ) {
			// @ suppresses warnings from a malformed custom pattern; a broken
			// user rule must never fatal the request path.
			if ( @preg_match( $regex, $value ) === 1 ) {
				return true;
			}
		}

		return false;
	}
}
