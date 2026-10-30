<?php
/**
 * Per-IP decaying risk score.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Anomaly;

defined( 'ABSPATH' ) || exit;

/**
 * Accumulates a per-IP risk score from behavioural signals (failed logins, 404
 * scanning, firewall hits, rate spikes) that decays over time. Cheap and
 * PHP-only: one transient per active IP, exponential half-life decay computed
 * on read/write — no background job, no ML. The firewall consults the score to
 * escalate (challenge/block) an IP that is misbehaving across many signals,
 * even if no single request crosses a rule threshold.
 */
final class RiskEngine {

	const PREFIX    = 'pressguard_risk_';
	const HALF_LIFE = 600; // Seconds for the score to halve.
	const TTL       = 3600;

	/**
	 * Default signal weights.
	 *
	 * @var array<string,int>
	 */
	private static $weights = array(
		'login_failed' => 6,
		'rule'         => 8,
		'rate'         => 5,
		'ua'           => 4,
		'geo'          => 5,
		'404'          => 2,
		'probe'        => 7,
		'enum'         => 5,
	);

	/**
	 * Record a signal for an IP and return the new score.
	 *
	 * @param string $ip     Client IP.
	 * @param string $signal Signal name.
	 * @return float
	 */
	public static function record( $ip, $signal ) {
		if ( '' === $ip ) {
			return 0.0;
		}
		$weight = isset( self::$weights[ $signal ] ) ? self::$weights[ $signal ] : 3;

		$state = get_transient( self::key( $ip ) );
		list( $score, $ts ) = self::decay( $state );

		$score += $weight;
		set_transient( self::key( $ip ), array( 'score' => $score, 'ts' => time() ), self::TTL );
		unset( $ts );

		return $score;
	}

	/**
	 * Current (decayed) score for an IP.
	 *
	 * @param string $ip Client IP.
	 * @return float
	 */
	public static function score( $ip ) {
		if ( '' === $ip ) {
			return 0.0;
		}
		list( $score ) = self::decay( get_transient( self::key( $ip ) ) );
		return $score;
	}

	/**
	 * Apply time decay to a stored state.
	 *
	 * @param mixed $state Stored {score,ts} or false.
	 * @return array{0:float,1:int} [score, ts]
	 */
	private static function decay( $state ) {
		if ( ! is_array( $state ) || ! isset( $state['score'], $state['ts'] ) ) {
			return array( 0.0, time() );
		}
		$elapsed = max( 0, time() - (int) $state['ts'] );
		$factor  = pow( 0.5, $elapsed / self::HALF_LIFE );
		return array( (float) $state['score'] * $factor, (int) $state['ts'] );
	}

	/**
	 * Transient key for an IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private static function key( $ip ) {
		return self::PREFIX . md5( $ip );
	}
}
