<?php
/**
 * Simple sliding-window anomaly core.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Anomaly;

use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * A deliberately cheap, PHP-only attack detector: it counts security hits in a
 * rolling per-minute window and reports an "under attack" state when the rate
 * crosses a threshold. This is the lightweight statistical core the plan calls
 * for (real ML stays offline/cloud); it drives automatic Under Attack mode.
 */
final class Anomaly {

	const BUCKET_PREFIX = 'pressguard_anom_';
	const ATTACK_FLAG   = 'pressguard_under_attack_until';

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
	 * Record one "hit" (firewall match, auth failure, 404 scan, …) into the
	 * current minute bucket, and raise the attack flag if the window is hot.
	 *
	 * @param string $signal Signal name (for future per-signal tuning).
	 */
	public function record_hit( $signal = 'generic' ) {
		unset( $signal );

		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		$key    = self::BUCKET_PREFIX . $minute;
		$count  = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, 2 * MINUTE_IN_SECONDS );

		$config    = $this->plugin->config();
		$threshold = max( 5, (int) $config->get( 'anomaly.attack_threshold', 30 ) );

		if ( $count >= $threshold ) {
			$cooldown = max( MINUTE_IN_SECONDS, (int) $config->get( 'anomaly.attack_cooldown', 600 ) );
			$until    = time() + $cooldown;
			if ( (int) get_option( self::ATTACK_FLAG, 0 ) < time() ) {
				// Transition into attack state: log it once.
				$this->plugin->logger()->log(
					'anomaly',
					'under_attack_start',
					array(
						'severity' => 4,
						'message'  => sprintf( 'Auto Under Attack: %d hits/min (threshold %d).', $count, $threshold ),
					)
				);
				/**
				 * Fires when automatic attack detection engages.
				 *
				 * @param int $until Unix timestamp the attack state lasts until.
				 */
				do_action( 'pressguard_under_attack_detected', $until );
			}
			update_option( self::ATTACK_FLAG, $until, false );
		}
	}

	/**
	 * Current hit count in the live minute window.
	 *
	 * @return int
	 */
	public function current_rate() {
		$minute = (int) floor( time() / MINUTE_IN_SECONDS );
		return (int) get_transient( self::BUCKET_PREFIX . $minute );
	}

	/**
	 * Whether the site is currently in an auto-detected attack state.
	 *
	 * @return bool
	 */
	public function is_under_attack() {
		return (int) get_option( self::ATTACK_FLAG, 0 ) > time();
	}
}
