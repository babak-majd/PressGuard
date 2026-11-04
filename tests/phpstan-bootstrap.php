<?php
/**
 * PHPStan bootstrap: define the plugin's runtime constants so static analysis
 * resolves them. ABSPATH is already provided by phpstan-wordpress, so we only
 * define it defensively.
 *
 * @package PressGuard
 */

defined( 'ABSPATH' ) || define( 'ABSPATH', __DIR__ . '/../' );
defined( 'PRESSGUARD_WAF' ) || define( 'PRESSGUARD_WAF', true );
defined( 'PRESSGUARD_VERSION' ) || define( 'PRESSGUARD_VERSION', '0.0.0' );
defined( 'PRESSGUARD_FILE' ) || define( 'PRESSGUARD_FILE', __DIR__ . '/../pressguard.php' );
defined( 'PRESSGUARD_DIR' ) || define( 'PRESSGUARD_DIR', __DIR__ . '/../' );
defined( 'PRESSGUARD_URL' ) || define( 'PRESSGUARD_URL', 'https://example.test/wp-content/plugins/pressguard/' );
defined( 'PRESSGUARD_BASENAME' ) || define( 'PRESSGUARD_BASENAME', 'pressguard/pressguard.php' );
defined( 'PRESSGUARD_MIN_PHP' ) || define( 'PRESSGUARD_MIN_PHP', '7.4' );
defined( 'PRESSGUARD_MIN_WP' ) || define( 'PRESSGUARD_MIN_WP', '5.6' );

require __DIR__ . '/../src/autoload.php';
