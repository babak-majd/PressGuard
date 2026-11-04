<?php
/**
 * PHPUnit bootstrap for PressGuard pure-logic unit tests.
 *
 * These tests exercise classes that do not depend on WordPress (crypto, rule
 * matching, normalization, IP math, signatures). We define the guard constants
 * and load the bundled PSR-4 autoloader — no WordPress bootstrap required.
 *
 * @package PressGuard
 */

define( 'ABSPATH', __DIR__ . '/../' );
define( 'PRESSGUARD_WAF', true );
define( 'PRESSGUARD_DIR', __DIR__ . '/../' );
define( 'PRESSGUARD_VERSION', 'test' );

require __DIR__ . '/../src/autoload.php';
