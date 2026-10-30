<?php
/**
 * Self-update from GitHub releases.
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Update;

use PressGuard\Module;
use PressGuard\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Lets PressGuard update itself from GitHub releases (it isn't hosted on
 * WordPress.org). It checks the latest release, and when the tag is newer than
 * the installed version it feeds WordPress's normal plugin-update flow — so the
 * admin sees an update on the Plugins screen and can one-click upgrade. The
 * downloaded zipball's folder is renamed back to `pressguard` on install.
 */
final class Updater implements Module {

	const REPO       = 'babak-majd/PressGuard';
	const CACHE_KEY  = 'pressguard_update_check';
	const CACHE_TTL  = 43200; // 12h.

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
	 * {@inheritDoc}
	 */
	public function id() {
		return 'updater';
	}

	/**
	 * {@inheritDoc}
	 */
	public function register() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'inject_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_source_dir' ), 10, 4 );
		add_action( 'pressguard_force_update_check', array( $this, 'flush' ) );
	}

	/**
	 * Clear the cached remote check.
	 */
	public function flush() {
		delete_transient( self::CACHE_KEY );
	}

	/**
	 * Fetch the latest release from GitHub (cached).
	 *
	 * @return array|null { version, package, url, body, published }
	 */
	private function latest_release() {
		$cached = get_transient( self::CACHE_KEY );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$res = wp_remote_get(
			'https://api.github.com/repos/' . self::REPO . '/releases/latest',
			array(
				'timeout' => 15,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'PressGuard',
				),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			set_transient( self::CACHE_KEY, array(), HOUR_IN_SECONDS ); // Back off on failure.
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( empty( $body['tag_name'] ) ) {
			return null;
		}

		// Prefer an attached .zip asset; otherwise fall back to the zipball.
		$package = isset( $body['zipball_url'] ) ? $body['zipball_url'] : '';
		foreach ( (array) ( $body['assets'] ?? array() ) as $asset ) {
			if ( isset( $asset['browser_download_url'] ) && '.zip' === substr( $asset['name'], -4 ) ) {
				$package = $asset['browser_download_url'];
				break;
			}
		}

		$data = array(
			'version'   => ltrim( (string) $body['tag_name'], 'v' ),
			'package'   => $package,
			'url'       => isset( $body['html_url'] ) ? $body['html_url'] : '',
			'body'      => isset( $body['body'] ) ? (string) $body['body'] : '',
			'published' => isset( $body['published_at'] ) ? $body['published_at'] : '',
		);
		set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * Inject an available update into the plugins update transient.
	 *
	 * @param mixed $transient Update transient.
	 * @return mixed
	 */
	public function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}

		$release = $this->latest_release();
		if ( ! $release || '' === $release['package'] ) {
			return $transient;
		}

		if ( version_compare( $release['version'], PRESSGUARD_VERSION, '<=' ) ) {
			return $transient;
		}

		$item = array(
			'slug'        => 'pressguard',
			'plugin'      => PRESSGUARD_BASENAME,
			'new_version' => $release['version'],
			'url'         => $release['url'],
			'package'     => $release['package'],
		);

		$transient->response[ PRESSGUARD_BASENAME ] = (object) $item;
		return $transient;
	}

	/**
	 * Provide the "View details" payload.
	 *
	 * @param false|object|array $result Default result.
	 * @param string             $action API action.
	 * @param object             $args   Request args.
	 * @return false|object
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || 'pressguard' !== $args->slug ) {
			return $result;
		}
		$release = $this->latest_release();
		if ( ! $release ) {
			return $result;
		}

		return (object) array(
			'name'          => 'PressGuard',
			'slug'          => 'pressguard',
			'version'       => $release['version'],
			'author'        => '<a href="https://bobclub.ir">Babak Majd</a>',
			'homepage'      => 'https://github.com/' . self::REPO,
			'download_link' => $release['package'],
			'sections'      => array(
				'changelog' => wpautop( esc_html( $release['body'] ) ),
			),
		);
	}

	/**
	 * Rename the extracted GitHub zip folder back to `pressguard`.
	 *
	 * @param string $source        Extracted source dir.
	 * @param string $remote_source Remote source dir.
	 * @param object $upgrader       Upgrader instance.
	 * @param array  $args          Hook args.
	 * @return string|\WP_Error
	 */
	public function fix_source_dir( $source, $remote_source, $upgrader, $args = array() ) {
		if ( empty( $args['plugin'] ) || PRESSGUARD_BASENAME !== $args['plugin'] ) {
			return $source;
		}
		global $wp_filesystem;
		$desired = trailingslashit( $remote_source ) . 'pressguard';
		if ( $source === $desired ) {
			return $source;
		}
		if ( $wp_filesystem && $wp_filesystem->move( $source, $desired ) ) {
			return trailingslashit( $desired );
		}
		return $source;
	}
}
