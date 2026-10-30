<?php
/**
 * .htaccess-based hardening (Apache).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Writes/removes .htaccess rules for two hardening switches:
 *  - block PHP execution inside wp-content/uploads (stops uploaded webshells
 *    from running), and
 *  - deny direct access to sensitive files (wp-config.php, .htaccess, etc).
 *
 * Changes are marker-bounded and reversible. On non-Apache stacks these files
 * are ignored by the server; we still write them (harmless) and surface guidance
 * elsewhere. All writes are guarded and never fatal.
 */
final class Htaccess {

	const UPLOADS_MARKER = 'PressGuard Uploads';
	const PROTECT_MARKER = 'PressGuard Protect';

	/**
	 * Sync both switches to the current settings.
	 *
	 * @param bool $block_uploads   Block PHP in uploads.
	 * @param bool $protect_files   Deny access to sensitive files.
	 */
	public function sync( $block_uploads, $protect_files ) {
		$this->block_uploads_php( (bool) $block_uploads );
		$this->protect_sensitive( (bool) $protect_files );
	}

	/**
	 * Remove all PressGuard hardening blocks (used when hardening is disabled).
	 */
	public function remove_all() {
		$this->block_uploads_php( false );
		$this->protect_sensitive( false );
	}

	/**
	 * Write/remove the uploads PHP-execution block.
	 *
	 * @param bool $enable Enable the rule.
	 * @return bool
	 */
	public function block_uploads_php( $enable ) {
		$uploads = wp_upload_dir();
		$dir     = isset( $uploads['basedir'] ) ? $uploads['basedir'] : WP_CONTENT_DIR . '/uploads';
		if ( ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		$file = trailingslashit( $dir ) . '.htaccess';

		$lines = $enable ? array(
			'<FilesMatch "\.(?i:php|phtml|php3|php4|php5|php7|phps|phar)$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		) : array();

		return $this->write_markers( $file, self::UPLOADS_MARKER, $lines );
	}

	/**
	 * Write/remove the sensitive-file protection block in the root .htaccess.
	 *
	 * @param bool $enable Enable the rule.
	 * @return bool
	 */
	public function protect_sensitive( $enable ) {
		$file = ABSPATH . '.htaccess';

		$lines = $enable ? array(
			'<FilesMatch "^(wp-config\.php|wp-config-sample\.php|\.htaccess|\.user\.ini|readme\.html|license\.txt|debug\.log|liesmich\.html)$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		) : array();

		return $this->write_markers( $file, self::PROTECT_MARKER, $lines );
	}

	/**
	 * Insert or remove a marker-bounded block in a file.
	 *
	 * @param string   $file   Absolute path.
	 * @param string   $marker Marker label.
	 * @param string[] $lines  Lines (empty to remove).
	 * @return bool
	 */
	private function write_markers( $file, $marker, array $lines ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		// Creating the file requires a writable directory.
		if ( ! file_exists( $file ) ) {
			if ( empty( $lines ) ) {
				return true; // Nothing to remove.
			}
			if ( ! is_writable( dirname( $file ) ) ) {
				return false;
			}
		} elseif ( ! is_writable( $file ) ) {
			return false;
		}

		return insert_with_markers( $file, $marker, $lines );
	}
}
