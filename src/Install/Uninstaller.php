<?php
/**
 * Removes everything the plugin creates (plan 6.6), and nothing else.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Install;

use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Called from uninstall.php only. Deactivation removes nothing.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- uninstall drops the plugin's own tables and sweeps its own prefixed rows; there is no API for either and nothing to cache.
 */
final class Uninstaller {

	/**
	 * Uninstalls from every site, then removes network-global data.
	 */
	public static function run(): void {
		global $wpdb;

		if ( is_multisite() ) {
			$site_ids = get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			);
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				self::uninstall_site( $wpdb );
				restore_current_blog();
			}
		} else {
			self::uninstall_site( $wpdb );
		}

		self::uninstall_network( $wpdb );
	}

	/**
	 * Per-site data: tables, options, transients, cron.
	 *
	 * @param \wpdb $db Database handle.
	 */
	public static function uninstall_site( \wpdb $db ): void {
		foreach ( Schema::site_tables( $db ) as $table ) {
			self::execute( $db, $db->prepare( 'DROP TABLE IF EXISTS %i', $table ) );
		}

		foreach ( array_keys( Options::all() ) as $option ) {
			delete_option( $option );
		}

		wp_clear_scheduled_hook( Options::CRON_PURGE );

		// Sweep: options and transients (including dynamic names such as
		// mdmfa_ipthrottle_{hash}) that the named deletes above cannot reach.
		self::execute(
			$db,
			$db->prepare(
				'DELETE FROM %i WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s',
				$db->options,
				$db->esc_like( 'mdmfa_' ) . '%',
				$db->esc_like( '_transient_mdmfa_' ) . '%',
				$db->esc_like( '_transient_timeout_mdmfa_' ) . '%',
				$db->esc_like( '_site_transient_mdmfa_' ) . '%',
				$db->esc_like( '_site_transient_timeout_mdmfa_' ) . '%'
			)
		);

		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}

	/**
	 * Network-global data: the credentials table, user meta, network transients.
	 *
	 * @param \wpdb $db Database handle.
	 */
	public static function uninstall_network( \wpdb $db ): void {
		self::execute( $db, $db->prepare( 'DROP TABLE IF EXISTS %i', Schema::credentials_table( $db ) ) );

		foreach ( Options::user_meta_keys() as $meta_key ) {
			delete_metadata( 'user', 0, $meta_key, '', true );
		}

		// Sweep for any mdmfa_ user meta the named list missed.
		self::execute(
			$db,
			$db->prepare(
				'DELETE FROM %i WHERE meta_key LIKE %s',
				$db->usermeta,
				$db->esc_like( 'mdmfa_' ) . '%'
			)
		);

		if ( is_multisite() ) {
			self::execute(
				$db,
				$db->prepare(
					'DELETE FROM %i WHERE meta_key LIKE %s OR meta_key LIKE %s OR meta_key LIKE %s',
					$db->sitemeta,
					$db->esc_like( 'mdmfa_' ) . '%',
					$db->esc_like( '_site_transient_mdmfa_' ) . '%',
					$db->esc_like( '_site_transient_timeout_mdmfa_' ) . '%'
				)
			);
		}
	}

	/**
	 * Runs a prepared statement; prepare() returns null on a placeholder mismatch.
	 *
	 * @param \wpdb       $db  Database handle.
	 * @param string|null $sql Prepared SQL.
	 */
	private static function execute( \wpdb $db, ?string $sql ): void {
		if ( null !== $sql ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- always the output of $wpdb->prepare().
			$db->query( $sql );
		}
	}
}
