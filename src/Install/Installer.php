<?php
/**
 * Activation and schema upgrades (plan 6).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Install;

use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Location\SlugChanger;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Creates the tables and default options. Idempotent: add_option() never overwrites an
 * owner's value and dbDelta() only alters what differs.
 */
final class Installer {

	/**
	 * Activation hook. On network activation each site installs itself on its first
	 * request through maybe_upgrade(), so activation never loops over a large network.
	 */
	public static function activate(): void {
		self::install();
	}

	/**
	 * Runs on plugins_loaded. Reads one autoloaded option, so it adds no query.
	 */
	public static function maybe_upgrade(): void {
		if ( Schema::VERSION !== get_option( Options::DB_VERSION ) ) {
			self::install();
		}
	}

	/**
	 * Creates or upgrades the schema and seeds default options for the current site.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta( Schema::credentials_sql( $wpdb ) );
		dbDelta( Schema::site_sql( $wpdb ) );

		$login = Settings::login_defaults();
		// With plain permalinks an Apache site has no rewrite rules, so /{address} would be a
		// server 404 while wp-login.php is hidden: a lockout. Leave the login where it is.
		$plain = '' === (string) get_option( 'permalink_structure' );
		if ( $plain ) {
			$login['enabled'] = false;
		} else {
			// Carried in the autoloaded option, so checking it costs no query.
			$login['announce'] = true;
		}
		if ( add_option( Options::LOGIN, $login, '', true ) ) {
			if ( $plain ) {
				add_option( Options::NOTICES, array( 'location_off' => Clock::now() ), '', false );
			} else {
				// New login address: show it to administrators for a day
				// (Plugin::render_slug_notice()) and email it, so nobody depends on having
				// seen the notice (lost-address recovery, plan 5.5). The mail waits for
				// `init` (maybe_announce()): this can run on plugins_loaded, before roles exist.
				add_option( Options::NOTICES, array( 'slug_changed' => Clock::now() ), '', false );
			}
		}
		add_option( Options::SETTINGS, Settings::defaults(), '', false );
		add_option( Options::ACTIVATED_AT, time(), '', false );
		add_option( Options::KEY_CHECK, self::key_fingerprint(), '', false );

		update_option( Options::DB_VERSION, Schema::VERSION, true );

		Maintenance::schedule();
	}

	/**
	 * Emails administrators the login address once after the login was first moved.
	 * Runs on `init`, when roles and users can be queried.
	 */
	public static function maybe_announce(): void {
		$login = get_option( Options::LOGIN );
		if ( ! is_array( $login ) || empty( $login['announce'] ) ) {
			return;
		}
		unset( $login['announce'] );
		update_option( Options::LOGIN, $login, true );
		if ( LoginLocation::enabled() ) {
			SlugChanger::announce( LoginLocation::url(), true );
		}
	}

	/**
	 * Multisite: a site created on a network where the plugin is network-active installs
	 * at once, so its login slug exists before its welcome email is sent.
	 *
	 * @param mixed $site New site (WP_Site).
	 */
	public static function initialize_site( mixed $site ): void {
		if ( ! $site instanceof \WP_Site ) {
			return;
		}
		$network = (array) get_site_option( 'active_sitewide_plugins', array() );
		if ( ! isset( $network[ plugin_basename( MDMFA_FILE ) ] ) ) {
			return;
		}
		switch_to_blog( (int) $site->blog_id );
		self::install();
		restore_current_blog();
	}

	/**
	 * Deactivation hook: stops the cron event. No data is removed, and core login returns
	 * at once because none of the plugin's hooks run any more (plan 6.6).
	 */
	public static function deactivate(): void {
		Maintenance::unschedule();
	}

	/**
	 * Key id and source of the current encryption key; never key material.
	 *
	 * @return array{kid: string, source: string}
	 */
	private static function key_fingerprint(): array {
		try {
			$keys = KeyProvider::from_environment();

			return array(
				'kid'    => $keys->kid(),
				'source' => $keys->source(),
			);
		} catch ( InvalidKeyException $e ) {
			return array(
				'kid'    => '',
				'source' => 'invalid',
			);
		}
	}
}
