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
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;

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

		add_option( Options::LOGIN, Settings::login_defaults(), '', true );
		add_option( Options::SETTINGS, Settings::defaults(), '', false );
		add_option( Options::ACTIVATED_AT, time(), '', false );
		add_option( Options::KEY_CHECK, self::key_fingerprint(), '', false );

		update_option( Options::DB_VERSION, Schema::VERSION, true );

		Maintenance::schedule();
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
