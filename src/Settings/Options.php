<?php
/**
 * Every option, user meta key, transient prefix and cron hook the plugin owns (plan 6.2-6.4).
 * uninstall.php deletes from these lists, so a new key must be added here first.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Storage key registry.
 */
final class Options {

	/** Autoloaded, small: login location. Read on every request at zero added queries. */
	public const LOGIN = 'mdmfa_login';

	/** Not autoloaded: role policy matrix and every other setting. */
	public const SETTINGS = 'mdmfa_settings';

	/** Autoloaded: installed schema version, compared on plugins_loaded. */
	public const DB_VERSION = 'mdmfa_db_version';

	/** Key id fingerprint only, never key material. */
	public const KEY_CHECK = 'mdmfa_key_check';

	public const ACTIVATED_AT = 'mdmfa_activated_at';
	public const NOTICES      = 'mdmfa_notices';

	/** Daily purge of expired pending rows, old log rows, expired trusted devices. */
	public const CRON_PURGE = 'mdmfa_purge';

	/**
	 * Options this plugin creates, with their autoload flag.
	 *
	 * @return array<string, bool>
	 */
	public static function all(): array {
		return array(
			self::LOGIN        => true,
			self::SETTINGS     => false,
			self::DB_VERSION   => true,
			self::KEY_CHECK    => false,
			self::ACTIVATED_AT => false,
			self::NOTICES      => false,
		);
	}

	/**
	 * User meta keys (network-global on multisite by nature).
	 *
	 * @return string[]
	 */
	public static function user_meta_keys(): array {
		return array(
			'mdmfa_totp',
			'mdmfa_recovery',
			'mdmfa_email',
			'mdmfa_user_handle',
			'mdmfa_enrolled',
			'mdmfa_grace_started',
			'mdmfa_failures',
			'mdmfa_trusted',
			'mdmfa_prefs',
		);
	}

	/**
	 * Transient names (without the _transient_ prefix). Dynamic ones end in an underscore.
	 *
	 * @return string[]
	 */
	public static function transients(): array {
		return array(
			'mdmfa_status_cache',
			'mdmfa_ipthrottle_',
		);
	}
}
