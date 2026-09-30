<?php
/**
 * Database schema v1 (plan section 6.1).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Install;

defined( 'ABSPATH' ) || exit;

/**
 * Table names and dbDelta definitions. Credentials are network-global
 * ({$wpdb->base_prefix}, plan decision 5); pending and log are per site.
 */
final class Schema {

	/**
	 * Bump when any definition below changes; the installer re-runs dbDelta on mismatch.
	 */
	public const VERSION = '1';

	public const CREDENTIALS = 'mdmfa_credentials';
	public const PENDING     = 'mdmfa_pending';
	public const LOG         = 'mdmfa_log';

	/**
	 * Network-global passkey table.
	 *
	 * @param \wpdb $db Database handle.
	 */
	public static function credentials_table( \wpdb $db ): string {
		return $db->base_prefix . self::CREDENTIALS;
	}

	/**
	 * Per-site tables, keyed by short name.
	 *
	 * @param \wpdb $db Database handle.
	 * @return array{pending: string, log: string}
	 */
	public static function site_tables( \wpdb $db ): array {
		return array(
			'pending' => $db->prefix . self::PENDING,
			'log'     => $db->prefix . self::LOG,
		);
	}

	/**
	 * CREATE TABLE statement for the network-global credentials table.
	 *
	 * @param \wpdb $db Database handle.
	 */
	public static function credentials_sql( \wpdb $db ): string {
		$table   = self::credentials_table( $db );
		$collate = $db->get_charset_collate();

		// dbDelta format: one column per line, two spaces after PRIMARY KEY.
		return "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned NOT NULL,
  cred_hash char(64) NOT NULL,
  cred_id varchar(1400) NOT NULL,
  public_key text NOT NULL,
  alg smallint(6) NOT NULL,
  sign_count int(10) unsigned NOT NULL DEFAULT 0,
  transports varchar(191) NOT NULL DEFAULT '',
  aaguid char(36) NOT NULL DEFAULT '',
  be tinyint(1) unsigned NOT NULL DEFAULT 0,
  bs tinyint(1) unsigned NOT NULL DEFAULT 0,
  rp_id varchar(253) NOT NULL,
  name varchar(191) NOT NULL DEFAULT '',
  created_at datetime NOT NULL,
  last_used_at datetime NULL DEFAULT NULL,
  flagged tinyint(1) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  UNIQUE KEY cred_hash (cred_hash),
  KEY user_id (user_id),
  KEY rp_user (rp_id(191),user_id)
) {$collate};";
	}

	/**
	 * CREATE TABLE statements for the per-site tables.
	 *
	 * @param \wpdb $db Database handle.
	 * @return string[]
	 */
	public static function site_sql( \wpdb $db ): array {
		$tables  = self::site_tables( $db );
		$collate = $db->get_charset_collate();

		return array(
			"CREATE TABLE {$tables['pending']} (
  token_hash char(64) NOT NULL,
  kind varchar(16) NOT NULL,
  user_id bigint(20) unsigned NULL DEFAULT NULL,
  payload text NOT NULL,
  created_at int(10) unsigned NOT NULL,
  expires_at int(10) unsigned NOT NULL,
  PRIMARY KEY  (token_hash),
  KEY expires_at (expires_at),
  KEY user_id (user_id)
) {$collate};",
			"CREATE TABLE {$tables['log']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned NULL DEFAULT NULL,
  event varchar(32) NOT NULL,
  factor varchar(16) NOT NULL DEFAULT '',
  context varchar(16) NOT NULL DEFAULT '',
  ip varbinary(16) NULL DEFAULT NULL,
  actor_id bigint(20) unsigned NULL DEFAULT NULL,
  created_at int(10) unsigned NOT NULL,
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY user_event (user_id,event)
) {$collate};",
		);
	}
}
