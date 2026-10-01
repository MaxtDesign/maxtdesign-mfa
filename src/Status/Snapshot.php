<?php
/**
 * Read-only status contract (plan 7.3). Never contains secrets, key material, user names
 * or the login slug. Source of `wp mdmfa status`, the admin counts and the suite status.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Status;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Integrations\Conflicts;
use MaxtDesign\Mfa\Integrations\Jetpack;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Snapshot builder, cached for 15 minutes.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- counts over the plugin's own tables and user meta; the result is cached in a transient.
 */
final class Snapshot {

	public const CACHE = 'mdmfa_status_cache';
	public const TTL   = 15 * MINUTE_IN_SECONDS;

	/** Users scanned for unverified sessions; larger sites report `sessions_truncated`. */
	public const SESSION_SCAN_LIMIT = 1000;

	/**
	 * The snapshot, from cache unless a fresh one is asked for.
	 *
	 * @param bool $fresh Rebuild and replace the cache.
	 * @return array<string, mixed>
	 */
	public static function get( bool $fresh = false ): array {
		$cached = $fresh ? false : get_transient( self::CACHE );
		if ( is_array( $cached ) && isset( $cached['generated_at'] ) ) {
			return $cached;
		}
		$snapshot = self::build();
		set_transient( self::CACHE, $snapshot, self::TTL );

		return $snapshot;
	}

	/**
	 * Drops the cache (settings saved, user reset).
	 */
	public static function flush(): void {
		delete_transient( self::CACHE );
	}

	/**
	 * Builds the snapshot.
	 *
	 * @return array<string, mixed>
	 */
	public static function build(): array {
		$db_version = get_option( Options::DB_VERSION, '' );
		$stored     = get_option( Options::KEY_CHECK, array() );
		$source     = 'invalid';
		$key_ok     = false;
		$migrating  = false;
		try {
			$keys   = KeyProvider::from_environment();
			$source = $keys->source();
			$first  = is_array( $stored ) && isset( $stored['kid'] ) && is_string( $stored['kid'] ) ? $stored['kid'] : '';
			$key_ok = hash_equals( $first, $keys->kid() );
			// The key the site started with is still derivable: secrets convert as they are read.
			foreach ( KeyProvider::older() as $old ) {
				$migrating = $migrating || ( ! $key_ok && hash_equals( $first, $old->kid() ) );
			}
		} catch ( InvalidKeyException $e ) {
			$key_ok = false;
		}

		$roles    = self::roles();
		$sessions = self::unverified_sessions( array_keys( array_filter( $roles, static fn ( array $r ): bool => Settings::POLICY_REQUIRED === $r['policy'] ) ) );
		$snapshot = array(
			'version'             => MDMFA_VERSION,
			'schema'              => is_string( $db_version ) ? $db_version : '',
			'schema_current'      => Schema::VERSION === $db_version,
			'disabled'            => Plugin::is_disabled(),
			'login_location'      => LoginLocation::enabled(),
			'key_source'          => $source,
			'key_ok'              => $key_ok,
			'key_migrating'       => $migrating,
			'passkey_only_signin' => Passkeys::passkey_only_enabled(),
			'app_passwords'       => SideDoors::app_password_mode(),
			'xmlrpc'              => SideDoors::xmlrpc_mode(),
			'jetpack'             => Jetpack::detected(),
			'wpcom_sso'           => Jetpack::sso_blocked() ? 'blocked' : ( Jetpack::sso_active() ? 'challenged' : 'inactive' ),
			'conflicts'           => Conflicts::detect(),
			'roles'               => $roles,
			'total_users'         => (int) count_users()['total_users'],
			'enrolled_users'      => count( self::enrolled_ids() ),
			'active_lockouts'     => self::active_lockouts(),
			'failures_24h'        => self::events_24h( 'challenge_fail' ),
			'bypass_blocks_24h'   => self::events_24h( 'bypass_blocked' ),
			'unverified_sessions' => $sessions['count'],
			'sessions_truncated'  => $sessions['truncated'],
			'generated_at'        => Clock::now(),
		);
		$filtered = apply_filters( 'mdmfa_status', $snapshot );

		return is_array( $filtered ) ? $filtered : $snapshot;
	}

	/**
	 * Per-role policy and counts. A user with several roles is counted under each, like
	 * core's own role counts.
	 *
	 * @return array<string, array{policy: string, factors: string[], grace_days: int, users: int, enrolled: int, by_factor: array{totp: int, passkey: int, email: int}, in_grace: int, overdue: int}>
	 */
	private static function roles(): array {
		$settings = Settings::get();
		$configs  = is_array( $settings['roles'] ) ? $settings['roles'] : array();
		$unlisted = is_array( $settings['unlisted_role'] ) ? $settings['unlisted_role'] : array();
		$counts   = count_users();
		$out      = array();
		foreach ( array_keys( wp_roles()->roles ) as $role ) {
			$config       = isset( $configs[ $role ] ) && is_array( $configs[ $role ] ) ? $configs[ $role ] : $unlisted;
			$factors      = isset( $config['factors'] ) && is_array( $config['factors'] ) ? array_keys( array_filter( $config['factors'] ) ) : array();
			$out[ $role ] = array(
				'policy'     => is_string( $config['policy'] ?? null ) ? $config['policy'] : Settings::POLICY_OPTIONAL,
				'factors'    => array_map( 'strval', $factors ),
				'grace_days' => is_int( $config['grace_days'] ?? null ) ? $config['grace_days'] : 0,
				'users'      => (int) ( $counts['avail_roles'][ $role ] ?? 0 ),
				'enrolled'   => 0,
				'by_factor'  => array(
					'totp'    => 0,
					'passkey' => 0,
					'email'   => 0,
				),
				'in_grace'   => 0,
				'overdue'    => 0,
			);
		}

		$passkey_users = self::passkey_user_ids();
		$enrolled      = self::enrolled_ids();
		// One query for the users and one for their meta, instead of two per user.
		cache_users( $enrolled );
		foreach ( $enrolled as $user_id ) {
			$user = get_userdata( $user_id );
			if ( ! $user instanceof \WP_User || ! Policy::is_enrolled( $user_id ) ) {
				continue;
			}
			foreach ( (array) $user->roles as $role ) {
				if ( ! isset( $out[ $role ] ) ) {
					continue;
				}
				++$out[ $role ]['enrolled'];
				$out[ $role ]['by_factor']['totp']    += TotpStore::has( $user_id ) ? 1 : 0;
				$out[ $role ]['by_factor']['passkey'] += isset( $passkey_users[ $user_id ] ) ? 1 : 0;
				$out[ $role ]['by_factor']['email']   += EmailCode::has( $user_id ) ? 1 : 0;
			}
		}

		$in_setup = self::user_ids_with_meta( Policy::GRACE_META );
		cache_users( $in_setup );
		foreach ( $in_setup as $user_id ) {
			$user = get_userdata( $user_id );
			if ( ! $user instanceof \WP_User || Policy::is_enrolled( $user_id ) || Settings::POLICY_REQUIRED !== Policy::policy( $user ) ) {
				continue;
			}
			$key = Policy::grace_remaining( $user ) > 0 ? 'in_grace' : 'overdue';
			foreach ( (array) $user->roles as $role ) {
				if ( isset( $out[ $role ] ) ) {
					++$out[ $role ][ $key ];
				}
			}
		}

		return $out;
	}

	/**
	 * IDs of users flagged as enrolled.
	 *
	 * @return int[]
	 */
	private static function enrolled_ids(): array {
		return self::user_ids_with_meta( 'mdmfa_enrolled' );
	}

	/**
	 * IDs of this site's users that carry a meta key.
	 *
	 * @param string $meta_key Meta key.
	 * @return int[]
	 */
	private static function user_ids_with_meta( string $meta_key ): array {
		$ids = get_users(
			array(
				'meta_key' => $meta_key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- counted once per 15 minutes for the cached status.
				'fields'   => 'ID',
				'number'   => 5000,
			)
		);

		return array_map( 'intval', $ids );
	}

	/**
	 * User IDs holding at least one passkey, as a set.
	 *
	 * @return array<int, true>
	 */
	private static function passkey_user_ids(): array {
		global $wpdb;

		$ids = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT user_id FROM %i', Schema::credentials_table( $wpdb ) ) );

		return array_fill_keys( array_map( 'intval', is_array( $ids ) ? $ids : array() ), true );
	}

	/**
	 * Users whose second step is locked right now.
	 */
	private static function active_lockouts(): int {
		$locked = 0;
		$ids    = self::user_ids_with_meta( Lockout::META );
		cache_users( $ids );
		foreach ( $ids as $user_id ) {
			$locked += Lockout::state( $user_id )['locked_until'] > Clock::now() ? 1 : 0;
		}

		return $locked;
	}

	/**
	 * Log rows of one event in the last 24 hours.
	 *
	 * @param string $event Event name.
	 */
	private static function events_24h( string $event ): int {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE event = %s AND created_at > %d',
				Schema::site_tables( $wpdb )['log'],
				$event,
				Clock::now() - DAY_IN_SECONDS
			)
		);
	}

	/**
	 * Users in Required roles with a live session that never passed the second step
	 * (sessions older than the policy, or grace skips).
	 *
	 * @param string[] $roles Required role slugs.
	 * @return array{count: int, truncated: bool}
	 */
	private static function unverified_sessions( array $roles ): array {
		if ( array() === $roles ) {
			return array(
				'count'     => 0,
				'truncated' => false,
			);
		}
		$ids   = get_users(
			array(
				'role__in' => $roles,
				'fields'   => 'ID',
				'number'   => self::SESSION_SCAN_LIMIT + 1,
			)
		);
		$count = 0;
		cache_users( array_map( 'intval', array_slice( $ids, 0, self::SESSION_SCAN_LIMIT ) ) );
		foreach ( array_slice( $ids, 0, self::SESSION_SCAN_LIMIT ) as $user_id ) {
			foreach ( \WP_Session_Tokens::get_instance( (int) $user_id )->get_all() as $session ) {
				if ( ! isset( $session['mdmfa'] ) ) {
					++$count;
					break;
				}
			}
		}

		return array(
			'count'     => $count,
			'truncated' => count( $ids ) > self::SESSION_SCAN_LIMIT,
		);
	}
}
