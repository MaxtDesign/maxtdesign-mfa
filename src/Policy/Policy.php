<?php
/**
 * Effective per-user policy and the login decision (plan 4.1).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Policy;

use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Effective policy = the strictest across the user's roles on this site (Required >
 * Optional > Off); the role that sets it also supplies factors, grace and the rest, and
 * roles that tie are combined, restriction by restriction. Super admins are always Required. Filter: mdmfa_user_policy.
 *
 * On a network the account, its factors, its sessions and a reset are shared by every
 * site, so each site the user belongs to contributes its governing configuration and the
 * result is the strictest of them, setting by setting (see strictest()). The answer is
 * the same whichever site the user signs in on.
 */
final class Policy {

	/** Core behaviour: the password is enough. */
	public const NONE = 'none';

	/** Enrolled: ask for the second factor. */
	public const CHALLENGE = 'challenge';

	/** Required, not enrolled, still in grace: enroll now or skip. */
	public const GRACE = 'grace';

	/** Required, not enrolled, grace over: enroll before the session starts. */
	public const ENROLL = 'enroll';

	public const GRACE_META = 'mdmfa_grace_started';

	/**
	 * Other sites' configurations per "user:site", for this request.
	 *
	 * @var array<string, array<int, array<string, mixed>>>
	 */
	private static array $network = array();

	private const RANK = array(
		Settings::POLICY_OFF      => 0,
		Settings::POLICY_OPTIONAL => 1,
		Settings::POLICY_REQUIRED => 2,
	);

	/**
	 * Configuration that governs this user, with the resolved policy. Site-level switches
	 * are folded in: `app_passwords` already reflects the site's application-password
	 * mode, `xmlrpc_password` says whether XML-RPC accepts the account password, and
	 * `trusted_device_days` is the lifetime of a new trusted device.
	 *
	 * @param \WP_User $user User.
	 * @return array<string, mixed>
	 */
	public static function effective( \WP_User $user ): array {
		$settings = Settings::get();
		$best     = self::site_rules( self::governing( $settings, (array) $user->roles ), $settings );

		if ( is_multisite() ) {
			// Raising the policy alone would leave the weaker site's recovery, grace and
			// application-password settings in force for a network-wide identity.
			$best = self::strictest( array_merge( array( $best ), self::other_sites( $user ) ) );
			if ( is_super_admin( $user->ID ) ) {
				$best['policy'] = Settings::POLICY_REQUIRED;
			}
		}
		// Roles or sites that each allow a different strong method share none; someone Required
		// must still be able to enroll (the rule Settings::sanitize_role() applies to a role).
		if ( Settings::POLICY_REQUIRED === ( $best['policy'] ?? '' ) && isset( $best['factors'] ) && is_array( $best['factors'] ) && empty( $best['factors']['totp'] ) && empty( $best['factors']['passkey'] ) ) {
			$best['factors']['totp'] = true;
		}

		// A stored "passkey-only sign-in" has no effect unless the site opted in (beta).
		if ( ! Passkeys::passkey_only_enabled() ) {
			$best['passwordless'] = false;
		}

		$policy         = apply_filters( 'mdmfa_user_policy', $best['policy'] ?? Settings::POLICY_OPTIONAL, $user );
		$best['policy'] = is_string( $policy ) && isset( self::RANK[ $policy ] ) ? $policy : ( $best['policy'] ?? Settings::POLICY_OPTIONAL );

		return $best;
	}

	/**
	 * The user's effective policy.
	 *
	 * @param \WP_User $user User.
	 */
	public static function policy( \WP_User $user ): string {
		$policy = self::effective( $user )['policy'];

		return is_string( $policy ) ? $policy : Settings::POLICY_OPTIONAL;
	}

	/**
	 * Whether the user may enroll a factor (role allow-list, filter mdmfa_allowed_factors).
	 *
	 * @param \WP_User $user   User.
	 * @param string   $factor Factor key.
	 */
	public static function allows( \WP_User $user, string $factor ): bool {
		$config  = self::effective( $user );
		$factors = isset( $config['factors'] ) && is_array( $config['factors'] ) ? $config['factors'] : array();
		$allowed = array_keys( array_filter( $factors ) );
		$allowed = apply_filters( 'mdmfa_allowed_factors', $allowed, $user );

		return is_array( $allowed ) && in_array( $factor, $allowed, true );
	}

	/**
	 * Whether the user holds a second factor: an authenticator app, a passkey, or the
	 * emailed code where the role allows it. Recovery codes alone do not count.
	 *
	 * A passkey counts even when it cannot be used here (registered for another site of
	 * the network, or the site address changed), and so does an email factor whose address
	 * has changed and is not confirmed yet: the account must stay challenged, with its
	 * other methods or a recovery code, rather than fall back to the password alone.
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_enrolled( int $user_id ): bool {
		return TotpStore::has( $user_id ) || PasskeyStore::count( $user_id ) > 0 || EmailCode::enrolled( $user_id );
	}

	/**
	 * The role configuration that governs a user with these roles under these settings:
	 * the role with the strictest policy, or the unlisted-role configuration. Roles that
	 * tie on policy are combined like sites are (strictest()), so the order the roles are
	 * stored in decides nothing.
	 *
	 * @param array<string, mixed>    $settings Resolved settings of one site.
	 * @param array<array-key, mixed> $roles    Role names.
	 * @return array<string, mixed>
	 */
	private static function governing( array $settings, array $roles ): array {
		$configs  = is_array( $settings['roles'] ?? null ) ? $settings['roles'] : array();
		$unlisted = is_array( $settings['unlisted_role'] ?? null ) ? $settings['unlisted_role'] : Settings::role_defaults( Settings::POLICY_OPTIONAL, true );

		$top  = -1;
		$tied = array();
		foreach ( $roles as $role ) {
			$config = is_string( $role ) && isset( $configs[ $role ] ) && is_array( $configs[ $role ] ) ? $configs[ $role ] : $unlisted;
			$rank   = self::rank( $config['policy'] ?? '' );
			if ( $rank > $top ) {
				$top  = $rank;
				$tied = array();
			}
			if ( $rank === $top ) {
				$tied[] = $config;
			}
		}
		if ( array() === $tied ) {
			return $unlisted;
		}

		return 1 === count( $tied ) ? $tied[0] : self::strictest( $tied );
	}

	/**
	 * Folds a site's own switches into the role configuration, so that configurations of
	 * different sites can be compared: the application-password mode (off and on override
	 * the role), whether XML-RPC accepts an account password, and the trusted-device lifetime.
	 *
	 * @param array<string, mixed> $config   Governing role configuration.
	 * @param array<string, mixed> $settings Resolved settings of the same site.
	 * @return array<string, mixed>
	 */
	private static function site_rules( array $config, array $settings ): array {
		$mode = $settings['application_passwords'] ?? SideDoors::APP_PER_ROLE;
		if ( SideDoors::APP_OFF === $mode ) {
			$config['app_passwords'] = false;
		} elseif ( SideDoors::APP_ON === $mode ) {
			$config['app_passwords'] = true;
		}
		$config['xmlrpc_password']     = SideDoors::XMLRPC_ALLOW === ( $settings['xmlrpc'] ?? '' );
		$days                          = $settings['trusted_device_days'] ?? 30;
		$config['trusted_device_days'] = is_int( $days ) ? max( 1, $days ) : 30;

		return $config;
	}

	/**
	 * The strictest combination of several configurations for one user (one per site of a
	 * network, or one per role when a site's roles tie on policy):
	 *
	 * - policy: the strictest;
	 * - email recovery, application passwords, account passwords over XML-RPC, trusted
	 *   devices, passkey-only sign-in and each enrollable method: allowed only where every site allows it (recovery codes
	 *   always are);
	 * - recovery wait: the longest; trusted-device lifetime: the shortest;
	 * - grace: the shortest among the sites that set the winning policy. A setup period
	 *   means nothing on a site that does not require setup, so those sites do not count.
	 *
	 * Sites of equal rank therefore never cancel each other's restrictions.
	 *
	 * @param array<int, array<string, mixed>> $configs One configuration per site, never empty.
	 * @return array<string, mixed>
	 */
	private static function strictest( array $configs ): array {
		$top = 0;
		foreach ( $configs as $config ) {
			$top = max( $top, self::rank( $config['policy'] ?? '' ) );
		}
		$out     = $configs[0];
		$factors = array_fill_keys( Settings::FACTORS, true );
		$flags   = array_fill_keys( array( 'passwordless', 'trusted_devices', 'email_recovery', 'app_passwords', 'xmlrpc_password' ), true );
		$grace   = null;
		$wait    = 0;
		$days    = null;
		foreach ( $configs as $config ) {
			$allowed = isset( $config['factors'] ) && is_array( $config['factors'] ) ? $config['factors'] : array();
			foreach ( array_keys( $factors ) as $factor ) {
				$factors[ $factor ] = $factors[ $factor ] && ( 'recovery' === $factor || ! empty( $allowed[ $factor ] ) );
			}
			foreach ( array_keys( $flags ) as $flag ) {
				$flags[ $flag ] = $flags[ $flag ] && ! empty( $config[ $flag ] );
			}
			$wait = max( $wait, self::number( $config['recovery_wait_hours'] ?? 0 ) );
			$life = max( 1, self::number( $config['trusted_device_days'] ?? 30 ) );
			$days = null === $days ? $life : min( $days, $life );
			if ( self::rank( $config['policy'] ?? '' ) === $top ) {
				$mine  = self::number( $config['grace_days'] ?? 0 );
				$grace = null === $grace ? $mine : min( $grace, $mine );
			}
		}

		$out['policy']              = (string) array_search( $top, self::RANK, true );
		$out['factors']             = $factors;
		$out['grace_days']          = $grace ?? 0;
		$out['recovery_wait_hours'] = $wait;
		$out['trusted_device_days'] = $days ?? 30;

		return array_merge( $out, $flags );
	}

	/**
	 * Drops the per-request cache of other sites' configurations.
	 */
	public static function forget(): void {
		self::$network = array();
	}

	/**
	 * The governing configuration on every other site of the network the user belongs to
	 * (multisite). Cached per request; one query per site.
	 *
	 * @param \WP_User $user User.
	 * @return array<int, array<string, mixed>>
	 */
	private static function other_sites( \WP_User $user ): array {
		global $wpdb;

		$key = $user->ID . ':' . get_current_blog_id();
		if ( isset( self::$network[ $key ] ) ) {
			return self::$network[ $key ];
		}
		// The user's sites, from their per-site capability meta keys. Core's helpers
		// (get_blogs_of_user(), get_blog_option()) switch blogs, and switching re-enters the
		// current-user lookup: this runs inside it when an application password is checked.
		$base  = preg_quote( $wpdb->base_prefix, '/' );
		$sites = array();
		foreach ( array_keys( (array) get_user_meta( $user->ID ) ) as $meta_key ) {
			if ( 1 === preg_match( '/^' . $base . '(?:(\d+)_)?capabilities$/', (string) $meta_key, $m ) ) {
				$sites[] = isset( $m[1] ) && '' !== $m[1] ? (int) $m[1] : 1;
			}
		}
		// Every site counts: a cap here would let the site past it be ignored.
		$configs = array();
		foreach ( array_unique( $sites ) as $blog_id ) {
			// A capability row can outlive its site; a deleted site sets no policy.
			if ( get_current_blog_id() === $blog_id || null === get_site( $blog_id ) ) {
				continue;
			}
			$prefix = $wpdb->get_blog_prefix( $blog_id );
			$caps   = get_user_meta( $user->ID, $prefix . 'capabilities', true );
			$rows   = $wpdb->get_results( $wpdb->prepare( 'SELECT option_name, option_value FROM %i WHERE option_name IN ( %s, %s )', $prefix . 'options', Options::SETTINGS, $prefix . 'user_roles' ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one query per site the user belongs to, when a sign-in or a credential is checked; cached for the request.
			$values = array();
			foreach ( is_array( $rows ) ? $rows : array() as $row ) {
				if ( is_array( $row ) && isset( $row['option_name'], $row['option_value'] ) && is_string( $row['option_value'] ) ) {
					$values[ (string) $row['option_name'] ] = maybe_unserialize( $row['option_value'] );
				}
			}
			$stored   = $values[ Options::SETTINGS ] ?? array();
			$settings = Settings::resolve( is_array( $stored ) ? $stored : array() );
			// The roles as that site sees them (WP_User::$roles: capability keys that name a
			// role registered there), so both sites reach the same answer about each other.
			$names      = array_keys( is_array( $caps ) ? $caps : array() );
			$registered = $values[ $prefix . 'user_roles' ] ?? null;
			if ( is_array( $registered ) && array() !== $registered ) {
				$names = array_values( array_filter( $names, static fn ( mixed $name ): bool => isset( $registered[ $name ] ) ) );
			}
			$configs[] = self::site_rules( self::governing( $settings, $names ), $settings );
		}
		self::$network[ $key ] = $configs;

		return $configs;
	}

	/**
	 * Starts the grace clock at the first login after a Required policy applies (plan 4.3).
	 *
	 * @param \WP_User $user User.
	 */
	public static function maybe_start_grace( \WP_User $user ): void {
		if ( Settings::POLICY_REQUIRED === self::policy( $user )
			&& ! self::is_enrolled( $user->ID )
			&& '' === (string) get_user_meta( $user->ID, self::GRACE_META, true ) ) {
			update_user_meta( $user->ID, self::GRACE_META, (string) Clock::now() );
		}
	}

	/**
	 * Seconds of grace left (0 when over, or when it never started).
	 *
	 * @param \WP_User $user User.
	 */
	public static function grace_remaining( \WP_User $user ): int {
		$started = (int) get_user_meta( $user->ID, self::GRACE_META, true );
		if ( $started <= 0 ) {
			return 0;
		}
		$days = self::effective( $user )['grace_days'] ?? 0;
		$end  = $started + ( is_int( $days ) ? max( 0, $days ) : 0 ) * DAY_IN_SECONDS;

		return max( 0, $end - Clock::now() );
	}

	/**
	 * What must happen after a correct password.
	 *
	 * @param \WP_User $user User.
	 */
	public static function decide( \WP_User $user ): string {
		if ( Plugin::is_disabled() ) {
			return self::NONE;
		}
		$policy   = self::policy( $user );
		$enrolled = self::is_enrolled( $user->ID );
		// On a network an enrolled account is challenged on every site: one site's "Off"
		// would otherwise hand out a session that works on all of them.
		if ( Settings::POLICY_OFF === $policy && ! ( $enrolled && is_multisite() ) ) {
			return self::NONE;
		}
		if ( $enrolled ) {
			return self::CHALLENGE;
		}
		if ( Settings::POLICY_OPTIONAL === $policy ) {
			return self::NONE;
		}

		return self::grace_remaining( $user ) > 0 ? self::GRACE : self::ENROLL;
	}

	/**
	 * Whether a session for this user must have passed MFA (the bypass guard's test,
	 * plan 4.6): enrolled, or Required with grace over. Policy Off exempts.
	 *
	 * @param \WP_User $user User.
	 */
	public static function is_subject( \WP_User $user ): bool {
		if ( Plugin::is_disabled() ) {
			return false;
		}
		$policy   = self::policy( $user );
		$enrolled = self::is_enrolled( $user->ID );
		if ( Settings::POLICY_OFF === $policy && ! ( $enrolled && is_multisite() ) ) {
			return false;
		}
		if ( $enrolled ) {
			return true;
		}

		return Settings::POLICY_REQUIRED === $policy
			&& (int) get_user_meta( $user->ID, self::GRACE_META, true ) > 0
			&& 0 === self::grace_remaining( $user );
	}

	/**
	 * A stored whole number, never negative.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function number( mixed $value ): int {
		return is_int( $value ) ? max( 0, $value ) : 0;
	}

	/**
	 * Numeric strictness.
	 *
	 * @param mixed $policy Policy value.
	 */
	private static function rank( mixed $policy ): int {
		return is_string( $policy ) && isset( self::RANK[ $policy ] ) ? self::RANK[ $policy ] : 0;
	}
}
