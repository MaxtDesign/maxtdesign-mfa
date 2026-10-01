<?php
/**
 * Effective per-user policy and the login decision (plan 4.1).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Policy;

use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Effective policy = the strictest across the user's roles on this site (Required >
 * Optional > Off); the role that sets it also supplies factors, grace and the rest. Super
 * admins are always Required. Filter: mdmfa_user_policy.
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

	private const RANK = array(
		Settings::POLICY_OFF      => 0,
		Settings::POLICY_OPTIONAL => 1,
		Settings::POLICY_REQUIRED => 2,
	);

	/**
	 * Role configuration that governs this user, with the resolved policy.
	 *
	 * @param \WP_User $user User.
	 * @return array<string, mixed>
	 */
	public static function effective( \WP_User $user ): array {
		$settings = Settings::get();
		$roles    = is_array( $settings['roles'] ) ? $settings['roles'] : array();
		$unlisted = is_array( $settings['unlisted_role'] ) ? $settings['unlisted_role'] : Settings::role_defaults( Settings::POLICY_OPTIONAL, true );

		$best = null;
		foreach ( (array) $user->roles as $role ) {
			$config = isset( $roles[ $role ] ) && is_array( $roles[ $role ] ) ? $roles[ $role ] : $unlisted;
			if ( null === $best || self::rank( $config['policy'] ?? '' ) > self::rank( $best['policy'] ?? '' ) ) {
				$best = $config;
			}
		}
		$best = $best ?? $unlisted;

		if ( is_multisite() ) {
			// Sessions are network-wide, so the strictest policy across the user's sites applies.
			$floor = self::network_floor( $user );
			if ( self::rank( $floor ) > self::rank( $best['policy'] ?? '' ) ) {
				$best['policy'] = $floor;
			}
			if ( is_super_admin( $user->ID ) ) {
				$best['policy'] = Settings::POLICY_REQUIRED;
			}
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
	 * The strictest policy any other site of the network gives this user (multisite).
	 * Cached per request; reads one option row per site the user belongs to.
	 *
	 * @param \WP_User $user User.
	 */
	private static function network_floor( \WP_User $user ): string {
		global $wpdb;
		static $cache = array();

		$key = $user->ID . ':' . get_current_blog_id();
		if ( isset( $cache[ $key ] ) ) {
			return $cache[ $key ];
		}
		$floor = Settings::POLICY_OFF;
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
		foreach ( array_slice( array_unique( $sites ), 0, 50 ) as $blog_id ) {
			// A capability row can outlive its site; a deleted site sets no policy.
			if ( get_current_blog_id() === $blog_id || null === get_site( $blog_id ) ) {
				continue;
			}
			$caps     = get_user_meta( $user->ID, $wpdb->get_blog_prefix( $blog_id ) . 'capabilities', true );
			$raw      = $wpdb->get_var( $wpdb->prepare( 'SELECT option_value FROM %i WHERE option_name = %s', $wpdb->get_blog_prefix( $blog_id ) . 'options', Options::SETTINGS ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one row per site the user belongs to, at sign-in only; cached for the request.
			$stored   = is_string( $raw ) ? maybe_unserialize( $raw ) : array();
			$settings = Settings::resolve( is_array( $stored ) ? $stored : array() );
			$roles    = is_array( $settings['roles'] ) ? $settings['roles'] : array();
			$unlisted = is_array( $settings['unlisted_role'] ) ? $settings['unlisted_role'] : array();
			foreach ( array_keys( array_filter( is_array( $caps ) ? $caps : array() ) ) as $role ) {
				$config = isset( $roles[ $role ] ) && is_array( $roles[ $role ] ) ? $roles[ $role ] : $unlisted;
				if ( self::rank( $config['policy'] ?? '' ) > self::rank( $floor ) ) {
					$floor = (string) $config['policy'];
				}
			}
		}
		$cache[ $key ] = $floor;

		return $floor;
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
	 * Numeric strictness.
	 *
	 * @param mixed $policy Policy value.
	 */
	private static function rank( mixed $policy ): int {
		return is_string( $policy ) && isset( self::RANK[ $policy ] ) ? self::RANK[ $policy ] : 0;
	}
}
