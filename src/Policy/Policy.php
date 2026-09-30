<?php
/**
 * Effective per-user policy and the login decision (plan 4.1).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Policy;

use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Plugin;
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

		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			$best['policy'] = Settings::POLICY_REQUIRED;
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
	 * Whether the user holds a second factor. Recovery codes alone do not count.
	 * P5 adds passkeys and P6 the email code.
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_enrolled( int $user_id ): bool {
		return TotpStore::has( $user_id );
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
		$policy = self::policy( $user );
		if ( Settings::POLICY_OFF === $policy ) {
			return self::NONE;
		}
		if ( self::is_enrolled( $user->ID ) ) {
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
		$policy = self::policy( $user );
		if ( Settings::POLICY_OFF === $policy ) {
			return false;
		}
		if ( self::is_enrolled( $user->ID ) ) {
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
