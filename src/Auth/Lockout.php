<?php
/**
 * Per-user second-factor throttle and lockout (plan 11.1, decision 14).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Notify\Mailer;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Consecutive failures across pending records, kept in user meta (authoritative; survives
 * object-cache eviction). From the 5th failure each attempt waits 30 s, doubling, capped
 * at 15 minutes. The 20th failure locks second-factor attempts for 1 hour; a repeat lock
 * lasts 24 hours. A success clears everything. A lock only blocks the second factor: an
 * attacker needs the password to reach it.
 *
 * @phpstan-type State array{count: int, last_fail: int, locked_until: int, lock_level: int}
 */
final class Lockout {

	public const META = 'mdmfa_failures';

	/** Longest backoff between attempts before the lock threshold. */
	public const MAX_BACKOFF = 900;

	/**
	 * Runs a factor check while holding a per-user database lock, so parallel requests
	 * cannot each read the counter before any of them writes it. Returns null when the
	 * lock is busy (another attempt for this user is in flight): the caller refuses.
	 * A database without named locks runs the check unlocked.
	 *
	 * @template T
	 * @param int          $user_id User ID.
	 * @param callable():T $check   The check, including its failure accounting.
	 * @return T|null
	 */
	public static function with_lock( int $user_id, callable $check ): mixed {
		global $wpdb;

		$name = 'mdmfa_u' . $user_id . '_' . substr( md5( ( defined( 'DB_NAME' ) ? (string) constant( 'DB_NAME' ) : '' ) . $wpdb->base_prefix ), 0, 12 );
		$got  = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, 5 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- a named lock, not data.
		if ( null !== $got && '1' !== (string) $got ) {
			return null;
		}
		if ( null === $got && false === get_transient( 'mdmfa_lock_unavailable' ) ) {
			// Recorded once a day: on this database the counters are not exact under
			// parallel attempts.
			set_transient( 'mdmfa_lock_unavailable', 1, DAY_IN_SECONDS );
			Logger::log( 'lock_unavailable', $user_id, '', '', null, 'GET_LOCK' );
		}
		// This request read the user's meta before it held the lock. Drop that copy, so
		// the counter, the TOTP step and the email-code state are read fresh inside it.
		wp_cache_delete( $user_id, 'user_meta' );
		try {
			return $check();
		} finally {
			if ( null !== $got ) {
				$wpdb->query( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- a named lock, not data.
			}
		}
	}

	/**
	 * Current state, with defaults.
	 *
	 * @param int $user_id User ID.
	 * @return State
	 */
	public static function state( int $user_id ): array {
		$raw = get_user_meta( $user_id, self::META, true );
		$raw = is_array( $raw ) ? $raw : array();

		return array(
			'count'        => isset( $raw['count'] ) ? (int) $raw['count'] : 0,
			'last_fail'    => isset( $raw['last_fail'] ) ? (int) $raw['last_fail'] : 0,
			'locked_until' => isset( $raw['locked_until'] ) ? (int) $raw['locked_until'] : 0,
			'lock_level'   => isset( $raw['lock_level'] ) ? (int) $raw['lock_level'] : 0,
		);
	}

	/**
	 * Thresholds from settings, filterable (mdmfa_lockout_thresholds).
	 *
	 * @return array{backoff_after: int, backoff_seconds: int, lock_after: int, lock_seconds: int, repeat_lock_seconds: int}
	 */
	public static function thresholds(): array {
		$settings = Settings::get();
		$lockout  = is_array( $settings['lockout'] ) ? $settings['lockout'] : array();
		$values   = apply_filters( 'mdmfa_lockout_thresholds', $lockout );
		$values   = is_array( $values ) ? $values : $lockout;
		$int      = static fn ( string $key, int $fallback ): int => isset( $values[ $key ] ) && is_int( $values[ $key ] ) && $values[ $key ] > 0 ? $values[ $key ] : $fallback;

		return array(
			'backoff_after'       => $int( 'backoff_after', 5 ),
			'backoff_seconds'     => $int( 'backoff_seconds', 30 ),
			'lock_after'          => $int( 'lock_after', 20 ),
			'lock_seconds'        => $int( 'lock_seconds', HOUR_IN_SECONDS ),
			'repeat_lock_seconds' => $int( 'repeat_lock_seconds', DAY_IN_SECONDS ),
		);
	}

	/**
	 * Unix time before which no second-factor attempt is accepted, or 0.
	 *
	 * @param int $user_id User ID.
	 */
	public static function blocked_until( int $user_id ): int {
		$state = self::state( $user_id );
		$now   = Clock::now();
		if ( $state['locked_until'] > $now ) {
			return $state['locked_until'];
		}
		$until = self::backoff_until( $state );

		return $until > $now ? $until : 0;
	}

	/**
	 * Whether the user is under a full lock (not just backoff).
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_locked( int $user_id ): bool {
		return self::state( $user_id )['locked_until'] > Clock::now();
	}

	/**
	 * Records one failed second-factor attempt.
	 *
	 * @param int $user_id User ID.
	 * @return State The new state.
	 */
	public static function record_failure( int $user_id ): array {
		$state              = self::state( $user_id );
		$limits             = self::thresholds();
		$now                = Clock::now();
		$state['count']    += 1;
		$state['last_fail'] = $now;

		if ( $state['count'] >= $limits['lock_after'] ) {
			$state['lock_level']  += 1;
			$duration              = $state['lock_level'] > 1 ? $limits['repeat_lock_seconds'] : $limits['lock_seconds'];
			$state['locked_until'] = $now + $duration;
			$state['count']        = 0;
			update_user_meta( $user_id, self::META, $state );

			$user = get_userdata( $user_id );
			Logger::log( 'locked', $user_id, '', '', null, (string) $duration );
			if ( $user instanceof \WP_User ) {
				do_action( 'mdmfa_user_locked', $user, $state['locked_until'] );
				Mailer::locked( $user, $state['locked_until'] );
			}

			return $state;
		}

		update_user_meta( $user_id, self::META, $state );

		return $state;
	}

	/**
	 * Clears failures after a successful second factor.
	 *
	 * @param int $user_id User ID.
	 */
	public static function reset( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
	}

	/**
	 * Admin or CLI unlock.
	 *
	 * @param int      $user_id User ID.
	 * @param int|null $actor   Acting user, or null for CLI.
	 */
	public static function unlock( int $user_id, ?int $actor ): void {
		self::reset( $user_id );
		Logger::log( 'unlocked', $user_id, '', null === $actor ? 'cli' : 'admin', $actor );
		$user = get_userdata( $user_id );
		if ( $user instanceof \WP_User ) {
			do_action( 'mdmfa_user_unlocked', $user, (int) $actor );
		}
	}

	/**
	 * End of the backoff delay implied by a state.
	 *
	 * @param array<string, int> $state Failure state.
	 * @phpstan-param State $state
	 */
	public static function backoff_until( array $state ): int {
		$limits = self::thresholds();
		if ( $state['count'] < $limits['backoff_after'] ) {
			return 0;
		}
		$exponent = min( 20, $state['count'] - $limits['backoff_after'] );
		$delay    = (int) min( self::MAX_BACKOFF, $limits['backoff_seconds'] * ( 2 ** $exponent ) );

		return $state['last_fail'] + $delay;
	}
}
