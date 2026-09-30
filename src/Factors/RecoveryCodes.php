<?php
/**
 * Single-use recovery codes (plan 11.2): 10 codes of 16 base32 characters (80 bits each),
 * stored only as password hashes.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Support\Base32;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Recovery code set.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- consuming a code is a compare-and-swap on the meta row so a code cannot be spent twice; the user meta cache is invalidated right after.
 */
final class RecoveryCodes {

	public const META   = 'mdmfa_recovery';
	public const COUNT  = 10;
	public const LENGTH = 16;

	/** Warn the user when this many or fewer remain. */
	public const LOW = 3;

	/**
	 * Replaces the user's codes with a new set.
	 *
	 * @param int $user_id User ID.
	 * @return string[] Plaintext codes, formatted XXXX-XXXX-XXXX-XXXX. Shown once, never stored.
	 */
	public static function generate( int $user_id ): array {
		$codes  = array();
		$hashes = array();
		for ( $i = 0; $i < self::COUNT; $i++ ) {
			$code     = substr( Base32::encode( random_bytes( 10 ) ), 0, self::LENGTH );
			$hashes[] = wp_hash_password( $code );
			$codes[]  = implode( '-', str_split( $code, 4 ) );
		}
		update_user_meta(
			$user_id,
			self::META,
			array(
				'hashes'  => $hashes,
				'created' => Clock::now(),
			)
		);

		return $codes;
	}

	/**
	 * Canonical form of user input: upper case, base32 characters only.
	 *
	 * @param string $input Raw input.
	 */
	public static function normalize( string $input ): string {
		return (string) preg_replace( '/[^A-Z2-7]/', '', strtoupper( $input ) );
	}

	/**
	 * Codes left.
	 *
	 * @param int $user_id User ID.
	 */
	public static function remaining( int $user_id ): int {
		return count( self::hashes( $user_id ) );
	}

	/**
	 * Verifies and consumes a code. Returns the number left, or null when the code is wrong
	 * or was spent by a concurrent request.
	 *
	 * @param int    $user_id User ID.
	 * @param string $input   Submitted code.
	 */
	public static function consume( int $user_id, string $input ): ?int {
		global $wpdb;

		$code = self::normalize( $input );
		if ( self::LENGTH !== strlen( $code ) ) {
			return null;
		}

		$stored = get_user_meta( $user_id, self::META, true );
		$hashes = self::hashes( $user_id );
		foreach ( $hashes as $index => $hash ) {
			if ( ! wp_check_password( $code, $hash ) ) {
				continue;
			}
			unset( $hashes[ $index ] );
			$next = array(
				'hashes'  => array_values( $hashes ),
				'created' => is_array( $stored ) && isset( $stored['created'] ) ? (int) $stored['created'] : 0,
			);
			// Compare-and-swap: only the request that still sees the old value wins.
			$updated = $wpdb->update(
				$wpdb->usermeta,
				array( 'meta_value' => maybe_serialize( $next ) ), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_query_meta_value -- primary-key-scoped CAS on one row.
				array(
					'user_id'    => $user_id,
					'meta_key'   => self::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_query_meta_key -- scoped by user_id.
					'meta_value' => maybe_serialize( $stored ), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_query_meta_value -- the CAS condition.
				)
			);
			wp_cache_delete( $user_id, 'user_meta' );

			return 1 === $updated ? count( $next['hashes'] ) : null;
		}

		return null;
	}

	/**
	 * Removes every code.
	 *
	 * @param int $user_id User ID.
	 */
	public static function remove( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
	}

	/**
	 * Stored hashes.
	 *
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	private static function hashes( int $user_id ): array {
		$stored = get_user_meta( $user_id, self::META, true );
		if ( ! is_array( $stored ) || ! isset( $stored['hashes'] ) || ! is_array( $stored['hashes'] ) ) {
			return array();
		}

		return array_values( array_filter( $stored['hashes'], 'is_string' ) );
	}
}
