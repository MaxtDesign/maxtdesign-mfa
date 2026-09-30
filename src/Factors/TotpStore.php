<?php
/**
 * Per-user TOTP secret storage (plan 6.2, 6.5) and replay protection (plan 11.1).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Crypto\SecretBox;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * The secret lives encrypted in mdmfa_totp. The last accepted step lives in its own meta
 * row, mdmfa_totp_step, so it can be advanced with one conditional UPDATE: two requests
 * racing with the same code cannot both win. (Plan 6.2 put last_step inside mdmfa_totp;
 * split out for atomicity.)
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the atomic step claim needs a conditional UPDATE; the user meta cache is invalidated right after.
 */
final class TotpStore {

	public const META         = 'mdmfa_totp';
	public const STEP_META    = 'mdmfa_totp_step';
	public const PENDING_META = 'mdmfa_totp_pending';

	/** Seconds a My security enrollment secret stays valid before it must be confirmed. */
	public const PENDING_TTL = 900;

	/**
	 * Whether the user has a TOTP secret stored (readable or not).
	 *
	 * @param int $user_id User ID.
	 */
	public static function has( int $user_id ): bool {
		$box = get_user_meta( $user_id, self::META, true );

		return is_array( $box ) && isset( $box['ct'] );
	}

	/**
	 * Stores a confirmed secret and resets the replay counter.
	 *
	 * @param int    $user_id User ID.
	 * @param string $secret  Raw secret bytes.
	 * @param int    $step    Step already used to confirm enrollment (it cannot be reused).
	 * @throws InvalidKeyException When no usable encryption key exists.
	 */
	public static function save( int $user_id, string $secret, int $step = 0 ): void {
		$box            = self::box()->encrypt( $secret, SecretBox::totp_aad( $user_id ) );
		$box['created'] = Clock::now();
		update_user_meta( $user_id, self::META, $box );
		update_user_meta( $user_id, self::STEP_META, (string) $step );
		delete_user_meta( $user_id, self::PENDING_META );
	}

	/**
	 * Decrypted secret, or null when absent or unreadable (key changed, tampered).
	 *
	 * @param int $user_id User ID.
	 */
	public static function secret( int $user_id ): ?string {
		$box = get_user_meta( $user_id, self::META, true );
		if ( ! is_array( $box ) ) {
			return null;
		}
		try {
			return self::box()->decrypt( $box, SecretBox::totp_aad( $user_id ) );
		} catch ( InvalidKeyException $e ) {
			return null;
		}
	}

	/**
	 * Removes the secret and its counters.
	 *
	 * @param int $user_id User ID.
	 */
	public static function remove( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
		delete_user_meta( $user_id, self::STEP_META );
		delete_user_meta( $user_id, self::PENDING_META );
	}

	/**
	 * Verifies a code and consumes its step. A code whose step is not newer than the last
	 * accepted one is rejected (replay).
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted code.
	 */
	public static function verify( int $user_id, string $code ): bool {
		$secret = self::secret( $user_id );
		if ( null === $secret ) {
			return false;
		}
		$step = Totp::match( $secret, Totp::normalize( $code ), Clock::now() );

		return null !== $step && self::claim_step( $user_id, $step );
	}

	/**
	 * Atomically advances the last accepted step. True only for the request that moved it.
	 *
	 * @param int $user_id User ID.
	 * @param int $step    Matched step.
	 */
	public static function claim_step( int $user_id, int $step ): bool {
		global $wpdb;

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET meta_value = %s WHERE user_id = %d AND meta_key = %s AND CAST(meta_value AS UNSIGNED) < %d',
				$wpdb->usermeta,
				(string) $step,
				$user_id,
				self::STEP_META,
				$step
			)
		);
		wp_cache_delete( $user_id, 'user_meta' );

		return 1 === $updated;
	}

	/**
	 * Starts a My security enrollment: a fresh secret held encrypted until confirmed.
	 *
	 * @param int $user_id User ID.
	 * @return string Raw secret bytes, for the QR code and the text fallback.
	 * @throws InvalidKeyException When no usable encryption key exists.
	 */
	public static function begin_pending( int $user_id ): string {
		$secret         = Totp::generate_secret();
		$box            = self::box()->encrypt( $secret, self::pending_aad( $user_id ) );
		$box['expires'] = Clock::now() + self::PENDING_TTL;
		update_user_meta( $user_id, self::PENDING_META, $box );

		return $secret;
	}

	/**
	 * The pending enrollment secret, or null when absent or expired.
	 *
	 * @param int $user_id User ID.
	 */
	public static function pending( int $user_id ): ?string {
		$box = get_user_meta( $user_id, self::PENDING_META, true );
		if ( ! is_array( $box ) || ! isset( $box['expires'] ) || (int) $box['expires'] < Clock::now() ) {
			return null;
		}
		try {
			return self::box()->decrypt( $box, self::pending_aad( $user_id ) );
		} catch ( InvalidKeyException $e ) {
			return null;
		}
	}

	/**
	 * Encrypts a secret for a login-flow enrollment (kept in the pending record payload).
	 *
	 * @param int    $user_id User ID.
	 * @param string $secret  Raw secret bytes.
	 * @return array{ct: string, nonce: string, kid: string}
	 * @throws InvalidKeyException When no usable encryption key exists.
	 */
	public static function seal_for_login( int $user_id, string $secret ): array {
		return self::box()->encrypt( $secret, self::pending_aad( $user_id ) );
	}

	/**
	 * Opens a secret sealed by seal_for_login().
	 *
	 * @param int                     $user_id User ID.
	 * @param array<array-key, mixed> $box     Sealed secret.
	 */
	public static function open_for_login( int $user_id, array $box ): ?string {
		try {
			return self::box()->decrypt( $box, self::pending_aad( $user_id ) );
		} catch ( InvalidKeyException $e ) {
			return null;
		}
	}

	/**
	 * Associated data for an unconfirmed secret; distinct from the enrolled one.
	 *
	 * @param int $user_id User ID.
	 */
	private static function pending_aad( int $user_id ): string {
		return 'mdmfa:totp-enroll:v1:' . $user_id;
	}

	/**
	 * Secret box over the site's key.
	 *
	 * @throws InvalidKeyException When MDMFA_ENCRYPTION_KEY is malformed.
	 */
	private static function box(): SecretBox {
		return new SecretBox( KeyProvider::from_environment() );
	}
}
