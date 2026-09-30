<?php
/**
 * Server side of the pending login (plan 4.5): only sha256(token) is stored.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * CRUD over mdmfa_pending. Single use and the attempt cap are enforced by the database:
 * claim() is a DELETE that must affect exactly one row, and reserve_attempt() is an
 * UPDATE guarded by attempts < MAX_ATTEMPTS.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own table; atomic single-use semantics rule out caching.
 */
final class PendingStore {

	public const KIND_LOGIN   = 'login';
	public const TTL          = 600;
	public const MAX_ATTEMPTS = 5;

	/** Cookie tokens are 32 random bytes, base64url: exactly 43 characters. */
	public const TOKEN_PATTERN = '/^[A-Za-z0-9_-]{43}$/';

	/**
	 * Creates a record and returns the raw token for the cookie.
	 *
	 * @param int                  $user_id User ID.
	 * @param string               $kind    Record kind.
	 * @param array<string, mixed> $payload Payload (JSON-encodable).
	 * @param int                  $ttl     Lifetime in seconds.
	 */
	public static function create( int $user_id, string $kind, array $payload, int $ttl = self::TTL ): string {
		global $wpdb;

		$token = Base64Url::random( 32 );
		$now   = Clock::now();
		$wpdb->insert(
			self::table(),
			array(
				'token_hash' => self::hash( $token ),
				'kind'       => $kind,
				'user_id'    => $user_id,
				'payload'    => (string) wp_json_encode( $payload ),
				'attempts'   => 0,
				'created_at' => $now,
				'expires_at' => $now + $ttl,
			),
			array( '%s', '%s', '%d', '%s', '%d', '%d', '%d' )
		);

		return $token;
	}

	/**
	 * Live record for a raw token, or null (unknown, expired, wrong kind, malformed token).
	 *
	 * @param string $token Raw cookie token.
	 * @param string $kind  Expected kind.
	 */
	public static function find( string $token, string $kind = self::KIND_LOGIN ): ?PendingRecord {
		global $wpdb;

		if ( 1 !== preg_match( self::TOKEN_PATTERN, $token ) ) {
			return null;
		}
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT token_hash, kind, user_id, payload, attempts, expires_at FROM %i WHERE token_hash = %s AND kind = %s AND expires_at > %d',
				self::table(),
				self::hash( $token ),
				$kind,
				Clock::now()
			),
			ARRAY_A
		);
		if ( ! is_array( $row ) ) {
			return null;
		}
		$payload = json_decode( (string) $row['payload'], true );

		return new PendingRecord(
			(string) $row['token_hash'],
			(string) $row['kind'],
			(int) $row['user_id'],
			is_array( $payload ) ? $payload : array(),
			(int) $row['attempts'],
			(int) $row['expires_at']
		);
	}

	/**
	 * Takes one factor attempt. False once MAX_ATTEMPTS are used or the record expired:
	 * the caller burns the record and the user starts again from the password.
	 *
	 * @param PendingRecord $record Record.
	 */
	public static function reserve_attempt( PendingRecord $record ): bool {
		global $wpdb;

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET attempts = attempts + 1 WHERE token_hash = %s AND attempts < %d AND expires_at > %d',
				self::table(),
				$record->token_hash,
				self::MAX_ATTEMPTS,
				Clock::now()
			)
		);

		return 1 === $updated;
	}

	/**
	 * Replaces the payload.
	 *
	 * @param PendingRecord        $record  Record.
	 * @param array<string, mixed> $payload New payload.
	 */
	public static function update_payload( PendingRecord $record, array $payload ): PendingRecord {
		global $wpdb;

		$wpdb->update(
			self::table(),
			array( 'payload' => (string) wp_json_encode( $payload ) ),
			array( 'token_hash' => $record->token_hash ),
			array( '%s' ),
			array( '%s' )
		);

		return new PendingRecord( $record->token_hash, $record->kind, $record->user_id, $payload, $record->attempts, $record->expires_at );
	}

	/**
	 * Atomically consumes the record. Exactly one caller ever gets true.
	 *
	 * @param PendingRecord $record Record.
	 */
	public static function claim( PendingRecord $record ): bool {
		global $wpdb;

		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE token_hash = %s AND expires_at > %d',
				self::table(),
				$record->token_hash,
				Clock::now()
			)
		);

		return 1 === $deleted;
	}

	/**
	 * Deletes a record (burned or abandoned).
	 *
	 * @param PendingRecord $record Record.
	 */
	public static function delete( PendingRecord $record ): void {
		global $wpdb;

		$wpdb->delete( self::table(), array( 'token_hash' => $record->token_hash ), array( '%s' ) );
	}

	/**
	 * Deletes every record for a user (account deleted, factors reset).
	 *
	 * @param int $user_id User ID.
	 */
	public static function delete_for_user( int $user_id ): void {
		global $wpdb;

		$wpdb->delete( self::table(), array( 'user_id' => $user_id ), array( '%d' ) );
	}

	/**
	 * Deletes expired records.
	 *
	 * @return int Rows deleted.
	 */
	public static function purge_expired(): int {
		global $wpdb;

		$deleted = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE expires_at <= %d', self::table(), Clock::now() ) );

		return is_int( $deleted ) ? $deleted : 0;
	}

	/**
	 * Hex sha256 of a raw token.
	 *
	 * @param string $token Raw token.
	 */
	public static function hash( string $token ): string {
		return hash( 'sha256', $token );
	}

	/**
	 * Table name for the current site.
	 */
	private static function table(): string {
		global $wpdb;

		return Schema::site_tables( $wpdb )['pending'];
	}
}
