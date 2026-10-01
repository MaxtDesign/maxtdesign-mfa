<?php
/**
 * Passkey storage in {base_prefix}mdmfa_credentials (plan 6.1) and the per-user WebAuthn
 * user handle (32 random bytes, never the user ID, plan 6.2).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\WebAuthn\RegisteredCredential;

defined( 'ABSPATH' ) || exit;

/**
 * Credential rows.
 *
 * @phpstan-type Row array{id: int, user_id: int, cred_id: string, public_key: string, alg: int, sign_count: int, transports: string[], be: bool, bs: bool, rp_id: string, name: string, created_at: string, last_used_at: string, flagged: bool}
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own credentials table; lookups are by primary or unique key and always fresh.
 */
final class PasskeyStore {

	public const HANDLE_META = 'mdmfa_user_handle';

	/** Per-user limit (plan 12). */
	public const MAX_PER_USER = 20;

	/**
	 * The user's WebAuthn handle, created on first use.
	 *
	 * @param int $user_id User ID.
	 * @return string Raw 32 bytes.
	 */
	public static function user_handle( int $user_id ): string {
		$stored = (string) get_user_meta( $user_id, self::HANDLE_META, true );
		$raw    = '' !== $stored ? Base64Url::decode( $stored ) : null;
		if ( null !== $raw && 32 === strlen( $raw ) ) {
			return $raw;
		}
		$raw = random_bytes( 32 );
		update_user_meta( $user_id, self::HANDLE_META, Base64Url::encode( $raw ) );

		return $raw;
	}

	/**
	 * Stores a verified credential.
	 *
	 * @param int                  $user_id    User ID.
	 * @param RegisteredCredential $credential Verified credential.
	 * @param string               $rp_id      RP ID it is bound to.
	 * @param string[]             $transports Transport hints from the browser.
	 * @param string               $name       Owner-facing label.
	 * @return bool False when the credential ID is already registered or the limit is reached.
	 */
	public static function add( int $user_id, RegisteredCredential $credential, string $rp_id, array $transports, string $name ): bool {
		global $wpdb;

		if ( self::count( $user_id ) >= self::MAX_PER_USER || null !== self::find( $credential->id ) ) {
			return false;
		}
		$inserted = $wpdb->insert(
			self::table(),
			array(
				'user_id'    => $user_id,
				'cred_hash'  => hash( 'sha256', $credential->id ),
				'cred_id'    => Base64Url::encode( $credential->id ),
				'public_key' => Base64Url::encode( $credential->public_key ),
				'alg'        => $credential->alg,
				'sign_count' => $credential->sign_count,
				'transports' => implode( ',', $transports ),
				'aaguid'     => self::uuid( $credential->aaguid ),
				'be'         => (int) $credential->be,
				'bs'         => (int) $credential->bs,
				'rp_id'      => $rp_id,
				'name'       => substr( $name, 0, 64 ),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%d', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%d', '%d', '%s', '%s', '%s' )
		);

		return 1 === $inserted;
	}

	/**
	 * A credential by raw ID, or null.
	 *
	 * @param string $raw_id Raw credential ID.
	 * @return Row|null
	 */
	public static function find( string $raw_id ): ?array {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE cred_hash = %s', self::table(), hash( 'sha256', $raw_id ) ),
			ARRAY_A
		);

		return is_array( $row ) ? self::shape( $row ) : null;
	}

	/**
	 * The user's credentials for an RP ID.
	 *
	 * @param int    $user_id User ID.
	 * @param string $rp_id   RP ID.
	 * @return Row[]
	 */
	public static function for_user( int $user_id, string $rp_id ): array {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM %i WHERE user_id = %d AND rp_id = %s ORDER BY id', self::table(), $user_id, $rp_id ),
			ARRAY_A
		);

		return array_map( array( self::class, 'shape' ), is_array( $rows ) ? $rows : array() );
	}

	/**
	 * Number of credentials a user holds (any RP ID).
	 *
	 * @param int $user_id User ID.
	 */
	public static function count( int $user_id ): int {
		global $wpdb;

		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE user_id = %d', self::table(), $user_id ) );
	}

	/**
	 * Records a successful use.
	 *
	 * @param int  $id         Row ID.
	 * @param int  $sign_count New counter.
	 * @param bool $bs         Current backup state.
	 * @param bool $flag       Whether to flag a counter anomaly.
	 */
	public static function used( int $id, int $sign_count, bool $bs, bool $flag ): void {
		global $wpdb;

		$data = array(
			'sign_count'   => $sign_count,
			'bs'           => (int) $bs,
			'last_used_at' => gmdate( 'Y-m-d H:i:s' ),
		);
		if ( $flag ) {
			$data['flagged'] = 1;
		}
		$wpdb->update( self::table(), $data, array( 'id' => $id ) );
	}

	/**
	 * Deletes one of the user's credentials.
	 *
	 * @param int $user_id User ID.
	 * @param int $id      Row ID.
	 */
	public static function delete( int $user_id, int $id ): bool {
		global $wpdb;

		return 1 === $wpdb->delete(
			self::table(),
			array(
				'id'      => $id,
				'user_id' => $user_id,
			),
			array( '%d', '%d' )
		);
	}

	/**
	 * Deletes all of a user's credentials.
	 *
	 * @param int $user_id User ID.
	 */
	public static function delete_all( int $user_id ): void {
		global $wpdb;

		$wpdb->delete( self::table(), array( 'user_id' => $user_id ), array( '%d' ) );
	}

	/**
	 * Descriptor data for options (raw IDs and transports).
	 *
	 * @param Row[] $rows Credentials.
	 * @return array<int, array{id: string, transports: string[]}>
	 */
	public static function descriptors( array $rows ): array {
		return array_map(
			static fn ( array $row ): array => array(
				'id'         => $row['cred_id'],
				'transports' => $row['transports'],
			),
			$rows
		);
	}

	/**
	 * Normalises a database row.
	 *
	 * @param array<string, mixed> $row Raw row.
	 * @return Row
	 */
	private static function shape( array $row ): array {
		return array(
			'id'           => (int) $row['id'],
			'user_id'      => (int) $row['user_id'],
			'cred_id'      => (string) Base64Url::decode( (string) $row['cred_id'] ),
			'public_key'   => (string) Base64Url::decode( (string) $row['public_key'] ),
			'alg'          => (int) $row['alg'],
			'sign_count'   => (int) $row['sign_count'],
			'transports'   => array_values( array_filter( explode( ',', (string) $row['transports'] ) ) ),
			'be'           => (bool) $row['be'],
			'bs'           => (bool) $row['bs'],
			'rp_id'        => (string) $row['rp_id'],
			'name'         => (string) $row['name'],
			'created_at'   => (string) $row['created_at'],
			'last_used_at' => (string) ( $row['last_used_at'] ?? '' ),
			'flagged'      => (bool) $row['flagged'],
		);
	}

	/**
	 * AAGUID bytes as a UUID string.
	 *
	 * @param string $bytes 16 bytes.
	 */
	private static function uuid( string $bytes ): string {
		if ( 16 !== strlen( $bytes ) ) {
			return '';
		}
		$hex = bin2hex( $bytes );

		return substr( $hex, 0, 8 ) . '-' . substr( $hex, 8, 4 ) . '-' . substr( $hex, 12, 4 ) . '-' . substr( $hex, 16, 4 ) . '-' . substr( $hex, 20 );
	}

	/**
	 * Credentials table.
	 */
	private static function table(): string {
		global $wpdb;

		return Schema::credentials_table( $wpdb );
	}
}
