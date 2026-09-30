<?php
/**
 * One row of mdmfa_pending, read-only.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * A password-verified login waiting for its second factor (plan 4.5).
 */
final class PendingRecord {

	/**
	 * Constructor.
	 *
	 * @param string               $token_hash sha256 of the cookie token (hex).
	 * @param string               $kind       Record kind.
	 * @param int                  $user_id    User ID.
	 * @param array<string, mixed> $payload    Decoded payload.
	 * @param int                  $attempts   Factor attempts used.
	 * @param int                  $expires_at Unix expiry.
	 */
	public function __construct(
		public readonly string $token_hash,
		public readonly string $kind,
		public readonly int $user_id,
		public readonly array $payload,
		public readonly int $attempts,
		public readonly int $expires_at
	) {
	}

	/**
	 * String payload field.
	 *
	 * @param string $key Field.
	 */
	public function string( string $key ): string {
		return isset( $this->payload[ $key ] ) && is_string( $this->payload[ $key ] ) ? $this->payload[ $key ] : '';
	}

	/**
	 * Boolean payload field.
	 *
	 * @param string $key Field.
	 */
	public function flag( string $key ): bool {
		return ! empty( $this->payload[ $key ] );
	}

	/**
	 * Login context the record was created in.
	 */
	public function context(): string {
		return $this->string( 'context' );
	}

	/**
	 * Same record with extra payload fields (not persisted; see PendingStore::update_payload()).
	 *
	 * @param array<string, mixed> $fields Fields to merge.
	 */
	public function with( array $fields ): self {
		return new self( $this->token_hash, $this->kind, $this->user_id, array_merge( $this->payload, $fields ), $this->attempts, $this->expires_at );
	}
}
