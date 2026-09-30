<?php
/**
 * The PublicKeyCredential the browser module posts (PublicKeyCredential.toJSON() shape,
 * base64url fields), decoded strictly before anything is verified (plan 10.1: at most
 * 16 KB, strict JSON).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

use MaxtDesign\Mfa\Support\Base64Url;

defined( 'ABSPATH' ) || exit;

/**
 * Decoded credential response.
 */
final class CredentialJson {

	public const MAX_BYTES = 16384;

	/**
	 * Constructor.
	 *
	 * @param string   $raw_id             Credential ID.
	 * @param string   $client_data_json   clientDataJSON.
	 * @param string   $attestation_object attestationObject (registration), else ''.
	 * @param string   $authenticator_data authenticatorData (assertion), else ''.
	 * @param string   $signature          Signature (assertion), else ''.
	 * @param string   $user_handle        userHandle (assertion, may be ''), raw.
	 * @param string[] $transports         Transports hint (registration).
	 */
	private function __construct(
		public readonly string $raw_id,
		public readonly string $client_data_json,
		public readonly string $attestation_object,
		public readonly string $authenticator_data,
		public readonly string $signature,
		public readonly string $user_handle,
		public readonly array $transports
	) {
	}

	/**
	 * Parses a registration response.
	 *
	 * @param string $json Posted JSON.
	 * @throws VerificationException When malformed.
	 */
	public static function registration( string $json ): self {
		$data       = self::envelope( $json );
		$response   = self::response( $data );
		$transports = array();
		if ( isset( $response['transports'] ) && is_array( $response['transports'] ) ) {
			foreach ( $response['transports'] as $transport ) {
				if ( is_string( $transport ) && 1 === preg_match( '/^[a-z-]{1,16}$/', $transport ) ) {
					$transports[] = $transport;
				}
			}
		}

		return new self(
			self::raw_id( $data ),
			self::field( $response, 'clientDataJSON', true ),
			self::field( $response, 'attestationObject', true ),
			'',
			'',
			'',
			array_slice( array_values( array_unique( $transports ) ), 0, 8 )
		);
	}

	/**
	 * Parses an assertion response.
	 *
	 * @param string $json Posted JSON.
	 * @throws VerificationException When malformed.
	 */
	public static function assertion( string $json ): self {
		$data     = self::envelope( $json );
		$response = self::response( $data );

		return new self(
			self::raw_id( $data ),
			self::field( $response, 'clientDataJSON', true ),
			'',
			self::field( $response, 'authenticatorData', true ),
			self::field( $response, 'signature', true ),
			self::field( $response, 'userHandle', false ),
			array()
		);
	}

	/**
	 * Decodes the posted JSON object.
	 *
	 * @param string $json Posted JSON.
	 * @return array<array-key, mixed>
	 * @throws VerificationException When malformed.
	 */
	private static function envelope( string $json ): array {
		if ( '' === $json || strlen( $json ) > self::MAX_BYTES ) {
			throw new VerificationException( 'credential: size' );
		}
		try {
			$data = json_decode( $json, true, 6, JSON_THROW_ON_ERROR );
		} catch ( \JsonException $e ) {
			throw new VerificationException( 'credential: not JSON' );
		}
		if ( ! is_array( $data ) || ( $data['type'] ?? '' ) !== 'public-key' ) {
			throw new VerificationException( 'credential: malformed' );
		}

		return $data;
	}

	/**
	 * The response object inside the credential.
	 *
	 * @param array<array-key, mixed> $data Whole object.
	 * @return array<array-key, mixed>
	 * @throws VerificationException When missing.
	 */
	private static function response( array $data ): array {
		if ( ! isset( $data['response'] ) || ! is_array( $data['response'] ) ) {
			throw new VerificationException( 'credential: malformed' );
		}

		return $data['response'];
	}

	/**
	 * The rawId, which must match id.
	 *
	 * @param array<array-key, mixed> $data Whole object.
	 * @throws VerificationException When missing or inconsistent.
	 */
	private static function raw_id( array $data ): string {
		$id  = isset( $data['id'] ) && is_string( $data['id'] ) ? $data['id'] : '';
		$raw = isset( $data['rawId'] ) && is_string( $data['rawId'] ) ? $data['rawId'] : $id;
		if ( '' === $id || $id !== $raw ) {
			throw new VerificationException( 'credential: id mismatch' );
		}
		$bytes = Base64Url::decode( $id );
		if ( null === $bytes || '' === $bytes || strlen( $bytes ) > AuthenticatorData::MAX_CREDENTIAL_ID ) {
			throw new VerificationException( 'credential: bad id' );
		}

		return $bytes;
	}

	/**
	 * A base64url response field.
	 *
	 * @param array<array-key, mixed> $response Response object.
	 * @param string                  $key      Field.
	 * @param bool                    $required Whether it must be present and non-empty.
	 * @throws VerificationException When invalid.
	 */
	private static function field( array $response, string $key, bool $required ): string {
		if ( ! isset( $response[ $key ] ) || '' === $response[ $key ] ) {
			if ( $required ) {
				throw new VerificationException( 'credential: missing field' );
			}
			return '';
		}
		$bytes = is_string( $response[ $key ] ) ? Base64Url::decode( $response[ $key ] ) : null;
		if ( null === $bytes ) {
			throw new VerificationException( 'credential: bad field' );
		}

		return $bytes;
	}
}
