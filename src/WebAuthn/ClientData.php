<?php
/**
 * Checks on clientDataJSON (WebAuthn L3 sections 7.1 steps 7-10, 7.2 steps 11-14): type,
 * challenge (constant time), origin (exact scheme + host + port against an allow-list
 * built from the site's configured URLs, never from request headers), and crossOrigin
 * true rejected. tokenBinding is ignored (removed from the spec).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

use MaxtDesign\Mfa\Support\Base64Url;

defined( 'ABSPATH' ) || exit;

/**
 * Verified client data.
 */
final class ClientData {

	public const MAX_BYTES = 8192;

	/**
	 * Verifies and returns SHA-256 of the raw JSON (the value the authenticator signed).
	 *
	 * @param string   $json      clientDataJSON bytes.
	 * @param string   $type      webauthn.create or webauthn.get.
	 * @param string   $challenge Expected raw challenge bytes.
	 * @param string[] $origins   Allowed origins, e.g. https://example.com:8443.
	 * @throws VerificationException On any mismatch.
	 */
	public static function verify( string $json, string $type, string $challenge, array $origins ): string {
		if ( '' === $json || strlen( $json ) > self::MAX_BYTES ) {
			throw new VerificationException( 'clientData: size' );
		}
		try {
			$data = json_decode( $json, true, 8, JSON_THROW_ON_ERROR );
		} catch ( \JsonException $e ) {
			throw new VerificationException( 'clientData: not JSON' );
		}
		if ( ! is_array( $data ) || array_is_list( $data ) ) {
			throw new VerificationException( 'clientData: not an object' );
		}
		if ( ! isset( $data['type'] ) || $type !== $data['type'] ) {
			throw new VerificationException( 'clientData: wrong type' );
		}
		$given = isset( $data['challenge'] ) && is_string( $data['challenge'] ) ? Base64Url::decode( $data['challenge'] ) : null;
		if ( null === $given || '' === $challenge || ! hash_equals( $challenge, $given ) ) {
			throw new VerificationException( 'clientData: challenge mismatch' );
		}
		if ( ! isset( $data['origin'] ) || ! is_string( $data['origin'] ) || ! in_array( $data['origin'], $origins, true ) ) {
			throw new VerificationException( 'clientData: origin not allowed' );
		}
		if ( isset( $data['crossOrigin'] ) && true === $data['crossOrigin'] ) {
			throw new VerificationException( 'clientData: cross-origin' );
		}

		return hash( 'sha256', $json, true );
	}
}
