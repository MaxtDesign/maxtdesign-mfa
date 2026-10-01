<?php
/**
 * The two WebAuthn ceremonies (plan 12; WebAuthn L3 sections 7.1 and 7.2), attestation
 * "none": the attestation statement is not verified (no authenticator provenance is
 * claimed), so any fmt is accepted and attStmt ignored. Steps the relying party must do
 * outside the verifier (challenge storage and single use, credential ownership and
 * userHandle binding, counter storage) are the caller's and are marked below.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Stateless verification.
 */
final class Verifier {

	/**
	 * Registration (7.1). Returns the new credential.
	 *
	 * @param string   $client_data_json   clientDataJSON bytes.
	 * @param string   $attestation_object attestationObject bytes.
	 * @param string   $challenge          Expected challenge (raw).
	 * @param string   $rp_id              Relying party ID.
	 * @param string[] $origins            Allowed origins.
	 * @param bool     $require_uv         Whether user verification is required (policy, never client input).
	 * @throws VerificationException On any failed step.
	 */
	public static function register( string $client_data_json, string $attestation_object, string $challenge, string $rp_id, array $origins, bool $require_uv ): RegisteredCredential {
		// 7.1 steps 5-11: clientData type, challenge, origin, crossOrigin; hash.
		ClientData::verify( $client_data_json, 'webauthn.create', $challenge, $origins );

		// Step 12: decode attestationObject; fmt, attStmt, authData.
		$object = Cbor::decode( $attestation_object );
		if ( ! is_array( $object ) || ! isset( $object['fmt'], $object['authData'] ) || ! is_string( $object['fmt'] )
			|| ! array_key_exists( 'attStmt', $object ) || ! is_array( $object['attStmt'] ) || ! $object['authData'] instanceof ByteString ) {
			throw new VerificationException( 'attestationObject: malformed' );
		}
		$data = AuthenticatorData::parse( $object['authData']->bytes );

		// Steps 13-16: rpIdHash, UP, UV (from policy), BE/BS consistency (checked in parse).
		self::check_rp_and_flags( $data, $rp_id, $require_uv );

		// Steps 17-18: attested credential data with a supported algorithm.
		if ( ! $data->has( AuthenticatorData::FLAG_AT ) || null === $data->key ) {
			throw new VerificationException( 'registration: no attested credential' );
		}
		if ( ! in_array( $data->key->alg, CoseKey::SUPPORTED, true ) || ! $data->key->loads() ) {
			throw new VerificationException( 'registration: key unusable' );
		}

		// Steps 19-24 (attestation statement verification and trust): "none" policy, skipped.
		// Steps 25-27 (credential ID not already registered, store): the caller's.
		return new RegisteredCredential(
			$data->credential_id,
			$data->public_key,
			$data->key->alg,
			$data->sign_count,
			$data->aaguid,
			$data->has( AuthenticatorData::FLAG_BE ),
			$data->has( AuthenticatorData::FLAG_BS ),
			$data->has( AuthenticatorData::FLAG_UV )
		);
	}

	/**
	 * Assertion (7.2). The caller has already resolved the credential from rawId and, for
	 * usernameless login, checked userHandle ownership (steps 5-6).
	 *
	 * @param string   $public_key         Stored COSE key bytes.
	 * @param int      $stored_count       Stored signature counter.
	 * @param string   $client_data_json   clientDataJSON bytes.
	 * @param string   $authenticator_data authenticatorData bytes.
	 * @param string   $signature          Signature bytes.
	 * @param string   $challenge          Expected challenge (raw).
	 * @param string   $rp_id              Relying party ID.
	 * @param string[] $origins            Allowed origins.
	 * @param bool     $require_uv         Whether user verification is required.
	 * @throws VerificationException On any failed step.
	 */
	public static function assert( string $public_key, int $stored_count, string $client_data_json, string $authenticator_data, string $signature, string $challenge, string $rp_id, array $origins, bool $require_uv ): AssertionResult {
		// Steps 8-15: clientData type, challenge, origin, crossOrigin.
		$client_hash = ClientData::verify( $client_data_json, 'webauthn.get', $challenge, $origins );

		// Steps 16-19: rpIdHash, UP, UV, BE/BS.
		$data = AuthenticatorData::parse( $authenticator_data );
		self::check_rp_and_flags( $data, $rp_id, $require_uv );
		if ( $data->has( AuthenticatorData::FLAG_AT ) ) {
			throw new VerificationException( 'assertion: unexpected attested data' );
		}

		// Steps 20-21: signature over authenticatorData || SHA-256(clientDataJSON).
		$key = CoseKey::from_cbor( $public_key );
		if ( '' === $signature || ! $key->verify( $authenticator_data . $client_hash, $signature ) ) {
			throw new VerificationException( 'assertion: bad signature' );
		}

		// Step 22: counter. Both zero means the authenticator does not count (synced
		// passkeys); otherwise a counter that did not grow suggests a clone (eval 5.3).
		$count   = $data->sign_count;
		$anomaly = ! ( 0 === $count && 0 === $stored_count ) && $count <= $stored_count;

		return new AssertionResult( $count, $anomaly, $data->has( AuthenticatorData::FLAG_UV ), $data->has( AuthenticatorData::FLAG_BS ) );
	}

	/**
	 * RP ID hash and flags shared by both ceremonies.
	 *
	 * @param AuthenticatorData $data       Parsed data.
	 * @param string            $rp_id      Relying party ID.
	 * @param bool              $require_uv Whether UV is required.
	 * @throws VerificationException On mismatch.
	 */
	private static function check_rp_and_flags( AuthenticatorData $data, string $rp_id, bool $require_uv ): void {
		if ( ! hash_equals( hash( 'sha256', $rp_id, true ), $data->rp_id_hash ) ) {
			throw new VerificationException( 'authData: rpIdHash mismatch' );
		}
		if ( ! $data->has( AuthenticatorData::FLAG_UP ) ) {
			throw new VerificationException( 'authData: user not present' );
		}
		if ( $require_uv && ! $data->has( AuthenticatorData::FLAG_UV ) ) {
			throw new VerificationException( 'authData: user not verified' );
		}
	}
}
