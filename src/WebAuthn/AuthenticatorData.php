<?php
/**
 * The authenticatorData structure (WebAuthn L3 section 6.1): rpIdHash, flags, signCount, and when AT is
 * set the attested credential data (AAGUID, credential ID up to 1023 bytes, COSE key);
 * extensions when ED is set; nothing may follow.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Parsed authenticator data.
 */
final class AuthenticatorData {

	public const FLAG_UP = 0x01;
	public const FLAG_UV = 0x04;
	public const FLAG_BE = 0x08;
	public const FLAG_BS = 0x10;
	public const FLAG_AT = 0x40;
	public const FLAG_ED = 0x80;

	public const MAX_CREDENTIAL_ID = 1023;

	/**
	 * Constructor.
	 *
	 * @param string       $raw           The bytes (signed over in assertions).
	 * @param string       $rp_id_hash    SHA-256 of the RP ID.
	 * @param int          $flags         Flags byte.
	 * @param int          $sign_count    Unsigned 32-bit counter.
	 * @param string       $aaguid        AAGUID (16 bytes) when AT is set, else ''.
	 * @param string       $credential_id Credential ID when AT is set, else ''.
	 * @param string       $public_key    COSE key bytes when AT is set, else ''.
	 * @param CoseKey|null $key          Parsed COSE key when AT is set.
	 */
	private function __construct(
		public readonly string $raw,
		public readonly string $rp_id_hash,
		public readonly int $flags,
		public readonly int $sign_count,
		public readonly string $aaguid,
		public readonly string $credential_id,
		public readonly string $public_key,
		public readonly ?CoseKey $key
	) {
	}

	/**
	 * Parses and structurally validates the bytes.
	 *
	 * @param string $raw Authenticator data.
	 * @throws VerificationException When malformed.
	 */
	public static function parse( string $raw ): self {
		$length = strlen( $raw );
		if ( $length < 37 ) {
			throw new VerificationException( 'authData: too short' );
		}
		$rp_id_hash = substr( $raw, 0, 32 );
		$flags      = ord( $raw[32] );
		$sign_count = Cbor::uint( 'N', substr( $raw, 33, 4 ) );
		$offset     = 37;

		if ( ( $flags & self::FLAG_BS ) && ! ( $flags & self::FLAG_BE ) ) {
			throw new VerificationException( 'authData: backed up but not backup-eligible' );
		}

		$aaguid        = '';
		$credential_id = '';
		$public_key    = '';
		$key           = null;
		if ( $flags & self::FLAG_AT ) {
			if ( $length < $offset + 18 ) {
				throw new VerificationException( 'authData: attested data truncated' );
			}
			$aaguid    = substr( $raw, $offset, 16 );
			$id_length = Cbor::uint( 'n', substr( $raw, $offset + 16, 2 ) );
			$offset   += 18;
			if ( 0 === $id_length || $id_length > self::MAX_CREDENTIAL_ID || $length < $offset + $id_length ) {
				throw new VerificationException( 'authData: bad credential ID length' );
			}
			$credential_id       = substr( $raw, $offset, $id_length );
			$offset             += $id_length;
			list( $map, $after ) = Cbor::decode_prefix( $raw, $offset );
			$key                 = CoseKey::from_map( $map );
			$public_key          = substr( $raw, $offset, $after - $offset );
			$offset              = $after;
		}
		if ( $flags & self::FLAG_ED ) {
			list( $extensions, $offset ) = Cbor::decode_prefix( $raw, $offset );
			if ( ! is_array( $extensions ) ) {
				throw new VerificationException( 'authData: extensions must be a map' );
			}
		}
		if ( $offset !== $length ) {
			throw new VerificationException( 'authData: trailing bytes' );
		}

		return new self( $raw, $rp_id_hash, $flags, $sign_count, $aaguid, $credential_id, $public_key, $key );
	}

	/**
	 * Whether a flag is set.
	 *
	 * @param int $flag FLAG_* constant.
	 */
	public function has( int $flag ): bool {
		return 0 !== ( $this->flags & $flag );
	}
}
