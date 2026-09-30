<?php
/**
 * COSE public keys (RFC 9053) to something openssl or libsodium can verify with (plan 12):
 * EC2 P-256 / ES256, RSA / RS256, OKP Ed25519 / EdDSA. The DER for SubjectPublicKeyInfo
 * is built by hand; openssl then parses it, which also rejects EC points off the curve.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * A parsed, validated public key.
 */
final class CoseKey {

	public const ES256 = -7;
	public const RS256 = -257;
	public const EDDSA = -8;

	/** Algorithms in the order offered to authenticators (EdDSA last, plan 12). */
	public const SUPPORTED = array( self::ES256, self::RS256, self::EDDSA );

	private const KTY_OKP = 1;
	private const KTY_EC2 = 2;
	private const KTY_RSA = 3;

	/**
	 * Constructor.
	 *
	 * @param int    $alg      COSE algorithm.
	 * @param string $material PEM for ES256/RS256, raw 32 bytes for EdDSA.
	 */
	private function __construct(
		public readonly int $alg,
		public readonly string $material
	) {
	}

	/**
	 * Parses a decoded COSE_Key map.
	 *
	 * @param mixed $map Decoded CBOR.
	 * @throws VerificationException When the key is malformed or unsupported.
	 */
	public static function from_map( mixed $map ): self {
		if ( ! is_array( $map ) || ! isset( $map[1], $map[3] ) || ! is_int( $map[1] ) || ! is_int( $map[3] ) ) {
			throw new VerificationException( 'COSE: kty and alg required' );
		}
		$kty = $map[1];
		$alg = $map[3];

		if ( self::ES256 === $alg ) {
			$x = self::bytes( $map, -2, 32 );
			$y = self::bytes( $map, -3, 32 );
			if ( self::KTY_EC2 !== $kty || 1 !== ( $map[-1] ?? null ) ) {
				throw new VerificationException( 'COSE: ES256 needs EC2 on P-256' );
			}
			$spki = self::sequence(
				self::sequence( self::oid( '2a8648ce3d0201' ) . self::oid( '2a8648ce3d030107' ) )
				. self::bit_string( "\x04" . $x . $y )
			);
			return new self( $alg, self::pem( $spki ) );
		}

		if ( self::RS256 === $alg ) {
			$n = self::bytes( $map, -1, null );
			$e = self::bytes( $map, -2, null );
			if ( self::KTY_RSA !== $kty ) {
				throw new VerificationException( 'COSE: RS256 needs an RSA key' );
			}
			$bits = strlen( ltrim( $n, "\0" ) ) * 8;
			if ( $bits < 2048 || $bits > 8192 || '' === ltrim( $e, "\0" ) || strlen( $e ) > 8 ) {
				throw new VerificationException( 'COSE: RSA key size out of range' );
			}
			$spki = self::sequence(
				self::sequence( self::oid( '2a864886f70d010101' ) . "\x05\x00" )
				. self::bit_string( self::sequence( self::integer( $n ) . self::integer( $e ) ) )
			);
			return new self( $alg, self::pem( $spki ) );
		}

		if ( self::EDDSA === $alg ) {
			$x = self::bytes( $map, -2, 32 );
			if ( self::KTY_OKP !== $kty || 6 !== ( $map[-1] ?? null ) ) {
				throw new VerificationException( 'COSE: EdDSA needs OKP on Ed25519' );
			}
			return new self( $alg, $x );
		}

		throw new VerificationException( 'COSE: unsupported algorithm' );
	}

	/**
	 * Parses a stored COSE key (the CBOR bytes).
	 *
	 * @param string $cbor COSE_Key bytes.
	 * @throws VerificationException When malformed.
	 */
	public static function from_cbor( string $cbor ): self {
		return self::from_map( Cbor::decode( $cbor ) );
	}

	/**
	 * Verifies a signature. openssl_verify() returns -1 on error, so only === 1 passes.
	 *
	 * @param string $data      Signed bytes.
	 * @param string $signature Signature (DER for ES256).
	 */
	public function verify( string $data, string $signature ): bool {
		if ( self::EDDSA === $this->alg ) {
			$key = $this->material;
			if ( SODIUM_CRYPTO_SIGN_BYTES !== strlen( $signature ) || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $key ) ) {
				return false;
			}
			try {
				return sodium_crypto_sign_verify_detached( $signature, $data, $key );
			} catch ( \SodiumException $e ) {
				return false;
			}
		}
		if ( ! function_exists( 'openssl_verify' ) ) {
			return false;
		}
		$key = openssl_pkey_get_public( $this->material );
		if ( false === $key ) {
			return false;
		}

		return 1 === openssl_verify( $data, $signature, $key, OPENSSL_ALGO_SHA256 );
	}

	/**
	 * Whether openssl accepts the key (for ES256 this includes the on-curve check).
	 */
	public function loads(): bool {
		if ( self::EDDSA === $this->alg ) {
			return 32 === strlen( $this->material );
		}

		return function_exists( 'openssl_pkey_get_public' ) && false !== openssl_pkey_get_public( $this->material );
	}

	/**
	 * A byte-string field of the map.
	 *
	 * @param array<array-key, mixed> $map    COSE map.
	 * @param int                     $label  Field label.
	 * @param int|null                $length Exact length, or null for any non-empty.
	 * @throws VerificationException When missing or the wrong size.
	 */
	private static function bytes( array $map, int $label, ?int $length ): string {
		$value = $map[ $label ] ?? null;
		if ( ! $value instanceof ByteString || '' === $value->bytes || ( null !== $length && strlen( $value->bytes ) !== $length ) ) {
			throw new VerificationException( 'COSE: bad key parameter' );
		}

		return $value->bytes;
	}

	/**
	 * DER SEQUENCE.
	 *
	 * @param string $content Encoded members.
	 */
	private static function sequence( string $content ): string {
		return "\x30" . self::der_length( strlen( $content ) ) . $content;
	}

	/**
	 * DER OBJECT IDENTIFIER from its hex body.
	 *
	 * @param string $hex Encoded OID body in hex.
	 */
	private static function oid( string $hex ): string {
		$body = (string) hex2bin( $hex );

		return "\x06" . self::der_length( strlen( $body ) ) . $body;
	}

	/**
	 * DER BIT STRING with no unused bits.
	 *
	 * @param string $content Bytes.
	 */
	private static function bit_string( string $content ): string {
		return "\x03" . self::der_length( strlen( $content ) + 1 ) . "\x00" . $content;
	}

	/**
	 * DER INTEGER from unsigned big-endian bytes (minimal, positive).
	 *
	 * @param string $bytes Magnitude.
	 */
	private static function integer( string $bytes ): string {
		$bytes = ltrim( $bytes, "\0" );
		if ( '' === $bytes || ord( $bytes[0] ) > 0x7F ) {
			$bytes = "\0" . $bytes;
		}

		return "\x02" . self::der_length( strlen( $bytes ) ) . $bytes;
	}

	/**
	 * DER length octets.
	 *
	 * @param int $length Content length.
	 */
	private static function der_length( int $length ): string {
		if ( $length < 0x80 ) {
			return chr( $length );
		}
		$bytes = ltrim( pack( 'N', $length ), "\0" );

		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}

	/**
	 * PEM armour.
	 *
	 * @param string $der SubjectPublicKeyInfo.
	 */
	private static function pem( string $der ): string {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( sodium_bin2base64( $der, SODIUM_BASE64_VARIANT_ORIGINAL ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}
}
