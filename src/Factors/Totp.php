<?php
/**
 * RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30-second steps), the parameters every
 * authenticator app supports.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Support\Base32;

defined( 'ABSPATH' ) || exit;

/**
 * Stateless TOTP maths. Replay protection lives in TotpStore.
 */
final class Totp {

	public const DIGITS       = 6;
	public const PERIOD       = 30;
	public const WINDOW       = 1;
	public const SECRET_BYTES = 20;

	/**
	 * A new random secret (160 bits, the RFC 4226 recommendation).
	 */
	public static function generate_secret(): string {
		return random_bytes( self::SECRET_BYTES );
	}

	/**
	 * Time step for a Unix time.
	 *
	 * @param int $time Unix time.
	 */
	public static function step( int $time ): int {
		return intdiv( $time, self::PERIOD );
	}

	/**
	 * RFC 4226 HOTP value for a counter, zero-padded.
	 *
	 * @param string $secret  Raw secret bytes.
	 * @param int    $counter Counter (the time step).
	 * @param int    $digits  Output length.
	 */
	public static function code( string $secret, int $counter, int $digits = self::DIGITS ): string {
		// Big-endian 64-bit counter without relying on pack('J') (32-bit PHP safe).
		$message = pack( 'N2', ( $counter >> 32 ) & 0xFFFFFFFF, $counter & 0xFFFFFFFF );
		$hash    = hash_hmac( 'sha1', $message, $secret, true );
		$offset  = ord( $hash[19] ) & 0x0F;
		$value   = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ord( $hash[ $offset + 1 ] ) << 16 )
			| ( ord( $hash[ $offset + 2 ] ) << 8 )
			| ord( $hash[ $offset + 3 ] );

		return str_pad( (string) ( $value % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Finds the step, within +/- WINDOW of now, whose code matches. Every candidate is
	 * compared with hash_equals so timing does not reveal which step matched.
	 *
	 * @param string $secret Raw secret bytes.
	 * @param string $code   Submitted code (digits only).
	 * @param int    $time   Unix time.
	 * @return int|null The matched step, or null.
	 */
	public static function match( string $secret, string $code, int $time ): ?int {
		if ( 1 !== preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) ) {
			return null;
		}
		$now     = self::step( $time );
		$matched = null;
		for ( $offset = -self::WINDOW; $offset <= self::WINDOW; $offset++ ) {
			if ( hash_equals( self::code( $secret, $now + $offset ), $code ) && null === $matched ) {
				$matched = $now + $offset;
			}
		}

		return $matched;
	}

	/**
	 * Strips spaces and hyphens a user may type between digit groups.
	 *
	 * @param string $input Raw input.
	 */
	public static function normalize( string $input ): string {
		return (string) preg_replace( '/[\s-]/', '', $input );
	}

	/**
	 * Key URI for authenticator apps (Google Authenticator key URI format).
	 *
	 * @param string $secret  Raw secret bytes.
	 * @param string $issuer  Site name shown in the app.
	 * @param string $account Account label shown in the app.
	 */
	public static function uri( string $secret, string $issuer, string $account ): string {
		$issuer = str_replace( ':', '', $issuer );
		$label  = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		return 'otpauth://totp/' . $label . '?' . http_build_query(
			array(
				'secret'    => Base32::encode( $secret ),
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}
}
