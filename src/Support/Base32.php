<?php
/**
 * RFC 4648 base32 without padding, the encoding authenticator apps expect for TOTP secrets.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Base32 codec.
 */
final class Base32 {

	public const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encodes binary data.
	 *
	 * @param string $data Binary data.
	 */
	public static function encode( string $data ): string {
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$length = strlen( $data );
		for ( $i = 0; $i < $length; $i++ ) {
			$buffer = ( ( $buffer << 8 ) | ord( $data[ $i ] ) ) & 0xFFFF;
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::ALPHABET[ ( $buffer >> $bits ) & 31 ];
			}
		}
		if ( $bits > 0 ) {
			$out .= self::ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}

		return $out;
	}

	/**
	 * Decodes base32. Case, spaces, hyphens and padding are ignored.
	 *
	 * @param string $text Base32 text.
	 * @return string|null Binary data, or null when the text holds other characters.
	 */
	public static function decode( string $text ): ?string {
		$text = strtoupper( (string) preg_replace( '/[\s=-]/', '', $text ) );
		if ( '' === $text ) {
			return '';
		}
		if ( 1 !== preg_match( '/^[A-Z2-7]+$/', $text ) ) {
			return null;
		}
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$length = strlen( $text );
		for ( $i = 0; $i < $length; $i++ ) {
			$buffer = ( ( $buffer << 5 ) | strpos( self::ALPHABET, $text[ $i ] ) ) & 0xFFFF;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $out;
	}
}
