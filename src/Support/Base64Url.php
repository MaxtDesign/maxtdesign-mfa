<?php
/**
 * URL-safe base64 without padding, via libsodium's constant-time codec.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Base64url codec.
 */
final class Base64Url {

	/**
	 * Encodes binary data.
	 *
	 * @param string $data Binary data.
	 */
	public static function encode( string $data ): string {
		return sodium_bin2base64( $data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
	}

	/**
	 * Decodes, returning null for anything that is not canonical base64url.
	 *
	 * @param string $text Encoded text.
	 */
	public static function decode( string $text ): ?string {
		try {
			return sodium_base642bin( $text, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
		} catch ( \SodiumException $e ) {
			return null;
		}
	}

	/**
	 * A random token of $bytes bytes, encoded.
	 *
	 * @param int $bytes Entropy in bytes.
	 */
	public static function random( int $bytes = 32 ): string {
		return self::encode( random_bytes( max( 1, $bytes ) ) );
	}
}
