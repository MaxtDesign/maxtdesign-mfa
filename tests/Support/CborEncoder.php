<?php
/**
 * Minimal canonical CBOR encoder for tests (shortest-form lengths).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Support;

use MaxtDesign\Mfa\WebAuthn\ByteString;

// phpcs:ignoreFile

final class CborEncoder {

	public static function encode( mixed $value ): string {
		if ( is_int( $value ) ) {
			return $value >= 0 ? self::head( 0, $value ) : self::head( 1, -1 - $value );
		}
		if ( $value instanceof ByteString ) {
			return self::head( 2, strlen( $value->bytes ) ) . $value->bytes;
		}
		if ( is_string( $value ) ) {
			return self::head( 3, strlen( $value ) ) . $value;
		}
		if ( is_bool( $value ) ) {
			return $value ? "\xF5" : "\xF4";
		}
		if ( null === $value ) {
			return "\xF6";
		}
		if ( $value instanceof CborMap ) {
			$out = self::head( 5, count( $value->pairs ) );
			foreach ( $value->pairs as list( $k, $v ) ) {
				$out .= self::encode( $k ) . self::encode( $v );
			}
			return $out;
		}
		if ( is_array( $value ) && array_is_list( $value ) ) {
			$out = self::head( 4, count( $value ) );
			foreach ( $value as $item ) {
				$out .= self::encode( $item );
			}
			return $out;
		}
		if ( is_array( $value ) ) {
			$out = self::head( 5, count( $value ) );
			foreach ( $value as $k => $v ) {
				$out .= self::encode( $k ) . self::encode( $v );
			}
			return $out;
		}
		throw new \InvalidArgumentException( 'unsupported' );
	}

	public static function head( int $major, int $argument ): string {
		$m = $major << 5;
		if ( $argument < 24 ) {
			return chr( $m | $argument );
		}
		if ( $argument < 0x100 ) {
			return chr( $m | 24 ) . chr( $argument );
		}
		if ( $argument < 0x10000 ) {
			return chr( $m | 25 ) . pack( 'n', $argument );
		}
		if ( $argument < 0x100000000 ) {
			return chr( $m | 26 ) . pack( 'N', $argument );
		}
		return chr( $m | 27 ) . pack( 'J', $argument );
	}
}

