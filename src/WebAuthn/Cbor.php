<?php
/**
 * Restricted CBOR decoder (RFC 8949) for WebAuthn structures only (plan 12): major types
 * 0-5 and the simple values false, true and null from type 7. Definite lengths only;
 * tags, floats, undefined, indefinite lengths, duplicate map keys, non-shortest length
 * encodings and nesting deeper than MAX_DEPTH are rejected. Every length is checked
 * against the bytes remaining before anything is read. Binary-safe: strlen/substr only,
 * never mb_*.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Decoder. Returns ints, strings (text), ByteString (bytes), bools, null, lists and maps
 * (PHP arrays with int or string keys).
 */
final class Cbor {

	public const MAX_DEPTH = 16;

	/** Largest byte or text string accepted (a COSE RSA-4096 key is ~550 bytes). */
	public const MAX_STRING = 65536;

	/** Largest number of items in one array or map. */
	public const MAX_ITEMS = 256;

	/**
	 * Input bytes.
	 *
	 * @var string
	 */
	private string $data;

	/**
	 * Read position.
	 *
	 * @var int
	 */
	private int $offset;

	/**
	 * Constructor.
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Start position.
	 */
	private function __construct( string $data, int $offset ) {
		$this->data   = $data;
		$this->offset = $offset;
	}

	/**
	 * Decodes one item that must span the whole input.
	 *
	 * @param string $data Bytes.
	 * @return mixed
	 * @throws VerificationException On malformed or disallowed input, or trailing bytes.
	 */
	public static function decode( string $data ): mixed {
		list( $value, $end ) = self::decode_prefix( $data, 0 );
		if ( strlen( $data ) !== $end ) {
			throw new VerificationException( 'CBOR: trailing bytes' );
		}

		return $value;
	}

	/**
	 * Decodes one item starting at $offset; returns it and the offset after it. Used where
	 * CBOR is embedded in a larger structure (the COSE key inside authenticatorData).
	 *
	 * @param string $data   Bytes.
	 * @param int    $offset Start position.
	 * @return array{0: mixed, 1: int}
	 * @throws VerificationException On malformed or disallowed input.
	 */
	public static function decode_prefix( string $data, int $offset ): array {
		if ( $offset < 0 || $offset >= strlen( $data ) ) {
			throw new VerificationException( 'CBOR: no data' );
		}
		$decoder = new self( $data, $offset );
		$value   = $decoder->item( 0 );

		return array( $value, $decoder->offset );
	}

	/**
	 * Reads one item.
	 *
	 * @param int $depth Nesting depth.
	 * @return mixed
	 * @throws VerificationException On malformed or disallowed input.
	 */
	private function item( int $depth ): mixed {
		if ( $depth > self::MAX_DEPTH ) {
			throw new VerificationException( 'CBOR: nesting too deep' );
		}
		$initial = ord( $this->take( 1 ) );
		$major   = $initial >> 5;
		$info    = $initial & 0x1F;

		if ( 7 === $major ) {
			switch ( $info ) {
				case 20:
					return false;
				case 21:
					return true;
				case 22:
					return null;
				default:
					throw new VerificationException( 'CBOR: simple value or float not allowed' );
			}
		}
		if ( 6 === $major ) {
			throw new VerificationException( 'CBOR: tags not allowed' );
		}

		$argument = $this->argument( $info );

		switch ( $major ) {
			case 0:
				return $argument;
			case 1:
				return -1 - $argument;
			case 2:
				return new ByteString( $this->take( $this->length( $argument ) ) );
			case 3:
				$text = $this->take( $this->length( $argument ) );
				if ( 1 !== preg_match( '//u', $text ) ) {
					throw new VerificationException( 'CBOR: invalid UTF-8 text' );
				}
				return $text;
			case 4:
				$items = array();
				for ( $i = 0, $count = $this->count( $argument ); $i < $count; $i++ ) {
					$items[] = $this->item( $depth + 1 );
				}
				return $items;
			default:
				$map = array();
				for ( $i = 0, $count = $this->count( $argument ); $i < $count; $i++ ) {
					$key = $this->item( $depth + 1 );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new VerificationException( 'CBOR: map keys must be integers or text' );
					}
					// PHP would turn the text key "1" into the integer key 1, letting text
					// impersonate a COSE label. No WebAuthn structure uses such keys.
					if ( is_string( $key ) && 1 === preg_match( '/^(0|-?[1-9][0-9]*)$/', $key ) ) {
						throw new VerificationException( 'CBOR: numeric text map key' );
					}
					if ( array_key_exists( $key, $map ) ) {
						throw new VerificationException( 'CBOR: duplicate map key' );
					}
					$map[ $key ] = $this->item( $depth + 1 );
				}
				return $map;
		}
	}

	/**
	 * Reads the argument that follows the initial byte, requiring the shortest encoding.
	 *
	 * @param int $info Additional information (low 5 bits).
	 * @throws VerificationException On reserved or indefinite encodings, or values past PHP_INT_MAX.
	 */
	private function argument( int $info ): int {
		if ( $info < 24 ) {
			return $info;
		}
		switch ( $info ) {
			case 24:
				$value = ord( $this->take( 1 ) );
				$min   = 24;
				break;
			case 25:
				$value = self::uint( 'n', $this->take( 2 ) );
				$min   = 0x100;
				break;
			case 26:
				$value = self::uint( 'N', $this->take( 4 ) );
				$min   = 0x10000;
				break;
			case 27:
				$bytes = $this->take( 8 );
				$high  = self::uint( 'N', substr( $bytes, 0, 4 ) );
				if ( $high >= 0x80000000 ) {
					throw new VerificationException( 'CBOR: integer too large' );
				}
				$value = ( $high << 32 ) | self::uint( 'N', substr( $bytes, 4, 4 ) );
				$min   = 0x100000000;
				break;
			default:
				throw new VerificationException( 'CBOR: indefinite or reserved length' );
		}
		if ( $value < $min ) {
			throw new VerificationException( 'CBOR: non-shortest encoding' );
		}

		return (int) $value;
	}

	/**
	 * A string length, bounded by MAX_STRING and the bytes left.
	 *
	 * @param int $length Declared length.
	 * @throws VerificationException When it cannot be satisfied.
	 */
	private function length( int $length ): int {
		if ( $length > self::MAX_STRING || $length > strlen( $this->data ) - $this->offset ) {
			throw new VerificationException( 'CBOR: string longer than the data' );
		}

		return $length;
	}

	/**
	 * An item count, bounded by MAX_ITEMS and (at one byte per item) the bytes left.
	 *
	 * @param int $count Declared count.
	 * @throws VerificationException When it cannot be satisfied.
	 */
	private function count( int $count ): int {
		if ( $count > self::MAX_ITEMS || $count > strlen( $this->data ) - $this->offset ) {
			throw new VerificationException( 'CBOR: too many items' );
		}

		return $count;
	}

	/**
	 * Big-endian unsigned integer from exactly the bytes a format needs ('n' = 2, 'N' = 4).
	 *
	 * @param string $format unpack() format, n or N.
	 * @param string $bytes  Bytes.
	 * @throws VerificationException When the bytes do not fit the format.
	 */
	public static function uint( string $format, string $bytes ): int {
		$values = strlen( $bytes ) === ( 'n' === $format ? 2 : 4 ) ? unpack( $format, $bytes ) : false;
		if ( ! is_array( $values ) || ! isset( $values[1] ) || ! is_int( $values[1] ) ) {
			throw new VerificationException( 'binary: bad integer' );
		}

		return $values[1];
	}

	/**
	 * Consumes $length bytes.
	 *
	 * @param int $length Bytes to read.
	 * @throws VerificationException When the data ends first.
	 */
	private function take( int $length ): string {
		if ( $length > strlen( $this->data ) - $this->offset ) {
			throw new VerificationException( 'CBOR: unexpected end of data' );
		}
		$bytes         = substr( $this->data, $this->offset, $length );
		$this->offset += $length;

		return $bytes;
	}
}
