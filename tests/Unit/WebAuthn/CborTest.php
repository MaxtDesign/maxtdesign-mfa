<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\WebAuthn;

use MaxtDesign\Mfa\WebAuthn\ByteString;
use MaxtDesign\Mfa\WebAuthn\Cbor;
use MaxtDesign\Mfa\WebAuthn\VerificationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CborTest extends TestCase {

	/**
	 * RFC 8949 appendix A vectors within the allowed subset.
	 *
	 * @return iterable<string, array{string, mixed}>
	 */
	public static function valid(): iterable {
		yield '0' => array( '00', 0 );
		yield '23' => array( '17', 23 );
		yield '24' => array( '1818', 24 );
		yield '100' => array( '1864', 100 );
		yield '1000' => array( '1903e8', 1000 );
		yield '1000000' => array( '1a000f4240', 1000000 );
		yield '1000000000000' => array( '1b000000e8d4a51000', 1000000000000 );
		yield '-1' => array( '20', -1 );
		yield '-10' => array( '29', -10 );
		yield '-100' => array( '3863', -100 );
		yield '-1000' => array( '3903e7', -1000 );
		yield 'false' => array( 'f4', false );
		yield 'true' => array( 'f5', true );
		yield 'null' => array( 'f6', null );
		yield 'empty text' => array( '60', '' );
		yield 'a' => array( '6161', 'a' );
		yield 'IETF' => array( '6449455446', 'IETF' );
		yield 'ü' => array( '62c3bc', 'ü' );
		yield 'empty list' => array( '80', array() );
		yield '[1,2,3]' => array( '83010203', array( 1, 2, 3 ) );
		yield '[1,[2,3],[4,5]]' => array( '8301820203820405', array( 1, array( 2, 3 ), array( 4, 5 ) ) );
		yield 'empty map' => array( 'a0', array() );
		yield '{1:2,3:4}' => array( 'a201020304', array( 1 => 2, 3 => 4 ) );
		yield '{"a":1,"b":[2,3]}' => array( 'a26161016162820203', array( 'a' => 1, 'b' => array( 2, 3 ) ) );
	}

	#[DataProvider( 'valid' )]
	public function test_valid_vectors( string $hex, mixed $expected ): void {
		self::assertSame( $expected, Cbor::decode( (string) hex2bin( $hex ) ) );
	}

	public function test_byte_strings_are_distinct_from_text(): void {
		$value = Cbor::decode( (string) hex2bin( '4401020304' ) );

		self::assertInstanceOf( ByteString::class, $value );
		self::assertSame( "\x01\x02\x03\x04", $value->bytes );
	}

	/**
	 * @return iterable<string, array{string}>
	 */
	public static function rejected(): iterable {
		yield 'empty' => array( '' );
		yield 'float16' => array( 'f93c00' );
		yield 'float64' => array( 'fb3ff199999999999a' );
		yield 'undefined' => array( 'f7' );
		yield 'simple 16' => array( 'f0' );
		yield 'tag 1' => array( 'c11a514b67b0' );
		yield 'bignum tag' => array( 'c249010000000000000000' );
		yield 'indefinite bytes' => array( '5f42010243030405ff' );
		yield 'indefinite text' => array( '7f657374726561646d696e67ff' );
		yield 'indefinite list' => array( '9fff' );
		yield 'indefinite map' => array( 'bf61610161629f0203ffff' );
		yield 'break' => array( 'ff' );
		yield 'reserved info 28' => array( '1c' );
		yield 'non-shortest 1-byte' => array( '1817' );
		yield 'non-shortest 2-byte' => array( '190017' );
		yield 'integer above PHP_INT_MAX' => array( '1bffffffffffffffff' );
		yield 'truncated argument' => array( '19' );
		yield 'truncated bytes' => array( '4401' );
		yield 'huge declared length' => array( '5a7fffffff' );
		yield 'huge declared list' => array( '9a7fffffff' );
		yield 'trailing byte' => array( '0000' );
		yield 'duplicate key' => array( 'a201020103' );
		yield 'duplicate text key' => array( 'a2616101616102' );
		yield 'numeric text key' => array( 'a1613101' );
		yield 'map key is list' => array( 'a18001' );
		yield 'invalid UTF-8' => array( '62c328' );
		yield 'truncated map' => array( 'a20102' );
	}

	#[DataProvider( 'rejected' )]
	public function test_rejected_inputs( string $hex ): void {
		$this->expectException( VerificationException::class );
		Cbor::decode( (string) hex2bin( $hex ) );
	}

	public function test_nesting_is_bounded(): void {
		$this->expectException( VerificationException::class );
		Cbor::decode( str_repeat( "\x81", Cbor::MAX_DEPTH + 2 ) . "\x00" );
	}

	public function test_nesting_at_the_limit_is_fine(): void {
		self::assertIsArray( Cbor::decode( str_repeat( "\x81", Cbor::MAX_DEPTH ) . "\x00" ) );
	}

	public function test_prefix_decode_returns_the_end_offset(): void {
		list( $value, $end ) = Cbor::decode_prefix( "\xFF\x83\x01\x02\x03\xAA", 1 );

		self::assertSame( array( 1, 2, 3 ), $value );
		self::assertSame( 5, $end );
	}
}
