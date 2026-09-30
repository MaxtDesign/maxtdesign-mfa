<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Factors;

use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Support\Base32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase {

	/** RFC 6238 appendix B seed for HMAC-SHA1. */
	private const RFC_SECRET = '12345678901234567890';

	/**
	 * RFC 6238 appendix B, SHA1 column (8 digits).
	 *
	 * @return iterable<string, array{int, string}>
	 */
	public static function rfc6238_vectors(): iterable {
		yield 'T=59' => array( 59, '94287082' );
		yield 'T=1111111109' => array( 1111111109, '07081804' );
		yield 'T=1111111111' => array( 1111111111, '14050471' );
		yield 'T=1234567890' => array( 1234567890, '89005924' );
		yield 'T=2000000000' => array( 2000000000, '69279037' );
		yield 'T=20000000000' => array( 20000000000, '65353130' );
	}

	#[DataProvider( 'rfc6238_vectors' )]
	public function test_rfc6238_sha1_vectors( int $time, string $expected ): void {
		self::assertSame( $expected, Totp::code( self::RFC_SECRET, Totp::step( $time ), 8 ) );
		self::assertSame( substr( $expected, -6 ), Totp::code( self::RFC_SECRET, Totp::step( $time ) ) );
	}

	/**
	 * RFC 4226 appendix D HOTP values for counters 0-9.
	 */
	public function test_rfc4226_hotp_vectors(): void {
		$expected = array( '755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489' );
		foreach ( $expected as $counter => $code ) {
			self::assertSame( $code, Totp::code( self::RFC_SECRET, $counter ), "counter {$counter}" );
		}
	}

	public function test_match_accepts_one_step_either_side_and_returns_the_step(): void {
		$time = 1111111111;
		$now  = Totp::step( $time );

		self::assertSame( $now, Totp::match( self::RFC_SECRET, Totp::code( self::RFC_SECRET, $now ), $time ) );
		self::assertSame( $now - 1, Totp::match( self::RFC_SECRET, Totp::code( self::RFC_SECRET, $now - 1 ), $time ) );
		self::assertSame( $now + 1, Totp::match( self::RFC_SECRET, Totp::code( self::RFC_SECRET, $now + 1 ), $time ) );
		self::assertNull( Totp::match( self::RFC_SECRET, Totp::code( self::RFC_SECRET, $now - 2 ), $time ) );
		self::assertNull( Totp::match( self::RFC_SECRET, Totp::code( self::RFC_SECRET, $now + 2 ), $time ) );
	}

	public function test_match_rejects_malformed_input(): void {
		foreach ( array( '', '12345', '1234567', 'abcdef', '12 34 56', '050471 ' ) as $bad ) {
			self::assertNull( Totp::match( self::RFC_SECRET, $bad, 1111111111 ), var_export( $bad, true ) );
		}
	}

	public function test_normalize_strips_spaces_and_hyphens(): void {
		self::assertSame( '050471', Totp::normalize( ' 050 471 ' ) );
		self::assertSame( '050471', Totp::normalize( '050-471' ) );
	}

	public function test_secret_is_160_bits_and_random(): void {
		$a = Totp::generate_secret();

		self::assertSame( 20, strlen( $a ) );
		self::assertNotSame( $a, Totp::generate_secret() );
	}

	public function test_uri_follows_the_key_uri_format(): void {
		$uri = Totp::uri( self::RFC_SECRET, 'My: Shop', 'jane@example.com' );

		self::assertStringStartsWith( 'otpauth://totp/My%20Shop:jane%40example.com?', $uri );
		self::assertStringContainsString( 'secret=' . Base32::encode( self::RFC_SECRET ), $uri );
		self::assertStringContainsString( 'issuer=My%20Shop', $uri );
		self::assertStringContainsString( 'algorithm=SHA1&digits=6&period=30', $uri );
	}
}
