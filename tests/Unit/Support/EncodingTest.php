<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Support;

use MaxtDesign\Mfa\Support\Base32;
use MaxtDesign\Mfa\Support\Base64Url;
use PHPUnit\Framework\TestCase;

final class EncodingTest extends TestCase {

	public function test_base32_rfc4648_vectors(): void {
		$vectors = array(
			''       => '',
			'f'      => 'MY',
			'fo'     => 'MZXQ',
			'foo'    => 'MZXW6',
			'foob'   => 'MZXW6YQ',
			'fooba'  => 'MZXW6YTB',
			'foobar' => 'MZXW6YTBOI',
		);
		foreach ( $vectors as $plain => $encoded ) {
			self::assertSame( $encoded, Base32::encode( (string) $plain ) );
			self::assertSame( (string) $plain, Base32::decode( $encoded ) );
		}
	}

	public function test_base32_decode_is_forgiving_about_case_spaces_and_padding(): void {
		self::assertSame( 'foobar', Base32::decode( 'mzxw 6ytb-oi======' ) );
	}

	public function test_base32_decode_rejects_other_characters(): void {
		self::assertNull( Base32::decode( 'MZXW1' ) );
		self::assertNull( Base32::decode( 'MZ!W6' ) );
	}

	public function test_base32_round_trips_random_bytes(): void {
		for ( $i = 0; $i < 50; $i++ ) {
			$bytes = random_bytes( random_int( 1, 40 ) );
			self::assertSame( $bytes, Base32::decode( Base32::encode( $bytes ) ) );
		}
	}

	public function test_base64url_round_trip_and_shape(): void {
		$token = Base64Url::random( 32 );

		self::assertMatchesRegularExpression( '/^[A-Za-z0-9_-]{43}$/', $token );
		self::assertSame( 32, strlen( (string) Base64Url::decode( $token ) ) );
		self::assertNull( Base64Url::decode( 'not base64url!' ) );
	}
}
