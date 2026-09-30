<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Crypto;

use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class KeyProviderTest extends TestCase {

	public function test_base64_key_of_32_bytes_is_accepted(): void {
		$keys = KeyProvider::from_base64( base64_encode( str_repeat( 'k', 32 ) ) );

		self::assertSame( KeyProvider::SOURCE_CONSTANT, $keys->source() );
		self::assertSame( str_repeat( 'k', 32 ), $keys->key() );
	}

	public function test_invalid_base64_throws(): void {
		$this->expectException( InvalidKeyException::class );
		KeyProvider::from_base64( '!!not base64!!' );
	}

	public function test_wrong_length_throws(): void {
		$this->expectException( InvalidKeyException::class );
		KeyProvider::from_base64( base64_encode( str_repeat( 'k', 31 ) ) );
	}

	public function test_derivation_is_deterministic_and_32_bytes(): void {
		$a = KeyProvider::derive( 'material', KeyProvider::SOURCE_SALTS );
		$b = KeyProvider::derive( 'material', KeyProvider::SOURCE_SALTS );

		self::assertSame( 32, strlen( $a->key() ) );
		self::assertSame( $a->key(), $b->key() );
		self::assertSame( hash_hkdf( 'sha256', 'material', 32, 'mdmfa-totp-v1' ), $a->key() );
		self::assertNotSame( $a->key(), KeyProvider::derive( 'other', KeyProvider::SOURCE_SALTS )->key() );
	}

	public function test_empty_material_throws(): void {
		$this->expectException( InvalidKeyException::class );
		KeyProvider::derive( '', KeyProvider::SOURCE_DB );
	}

	public function test_kid_is_first_8_bytes_of_sha256_in_hex(): void {
		$keys = KeyProvider::from_base64( base64_encode( str_repeat( 'k', 32 ) ) );

		self::assertSame( substr( hash( 'sha256', str_repeat( 'k', 32 ) ), 0, 16 ), $keys->kid() );
	}

	public function test_without_constants_falls_back_to_database_salts(): void {
		$keys = KeyProvider::from_environment();

		self::assertSame( KeyProvider::SOURCE_DB, $keys->source() );
		self::assertSame( hash_hkdf( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), 32, 'mdmfa-totp-v1' ), $keys->key() );
	}

	#[RunInSeparateProcess]
	public function test_salt_constants_are_preferred_over_database(): void {
		define( 'AUTH_KEY', 'auth-constant' );
		define( 'SECURE_AUTH_KEY', 'secure-constant' );

		$keys = KeyProvider::from_environment();

		self::assertSame( KeyProvider::SOURCE_SALTS, $keys->source() );
		self::assertSame( hash_hkdf( 'sha256', 'auth-constantsecure-constant', 32, 'mdmfa-totp-v1' ), $keys->key() );
	}

	#[RunInSeparateProcess]
	public function test_placeholder_salts_count_as_missing(): void {
		define( 'AUTH_KEY', 'put your unique phrase here' );
		define( 'SECURE_AUTH_KEY', 'secure-constant' );

		self::assertSame( KeyProvider::SOURCE_DB, KeyProvider::from_environment()->source() );
	}

	#[RunInSeparateProcess]
	public function test_encryption_key_constant_wins(): void {
		define( 'AUTH_KEY', 'auth-constant' );
		define( 'SECURE_AUTH_KEY', 'secure-constant' );
		define( 'MDMFA_ENCRYPTION_KEY', base64_encode( str_repeat( 'c', 32 ) ) );

		$keys = KeyProvider::from_environment();

		self::assertSame( KeyProvider::SOURCE_CONSTANT, $keys->source() );
		self::assertSame( str_repeat( 'c', 32 ), $keys->key() );
	}

	#[RunInSeparateProcess]
	public function test_malformed_encryption_key_constant_throws_instead_of_falling_back(): void {
		define( 'AUTH_KEY', 'auth-constant' );
		define( 'SECURE_AUTH_KEY', 'secure-constant' );
		define( 'MDMFA_ENCRYPTION_KEY', 'too-short' );

		$this->expectException( InvalidKeyException::class );
		KeyProvider::from_environment();
	}
}
