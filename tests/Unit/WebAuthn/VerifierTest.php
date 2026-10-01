<?php
/**
 * Full ceremonies against real keys, and every rejection the plan lists (section 12).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\WebAuthn;

use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Tests\Support\CborEncoder;
use MaxtDesign\Mfa\Tests\Support\CborMap;
use MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator;
use MaxtDesign\Mfa\WebAuthn\ByteString;
use MaxtDesign\Mfa\WebAuthn\CoseKey;
use MaxtDesign\Mfa\WebAuthn\CredentialJson;
use MaxtDesign\Mfa\WebAuthn\VerificationException;
use MaxtDesign\Mfa\WebAuthn\Verifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class VerifierTest extends TestCase {

	private const RP     = 'shop.example';
	private const ORIGIN = 'https://shop.example';

	private static function creation( string $challenge ): array {
		return array(
			'rp'        => array( 'id' => self::RP, 'name' => 'Shop' ),
			'user'      => array( 'id' => Base64Url::encode( random_bytes( 32 ) ), 'name' => 'jane', 'displayName' => 'Jane' ),
			'challenge' => Base64Url::encode( $challenge ),
		);
	}

	private static function request( string $challenge ): array {
		return array( 'rpId' => self::RP, 'challenge' => Base64Url::encode( $challenge ) );
	}

	private static function register( VirtualAuthenticator $a, array $knobs = array(), bool $require_uv = false, ?string $expected_challenge = null ) {
		$challenge = random_bytes( 32 );
		$json      = CredentialJson::registration( $a->create( self::creation( $challenge ), self::ORIGIN, $knobs ) );
		return Verifier::register( $json->client_data_json, $json->attestation_object, $expected_challenge ?? $challenge, self::RP, array( self::ORIGIN ), $require_uv );
	}

	private static function assertion( VirtualAuthenticator $a, int $stored_count = 0, array $knobs = array(), bool $require_uv = false, ?string $expected_challenge = null ) {
		$challenge = random_bytes( 32 );
		$json      = CredentialJson::assertion( $a->get( self::request( $challenge ), self::ORIGIN, $knobs ) );
		return Verifier::assert( $a->cose(), $stored_count, $json->client_data_json, $json->authenticator_data, $json->signature, $expected_challenge ?? $challenge, self::RP, array( self::ORIGIN ), $require_uv );
	}

	/**
	 * @return iterable<string, array{int}>
	 */
	public static function algorithms(): iterable {
		yield 'ES256' => array( CoseKey::ES256 );
		yield 'RS256' => array( CoseKey::RS256 );
		yield 'EdDSA' => array( CoseKey::EDDSA );
	}

	#[DataProvider( 'algorithms' )]
	public function test_registration_and_assertion_round_trip( int $alg ): void {
		$a   = new VirtualAuthenticator( $alg );
		$reg = self::register( $a, array(), true );

		self::assertSame( $a->credential_id, $reg->id );
		self::assertSame( $a->cose(), $reg->public_key );
		self::assertSame( $alg, $reg->alg );
		self::assertTrue( $reg->be );
		self::assertTrue( $reg->bs );
		self::assertTrue( $reg->uv );

		$result = self::assertion( $a, 0, array(), true );
		self::assertFalse( $result->anomaly, 'both counters zero: skipped' );
		self::assertTrue( $result->uv );
	}

	public function test_counting_authenticator_and_regression(): void {
		$a         = new VirtualAuthenticator();
		$a->counts = true;

		self::assertFalse( self::assertion( $a, 0 )->anomaly, '1 > 0' );
		self::assertFalse( self::assertion( $a, 1 )->anomaly, '2 > 1' );
		self::assertTrue( self::assertion( $a, 7 )->anomaly, '3 <= 7: possible clone' );
		self::assertTrue( self::assertion( $a, 0, array( 'counter' => 0 ) + array() )->anomaly === false );
		self::assertTrue( self::assertion( $a, 5, array( 'counter' => 5 ) )->anomaly, 'equal counters are a regression' );
	}

	public function test_user_verification_is_enforced_only_when_policy_requires_it(): void {
		$a = new VirtualAuthenticator();

		self::assertFalse( self::assertion( $a, 0, array( 'uv' => false ), false )->uv, 'preferred: accepted without UV' );
		$this->expectException( VerificationException::class );
		self::assertion( $a, 0, array( 'uv' => false ), true );
	}

	/**
	 * @return iterable<string, array{array<string, mixed>}>
	 */
	public static function bad_registrations(): iterable {
		yield 'wrong type' => array( array( 'type' => 'webauthn.get' ) );
		yield 'wrong origin' => array( array( 'origin' => 'https://evil.example' ) );
		yield 'origin suffix trick' => array( array( 'origin' => 'https://evilshop.example' ) );
		yield 'origin subdomain' => array( array( 'origin' => 'https://a.shop.example' ) );
		yield 'origin port' => array( array( 'origin' => 'https://shop.example:8443' ) );
		yield 'origin scheme' => array( array( 'origin' => 'http://shop.example' ) );
		yield 'cross origin' => array( array( 'cross_origin' => true ) );
		yield 'wrong challenge' => array( array( 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ) );
		yield 'client data not JSON' => array( array( 'client_json' => 'nope' ) );
		yield 'client data is a list' => array( array( 'client_json' => '[1,2]' ) );
		yield 'wrong rp id' => array( array( 'rp_id' => 'evil.example' ) );
		yield 'user not present' => array( array( 'flags' => 0x44 ) );
		yield 'BS without BE' => array( array( 'flags' => 0x55 ) );
		yield 'no attested data' => array( array( 'flags' => 0x05 ) );
		yield 'authData trailing bytes' => array( array( 'auth_trailing' => "\x00" ) );
		yield 'attestationObject trailing bytes' => array( array( 'att_trailing' => "\x00" ) );
		yield 'unsupported alg' => array( array( 'cose' => CborEncoder::encode( new CborMap( array( array( 1, 2 ), array( 3, -35 ), array( -1, 2 ), array( -2, new ByteString( str_repeat( 'a', 48 ) ) ), array( -3, new ByteString( str_repeat( 'a', 48 ) ) ) ) ) ) ) );
		yield 'EC point off the curve' => array( array( 'cose' => CborEncoder::encode( new CborMap( array( array( 1, 2 ), array( 3, -7 ), array( -1, 1 ), array( -2, new ByteString( str_repeat( "\x01", 32 ) ) ), array( -3, new ByteString( str_repeat( "\x02", 32 ) ) ) ) ) ) ) );
		yield 'EC2 with wrong curve' => array( array( 'cose' => CborEncoder::encode( new CborMap( array( array( 1, 2 ), array( 3, -7 ), array( -1, 2 ), array( -2, new ByteString( str_repeat( "\x01", 32 ) ) ), array( -3, new ByteString( str_repeat( "\x02", 32 ) ) ) ) ) ) ) );
		yield 'short RSA key' => array( array( 'cose' => CborEncoder::encode( new CborMap( array( array( 1, 3 ), array( 3, -257 ), array( -1, new ByteString( str_repeat( "\xff", 128 ) ) ), array( -2, new ByteString( "\x01\x00\x01" ) ) ) ) ) ) );
		yield 'OKP with wrong curve' => array( array( 'cose' => CborEncoder::encode( new CborMap( array( array( 1, 1 ), array( 3, -8 ), array( -1, 4 ), array( -2, new ByteString( str_repeat( "\x01", 32 ) ) ) ) ) ) ) );
	}

	/**
	 * @param array<string, mixed> $knobs Overrides.
	 */
	#[DataProvider( 'bad_registrations' )]
	public function test_bad_registrations_are_rejected( array $knobs ): void {
		$this->expectException( VerificationException::class );
		self::register( new VirtualAuthenticator(), $knobs );
	}

	/**
	 * @return iterable<string, array{array<string, mixed>}>
	 */
	public static function bad_assertions(): iterable {
		yield 'wrong type' => array( array( 'type' => 'webauthn.create' ) );
		yield 'wrong origin' => array( array( 'origin' => 'https://evil.example' ) );
		yield 'cross origin' => array( array( 'cross_origin' => true ) );
		yield 'wrong challenge' => array( array( 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ) );
		yield 'wrong rp id' => array( array( 'rp_id' => 'evil.example' ) );
		yield 'user not present' => array( array( 'flags' => 0x04 ) );
		yield 'BS without BE' => array( array( 'flags' => 0x15 ) );
		yield 'attested data in an assertion' => array( array( 'flags' => 0x45 ) );
		yield 'trailing bytes' => array( array( 'auth_trailing' => "\x00" ) );
		yield 'tampered signature' => array( array( 'tamper_signature' => true ) );
	}

	/**
	 * @param array<string, mixed> $knobs Overrides.
	 */
	#[DataProvider( 'bad_assertions' )]
	public function test_bad_assertions_are_rejected( array $knobs ): void {
		$this->expectException( VerificationException::class );
		self::assertion( new VirtualAuthenticator(), 0, $knobs );
	}

	#[DataProvider( 'algorithms' )]
	public function test_signature_from_another_key_is_rejected( int $alg ): void {
		$real  = new VirtualAuthenticator( $alg );
		$other = new VirtualAuthenticator( $alg );
		$ch    = random_bytes( 32 );
		$json  = CredentialJson::assertion( $other->get( self::request( $ch ), self::ORIGIN ) );

		$this->expectException( VerificationException::class );
		Verifier::assert( $real->cose(), 0, $json->client_data_json, $json->authenticator_data, $json->signature, $ch, self::RP, array( self::ORIGIN ), false );
	}

	public function test_credential_json_rejects_malformed_envelopes(): void {
		foreach ( array( '', 'x', '[]', '{"type":"public-key"}', '{"type":"other","id":"AA","response":{}}', str_repeat( ' ', 20000 ) ) as $bad ) {
			try {
				CredentialJson::assertion( $bad );
				self::fail( 'accepted: ' . substr( $bad, 0, 40 ) );
			} catch ( VerificationException $e ) {
				self::assertNotSame( '', $e->getMessage() );
			}
		}
		$a    = new VirtualAuthenticator();
		$json = json_decode( $a->get( self::request( random_bytes( 32 ) ), self::ORIGIN ), true );
		$json['rawId'] = Base64Url::encode( random_bytes( 32 ) );
		$this->expectException( VerificationException::class );
		CredentialJson::assertion( (string) json_encode( $json ) );
	}
}
