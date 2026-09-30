<?php
/**
 * Differential tests (plan 12, P5 DoD): the same ceremonies go to the in-house verifier and
 * to two require-dev oracles, web-auth/webauthn-lib and lbuchs/webauthn. Whenever ours
 * accepts, both must accept. Where an oracle accepts something ours rejects, the case must
 * be listed below with the reason ours is the stricter, spec-correct side; anything else
 * fails the test. The oracles never ship (vendor/ is in .distignore).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\WebAuthn;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Cose\Algorithm\Signature\RSA\RS256;
use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator;
use MaxtDesign\Mfa\WebAuthn\CoseKey;
use MaxtDesign\Mfa\WebAuthn\CredentialJson;
use MaxtDesign\Mfa\WebAuthn\VerificationException;
use MaxtDesign\Mfa\WebAuthn\Verifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

// phpcs:ignoreFile

final class DifferentialTest extends TestCase {

	private const RP     = 'shop.example';
	private const ORIGIN = 'https://shop.example';

	/**
	 * Oracle acceptances ours deliberately does not share, with the reason.
	 */
	private const EXPECTED_DIVERGENCE = array(
		'lbuchs' => array(
			'origin suffix trick' => 'lbuchs matches the host as a suffix of the RP ID with no dot boundary (eval 4.1); the spec requires the exact origin',
			'origin subdomain'    => 'lbuchs accepts any host ending in the RP ID; ours allows only the configured origins',
			'origin port'         => 'lbuchs compares the host only; an origin is scheme + host + port',
			'cross origin'        => 'lbuchs ignores clientData.crossOrigin; ours rejects cross-origin ceremonies (plan 12)',
			'BS without BE'       => 'lbuchs exposes BE/BS but does not check them; the spec forbids BS=1 with BE=0',
			'authData trailing bytes' => 'lbuchs ignores bytes after the parsed authenticator data',
			'assertion trailing bytes' => 'lbuchs ignores bytes after the parsed authenticator data',
		),
		'webauthn-lib' => array(
			'wrong type'   => 'webauthn-lib 5.3.9 WebauthnAuthenticationCollector::supportedTypes() accepts webauthn.get and webauthn.create in either ceremony; the spec requires the ceremony\'s own type (7.1 step 7, 7.2 step 11)',
			'cross origin' => 'webauthn-lib 5.3.9 CheckTopOrigin returns early when topOrigin is absent, so crossOrigin true alone passes; ours rejects every cross-origin ceremony (plan 12)',
		),
	);

	/**
	 * @return iterable<string, array{array<string, mixed>, int}>
	 */
	public static function registrations(): iterable {
		foreach ( array( 'ES256' => CoseKey::ES256, 'RS256' => CoseKey::RS256, 'EdDSA' => CoseKey::EDDSA ) as $name => $alg ) {
			yield "valid {$name}" => array( array(), $alg );
		}
		yield 'wrong type' => array( array( 'type' => 'webauthn.get' ), CoseKey::ES256 );
		yield 'wrong origin' => array( array( 'origin' => 'https://evil.example' ), CoseKey::ES256 );
		yield 'origin suffix trick' => array( array( 'origin' => 'https://evilshop.example' ), CoseKey::ES256 );
		yield 'origin subdomain' => array( array( 'origin' => 'https://a.shop.example' ), CoseKey::ES256 );
		yield 'origin port' => array( array( 'origin' => 'https://shop.example:8443' ), CoseKey::ES256 );
		yield 'origin scheme' => array( array( 'origin' => 'http://shop.example' ), CoseKey::ES256 );
		yield 'cross origin' => array( array( 'cross_origin' => true ), CoseKey::ES256 );
		yield 'wrong challenge' => array( array( 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ), CoseKey::ES256 );
		yield 'wrong rp id' => array( array( 'rp_id' => 'evil.example' ), CoseKey::ES256 );
		yield 'user not present' => array( array( 'flags' => 0x44 ), CoseKey::ES256 );
		yield 'BS without BE' => array( array( 'flags' => 0x55 ), CoseKey::ES256 );
		yield 'no user verification' => array( array( 'uv' => false ), CoseKey::ES256 );
		yield 'authData trailing bytes' => array( array( 'auth_trailing' => "\x00" ), CoseKey::ES256 );
		yield 'attestationObject trailing bytes' => array( array( 'att_trailing' => "\x00" ), CoseKey::ES256 );
	}

	/**
	 * @param array<string, mixed> $knobs Overrides.
	 */
	#[DataProvider( 'registrations' )]
	public function test_registration_parity( array $knobs, int $alg ): void {
		$case      = (string) $this->dataName();
		$a         = new VirtualAuthenticator( $alg );
		$challenge = random_bytes( 32 );
		$handle    = random_bytes( 32 );
		$options   = array(
			'rp'        => array( 'id' => self::RP, 'name' => 'Shop' ),
			'user'      => array( 'id' => Base64Url::encode( $handle ), 'name' => 'jane', 'displayName' => 'Jane' ),
			'challenge' => Base64Url::encode( $challenge ),
		);
		$json      = $a->create( $options, self::ORIGIN, $knobs );
		$uv        = true; // Every case runs with UV required, so "no user verification" must fail everywhere.

		$ours = $this->accepts(
			static function () use ( $json, $challenge, $uv ): void {
				$c = CredentialJson::registration( $json );
				Verifier::register( $c->client_data_json, $c->attestation_object, $challenge, self::RP, array( self::ORIGIN ), $uv );
			}
		);
		$lbuchs = $this->accepts(
			static function () use ( $json, $challenge, $uv ): void {
				$c = CredentialJson::registration( $json );
				( new \lbuchs\WebAuthn\WebAuthn( 'Shop', self::RP, array( 'none' ) ) )->processCreate( $c->client_data_json, $c->attestation_object, $challenge, $uv, true );
			}
		);
		$spomky = $this->accepts(
			function () use ( $json, $challenge, $handle, $uv ): void {
				$pkc      = $this->serializer()->deserialize( $json, PublicKeyCredential::class, 'json' );
				$response = $pkc->response;
				self::assertInstanceOf( AuthenticatorAttestationResponse::class, $response );
				$options = PublicKeyCredentialCreationOptions::create(
					PublicKeyCredentialRpEntity::create( 'Shop', self::RP ),
					PublicKeyCredentialUserEntity::create( 'jane', $handle, 'Jane' ),
					$challenge,
					array( PublicKeyCredentialParameters::createPk( -7 ), PublicKeyCredentialParameters::createPk( -257 ), PublicKeyCredentialParameters::createPk( -8 ) ),
					AuthenticatorSelectionCriteria::create( null, $uv ? 'required' : 'preferred' ),
					'none'
				);
				AuthenticatorAttestationResponseValidator::create( $this->factory()->creationCeremony() )->check( $response, $options, self::RP );
			}
		);

		$this->assertParity( $case, $ours, array( 'lbuchs' => $lbuchs, 'webauthn-lib' => $spomky ) );
	}

	/**
	 * @return iterable<string, array{array<string, mixed>, int}>
	 */
	public static function assertions(): iterable {
		foreach ( array( 'ES256' => CoseKey::ES256, 'RS256' => CoseKey::RS256, 'EdDSA' => CoseKey::EDDSA ) as $name => $alg ) {
			yield "valid {$name}" => array( array(), $alg );
			yield "tampered signature {$name}" => array( array( 'tamper_signature' => true ), $alg );
		}
		yield 'wrong type' => array( array( 'type' => 'webauthn.create' ), CoseKey::ES256 );
		yield 'wrong origin' => array( array( 'origin' => 'https://evil.example' ), CoseKey::ES256 );
		yield 'origin suffix trick' => array( array( 'origin' => 'https://evilshop.example' ), CoseKey::ES256 );
		yield 'cross origin' => array( array( 'cross_origin' => true ), CoseKey::ES256 );
		yield 'wrong challenge' => array( array( 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ), CoseKey::ES256 );
		yield 'wrong rp id' => array( array( 'rp_id' => 'evil.example' ), CoseKey::ES256 );
		yield 'user not present' => array( array( 'flags' => 0x04 ), CoseKey::ES256 );
		yield 'no user verification' => array( array( 'uv' => false ), CoseKey::ES256 );
		yield 'BS without BE' => array( array( 'flags' => 0x15 ), CoseKey::ES256 );
		yield 'attested data in an assertion' => array( array( 'flags' => 0x45 ), CoseKey::ES256 );
		yield 'assertion trailing bytes' => array( array( 'auth_trailing' => "\x00" ), CoseKey::ES256 );
	}

	/**
	 * @param array<string, mixed> $knobs Overrides.
	 */
	#[DataProvider( 'assertions' )]
	public function test_assertion_parity( array $knobs, int $alg ): void {
		$case      = (string) $this->dataName();
		$a         = new VirtualAuthenticator( $alg );
		$a->user_handle = random_bytes( 32 );
		$challenge = random_bytes( 32 );
		$json      = $a->get( array( 'rpId' => self::RP, 'challenge' => Base64Url::encode( $challenge ) ), self::ORIGIN, $knobs );
		$uv        = true;
		$pem       = null;
		try {
			$pem = CoseKey::from_cbor( $a->cose() );
		} catch ( VerificationException $e ) {
			self::fail( 'fixture key did not parse' );
		}

		$ours = $this->accepts(
			static function () use ( $json, $challenge, $uv, $a ): void {
				$c = CredentialJson::assertion( $json );
				Verifier::assert( $a->cose(), 0, $c->client_data_json, $c->authenticator_data, $c->signature, $challenge, self::RP, array( self::ORIGIN ), $uv );
			}
		);
		$lbuchs = CoseKey::EDDSA === $alg ? null : $this->accepts(
			static function () use ( $json, $challenge, $uv, $pem ): void {
				$c = CredentialJson::assertion( $json );
				( new \lbuchs\WebAuthn\WebAuthn( 'Shop', self::RP, array( 'none' ) ) )->processGet( $c->client_data_json, $c->authenticator_data, $c->signature, $pem->material, $challenge, null, $uv, true );
			}
		);
		$spomky = $this->accepts(
			function () use ( $json, $challenge, $a, $uv ): void {
				$pkc      = $this->serializer()->deserialize( $json, PublicKeyCredential::class, 'json' );
				$response = $pkc->response;
				self::assertInstanceOf( AuthenticatorAssertionResponse::class, $response );
				$record = CredentialRecord::create( $a->credential_id, 'public-key', array(), 'none', EmptyTrustPath::create(), Uuid::fromString( '00000000-0000-0000-0000-000000000000' ), $a->cose(), $a->user_handle, 0, null, true, true, true );
				$request = PublicKeyCredentialRequestOptions::create( $challenge, self::RP, array( PublicKeyCredentialDescriptor::create( 'public-key', $a->credential_id ) ), $uv ? 'required' : 'preferred' );
				AuthenticatorAssertionResponseValidator::create( $this->factory()->requestCeremony() )->check( $record, $response, $request, self::RP, $a->user_handle );
			}
		);

		// lbuchs's EdDSA path needs an OKP PEM this key format does not produce; it is compared on ES256/RS256.
		$this->assertParity( $case, $ours, array_filter( array( 'lbuchs' => $lbuchs, 'webauthn-lib' => $spomky ), static fn ( ?bool $v ): bool => null !== $v ) );
	}

	/**
	 * @param array<string, bool> $oracles Oracle name => accepted.
	 */
	private function assertParity( string $case, bool $ours, array $oracles ): void {
		foreach ( $oracles as $name => $accepted ) {
			$reason = self::EXPECTED_DIVERGENCE[ $name ][ $case ] ?? null;
			if ( $ours === $accepted ) {
				// Keeps the list honest: a documented divergence that stopped happening is stale.
				self::assertNull( $reason, "{$case}: documented as a {$name} divergence, but {$name} now agrees" );
				continue;
			}
			if ( $ours ) {
				self::fail( "{$case}: ours accepts but {$name} rejects" );
			}
			self::assertNotNull( $reason, "{$case}: {$name} accepts what ours rejects, and no documented reason exists" );
		}
		self::assertTrue( true );
	}

	private function accepts( callable $ceremony ): bool {
		try {
			$ceremony();
			return true;
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	private function serializer(): \Symfony\Component\Serializer\SerializerInterface {
		return ( new WebauthnSerializerFactory( AttestationStatementSupportManager::create() ) )->create();
	}

	private function factory(): CeremonyStepManagerFactory {
		$factory = new CeremonyStepManagerFactory();
		$factory->setAllowedOrigins( array( self::ORIGIN ) );
		$factory->setAlgorithmManager( Manager::create()->add( ES256::create(), RS256::create(), Ed25519::create() ) );
		return $factory;
	}
}
