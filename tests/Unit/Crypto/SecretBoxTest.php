<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Crypto;

use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Crypto\SecretBox;
use PHPUnit\Framework\TestCase;

final class SecretBoxTest extends TestCase {

	private function box( string $seed = 'a' ): SecretBox {
		return new SecretBox( KeyProvider::from_base64( base64_encode( str_repeat( $seed, 32 ) ) ) );
	}

	public function test_round_trip(): void {
		$box    = $this->box();
		$sealed = $box->encrypt( 'JBSWY3DPEHPK3PXP', SecretBox::totp_aad( 7 ) );

		self::assertSame( 'JBSWY3DPEHPK3PXP', $box->decrypt( $sealed, SecretBox::totp_aad( 7 ) ) );
	}

	public function test_empty_plaintext_round_trips(): void {
		$box = $this->box();

		self::assertSame( '', $box->decrypt( $box->encrypt( '', 'aad' ), 'aad' ) );
	}

	public function test_ciphertext_does_not_contain_plaintext(): void {
		$sealed = $this->box()->encrypt( 'JBSWY3DPEHPK3PXP', 'aad' );

		self::assertStringNotContainsString( 'JBSWY3DPEHPK3PXP', (string) base64_decode( $sealed['ct'], true ) );
	}

	public function test_wrong_aad_is_rejected(): void {
		$box    = $this->box();
		$sealed = $box->encrypt( 'secret', SecretBox::totp_aad( 7 ) );

		self::assertNull( $box->decrypt( $sealed, SecretBox::totp_aad( 8 ) ), 'a ciphertext moved to another user must not decrypt' );
		self::assertNull( $box->decrypt( $sealed, '' ) );
	}

	public function test_different_key_is_rejected_by_kid(): void {
		$sealed = $this->box( 'a' )->encrypt( 'secret', 'aad' );

		self::assertNull( $this->box( 'b' )->decrypt( $sealed, 'aad' ) );
	}

	public function test_different_key_with_forged_kid_fails_authentication(): void {
		$other          = KeyProvider::from_base64( base64_encode( str_repeat( 'b', 32 ) ) );
		$sealed         = $this->box( 'a' )->encrypt( 'secret', 'aad' );
		$sealed['kid']  = $other->kid();

		self::assertNull( ( new SecretBox( $other ) )->decrypt( $sealed, 'aad' ) );
	}

	public function test_tampered_ciphertext_is_rejected(): void {
		$box        = $this->box();
		$sealed     = $box->encrypt( 'secret', 'aad' );
		$raw        = (string) base64_decode( $sealed['ct'], true );
		$raw[0]     = chr( ord( $raw[0] ) ^ 0x01 );
		$sealed['ct'] = base64_encode( $raw );

		self::assertNull( $box->decrypt( $sealed, 'aad' ) );
	}

	public function test_tampered_nonce_is_rejected(): void {
		$box             = $this->box();
		$sealed          = $box->encrypt( 'secret', 'aad' );
		$nonce           = (string) base64_decode( $sealed['nonce'], true );
		$nonce[0]        = chr( ord( $nonce[0] ) ^ 0x01 );
		$sealed['nonce'] = base64_encode( $nonce );

		self::assertNull( $box->decrypt( $sealed, 'aad' ) );
	}

	/**
	 * @return iterable<string, array{array<string, mixed>}>
	 */
	public static function malformed_boxes(): iterable {
		yield 'empty' => array( array() );
		yield 'missing nonce' => array( array( 'ct' => 'AAAA', 'kid' => 'x' ) );
		yield 'non-string ct' => array( array( 'ct' => 1, 'nonce' => 'AAAA', 'kid' => 'x' ) );
		yield 'not base64' => array( array( 'ct' => '***', 'nonce' => '***', 'kid' => 'x' ) );
	}

	/**
	 * @param array<string, mixed> $sealed Malformed box.
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'malformed_boxes' )]
	public function test_malformed_box_is_rejected( array $sealed ): void {
		self::assertNull( $this->box()->decrypt( $sealed, 'aad' ) );
	}

	public function test_short_ciphertext_with_valid_kid_is_rejected(): void {
		$box    = $this->box();
		$sealed = $box->encrypt( 'secret', 'aad' );
		$sealed['ct'] = base64_encode( 'short' );

		self::assertNull( $box->decrypt( $sealed, 'aad' ) );
	}

	public function test_nonce_is_fresh_per_encryption(): void {
		$box = $this->box();

		self::assertNotSame( $box->encrypt( 'x', 'aad' )['nonce'], $box->encrypt( 'x', 'aad' )['nonce'] );
	}

	public function test_totp_aad_binds_the_user(): void {
		self::assertSame( 'mdmfa:totp:v1:42', SecretBox::totp_aad( 42 ) );
	}
}
