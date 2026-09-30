<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\FormToken;
use MaxtDesign\Mfa\Auth\PendingRecord;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Log\Logger;
use PHPUnit\Framework\TestCase;

final class FormTokenTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_token_is_bound_to_record_and_purpose(): void {
		$hash  = PendingStore::hash( 'token-a' );
		$token = FormToken::make( $hash, 'verify' );

		self::assertTrue( FormToken::check( $token, $hash, 'verify' ) );
		self::assertFalse( FormToken::check( $token, $hash, 'enroll-totp' ), 'another form' );
		self::assertFalse( FormToken::check( $token, PendingStore::hash( 'token-b' ), 'verify' ), 'another record' );
		self::assertFalse( FormToken::check( null, $hash, 'verify' ) );
		self::assertFalse( FormToken::check( array( $token ), $hash, 'verify' ) );
		self::assertFalse( FormToken::check( '', $hash, 'verify' ) );
	}

	public function test_pending_record_accessors(): void {
		$record = new PendingRecord(
			str_repeat( 'a', 64 ),
			'login',
			3,
			array(
				'context'  => 'core',
				'remember' => true,
				'secure'   => 0,
				'redirect' => array( 'not a string' ),
			),
			2,
			123
		);

		self::assertSame( 'core', $record->context() );
		self::assertTrue( $record->flag( 'remember' ) );
		self::assertFalse( $record->flag( 'secure' ) );
		self::assertSame( '', $record->string( 'redirect' ) );
		self::assertSame( 'x', $record->with( array( 'stage' => 'x' ) )->string( 'stage' ) );
		self::assertSame( '', $record->string( 'stage' ), 'with() does not mutate' );
	}

	public function test_log_ip_truncation(): void {
		self::assertSame( '203.0.113.0', inet_ntop( Logger::truncate( (string) inet_pton( '203.0.113.77' ) ) ) );
		self::assertSame( '2001:db8:abcd::', inet_ntop( Logger::truncate( (string) inet_pton( '2001:db8:abcd:12:34::1' ) ) ) );
	}
}
