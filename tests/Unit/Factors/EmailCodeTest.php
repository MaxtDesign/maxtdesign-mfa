<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Factors;

use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;
use PHPUnit\Framework\TestCase;

final class EmailCodeTest extends TestCase {

	private const T0 = 1800000000;

	protected function setUp(): void {
		mdmfa_test_reset();
		Clock::freeze( self::T0 );
	}

	/**
	 * The code in the most recent mail.
	 */
	private static function mailed_code(): string {
		$mail = end( $GLOBALS['mdmfa_test']['mail'] );
		self::assertSame( 1, preg_match( '/\b(\d{8})\b/', (string) $mail[2], $m ) );
		return $m[1];
	}

	public function test_email_is_a_customer_factor_and_never_a_staff_factor_by_default(): void {
		$customer = new \WP_User( 5, array( 'customer' ) );
		$editor   = new \WP_User( 6, array( 'editor' ) );
		EmailCode::enable( 5 );
		EmailCode::enable( 6 );

		self::assertTrue( EmailCode::allowed( $customer ) );
		self::assertTrue( EmailCode::has( 5 ) );
		self::assertTrue( Policy::is_enrolled( 5 ), 'an emailed code counts as a second factor where the role allows it' );
		self::assertFalse( EmailCode::allowed( $editor ) );
		self::assertFalse( EmailCode::has( 6 ), 'a role that stops allowing email stops honouring it' );
		self::assertFalse( Policy::is_enrolled( 6 ) );
	}

	public function test_a_code_works_once_and_only_for_its_purpose_and_user(): void {
		$user  = new \WP_User( 5, array( 'customer' ) );
		$other = new \WP_User( 7, array( 'customer' ) );

		self::assertSame( EmailCode::SENT, EmailCode::send( $user, 'login:aaaa' ) );
		$code = self::mailed_code();
		self::assertSame( 'user5@example.com', end( $GLOBALS['mdmfa_test']['mail'] )[0] );
		self::assertStringNotContainsString( $code, serialize( $GLOBALS['mdmfa_test']['usermeta'] ), 'only a hash is stored' );

		self::assertTrue( EmailCode::issued( 5, 'login:aaaa' ) );
		self::assertFalse( EmailCode::issued( 5, 'login:bbbb' ) );
		self::assertFalse( EmailCode::check( 5, 'login:bbbb', $code ), 'another pending login cannot use it' );
		self::assertFalse( EmailCode::check( $other->ID, 'login:aaaa', $code ), 'another user cannot use it' );
		self::assertTrue( EmailCode::check( 5, 'login:aaaa', ' ' . substr( $code, 0, 4 ) . ' ' . substr( $code, 4 ) ), 'spaces are ignored' );
		self::assertFalse( EmailCode::check( 5, 'login:aaaa', $code ), 'single use' );
	}

	public function test_a_code_expires_after_ten_minutes(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		EmailCode::send( $user, 'setup' );
		$code = self::mailed_code();

		Clock::freeze( self::T0 + EmailCode::TTL - 1 );
		self::assertTrue( EmailCode::issued( 5, 'setup' ) );
		Clock::freeze( self::T0 + EmailCode::TTL );
		self::assertFalse( EmailCode::issued( 5, 'setup' ) );
		self::assertFalse( EmailCode::check( 5, 'setup', $code ) );
	}

	public function test_the_fifth_wrong_guess_destroys_the_code(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		EmailCode::send( $user, 'setup' );
		$code  = self::mailed_code();
		$wrong = str_pad( (string) ( ( (int) $code + 1 ) % 100000000 ), 8, '0', STR_PAD_LEFT );

		for ( $i = 1; $i <= 4; $i++ ) {
			self::assertFalse( EmailCode::check( 5, 'setup', $wrong ) );
			self::assertTrue( EmailCode::issued( 5, 'setup' ), "still live after miss {$i}" );
		}
		self::assertFalse( EmailCode::check( 5, 'setup', $wrong ) );
		self::assertFalse( EmailCode::issued( 5, 'setup' ) );
		self::assertFalse( EmailCode::check( 5, 'setup', $code ), 'the right code is too late' );
	}

	public function test_send_limits_three_per_fifteen_minutes_and_ten_per_day(): void {
		$user = new \WP_User( 5, array( 'customer' ) );

		for ( $i = 0; $i < 3; $i++ ) {
			self::assertSame( EmailCode::SENT, EmailCode::send( $user, 'setup' ) );
		}
		self::assertSame( EmailCode::LIMITED, EmailCode::send( $user, 'setup' ), 'the fourth send inside 15 minutes is refused' );
		self::assertCount( 3, $GLOBALS['mdmfa_test']['mail'] );

		// Three more in each later window: 3 + 3 + 3 + 1 = 10 in the day, then refused.
		$sent = 3;
		for ( $window = 1; $window <= 4; $window++ ) {
			Clock::freeze( self::T0 + $window * 16 * 60 );
			for ( $i = 0; $i < 3; $i++ ) {
				$sent += EmailCode::SENT === EmailCode::send( $user, 'setup' ) ? 1 : 0;
			}
		}
		self::assertSame( 10, $sent, 'ten per day' );
		self::assertCount( 10, $GLOBALS['mdmfa_test']['mail'] );

		Clock::freeze( self::T0 + DAY_IN_SECONDS + 1 );
		self::assertSame( EmailCode::SENT, EmailCode::send( $user, 'setup' ), 'the allowance returns as old sends age out' );
	}

	public function test_a_new_code_replaces_the_old_one(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		EmailCode::send( $user, 'setup' );
		$first = self::mailed_code();
		EmailCode::send( $user, 'setup' );
		$second = self::mailed_code();

		if ( $first !== $second ) {
			self::assertFalse( EmailCode::check( 5, 'setup', $first ) );
		}
		self::assertTrue( EmailCode::check( 5, 'setup', $second ) );
	}

	public function test_the_message_filter_is_validated(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		add_filter( 'mdmfa_email_code_message', static fn ( array $m ): array => array( 'subject' => 'Shop code', 'body' => $m['body'] ) );
		EmailCode::send( $user, 'setup' );
		self::assertSame( 'Shop code', end( $GLOBALS['mdmfa_test']['mail'] )[1] );

		mdmfa_test_reset();
		Clock::freeze( self::T0 );
		$user = new \WP_User( 5, array( 'customer' ) );
		add_filter( 'mdmfa_email_code_message', static fn (): string => 'broken' );
		EmailCode::send( $user, 'setup' );
		self::assertStringContainsString( 'Your sign-in code', end( $GLOBALS['mdmfa_test']['mail'] )[1], 'a bad filter value is ignored' );
		self::assertSame( 0, preg_match( '/\d{8}/', end( $GLOBALS['mdmfa_test']['mail'] )[1] ), 'the code never appears in the subject' );
	}

	public function test_the_factor_is_bound_to_the_confirmed_address(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		EmailCode::enable( 5 );
		self::assertTrue( EmailCode::has( 5 ) );

		// The address changes without going through the plugin's hook (a direct database
		// write, another plugin): the factor still stops, because the fingerprint differs.
		$user->user_email = 'attacker@evil.example';
		self::assertFalse( EmailCode::has( 5 ), 'codes are never sent to an address the user did not confirm' );
		self::assertTrue( Policy::is_enrolled( 5 ), 'but the account keeps its second step: it is challenged, not waved through' );
	}

	public function test_an_enrollment_stored_before_addresses_were_recorded_stays_enrolled_and_gets_bound(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		// What the previous version stored.
		update_user_meta( 5, EmailCode::META, array( 'enabled' => true, 'confirmed_at' => self::T0 - 100 ) );

		self::assertTrue( EmailCode::has( 5 ), 'never silently dropped to password-only' );
		self::assertTrue( Policy::is_enrolled( 5 ) );
		self::assertSame( hash( 'sha256', 'user5@example.com' ), get_user_meta( 5, EmailCode::META, true )['address'], 'bound on first read' );

		$user->user_email = 'other@example.com';
		self::assertFalse( EmailCode::has( 5 ), 'and from then on tied to that address' );
	}

	public function test_an_address_change_switches_the_factor_off_and_closes_email_recovery_for_a_day(): void {
		$GLOBALS['mdmfa_test']['options']['mdmfa_settings'] = array( 'roles' => array( 'customer' => array( 'trusted_devices' => true ) ) );
		$old             = new \WP_User( 5, array( 'customer' ) );
		$old             = clone $old;
		$user            = new \WP_User( 5, array( 'customer' ) );
		EmailCode::enable( 5 );
		\MaxtDesign\Mfa\Auth\TrustedDevice::issue( $user );
		update_user_meta( 5, \MaxtDesign\Mfa\Flow\EmailRecovery::META, self::T0 + 3600 );
		self::assertTrue( \MaxtDesign\Mfa\Flow\EmailRecovery::allowed( $user ) );
		$user->user_email = 'new@example.com';

		EmailCode::address_changed( 5, $old );

		self::assertFalse( EmailCode::has( 5 ) );
		self::assertTrue( EmailCode::enrolled( 5 ), 'an email-only account is not de-enrolled by an address change' );
		self::assertTrue( Policy::is_enrolled( 5 ) );
		self::assertSame( 0, \MaxtDesign\Mfa\Auth\TrustedDevice::count( 5 ) );
		self::assertSame( '', get_user_meta( 5, \MaxtDesign\Mfa\Flow\EmailRecovery::META, true ), 'a waiting recovery is dropped' );
		self::assertFalse( \MaxtDesign\Mfa\Flow\EmailRecovery::allowed( $user ), 'a mailbox that just changed proves nothing' );
		Clock::freeze( self::T0 + DAY_IN_SECONDS + 1 );
		self::assertTrue( \MaxtDesign\Mfa\Flow\EmailRecovery::allowed( $user ) );

		// Confirming the new address on the security screen turns codes back on.
		EmailCode::enable( 5 );
		self::assertTrue( EmailCode::has( 5 ) );

		// Same address in another case is not a change.
		$same             = clone $user;
		$same->user_email = 'NEW@example.com';
		EmailCode::address_changed( 5, $same );
		self::assertTrue( EmailCode::has( 5 ) );
	}

	public function test_masked_address(): void {
		self::assertSame( 'j***@example.com', EmailCode::masked( 'jane.doe@example.com' ) );
		self::assertSame( '', EmailCode::masked( 'not-an-address' ) );
	}
}
