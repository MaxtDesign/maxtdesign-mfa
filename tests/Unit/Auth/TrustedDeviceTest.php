<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Support\Clock;
use PHPUnit\Framework\TestCase;

final class TrustedDeviceTest extends TestCase {

	private const T0 = 1800000000;

	protected function setUp(): void {
		mdmfa_test_reset();
		Clock::freeze( self::T0 );
	}

	private static function allow( string $role ): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( $role => array( 'trusted_devices' => true ) ) );
	}

	public function test_off_for_every_role_at_install(): void {
		foreach ( array( 'administrator', 'editor', 'shop_manager', 'customer', 'subscriber' ) as $i => $role ) {
			self::assertFalse( TrustedDevice::allowed( new \WP_User( 10 + $i, array( $role ) ) ), $role );
		}
	}

	public function test_a_cookie_is_valid_only_for_its_user_and_until_it_expires(): void {
		self::allow( 'customer' );
		$user  = new \WP_User( 5, array( 'customer' ) );
		$other = new \WP_User( 6, array( 'customer' ) );

		$cookie = TrustedDevice::issue( $user );
		self::assertSame( self::T0 + 30 * DAY_IN_SECONDS, $cookie['expires'] );
		self::assertSame( 1, preg_match( '/^[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{43}$/', $cookie['value'] ) );
		list( , $validator ) = explode( ':', $cookie['value'] );
		self::assertStringNotContainsString( $validator, serialize( $GLOBALS['mdmfa_test']['usermeta'] ), 'only a hash of the validator is stored' );

		self::assertFalse( TrustedDevice::valid( $user ), 'no cookie, no trust' );
		$_COOKIE[ TrustedDevice::COOKIE ] = $cookie['value'];
		self::assertTrue( TrustedDevice::valid( $user ) );
		self::assertFalse( TrustedDevice::valid( $other ), 'another account cannot use it' );

		$_COOKIE[ TrustedDevice::COOKIE ] = substr( $cookie['value'], 0, -1 ) . ( 'A' === substr( $cookie['value'], -1 ) ? 'B' : 'A' );
		self::assertFalse( TrustedDevice::valid( $user ), 'a wrong validator fails' );
		$_COOKIE[ TrustedDevice::COOKIE ] = 'garbage';
		self::assertFalse( TrustedDevice::valid( $user ) );

		$_COOKIE[ TrustedDevice::COOKIE ] = $cookie['value'];
		Clock::freeze( $cookie['expires'] );
		self::assertFalse( TrustedDevice::valid( $user ), 'expired' );
		self::assertSame( 0, TrustedDevice::count( 5 ) );
	}

	public function test_turning_the_role_setting_off_stops_existing_cookies(): void {
		self::allow( 'customer' );
		$user                             = new \WP_User( 5, array( 'customer' ) );
		$_COOKIE[ TrustedDevice::COOKIE ] = TrustedDevice::issue( $user )['value'];
		self::assertTrue( TrustedDevice::valid( $user ) );

		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array();
		self::assertFalse( TrustedDevice::valid( $user ) );
	}

	public function test_a_password_change_revokes_every_device(): void {
		self::allow( 'customer' );
		$user                             = new \WP_User( 5, array( 'customer' ) );
		$_COOKIE[ TrustedDevice::COOKIE ] = TrustedDevice::issue( $user )['value'];
		TrustedDevice::issue( $user );
		self::assertSame( 2, TrustedDevice::count( 5 ) );

		TrustedDevice::password_changed( 'new-password', 5 );

		self::assertSame( 0, TrustedDevice::count( 5 ) );
		self::assertFalse( TrustedDevice::valid( $user ) );
	}

	public function test_at_most_ten_devices_are_kept_and_the_oldest_drops_out(): void {
		self::allow( 'customer' );
		$user  = new \WP_User( 5, array( 'customer' ) );
		$first = TrustedDevice::issue( $user )['value'];
		for ( $i = 0; $i < TrustedDevice::MAX; $i++ ) {
			$last = TrustedDevice::issue( $user )['value'];
		}

		self::assertSame( TrustedDevice::MAX, TrustedDevice::count( 5 ) );
		$_COOKIE[ TrustedDevice::COOKIE ] = $first;
		self::assertFalse( TrustedDevice::valid( $user ) );
		$_COOKIE[ TrustedDevice::COOKIE ] = $last;
		self::assertTrue( TrustedDevice::valid( $user ) );
	}

	public function test_lifetime_follows_the_setting_and_the_filter(): void {
		$user = new \WP_User( 5, array( 'customer' ) );
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'trusted_device_days' => 7 );
		self::assertSame( 7 * DAY_IN_SECONDS, TrustedDevice::lifetime( $user ) );

		add_filter( 'mdmfa_trusted_device_lifetime', static fn (): int => 3600 );
		self::assertSame( 3600, TrustedDevice::lifetime( $user ) );
	}
}
