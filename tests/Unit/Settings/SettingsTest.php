<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Settings;

use MaxtDesign\Mfa\Settings\LoginSlug;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_staff_roles_are_required_and_customers_optional(): void {
		$roles = Settings::defaults()['roles'];

		foreach ( array( 'administrator', 'editor', 'shop_manager' ) as $role ) {
			self::assertSame( Settings::POLICY_REQUIRED, $roles[ $role ]['policy'], $role );
		}
		self::assertSame( Settings::POLICY_OPTIONAL, $roles['customer']['policy'] );
	}

	public function test_email_is_off_for_staff_and_on_for_customers(): void {
		$roles = Settings::defaults()['roles'];

		self::assertFalse( $roles['administrator']['factors']['email'] );
		self::assertFalse( $roles['administrator']['email_recovery'] );
		self::assertSame( 24, $roles['administrator']['recovery_wait_hours'] );
		self::assertTrue( $roles['customer']['factors']['email'] );
		self::assertTrue( $roles['customer']['email_recovery'] );
		self::assertSame( 0, $roles['customer']['recovery_wait_hours'] );
	}

	public function test_decision_defaults(): void {
		$d = Settings::defaults();

		self::assertSame( 7, $d['roles']['administrator']['grace_days'] );
		self::assertFalse( $d['roles']['customer']['trusted_devices'] );
		self::assertFalse( $d['roles']['administrator']['trusted_devices'] );
		self::assertSame( 30, $d['trusted_device_days'] );
		self::assertSame( 5, $d['lockout']['attempts_per_record'] );
		self::assertSame( 20, $d['lockout']['lock_after'] );
		self::assertSame( 3600, $d['lockout']['lock_seconds'] );
		self::assertSame( 86400, $d['lockout']['repeat_lock_seconds'] );
		self::assertSame( 90, $d['log_retention_days'] );
		self::assertSame( 'truncated', $d['log_ip_mode'] );
		self::assertFalse( $d['block_wpcom_sso'] );
	}

	public function test_application_passwords_follow_policy(): void {
		$roles = Settings::defaults()['roles'];

		self::assertFalse( $roles['administrator']['app_passwords'] );
		self::assertTrue( $roles['customer']['app_passwords'] );
	}

	public function test_get_returns_defaults_when_nothing_is_stored(): void {
		self::assertSame( Settings::defaults(), Settings::get() );
	}

	public function test_stored_values_override_and_wrong_types_are_ignored(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array(
			'log_retention_days' => 30,
			'trusted_device_days' => 'forever',
			'unknown_key'        => array( 'x' => 1 ),
			'lockout'            => array( 'lock_after' => 10 ),
		);

		$s = Settings::get();

		self::assertSame( 30, $s['log_retention_days'] );
		self::assertSame( 30, $s['trusted_device_days'] );
		self::assertArrayNotHasKey( 'unknown_key', $s );
		self::assertSame( 10, $s['lockout']['lock_after'] );
		self::assertSame( 5, $s['lockout']['attempts_per_record'] );
	}

	public function test_custom_role_merges_over_unlisted_default(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array(
			'roles' => array(
				'wholesale'     => array( 'policy' => Settings::POLICY_REQUIRED ),
				'administrator' => array( 'grace_days' => 3 ),
				7               => array( 'policy' => 'off' ),
				'bad'           => 'not-an-array',
			),
		);

		$roles = Settings::get()['roles'];

		self::assertSame( Settings::POLICY_REQUIRED, $roles['wholesale']['policy'] );
		self::assertFalse( $roles['wholesale']['factors']['email'], 'unlisted roles inherit staff-safe factor defaults' );
		self::assertSame( 3, $roles['administrator']['grace_days'] );
		self::assertSame( Settings::POLICY_REQUIRED, $roles['administrator']['policy'] );
		self::assertArrayNotHasKey( 7, $roles );
		self::assertArrayNotHasKey( 'bad', $roles );
	}

	public function test_non_array_option_falls_back_to_defaults(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = 'corrupt';

		self::assertSame( Settings::defaults(), Settings::get() );
	}

	public function test_login_defaults_carry_a_fresh_slug(): void {
		$login = Settings::login_defaults();

		self::assertTrue( $login['enabled'] );
		self::assertMatchesRegularExpression( '/^[a-z0-9]{12}$/', $login['slug'] );
		self::assertNotSame( $login['slug'], Settings::login_defaults()['slug'] );
	}

	public function test_slug_shape_and_uniqueness(): void {
		$seen = array();
		for ( $i = 0; $i < 500; $i++ ) {
			$slug = LoginSlug::generate();
			self::assertMatchesRegularExpression( '/^[a-z0-9]{12}$/', $slug );
			$seen[ $slug ] = true;
		}
		self::assertCount( 500, $seen );
	}

	public function test_every_option_is_prefixed_and_only_login_and_db_version_autoload(): void {
		foreach ( Options::all() as $name => $autoload ) {
			self::assertStringStartsWith( 'mdmfa_', $name );
			self::assertSame( in_array( $name, array( Options::LOGIN, Options::DB_VERSION ), true ), $autoload, $name );
		}
		foreach ( array_merge( Options::user_meta_keys(), Options::transients() ) as $key ) {
			self::assertStringStartsWith( 'mdmfa_', $key );
		}
	}
}
