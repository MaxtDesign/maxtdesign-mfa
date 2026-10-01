<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Settings;

use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SanitizeTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_a_role_is_rebuilt_from_closed_sets_and_ranges(): void {
		$current = Settings::role_defaults( Settings::POLICY_OPTIONAL, true );
		$clean   = Settings::sanitize_role(
			array(
				'policy'              => 'required',
				'factors'             => array( 'totp' => '1', 'email' => 'yes', 'bogus' => '1' ),
				'passwordless'        => '1',
				'grace_days'          => '14',
				'trusted_devices'     => '1',
				'email_recovery'      => '',
				'recovery_wait_hours' => '48',
				'app_passwords'       => '1',
				'injected'            => '<script>',
			),
			$current
		);

		self::assertSame(
			array(
				'policy'              => 'required',
				'factors'             => array(
					'totp'     => true,
					'passkey'  => false,
					'recovery' => true,
					'email'    => true,
				),
				'passwordless'        => false,
				'grace_days'          => 14,
				'trusted_devices'     => true,
				'email_recovery'      => false,
				'recovery_wait_hours' => 48,
				'app_passwords'       => true,
			),
			$clean,
			'only known keys, typed; passkey-only sign-in is dropped without the passkey method'
		);
	}

	public function test_a_required_role_always_keeps_a_method_that_can_be_set_up_at_sign_in(): void {
		$current = Settings::role_defaults( Settings::POLICY_REQUIRED, true );

		$none = Settings::sanitize_role( array( 'policy' => 'required', 'factors' => array( 'email' => '1' ) ), $current );
		self::assertTrue( $none['factors']['totp'], 'email alone cannot be set up during sign-in' );

		$passkey = Settings::sanitize_role( array( 'policy' => 'required', 'factors' => array( 'passkey' => '1' ) ), $current );
		self::assertFalse( $passkey['factors']['totp'], 'a passkey is enough' );

		$optional = Settings::sanitize_role( array( 'policy' => 'optional', 'factors' => array() ), $current );
		self::assertFalse( $optional['factors']['totp'], 'an Optional role may have no methods' );
		self::assertTrue( $optional['factors']['recovery'], 'recovery codes are never switched off' );
	}

	public function test_an_unknown_policy_keeps_the_current_one(): void {
		$current = Settings::role_defaults( Settings::POLICY_REQUIRED, true );

		self::assertSame( 'required', Settings::sanitize_role( array( 'policy' => 'none' ), $current )['policy'] );
		self::assertSame( 'required', Settings::sanitize_role( array( 'policy' => array( 'off' ) ), $current )['policy'] );
		self::assertSame( 'off', Settings::sanitize_role( array( 'policy' => 'off' ), $current )['policy'] );
	}

	/**
	 * @return array<string, array{mixed, int, int, int, int}>
	 */
	public static function clamps(): array {
		return array(
			'in range'        => array( '12', 0, 90, 7, 12 ),
			'too high'        => array( '999', 0, 90, 7, 90 ),
			'too low'         => array( '0', 1, 365, 30, 1 ),
			'negative text'   => array( '-5', 0, 90, 7, 7 ),
			'not a number'    => array( 'abc', 0, 90, 7, 7 ),
			'decimal'         => array( '1.5', 0, 90, 7, 7 ),
			'array'           => array( array( 3 ), 0, 90, 7, 7 ),
			'integer'         => array( 30, 0, 90, 7, 30 ),
			'spaces'          => array( ' 9 ', 0, 90, 7, 9 ),
			'absurdly long'   => array( '99999999999', 0, 90, 7, 7 ),
			'false (missing)' => array( false, 0, 90, 7, 7 ),
		);
	}

	#[DataProvider( 'clamps' )]
	public function test_clamp( mixed $value, int $min, int $max, int $fallback, int $expected ): void {
		self::assertSame( $expected, Settings::clamp( $value, $min, $max, $fallback ) );
	}

	public function test_choice(): void {
		self::assertSame( 'off', Settings::choice( 'off', array( 'off', 'on' ), 'on' ) );
		self::assertSame( 'on', Settings::choice( 'OFF', array( 'off', 'on' ), 'on' ) );
		self::assertSame( 'on', Settings::choice( array( 'off' ), array( 'off', 'on' ), 'on' ) );
	}

	public function test_save_stores_a_complete_validated_structure_not_autoloaded(): void {
		Settings::save(
			array(
				'xmlrpc'       => 'off',
				'unknown_key'  => 'dropped',
				'log_ip_mode'  => 42,
				'roles'        => array( 'author' => array( 'policy' => 'required' ) ),
			)
		);

		$stored = $GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ];
		self::assertSame( 'off', $stored['xmlrpc'] );
		self::assertArrayNotHasKey( 'unknown_key', $stored );
		self::assertSame( 'truncated', $stored['log_ip_mode'], 'a wrong type falls back to the default' );
		self::assertSame( 'required', $stored['roles']['author']['policy'] );
		self::assertArrayHasKey( 'administrator', $stored['roles'] );
		self::assertFalse( $GLOBALS['mdmfa_test']['autoload'][ Options::SETTINGS ] ?? null );
	}
}
