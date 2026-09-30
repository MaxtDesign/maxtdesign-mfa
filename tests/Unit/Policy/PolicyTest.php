<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Policy;

use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class PolicyTest extends TestCase {

	private const T0 = 1800000000;

	protected function setUp(): void {
		mdmfa_test_reset();
		Clock::freeze( self::T0 );
	}

	private function enroll( int $user_id ): void {
		$GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ TotpStore::META ] = array(
			'ct'    => 'x',
			'nonce' => 'y',
			'kid'   => 'z',
		);
	}

	public function test_strictest_role_wins(): void {
		$user = new \WP_User( 2, array( 'customer', 'shop_manager' ) );

		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( $user ) );
		self::assertFalse( Policy::allows( $user, 'email' ), 'the governing (staff) role supplies the factors' );
	}

	public function test_unlisted_role_uses_the_unlisted_default(): void {
		self::assertSame( Settings::POLICY_OPTIONAL, Policy::policy( new \WP_User( 3, array( 'author' ) ) ) );
		self::assertSame( Settings::POLICY_OPTIONAL, Policy::policy( new \WP_User( 4, array() ) ) );
	}

	public function test_super_admin_is_always_required_on_multisite(): void {
		$GLOBALS['mdmfa_test']['multisite']    = true;
		$GLOBALS['mdmfa_test']['super_admins'] = array( 6 );

		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( new \WP_User( 6, array( 'subscriber' ) ) ) );
	}

	public function test_policy_filter_is_validated(): void {
		add_filter( 'mdmfa_user_policy', static fn (): string => 'off' );
		self::assertSame( Settings::POLICY_OFF, Policy::policy( new \WP_User( 2, array( 'administrator' ) ) ) );

		mdmfa_test_reset();
		add_filter( 'mdmfa_user_policy', static fn (): string => 'bogus' );
		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( new \WP_User( 2, array( 'administrator' ) ) ) );
	}

	public function test_decisions(): void {
		$optional = new \WP_User( 10, array( 'customer' ) );
		self::assertSame( Policy::NONE, Policy::decide( $optional ), 'optional and not enrolled: password only' );

		$this->enroll( 10 );
		self::assertSame( Policy::CHALLENGE, Policy::decide( $optional ), 'enrolled: challenge' );

		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'customer' => array( 'policy' => 'off' ) ) );
		self::assertSame( Policy::NONE, Policy::decide( $optional ), 'policy off ignores enrollment' );
	}

	public function test_required_grace_then_enroll(): void {
		$admin = new \WP_User( 11, array( 'administrator' ) );

		self::assertSame( Policy::ENROLL, Policy::decide( $admin ), 'grace never started: enroll' );

		Policy::maybe_start_grace( $admin );
		self::assertSame( (string) self::T0, $GLOBALS['mdmfa_test']['usermeta'][11][ Policy::GRACE_META ] );
		self::assertSame( Policy::GRACE, Policy::decide( $admin ) );
		self::assertSame( 7 * DAY_IN_SECONDS, Policy::grace_remaining( $admin ) );

		Clock::freeze( self::T0 + 7 * DAY_IN_SECONDS );
		self::assertSame( Policy::ENROLL, Policy::decide( $admin ), 'grace over' );

		Policy::maybe_start_grace( $admin );
		self::assertSame( (string) self::T0, $GLOBALS['mdmfa_test']['usermeta'][11][ Policy::GRACE_META ], 'the clock never restarts on its own' );
	}

	public function test_grace_of_zero_days_means_enroll_now(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) );
		$admin = new \WP_User( 12, array( 'administrator' ) );
		Policy::maybe_start_grace( $admin );

		self::assertSame( Policy::ENROLL, Policy::decide( $admin ) );
	}

	public function test_subject_rules_for_the_bypass_guard(): void {
		$customer = new \WP_User( 20, array( 'customer' ) );
		self::assertFalse( Policy::is_subject( $customer ), 'optional, not enrolled' );
		$this->enroll( 20 );
		self::assertTrue( Policy::is_subject( $customer ), 'enrolled' );

		$admin = new \WP_User( 21, array( 'administrator' ) );
		self::assertFalse( Policy::is_subject( $admin ), 'required but grace never started' );
		Policy::maybe_start_grace( $admin );
		self::assertFalse( Policy::is_subject( $admin ), 'required, in grace' );
		Clock::freeze( self::T0 + 8 * DAY_IN_SECONDS );
		self::assertTrue( Policy::is_subject( $admin ), 'required, grace over' );

		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'customer' => array( 'policy' => 'off' ) ) );
		self::assertFalse( Policy::is_subject( $customer ), 'policy off exempts' );
	}

	#[RunInSeparateProcess]
	public function test_escape_hatch_turns_every_decision_off(): void {
		define( 'MDMFA_DISABLE', true );
		$user = new \WP_User( 30, array( 'customer' ) );
		$this->enroll( 30 );

		self::assertSame( Policy::NONE, Policy::decide( $user ) );
		self::assertFalse( Policy::is_subject( $user ) );
	}
}
