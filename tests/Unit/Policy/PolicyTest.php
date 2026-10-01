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

	public function test_a_lower_ranked_role_does_not_restrict_the_governing_one(): void {
		// The Required role allows email recovery; the Optional one forbids it. Required governs.
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array(
			'roles' => array(
				'shop_manager' => array( 'email_recovery' => true, 'grace_days' => 3 ),
				'customer'     => array( 'email_recovery' => false, 'grace_days' => 0 ),
			),
		);
		foreach ( array( array( 'customer', 'shop_manager' ), array( 'shop_manager', 'customer' ) ) as $roles ) {
			$effective = Policy::effective( new \WP_User( 40, $roles ) );
			self::assertSame( Settings::POLICY_REQUIRED, $effective['policy'] );
			self::assertTrue( $effective['email_recovery'] );
			self::assertSame( 3, $effective['grace_days'] );
		}
	}

	public function test_roles_that_tie_on_policy_keep_each_others_restrictions_in_any_order(): void {
		// Both Required. Each is the stricter one on something.
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array(
			'roles' => array(
				'editor'       => array( 'email_recovery' => true, 'recovery_wait_hours' => 0, 'grace_days' => 10, 'app_passwords' => true, 'trusted_devices' => true, 'factors' => array( 'email' => true ) ),
				'shop_manager' => array( 'email_recovery' => false, 'recovery_wait_hours' => 48, 'grace_days' => 2, 'app_passwords' => false, 'trusted_devices' => true, 'factors' => array( 'email' => false ) ),
			),
		);
		$one = new \WP_User( 41, array( 'editor', 'shop_manager' ) );
		$two = new \WP_User( 42, array( 'shop_manager', 'editor' ) );

		self::assertSame( Policy::effective( $one ), Policy::effective( $two ), 'the stored order of the roles decides nothing' );
		$effective = Policy::effective( $one );
		self::assertSame( Settings::POLICY_REQUIRED, $effective['policy'] );
		self::assertFalse( $effective['email_recovery'] );
		self::assertFalse( \MaxtDesign\Mfa\Flow\EmailRecovery::allowed( $one ) );
		self::assertSame( 48, $effective['recovery_wait_hours'] );
		self::assertSame( 2, $effective['grace_days'] );
		self::assertFalse( \MaxtDesign\Mfa\Auth\SideDoors::app_passwords_for_user( true, $one ) );
		self::assertTrue( \MaxtDesign\Mfa\Auth\TrustedDevice::allowed( $one ), 'both roles allow it' );
		self::assertFalse( Policy::allows( $one, 'email' ) );
		self::assertTrue( Policy::allows( $one, 'totp' ) );

		// A single role is untouched by any of this.
		self::assertTrue( Policy::effective( new \WP_User( 43, array( 'editor' ) ) )['email_recovery'] );
		self::assertSame( 10, Policy::effective( new \WP_User( 43, array( 'editor' ) ) )['grace_days'] );
	}

	public function test_tied_roles_that_share_no_strong_method_still_let_a_required_user_enroll(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array(
			'roles' => array(
				'editor'       => array( 'factors' => array( 'totp' => true, 'passkey' => false ) ),
				'shop_manager' => array( 'factors' => array( 'totp' => false, 'passkey' => true ) ),
			),
		);
		$user = new \WP_User( 44, array( 'editor', 'shop_manager' ) );

		self::assertTrue( Policy::allows( $user, 'totp' ) );
		self::assertFalse( Policy::allows( $user, 'passkey' ), 'the passkey beta needs the consent of both roles' );
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

	public function test_on_a_network_the_strictest_site_decides(): void {
		$GLOBALS['mdmfa_test']['multisite']  = true;
		$GLOBALS['mdmfa_test']['blog_id']    = 2;
		$GLOBALS['mdmfa_test']['user_blogs'] = array( 7 => array( 1, 2 ), 8 => array( 2 ) );
		// Site 2 (current): subscribers are Off. Site 1: the same person is an editor (Required).
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ]                    = array( 'roles' => array( 'subscriber' => array( 'policy' => 'off' ) ) );
		$GLOBALS['mdmfa_test']['usermeta'][7]['wp_capabilities']                  = array( 'editor' => true );
		$GLOBALS['mdmfa_test']['usermeta'][7]['wp_2_capabilities']                = array( 'subscriber' => true );
		$GLOBALS['mdmfa_test']['usermeta'][7][ Policy::GRACE_META ]               = (string) ( self::T0 - 30 * DAY_IN_SECONDS );
		$user = new \WP_User( 7, array( 'subscriber' ) );

		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( $user ), 'Required on site 1 follows the user to site 2' );
		self::assertSame( Policy::ENROLL, Policy::decide( $user ), 'a password alone gets no network-wide session here' );
		self::assertTrue( Policy::is_subject( $user ) );

		// A capability row left behind by a deleted site sets no policy.
		$GLOBALS['mdmfa_test']['usermeta'][10]['wp_capabilities']   = array( 'editor' => true );
		$GLOBALS['mdmfa_test']['usermeta'][10]['wp_2_capabilities'] = array( 'subscriber' => true );
		$GLOBALS['mdmfa_test']['deleted_sites']                     = array( 1 );
		self::assertSame( Settings::POLICY_OFF, Policy::policy( new \WP_User( 10, array( 'subscriber' ) ) ) );
		$GLOBALS['mdmfa_test']['deleted_sites'] = array();

		// Someone who only belongs to site 2 follows site 2.
		self::assertSame( Settings::POLICY_OFF, Policy::policy( new \WP_User( 8, array( 'subscriber' ) ) ) );
	}

	public function test_on_a_network_an_enrolled_account_is_challenged_even_where_the_policy_is_off(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'subscriber' => array( 'policy' => 'off' ) ) );
		$user = new \WP_User( 9, array( 'subscriber' ) );
		$this->enroll( 9 );

		self::assertSame( Policy::NONE, Policy::decide( $user ), 'single site: Off means off' );
		self::assertFalse( Policy::is_subject( $user ) );

		$GLOBALS['mdmfa_test']['multisite'] = true;
		self::assertSame( Policy::CHALLENGE, Policy::decide( $user ), 'network: one site cannot switch another site\'s protection off' );
		self::assertTrue( Policy::is_subject( $user ) );
	}

	public function test_passkeys_are_a_beta_and_off_for_every_role_by_default(): void {
		foreach ( array( 'administrator', 'editor', 'shop_manager', 'customer', 'subscriber' ) as $i => $role ) {
			$user = new \WP_User( 20 + $i, array( $role ) );
			self::assertFalse( Policy::allows( $user, 'passkey' ), $role );
			self::assertTrue( Policy::allows( $user, 'totp' ), $role );
		}
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'editor' => array( 'factors' => array( 'passkey' => true ) ) ) );
		self::assertTrue( Policy::allows( new \WP_User( 30, array( 'editor' ) ), 'passkey' ), 'the owner turns them on per role' );
	}

	public function test_a_stored_passkey_only_setting_has_no_effect_without_the_site_constant(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'editor' => array( 'factors' => array( 'passkey' => true ), 'passwordless' => true ) ) );

		self::assertFalse( \MaxtDesign\Mfa\Factors\Passkeys::passkey_only_enabled() );
		self::assertFalse( Policy::effective( new \WP_User( 31, array( 'editor' ) ) )['passwordless'] );
		self::assertFalse( \MaxtDesign\Mfa\Factors\Passkeys::passwordless_offered() );
		self::assertFalse( Settings::sanitize_role( array( 'factors' => array( 'passkey' => '1' ), 'passwordless' => '1' ), array() )['passwordless'], 'and it cannot be saved either' );
	}

	#[RunInSeparateProcess]
	public function test_the_site_constant_opts_in_to_passkey_only_sign_in(): void {
		define( 'MDMFA_PASSKEY_ONLY_SIGNIN', true );
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'roles' => array( 'editor' => array( 'factors' => array( 'passkey' => true ), 'passwordless' => true ) ) );

		self::assertTrue( Policy::effective( new \WP_User( 32, array( 'editor' ) ) )['passwordless'] );
		self::assertTrue( Settings::sanitize_role( array( 'factors' => array( 'passkey' => '1' ), 'passwordless' => '1' ), array() )['passwordless'] );
		self::assertFalse( Settings::sanitize_role( array( 'factors' => array( 'totp' => '1' ), 'passwordless' => '1' ), array() )['passwordless'], 'still needs the passkey method' );
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
