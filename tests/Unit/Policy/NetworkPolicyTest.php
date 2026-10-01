<?php
/**
 * Independent review 2026-10-01, finding F1: on a network the strictest site used to raise
 * the policy mode only, and recovery, grace and application passwords still came from the
 * site being visited. Each test here looks at the consequences (recovery, grace, side
 * doors, methods, trust), from both sites, not at the policy value alone.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Policy;

use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;
use PHPUnit\Framework\TestCase;

// phpcs:ignoreFile

final class NetworkPolicyTest extends TestCase {

	private const T0 = 1800000000;

	private const ROLES = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber', 'customer', 'shop_manager' );

	/**
	 * Stored settings per site.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $sites = array();

	protected function setUp(): void {
		mdmfa_test_reset();
		Clock::freeze( self::T0 );
		$GLOBALS['mdmfa_test']['multisite'] = true;
		$this->sites                        = array();
	}

	/**
	 * Gives a site its stored settings (merged over the defaults by the plugin).
	 *
	 * @param array<string, mixed> $settings
	 */
	private function site( int $blog_id, array $settings ): void {
		$this->sites[ $blog_id ]                                              = $settings;
		$GLOBALS['mdmfa_test']['blog_options'][ $blog_id ]['mdmfa_settings'] = $settings;
	}

	private function member( int $user_id, int $blog_id, string $role ): void {
		$GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ ( 1 === $blog_id ? 'wp_' : 'wp_' . $blog_id . '_' ) . 'capabilities' ] = array( $role => true );
	}

	private function enroll( int $user_id ): void {
		$GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ TotpStore::META ] = array(
			'ct'    => 'x',
			'nonce' => 'y',
			'kid'   => 'z',
		);
	}

	/**
	 * The user as WordPress sees them on a request to one site: that site's settings are the
	 * current options, the roles are that site's roles.
	 */
	private function visit( int $user_id, int $blog_id ): \WP_User {
		$GLOBALS['mdmfa_test']['blog_id'] = $blog_id;
		$GLOBALS['wpdb']->prefix          = 1 === $blog_id ? 'wp_' : 'wp_' . $blog_id . '_';
		unset( $GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] );
		if ( isset( $this->sites[ $blog_id ] ) ) {
			$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = $this->sites[ $blog_id ];
		}
		Policy::forget();
		$caps = $GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ $GLOBALS['wpdb']->prefix . 'capabilities' ] ?? array();

		// WP_User::$roles: the capability keys that name a registered role.
		return new \WP_User( $user_id, array_values( array_intersect( array_keys( $caps ), self::ROLES ) ) );
	}

	/**
	 * What the user may do, as the callers ask it.
	 *
	 * @return array<string, mixed>
	 */
	private function consequences( \WP_User $user ): array {
		$effective = Policy::effective( $user );

		return array(
			'policy'          => Policy::policy( $user ),
			'grace_days'      => $effective['grace_days'],
			'email_recovery'  => EmailRecovery::allowed( $user ),
			'recovery_wait'   => $effective['recovery_wait_hours'],
			'app_passwords'   => SideDoors::app_passwords_for_user( true, $user ),
			'trusted_devices' => TrustedDevice::allowed( $user ),
			'trusted_seconds' => TrustedDevice::lifetime( $user ),
			'email_codes'     => EmailCode::allowed( $user ),
			'totp'            => Policy::allows( $user, 'totp' ),
			'passkey'         => Policy::allows( $user, 'passkey' ),
			'passwordless'    => $effective['passwordless'],
		);
	}

	public function test_the_reviews_reproduction_a_strict_staff_site_and_a_lenient_customer_site(): void {
		// Site 1: administrators Required, no email recovery, no grace. Site 2: defaults,
		// where customers are Optional with immediate email recovery, 7 days and app passwords.
		$this->site( 1, array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) ) );
		$this->member( 43, 1, 'administrator' );
		$this->member( 43, 2, 'customer' );
		$this->enroll( 43 );

		$expected = array(
			'policy'          => Settings::POLICY_REQUIRED,
			'grace_days'      => 0,
			'email_recovery'  => false,
			'recovery_wait'   => 24,
			'app_passwords'   => false,
			'trusted_devices' => false,
			'trusted_seconds' => 30 * DAY_IN_SECONDS,
			'email_codes'     => false,
			'totp'            => true,
			'passkey'         => false,
			'passwordless'    => false,
		);

		self::assertSame( $expected, $this->consequences( $this->visit( 43, 2 ) ), 'entering through the customer site' );
		self::assertSame( $expected, $this->consequences( $this->visit( 43, 1 ) ), 'entering through the staff site' );
		self::assertSame( Policy::effective( $this->visit( 43, 1 ) ), Policy::effective( $this->visit( 43, 2 ) ), 'one identity, one policy' );
	}

	public function test_a_reset_restarts_the_strict_grace_not_the_lenient_one(): void {
		$this->site( 1, array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) ) );
		$this->member( 44, 1, 'administrator' );
		$this->member( 44, 2, 'customer' );
		// After a reset the grace clock starts again at the next sign-in, here on site 2.
		$user = $this->visit( 44, 2 );
		Policy::maybe_start_grace( $user );

		self::assertSame( (string) self::T0, $GLOBALS['mdmfa_test']['usermeta'][44][ Policy::GRACE_META ] );
		self::assertSame( 0, Policy::grace_remaining( $user ) );
		self::assertSame( Policy::ENROLL, Policy::decide( $user ), 'no seven days of password-only sign-in through the customer site' );
		self::assertSame( Policy::ENROLL, Policy::decide( $this->visit( 44, 1 ) ) );
	}

	public function test_sites_of_equal_rank_keep_each_others_restrictions(): void {
		// Both sites Require. Each is the stricter one on something.
		$this->site(
			1,
			array(
				'roles'               => array(
					'editor' => array(
						'grace_days'          => 3,
						'email_recovery'      => true,
						'recovery_wait_hours' => 48,
						'app_passwords'       => true,
						'trusted_devices'     => true,
						'factors'             => array( 'email' => true, 'passkey' => true ),
					),
				),
				'trusted_device_days' => 7,
			)
		);
		$this->site(
			2,
			array(
				'roles'               => array(
					'shop_manager' => array(
						'grace_days'          => 10,
						'email_recovery'      => true,
						'recovery_wait_hours' => 0,
						'app_passwords'       => false,
						'trusted_devices'     => true,
						'factors'             => array( 'email' => false, 'passkey' => true ),
					),
				),
				'trusted_device_days' => 60,
			)
		);
		$this->member( 45, 1, 'editor' );
		$this->member( 45, 2, 'shop_manager' );

		$expected = array(
			'policy'          => Settings::POLICY_REQUIRED,
			'grace_days'      => 3,
			'email_recovery'  => true,
			'recovery_wait'   => 48,
			'app_passwords'   => false,
			'trusted_devices' => true,
			'trusted_seconds' => 7 * DAY_IN_SECONDS,
			'email_codes'     => false,
			'totp'            => true,
			'passkey'         => true,
			'passwordless'    => false,
		);
		self::assertSame( $expected, $this->consequences( $this->visit( 45, 1 ) ) );
		self::assertSame( $expected, $this->consequences( $this->visit( 45, 2 ) ) );

		// One site withdraws recovery and trust: nobody may use them, wherever they sign in.
		$this->sites[2]['roles']['shop_manager']['email_recovery']  = false;
		$this->sites[2]['roles']['shop_manager']['trusted_devices'] = false;
		$this->site( 2, $this->sites[2] );
		foreach ( array( 1, 2 ) as $entry ) {
			$now = $this->consequences( $this->visit( 45, $entry ) );
			self::assertFalse( $now['email_recovery'], "site {$entry}" );
			self::assertFalse( $now['trusted_devices'], "site {$entry}" );
		}
	}

	public function test_grace_comes_only_from_sites_that_require_setup(): void {
		// A setup period on a site that does not require setup is not a rule about anything.
		$this->site( 1, array( 'roles' => array( 'administrator' => array( 'grace_days' => 5 ) ) ) );
		$this->site( 2, array( 'roles' => array( 'customer' => array( 'grace_days' => 0 ) ) ) );
		$this->member( 46, 1, 'administrator' );
		$this->member( 46, 2, 'customer' );

		foreach ( array( 1, 2 ) as $entry ) {
			$user = $this->visit( 46, $entry );
			self::assertSame( 5, Policy::effective( $user )['grace_days'], "site {$entry}" );
		}
		$user = $this->visit( 46, 2 );
		Policy::maybe_start_grace( $user );
		self::assertSame( 5 * DAY_IN_SECONDS, Policy::grace_remaining( $user ) );
		self::assertSame( Policy::GRACE, Policy::decide( $user ) );
	}

	public function test_a_sites_application_password_mode_cannot_open_the_door_for_another_sites_staff(): void {
		// Site 2 switches application passwords on for everybody. Site 1 keeps them per role.
		$this->site( 2, array( 'application_passwords' => 'on' ) );
		$this->member( 47, 1, 'administrator' );
		$this->member( 47, 2, 'customer' );
		$this->member( 48, 2, 'customer' );

		self::assertFalse( SideDoors::app_passwords_for_user( true, $this->visit( 47, 2 ) ), 'the administrator of site 1 authenticating on site 2' );
		self::assertFalse( SideDoors::app_passwords_for_user( true, $this->visit( 47, 1 ) ) );
		self::assertTrue( SideDoors::app_passwords_for_user( true, $this->visit( 48, 2 ) ), 'someone who only belongs to site 2 follows site 2' );
		self::assertFalse( SideDoors::app_passwords_for_user( false, $this->visit( 48, 2 ) ), 'never turned on where core turned them off' );

		// And a site that switched them off takes them from its members everywhere.
		$this->site( 1, array( 'application_passwords' => 'off', 'roles' => array( 'subscriber' => array( 'app_passwords' => true ) ) ) );
		$this->member( 49, 1, 'subscriber' );
		$this->member( 49, 2, 'customer' );
		self::assertFalse( SideDoors::app_passwords_for_user( true, $this->visit( 49, 2 ) ) );
	}

	public function test_sites_that_share_no_strong_method_still_let_a_required_user_enroll(): void {
		$this->site( 1, array( 'roles' => array( 'editor' => array( 'factors' => array( 'totp' => true, 'passkey' => false ) ) ) ) );
		$this->site( 2, array( 'roles' => array( 'editor' => array( 'factors' => array( 'totp' => false, 'passkey' => true ) ) ) ) );
		$this->member( 50, 1, 'editor' );
		$this->member( 50, 2, 'editor' );

		foreach ( array( 1, 2 ) as $entry ) {
			$user = $this->visit( 50, $entry );
			self::assertTrue( Policy::allows( $user, 'totp' ), "site {$entry}: an authenticator app stays available" );
			self::assertFalse( Policy::allows( $user, 'passkey' ), "site {$entry}: the passkey beta needs every site's consent" );
			self::assertTrue( Policy::allows( $user, 'recovery' ) );
		}
	}

	public function test_a_super_admin_is_required_and_still_bound_by_every_sites_restrictions(): void {
		$GLOBALS['mdmfa_test']['super_admins'] = array( 51 );
		$this->site( 2, array( 'roles' => array( 'subscriber' => array( 'policy' => 'off', 'email_recovery' => true, 'app_passwords' => true ) ) ) );
		$this->member( 51, 1, 'administrator' );
		$this->member( 51, 2, 'subscriber' );

		foreach ( array( 1, 2 ) as $entry ) {
			$now = $this->consequences( $this->visit( 51, $entry ) );
			self::assertSame( Settings::POLICY_REQUIRED, $now['policy'], "site {$entry}" );
			self::assertFalse( $now['email_recovery'], "site {$entry}" );
			self::assertFalse( $now['app_passwords'], "site {$entry}" );
		}
	}

	public function test_a_member_of_one_site_gets_exactly_that_sites_configuration(): void {
		$this->site( 1, array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) ) );
		$this->member( 52, 2, 'customer' );
		// A capability row left behind by a deleted site contributes nothing.
		$this->member( 53, 1, 'administrator' );
		$this->member( 53, 2, 'customer' );
		$GLOBALS['mdmfa_test']['deleted_sites'] = array( 1 );

		$expected = array(
			'policy'          => Settings::POLICY_OPTIONAL,
			'grace_days'      => 7,
			'email_recovery'  => true,
			'recovery_wait'   => 0,
			'app_passwords'   => true,
			'trusted_devices' => false,
			'trusted_seconds' => 30 * DAY_IN_SECONDS,
			'email_codes'     => true,
			'totp'            => true,
			'passkey'         => false,
			'passwordless'    => false,
		);
		self::assertSame( $expected, $this->consequences( $this->visit( 52, 2 ) ) );
		self::assertSame( $expected, $this->consequences( $this->visit( 53, 2 ) ) );
	}

	public function test_a_site_that_accepts_passwords_over_xmlrpc_cannot_open_that_for_another_sites_staff(): void {
		$this->site( 2, array( 'xmlrpc' => 'allow' ) );
		$this->member( 55, 1, 'administrator' );
		$this->member( 55, 2, 'customer' );
		$this->member( 56, 2, 'customer' );

		self::assertFalse( Policy::effective( $this->visit( 55, 2 ) )['xmlrpc_password'], 'site 1 still blocks account passwords' );
		self::assertFalse( Policy::effective( $this->visit( 55, 1 ) )['xmlrpc_password'] );
		self::assertTrue( Policy::effective( $this->visit( 56, 2 ) )['xmlrpc_password'], 'someone who only belongs to site 2 follows site 2' );
	}

	public function test_every_site_counts_however_many_there_are(): void {
		// The one strict site is the last of sixty memberships.
		for ( $blog_id = 2; $blog_id <= 61; $blog_id++ ) {
			$this->member( 57, $blog_id, 'customer' );
		}
		$this->site( 61, array( 'roles' => array( 'customer' => array( 'policy' => 'required', 'email_recovery' => false, 'app_passwords' => false ) ) ) );

		$now = $this->consequences( $this->visit( 57, 2 ) );

		self::assertSame( Settings::POLICY_REQUIRED, $now['policy'] );
		self::assertFalse( $now['email_recovery'] );
		self::assertFalse( $now['app_passwords'] );
	}

	public function test_a_capability_that_is_not_a_role_does_not_change_which_role_governs(): void {
		// Site 2: administrators Optional, every unlisted role Required. A direct capability
		// in the same row is not a role, on either side of the comparison.
		$this->site( 2, array( 'roles' => array( 'administrator' => array( 'policy' => 'optional' ) ), 'unlisted_role' => array( 'policy' => 'required' ) ) );
		$GLOBALS['mdmfa_test']['usermeta'][58]['wp_2_capabilities'] = array( 'administrator' => true, 'manage_stuff' => true );
		$this->member( 58, 1, 'subscriber' );

		self::assertSame( Settings::POLICY_OPTIONAL, Policy::policy( $this->visit( 58, 2 ) ) );
		self::assertSame( Settings::POLICY_OPTIONAL, Policy::policy( $this->visit( 58, 1 ) ), 'site 1 reads site 2 the way site 2 reads itself' );
		self::assertSame( Policy::effective( $this->visit( 58, 2 ) ), Policy::effective( $this->visit( 58, 1 ) ) );

		// A membership with no role at all falls to that site's unlisted configuration.
		$GLOBALS['mdmfa_test']['usermeta'][59]['wp_2_capabilities'] = array();
		$this->member( 59, 1, 'subscriber' );
		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( $this->visit( 59, 1 ) ) );
		self::assertSame( Settings::POLICY_REQUIRED, Policy::policy( $this->visit( 59, 2 ) ) );
	}

	public function test_reading_other_sites_never_switches_blogs(): void {
		// Switching re-enters the current-user lookup during application-password checks.
		$this->member( 54, 1, 'administrator' );
		$this->member( 54, 2, 'customer' );
		$user = $this->visit( 54, 2 );

		SideDoors::app_passwords_for_user( true, $user );

		self::assertSame( 'wp_2_', $GLOBALS['wpdb']->prefix, 'the current site was never changed' );
		self::assertCount( 1, array_filter( $GLOBALS['wpdb']->queries, static fn ( string $q ): bool => str_contains( $q, 'mdmfa_settings' ) ), 'one settings row for the other site, read once' );
	}
}
