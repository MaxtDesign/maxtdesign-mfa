<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Integrations\Conflicts;
use MaxtDesign\Mfa\Integrations\Jetpack;
use MaxtDesign\Mfa\Settings\Options;
use PHPUnit\Framework\TestCase;

final class SideDoorsTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
		// A request that carries credentials: the only front-end case where the answer matters.
		$_SERVER['PHP_AUTH_USER'] = 'someone';
	}

	public function test_a_plain_page_view_never_reads_the_settings(): void {
		unset( $_SERVER['PHP_AUTH_USER'] );
		self::settings( array( 'application_passwords' => 'off' ) );
		$reads = 0;
		add_filter(
			'mdmfa_test_get_option',
			static function ( string $option ) use ( &$reads ): string {
				$reads += 'mdmfa_settings' === $option ? 1 : 0;
				return $option;
			}
		);

		self::assertTrue( SideDoors::app_passwords_available( true ), 'core asks on every request; a page view passes through' );
		self::assertSame( 0, $reads, 'and costs no option read (the settings are not autoloaded)' );

		$GLOBALS['mdmfa_test']['is_admin'] = true;
		self::assertFalse( SideDoors::app_passwords_available( true ), 'wp-admin gets the real answer' );
		self::assertSame( 1, $reads );
	}

	private static function settings( array $settings ): void {
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = $settings;
	}

	public function test_application_passwords_default_to_per_role(): void {
		$admin      = new \WP_User( 2, array( 'administrator' ) );
		$customer   = new \WP_User( 3, array( 'customer' ) );
		$subscriber = new \WP_User( 4, array( 'subscriber' ) );

		self::assertSame( SideDoors::APP_PER_ROLE, SideDoors::app_password_mode() );
		self::assertTrue( SideDoors::app_passwords_available( true ) );
		self::assertFalse( SideDoors::app_passwords_for_user( true, $admin ), 'Required roles have none by default' );
		self::assertTrue( SideDoors::app_passwords_for_user( true, $customer ) );
		self::assertTrue( SideDoors::app_passwords_for_user( true, $subscriber ), 'unlisted roles are Optional' );
	}

	public function test_the_owner_can_allow_them_for_a_required_role(): void {
		self::settings( array( 'roles' => array( 'administrator' => array( 'app_passwords' => true ) ) ) );

		self::assertTrue( SideDoors::app_passwords_for_user( true, new \WP_User( 2, array( 'administrator' ) ) ) );
		self::assertFalse( SideDoors::app_passwords_for_user( true, new \WP_User( 3, array( 'editor' ) ) ) );
	}

	public function test_off_and_on_modes(): void {
		$admin = new \WP_User( 2, array( 'administrator' ) );

		self::settings( array( 'application_passwords' => 'off' ) );
		self::assertFalse( SideDoors::app_passwords_available( true ) );

		self::settings( array( 'application_passwords' => 'on' ) );
		self::assertTrue( SideDoors::app_passwords_available( true ) );
		self::assertTrue( SideDoors::app_passwords_for_user( true, $admin ) );

		self::settings( array( 'application_passwords' => 'bogus' ) );
		self::assertSame( SideDoors::APP_PER_ROLE, SideDoors::app_password_mode(), 'an unknown value falls back to the default' );
	}

	public function test_never_turns_on_what_core_or_another_plugin_turned_off(): void {
		self::settings( array( 'application_passwords' => 'on' ) );

		self::assertFalse( SideDoors::app_passwords_available( false ) );
		self::assertFalse( SideDoors::app_passwords_for_user( false, new \WP_User( 3, array( 'customer' ) ) ) );
	}

	public function test_xmlrpc_modes(): void {
		self::assertSame( SideDoors::XMLRPC_BLOCK, SideDoors::xmlrpc_mode() );
		self::assertTrue( SideDoors::xmlrpc_enabled( true ), 'the default refuses passwords, not the endpoint' );

		self::settings( array( 'xmlrpc' => 'off' ) );
		self::assertFalse( SideDoors::xmlrpc_enabled( true ) );

		self::settings( array( 'xmlrpc' => 'allow' ) );
		self::assertTrue( SideDoors::xmlrpc_enabled( true ) );
		self::assertFalse( SideDoors::xmlrpc_enabled( false ) );
	}

	public function test_application_password_use_is_logged_once_an_hour_per_password(): void {
		$user = new \WP_User( 3, array( 'customer' ) );

		SideDoors::log_app_password( $user, array( 'uuid' => 'aaaa-1' ) );
		SideDoors::log_app_password( $user, array( 'uuid' => 'aaaa-1' ) );
		SideDoors::log_app_password( $user, array( 'uuid' => 'bbbb-2' ) );

		$events = array_column( array_column( $GLOBALS['mdmfa_test']['inserts'], 1 ), 'event' );
		self::assertSame( array( 'app_password_used', 'app_password_used' ), $events );
	}

	public function test_jetpack_sso_module_is_removed_only_when_the_owner_blocks_it(): void {
		$modules = array( 'sso' => '2.6', 'stats' => '1.1' );

		self::assertSame( $modules, Jetpack::filter_modules( $modules ), 'default: the bypass guard challenges SSO instead' );
		self::assertFalse( Jetpack::sso_blocked() );

		self::settings( array( 'block_wpcom_sso' => true ) );
		self::assertSame( array( 'stats' => '1.1' ), Jetpack::filter_modules( $modules ) );
		self::assertSame( 'not-an-array', Jetpack::filter_modules( 'not-an-array' ) );
	}

	public function test_conflict_detector_reports_other_two_factor_plugins(): void {
		self::assertSame( array(), Conflicts::detect() );

		add_filter( 'mdmfa_conflicts', static fn ( array $found ): array => array_merge( $found, array( 'Two Factor', 7 ) ) );
		self::assertSame( array( 'Two Factor' ), Conflicts::detect(), 'non-string entries are dropped' );
	}
}
