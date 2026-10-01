<?php
/**
 * Independent review 2026-10-01, finding F2, against real WordPress + WooCommerce over HTTP
 * (CI job "e2e-wc"). With WooCommerce active, its Security tab handler (wp_loaded) used to
 * run wp-admin's security forms before Users > My security did, so a first setup in
 * wp-admin enrolled the user, showed "Setup expired" and never showed the recovery codes.
 * Each operation must run once, in the presenter that rendered the form.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2eWc;

use MaxtDesign\Mfa\Support\Base32;
use MaxtDesign\Mfa\Tests\E2e\Browser;
use MaxtDesign\Mfa\Tests\E2e\E2eTestCase;
use MaxtDesign\Mfa\Tests\E2e\Response;
use MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator;

// phpcs:ignoreFile

final class SecurityPresentersTest extends E2eTestCase {

	private const ADMIN_PAGE = 'wp-admin/users.php?page=mdmfa-account';
	private const CODES      = '/<li><code>([A-Z2-7]{4}(?:-[A-Z2-7]{4}){3})<\/code><\/li>/';

	private static string $account = '';
	private static string $tab     = '';

	protected function setUp(): void {
		parent::setUp();
		if ( '' === self::$account ) {
			self::assertSame( 'yes', self::eval( 'echo class_exists( "WooCommerce" ) ? "yes" : "no";' ), 'this suite needs WooCommerce active' );
			self::$account = self::eval( 'echo wc_get_page_permalink( "myaccount" );' );
			self::$tab     = self::eval( 'echo wc_get_account_endpoint_url( "mdmfa-security" );' );
		}
		// The condition the defect needs: WooCommerce's notice functions exist in wp-admin
		// (see the fixture). Without it WooCommerce's handler had nothing to call and stood down.
		self::wp( 'option', 'update', 'e2e_wc_cart_in_admin', '1' );
	}

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::wp( 'option', 'delete', 'e2e_wc_cart_in_admin' );
			self::reset_settings();
		}
		parent::tearDown();
	}

	/**
	 * An administrator signed in through the login page, in the setup period (nothing set up).
	 *
	 * @return array{Browser, int}
	 */
	private function administrator(): array {
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$browser                   = $this->browser();
		$first                     = $this->password( $browser, $login, $pass );
		$page                      = $browser->get( $first->location() );
		$skip                      = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_skip' => '1' ) );
		self::assertTrue( $skip->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		return array( $browser, $id );
	}

	/**
	 * A customer signed in through My Account.
	 *
	 * @return array{Browser, int}
	 */
	private function customer(): array {
		list( $id, $login, $pass ) = self::user( 'customer' );
		$browser                   = $this->browser();
		$page                      = $browser->get( self::$account );
		$in                        = $browser->post(
			self::$account,
			array(
				'username'                => $login,
				'password'                => $pass,
				'login'                   => 'Log in',
				'woocommerce-login-nonce' => $page->input( 'woocommerce-login-nonce' ),
			)
		);
		self::assertTrue( $in->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		return array( $browser, $id );
	}

	/**
	 * Posts an operation with the nonce of the page it is posted to, as that page's form does.
	 *
	 * @param array<string, string> $fields
	 */
	private function op( Browser $browser, string $page, string $op, array $fields = array() ): Response {
		return $browser->post( $page, array_merge( array( 'mdmfa_op' => $op, '_wpnonce' => $browser->get( $page )->input( '_wpnonce' ) ), $fields ) );
	}

	/**
	 * Starts authenticator setup on a page and returns the secret it shows.
	 */
	private function begin_totp( Browser $browser, string $page ): string {
		$begin = $this->op( $browser, $page, 'totp_begin' );
		self::assertSame( 302, $begin->status );
		self::assertStringContainsString( 'view=totp', $begin->location() );
		$setup = $browser->get( $begin->location() );
		self::assertSame( 1, preg_match( '/<code class="mdmfa-secret">([A-Z2-7 ]+)<\/code>/', $setup->body, $m ), 'the setup view shows the key' );
		return (string) Base32::decode( $m[1] );
	}

	/**
	 * @return string[]
	 */
	private static function shown_codes( Response $response ): array {
		preg_match_all( self::CODES, $response->body, $m );
		return $m[1];
	}

	/**
	 * Log rows of one event for the user.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function events( int $user_id, string $event ): array {
		return array_values( array_filter( self::log_events( $user_id ), static fn ( array $row ): bool => $event === $row['event'] ) );
	}

	private static function remaining( int $user_id ): int {
		return (int) self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\RecoveryCodes::remaining( %d );', $user_id ) );
	}

	private static function has_totp( int $user_id ): bool {
		return 'true' === self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $user_id ) );
	}

	public function test_first_authenticator_setup_in_wp_admin_shows_the_recovery_codes_there_once(): void {
		list( $browser, $id ) = $this->administrator();
		self::assertSame( '1', $browser->get( self::ADMIN_PAGE )->headers['x-e2e-wc-notices'] ?? '', 'WooCommerce\'s notice functions are loaded on this wp-admin request' );
		$secret               = $this->begin_totp( $browser, self::ADMIN_PAGE );
		$fields               = array( 'mdmfa_op' => 'totp_confirm', '_wpnonce' => $browser->get( self::ADMIN_PAGE . '&view=totp' )->input( '_wpnonce' ), 'mdmfa_code' => self::code( $secret ) );

		$confirm = $browser->post( self::ADMIN_PAGE, $fields );

		self::assertSame( 200, $confirm->status, 'the codes render in this response, on the wp-admin page: ' . $confirm->location() );
		self::assertStringContainsString( '<div class="wrap"><h1>My security</h1>', $confirm->body );
		$codes = self::shown_codes( $confirm );
		self::assertCount( 10, $codes, 'ten recovery codes are shown' );
		self::assertCount( 10, array_unique( $codes ) );
		self::assertStringNotContainsString( 'Setup expired', $confirm->body );
		self::assertTrue( self::has_totp( $id ) );
		self::assertSame( 10, self::remaining( $id ) );

		$enrolled = self::events( $id, 'enrolled' );
		self::assertCount( 1, $enrolled, 'the operation ran exactly once' );
		self::assertSame( 'account', $enrolled[0]['context'], 'and the wp-admin presenter ran it' );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );

		// The codes are shown once: a reload or a resubmission shows none and changes nothing.
		self::assertSame( array(), self::shown_codes( $browser->get( self::ADMIN_PAGE ) ) );
		$again = $browser->post( self::ADMIN_PAGE, $fields );
		self::assertSame( 302, $again->status );
		self::assertStringContainsString( 'wp-admin/users.php?page=mdmfa-account', $again->location() );
		self::assertStringContainsString( 'mdmfa_notice=setup_expired', $again->location() );
		self::assertSame( 10, self::remaining( $id ) );
		self::assertCount( 1, self::events( $id, 'enrolled' ) );

		// Nothing was queued for the shop's own screen.
		$shop = $browser->get( self::$tab );
		self::assertStringNotContainsString( 'Two-step verification is on.', $shop->body, 'no WooCommerce notice from a wp-admin action' );
		self::assertSame( array(), self::shown_codes( $shop ) );
	}

	public function test_first_authenticator_setup_in_wp_admin_on_plain_woocommerce(): void {
		// WooCommerce alone: no notice functions in wp-admin. The result must be the same.
		self::wp( 'option', 'delete', 'e2e_wc_cart_in_admin' );
		list( $browser, $id ) = $this->administrator();
		self::assertSame( '0', $browser->get( self::ADMIN_PAGE )->headers['x-e2e-wc-notices'] ?? '' );
		$secret = $this->begin_totp( $browser, self::ADMIN_PAGE );

		$confirm = $this->op( $browser, self::ADMIN_PAGE . '&view=totp', 'totp_confirm', array( 'mdmfa_code' => self::code( $secret ) ) );

		self::assertSame( 200, $confirm->status );
		self::assertCount( 10, self::shown_codes( $confirm ) );
		self::assertCount( 1, self::events( $id, 'enrolled' ) );
		self::assertSame( 'account', self::events( $id, 'enrolled' )[0]['context'] );
	}

	public function test_wp_admin_step_up_and_new_recovery_codes_stay_in_wp_admin(): void {
		list( $browser, $id ) = $this->administrator();
		$secret               = $this->begin_totp( $browser, self::ADMIN_PAGE );
		$first                = self::shown_codes( $this->op( $browser, self::ADMIN_PAGE . '&view=totp', 'totp_confirm', array( 'mdmfa_code' => self::code( $secret ) ) ) );
		self::assertCount( 10, $first );
		self::age_sessions( $id );

		// Without a recent verification: refused, back on the wp-admin page.
		$refused = $this->op( $browser, self::ADMIN_PAGE, 'recovery_generate' );
		self::assertSame( 302, $refused->status );
		self::assertStringContainsString( 'wp-admin/users.php?page=mdmfa-account', $refused->location(), 'a wp-admin post never lands on My Account' );
		self::assertStringContainsString( 'mdmfa_notice=stepup_needed', $refused->location() );
		self::assertStringContainsString( 'Confirm it is you with a code first.', $browser->get( $refused->location() )->body );
		self::assertSame( array(), self::events( $id, 'recovery_regenerated' ) );

		// A wrong code fails there too; the right one confirms.
		$wrong = $this->op( $browser, self::ADMIN_PAGE, 'stepup', array( 'mdmfa_method' => 'totp', 'mdmfa_code' => self::wrong_code( $secret ) ) );
		self::assertStringContainsString( 'wp-admin/users.php?page=mdmfa-account', $wrong->location() );
		self::assertStringContainsString( 'mdmfa_notice=code_invalid', $wrong->location() );
		$ok = $this->op( $browser, self::ADMIN_PAGE, 'stepup', array( 'mdmfa_method' => 'totp', 'mdmfa_code' => self::code( $secret, 1 ) ) );
		self::assertStringContainsString( 'wp-admin/users.php?page=mdmfa-account', $ok->location() );
		self::assertStringContainsString( 'mdmfa_notice=stepup_ok', $ok->location(), 'the code was used once, by the wp-admin page' );

		$new = $this->op( $browser, self::ADMIN_PAGE, 'recovery_generate' );
		self::assertSame( 200, $new->status );
		$codes = self::shown_codes( $new );
		self::assertCount( 10, $codes, 'the new set is shown on the wp-admin page' );
		self::assertSame( array(), array_intersect( $first, $codes ), 'and it is a new set' );
		self::assertSame( 10, self::remaining( $id ) );
		self::assertCount( 1, self::events( $id, 'recovery_regenerated' ), 'generated exactly once' );
		self::assertSame( 'account', self::events( $id, 'recovery_regenerated' )[0]['context'] );

		$shop = $browser->get( self::$tab );
		foreach ( array( 'Confirm it is you with a code first.', 'That code is not valid.', 'Confirmed. You can make changes', 'New recovery codes created.' ) as $notice ) {
			self::assertStringNotContainsString( $notice, $shop->body, 'no WooCommerce notice from a wp-admin action' );
		}
	}

	public function test_first_passkey_in_wp_admin_shows_the_recovery_codes_there_once(): void {
		self::settings( array( 'roles' => array( 'administrator' => array( 'factors' => array( 'passkey' => true ) ) ) ) );
		list( $browser, $id ) = $this->administrator();

		$forms = $browser->get( self::ADMIN_PAGE )->passkey_forms();
		self::assertCount( 1, $forms );
		self::assertStringContainsString( 'wp-admin/users.php?page=mdmfa-account', $forms[0]['action'] );
		$authenticator = new VirtualAuthenticator();
		$added         = $this->submit_passkey( $browser, $forms[0], $authenticator->create( $forms[0]['config']['options'], self::origin() ), array( 'mdmfa_passkey_name' => 'Office' ) );

		self::assertSame( 200, $added->status, 'the codes render on the wp-admin page: ' . $added->location() );
		self::assertCount( 10, self::shown_codes( $added ) );
		self::assertSame( 1, self::passkey_count( $id ), 'the passkey was registered once' );
		self::assertSame( 10, self::remaining( $id ) );
		self::assertStringContainsString( 'Passkeys (beta)', $added->body, 'still labelled a beta' );
		self::assertStringNotContainsString( 'Passkey added.', $browser->get( self::$tab )->body, 'no WooCommerce notice from a wp-admin action' );
	}

	public function test_my_account_setup_step_up_and_new_codes_stay_on_my_account(): void {
		list( $browser, $id ) = $this->customer();
		$secret               = $this->begin_totp( $browser, self::$tab );

		$confirm = $this->op( $browser, self::$tab, 'totp_confirm', array( 'mdmfa_code' => self::code( $secret ) ) );
		self::assertSame( 200, $confirm->status );
		$first = self::shown_codes( $confirm );
		self::assertCount( 10, $first, 'ten recovery codes on the Security tab' );
		self::assertStringContainsString( 'Two-step verification is on.', $confirm->body );
		self::assertStringContainsString( 'woocommerce-MyAccount-content', $confirm->body, 'rendered inside My Account' );
		$enrolled = self::events( $id, 'enrolled' );
		self::assertCount( 1, $enrolled, 'the operation ran exactly once' );
		self::assertSame( 'wc', $enrolled[0]['context'], 'and the My Account presenter ran it' );
		self::assertSame( array(), self::shown_codes( $browser->get( self::$tab ) ), 'shown once' );

		self::age_sessions( $id );
		$refused = $this->op( $browser, self::$tab, 'recovery_generate' );
		self::assertSame( 302, $refused->status );
		self::assertSame( self::$tab, $refused->location(), 'a My Account post never lands in wp-admin' );
		self::assertStringContainsString( 'Confirm it is you with a code first.', $browser->get( self::$tab )->body );

		$ok = $this->op( $browser, self::$tab, 'stepup', array( 'mdmfa_method' => 'totp', 'mdmfa_code' => self::code( $secret, 1 ) ) );
		self::assertSame( self::$tab, $ok->location() );
		self::assertStringContainsString( 'Confirmed. You can make changes', $browser->get( self::$tab )->body );

		$new = $this->op( $browser, self::$tab, 'recovery_generate' );
		self::assertSame( 200, $new->status );
		$codes = self::shown_codes( $new );
		self::assertCount( 10, $codes );
		self::assertSame( array(), array_intersect( $first, $codes ) );
		self::assertCount( 1, self::events( $id, 'recovery_regenerated' ), 'generated exactly once' );
		self::assertSame( 'wc', self::events( $id, 'recovery_regenerated' )[0]['context'] );
		foreach ( $browser->history as $url ) {
			self::assertStringNotContainsString( 'wp-admin', $url, 'the customer never saw wp-admin' );
		}
	}

	public function test_each_presenter_accepts_only_its_own_form(): void {
		list( $browser, $id ) = $this->administrator();
		$admin_nonce          = $browser->get( self::ADMIN_PAGE )->input( '_wpnonce' );
		$shop_nonce           = $browser->get( self::$tab )->input( '_wpnonce' );
		self::assertNotSame( $admin_nonce, $shop_nonce, 'each screen binds its forms to itself' );
		$pending = sprintf( 'echo null === MaxtDesign\Mfa\Factors\TotpStore::pending( %d ) ? "none" : "pending";', $id );

		// The My Account form posted at the wp-admin page.
		$to_admin = $browser->post( self::ADMIN_PAGE, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => $shop_nonce ) );
		self::assertSame( 403, $to_admin->status );
		self::assertSame( 'none', self::eval( $pending ) );

		// The wp-admin form posted at My Account.
		$to_shop = $browser->post( self::$tab, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => $admin_nonce ) );
		self::assertSame( 200, $to_shop->status );
		self::assertStringContainsString( 'This form expired. Please try again.', $to_shop->body );
		self::assertSame( 'none', self::eval( $pending ) );

		// A forged request with no valid nonce does nothing on either.
		self::assertSame( 403, $browser->post( self::ADMIN_PAGE, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => 'abcdef1234' ) )->status );
		$browser->post( self::$tab, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => 'abcdef1234' ) );
		self::assertSame( 'none', self::eval( $pending ) );

		// Each still works with its own.
		self::assertStringContainsString( 'view=totp', $browser->post( self::ADMIN_PAGE, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => $admin_nonce ) )->location() );
		self::assertSame( 'pending', self::eval( $pending ) );
	}
}
