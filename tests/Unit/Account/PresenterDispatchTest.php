<?php
/**
 * Independent review 2026-10-01, finding F2: with WooCommerce active, its Security tab
 * handler (wp_loaded) ran wp-admin's security forms before Users > My security did
 * (load-{page}), so the operation ran in the wrong presenter and the admin page reported
 * "setup expired" with no recovery codes. These tests call the two handlers in WordPress's
 * order and count what happened.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Account;

use MaxtDesign\Mfa\Account\AccountPage;
use MaxtDesign\Mfa\Account\SecurityActions;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Support\Clock;
use MaxtDesign\Mfa\WooCommerce\SecurityEndpoint;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

// phpcs:ignoreFile

#[RunTestsInSeparateProcesses]
final class PresenterDispatchTest extends TestCase {

	private const T0   = 1800000000;
	private const USER = 42;

	protected function setUp(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/presenter-shims.php';
		mdmfa_test_reset();
		Clock::freeze( self::T0 );
		new \WP_User( self::USER, array( 'administrator' ) );
		$GLOBALS['mdmfa_test']['current_user'] = self::USER;
		$GLOBALS['mdmfa_test']['wc_notices']   = array();
		$_POST                                 = array();
		$_REQUEST                              = array();
	}

	protected function tearDown(): void {
		$_POST    = array();
		$_REQUEST = array();
		unset( $_SERVER['REQUEST_METHOD'] );
	}

	/**
	 * A form post as the browser sends it.
	 *
	 * @param array<string, string> $fields
	 */
	private function post( bool $admin, string $nonce_action, string $op, array $fields = array() ): void {
		$GLOBALS['mdmfa_test']['is_admin'] = $admin;
		$_SERVER['REQUEST_METHOD']         = 'POST';
		$_POST                             = array_merge( array( 'mdmfa_op' => $op, '_wpnonce' => mdmfa_test_nonce( $nonce_action ) ), $fields );
		$_REQUEST                          = $_POST;
	}

	/**
	 * Runs the request the way WordPress does: wp_loaded first, then, on a wp-admin page,
	 * the page's load hook. Returns where each handler stopped ('' when it returned).
	 *
	 * @return array{wc: string, admin: string}
	 */
	private function dispatch(): array {
		$stops = array( 'wc' => '', 'admin' => '' );
		try {
			SecurityEndpoint::handle_post();
		} catch ( \Mdmfa_Test_Halt $halt ) {
			$stops['wc'] = $halt->getMessage();
			return $stops;
		}
		if ( is_admin() ) {
			try {
				AccountPage::handle();
			} catch ( \Mdmfa_Test_Halt $halt ) {
				$stops['admin'] = $halt->getMessage();
			}
		}
		return $stops;
	}

	/**
	 * @return string[]
	 */
	private static function held_by( string $presenter ): array {
		return (array) ( new \ReflectionProperty( $presenter, 'codes' ) )->getValue();
	}

	/**
	 * @return string[]
	 */
	private static function logged(): array {
		$events = array();
		foreach ( $GLOBALS['mdmfa_test']['inserts'] as $insert ) {
			if ( str_ends_with( (string) $insert[0], 'mdmfa_log' ) ) {
				$events[] = (string) $insert[1]['event'];
			}
		}
		return $events;
	}

	private function confirm_fields(): array {
		$secret = TotpStore::begin_pending( self::USER );
		return array( 'mdmfa_code' => Totp::code( $secret, Totp::step( Clock::now() ) ) );
	}

	public function test_first_authenticator_setup_in_wp_admin_runs_once_and_shows_the_codes_there(): void {
		$this->post( true, SecurityActions::NONCE_ADMIN, 'totp_confirm', $this->confirm_fields() );

		$stops = $this->dispatch();

		self::assertSame( array( 'wc' => '', 'admin' => '' ), $stops, 'no redirect: the codes render in this response' );
		self::assertTrue( TotpStore::has( self::USER ) );
		self::assertCount( 10, self::held_by( AccountPage::class ), 'the wp-admin page holds the recovery codes it will show' );
		self::assertSame( array(), self::held_by( SecurityEndpoint::class ), 'WooCommerce\'s tab took nothing' );
		self::assertSame( array(), $GLOBALS['mdmfa_test']['wc_notices'], 'and queued no notice for the shop' );
		self::assertSame( 10, RecoveryCodes::remaining( self::USER ) );
		self::assertSame( array( 'enrolled' ), self::logged(), 'the operation ran exactly once' );
	}

	public function test_first_authenticator_setup_on_my_account_runs_once_and_shows_the_codes_there(): void {
		$this->post( false, SecurityActions::NONCE_WC, 'totp_confirm', $this->confirm_fields() );

		$stops = $this->dispatch();

		self::assertSame( array( 'wc' => '', 'admin' => '' ), $stops );
		self::assertTrue( TotpStore::has( self::USER ) );
		self::assertCount( 10, self::held_by( SecurityEndpoint::class ) );
		self::assertSame( array(), self::held_by( AccountPage::class ) );
		self::assertSame( array( array( 'success', 'Two-step verification is on.' ) ), $GLOBALS['mdmfa_test']['wc_notices'] );
		self::assertSame( array( 'enrolled' ), self::logged() );
	}

	public function test_a_wp_admin_post_redirects_to_wp_admin_not_to_my_account(): void {
		// A wrong code during setup: back to the setup view of the page that was posted to.
		$fields               = $this->confirm_fields();
		$fields['mdmfa_code'] = '000000' === $fields['mdmfa_code'] ? '111111' : '000000';
		$this->post( true, SecurityActions::NONCE_ADMIN, 'totp_confirm', $fields );
		$stops = $this->dispatch();
		self::assertSame( '', $stops['wc'] );
		self::assertSame( 'redirect:https://example.test/wp-admin/users.php?page=mdmfa-account&mdmfa_notice=code_invalid&view=totp', $stops['admin'] );
		self::assertFalse( TotpStore::has( self::USER ) );

		// New recovery codes without a recent verification: refused, on the same page.
		TotpStore::save( self::USER, random_bytes( 20 ) );
		$this->post( true, SecurityActions::NONCE_ADMIN, 'recovery_generate' );
		$stops = $this->dispatch();
		self::assertSame( '', $stops['wc'] );
		self::assertSame( 'redirect:https://example.test/wp-admin/users.php?page=mdmfa-account&mdmfa_notice=stepup_needed', $stops['admin'] );
		self::assertSame( array(), $GLOBALS['mdmfa_test']['wc_notices'] );
		self::assertSame( 0, RecoveryCodes::remaining( self::USER ) );
	}

	public function test_a_my_account_post_redirects_to_my_account(): void {
		TotpStore::save( self::USER, random_bytes( 20 ) );
		$this->post( false, SecurityActions::NONCE_WC, 'recovery_generate' );

		$stops = $this->dispatch();

		self::assertSame( 'redirect:https://example.test/my-account/login-security/', $stops['wc'] );
		self::assertSame( array( array( 'error', 'Confirm it is you with a code first.' ) ), $GLOBALS['mdmfa_test']['wc_notices'] );
	}

	public function test_every_operation_posted_from_wp_admin_is_left_to_the_wp_admin_page(): void {
		foreach ( SecurityActions::OPS as $op ) {
			$this->post( true, SecurityActions::NONCE_ADMIN, $op );
			try {
				SecurityEndpoint::handle_post();
			} catch ( \Mdmfa_Test_Halt $halt ) {
				self::fail( "WooCommerce's handler acted on a wp-admin {$op}: " . $halt->getMessage() );
			}
		}
		self::assertSame( array(), $GLOBALS['mdmfa_test']['wc_notices'] );
		self::assertSame( array(), self::logged() );
		self::assertSame( array(), $GLOBALS['mdmfa_test']['usermeta'][ self::USER ] ?? array(), 'nothing was stored' );
	}

	public function test_each_presenter_refuses_the_other_presenters_form(): void {
		// The wp-admin page's nonce, posted to the shop: nothing runs.
		$this->post( false, SecurityActions::NONCE_ADMIN, 'totp_confirm', $this->confirm_fields() );
		$stops = $this->dispatch();
		self::assertSame( '', $stops['wc'] );
		self::assertFalse( TotpStore::has( self::USER ) );
		self::assertSame( array( array( 'error', 'This form expired. Please try again.' ) ), $GLOBALS['mdmfa_test']['wc_notices'] );

		// The shop tab's nonce, posted to the wp-admin page: WordPress's nonce check stops it.
		$GLOBALS['mdmfa_test']['wc_notices'] = array();
		$this->post( true, SecurityActions::NONCE_WC, 'totp_confirm', $this->confirm_fields() );
		$stops = $this->dispatch();
		self::assertSame( array( 'wc' => '', 'admin' => 'die:nonce' ), $stops );
		self::assertFalse( TotpStore::has( self::USER ) );
		self::assertSame( array(), self::logged() );
	}

	public function test_only_the_signed_in_users_own_account_is_touched(): void {
		// The handlers take no user from the request: a posted ID changes nothing.
		new \WP_User( 77, array( 'administrator' ) );
		$this->post( true, SecurityActions::NONCE_ADMIN, 'totp_confirm', array_merge( $this->confirm_fields(), array( 'user_id' => '77', 'user' => '77' ) ) );

		$this->dispatch();

		self::assertTrue( TotpStore::has( self::USER ) );
		self::assertFalse( TotpStore::has( 77 ) );

		// Signed out: neither handler does anything on a front-end post.
		$GLOBALS['mdmfa_test']['current_user'] = 0;
		$this->post( false, SecurityActions::NONCE_WC, 'totp_remove' );
		self::assertSame( array( 'wc' => '', 'admin' => '' ), $this->dispatch() );
		self::assertTrue( TotpStore::has( self::USER ) );
	}
}
