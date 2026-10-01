<?php
/**
 * P6 definition of done: emailed codes with their send limits, trusted devices and their
 * revocation, and the email recovery flow.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class EmailAndTrustTest extends E2eTestCase {

	private const ACCOUNT = 'wp-admin/profile.php?page=mdmfa-account';

	protected function setUp(): void {
		parent::setUp();
		self::eval( 'delete_option( "e2e_mail" );' );
	}

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::reset_settings();
		}
		parent::tearDown();
	}

	/**
	 * Authors may use emailed codes, trusted devices and email recovery with no wait.
	 *
	 * @param array<string, mixed> $extra
	 */
	private static function author_settings( array $extra = array() ): void {
		self::settings(
			array(
				'roles' => array(
					'author' => array_merge(
						array(
							'factors'             => array( 'email' => true ),
							'trusted_devices'     => true,
							'email_recovery'      => true,
							'recovery_wait_hours' => 0,
						),
						$extra
					),
				),
			)
		);
	}

	/**
	 * Posts a security-page operation with the page's nonce.
	 *
	 * @param array<string, string> $fields
	 */
	private function account_op( Browser $browser, string $op, array $fields = array() ): Response {
		$page = $browser->get( self::ACCOUNT );
		return $browser->post( self::ACCOUNT, array_merge( array( '_wpnonce' => $page->input( '_wpnonce' ), 'mdmfa_op' => $op ), $fields ) );
	}

	private function verify_post( Browser $browser, string $method, array $fields ): Response {
		$page = $browser->get( self::lp( 'action=mdmfa-verify&method=' . $method ) );
		return $browser->post( self::lp( 'action=mdmfa-verify&method=' . $method ), array_merge( array( 'mdmfa_form' => $page->form_token() ), $fields ) );
	}

	public function test_email_codes_are_not_offered_to_staff_roles(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );

		$page = $browser->get( self::ACCOUNT );
		self::assertStringNotContainsString( 'Email codes', $page->body, 'unlisted roles get staff-safe factors' );
		$this->account_op( $browser, 'email_begin' );
		self::assertSame( array(), self::mail_to( $login . '@example.com' ) );
	}

	public function test_turn_on_email_codes_then_sign_in_with_one(): void {
		self::author_settings();
		list( $id, $login, $pass ) = self::user( 'author' );
		$address                   = $login . '@example.com';
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );

		self::assertStringContainsString( 'Turn on email codes', $browser->get( self::ACCOUNT )->body );
		$this->account_op( $browser, 'email_begin' );
		self::assertCount( 1, self::mail_to( $address ) );
		self::assertStringNotContainsString( self::$login, self::mail_to( $address )[0]['message'], 'the mail never carries the login address' );

		$wrong = $this->account_op( $browser, 'email_confirm', array( 'mdmfa_code' => '000000' === self::mailed_code( $address ) ? '111111' : '000000' ) );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\EmailCode::has( %d ) ? "true" : "false";', $id ) ) );

		$confirmed = $this->account_op( $browser, 'email_confirm', array( 'mdmfa_code' => self::mailed_code( $address ) ) );
		self::assertSame( 200, $confirmed->status );
		self::assertSame( 10, preg_match_all( '/<li><code>[A-Z2-7]{4}(-[A-Z2-7]{4}){3}<\/code><\/li>/', $confirmed->body ), 'first recovery codes shown once' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\EmailCode::has( %d ) ? "true" : "false";', $id ) ) );

		// Next sign-in: the password opens a challenge; the code is sent only on request.
		$next  = $this->browser();
		$first = $this->password( $next, $login, $pass );
		self::assertStringContainsString( 'action=mdmfa-verify', $first->location() );
		self::assertNoAuthCookie( $first );
		$screen = $next->get( $first->location() );
		self::assertStringContainsString( 'Email me a code', $screen->body );
		self::assertCount( 1, self::mail_to( $address ), 'loading the screen sends nothing' );

		$sent = $this->verify_post( $next, 'email', array( 'mdmfa_send' => '1' ) );
		self::assertStringContainsString( 'We sent a code to ' . substr( $login, 0, 1 ) . '***@example.com', $sent->body );
		self::assertCount( 2, self::mail_to( $address ) );
		$code = self::mailed_code( $address );

		$bad = $this->verify_post( $next, 'email', array( 'mdmfa_code' => '000000' === $code ? '111111' : '000000' ) );
		self::assertStringContainsString( 'That code is not valid', $bad->body );
		self::assertNoAuthCookie( $bad );

		// A second browser with its own pending login cannot use this browser's code.
		$thief = $this->browser();
		$this->password( $thief, $login, $pass );
		self::assertNoAuthCookie( $this->verify_post( $thief, 'email', array( 'mdmfa_code' => $code ) ), 'the code is bound to the pending login it was sent for' );

		$ok = $this->verify_post( $next, 'email', array( 'mdmfa_code' => $code ) );
		self::assertSame( 302, $ok->status, substr( strip_tags( $ok->body ), 0, 300 ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertContains( 'email', array_column( array_filter( self::stamps( $id ) ), 'factor' ) );
	}

	public function test_email_send_limit_is_three_per_fifteen_minutes(): void {
		self::author_settings();
		list( $id, $login, $pass ) = self::user( 'author' );
		self::enroll_email( $id );
		$address = $login . '@example.com';
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );

		for ( $i = 1; $i <= 3; $i++ ) {
			$this->verify_post( $browser, 'email', array( 'mdmfa_send' => '1' ) );
		}
		self::assertCount( 3, self::mail_to( $address ) );

		$fourth = $this->verify_post( $browser, 'email', array( 'mdmfa_send' => '1' ) );
		self::assertStringContainsString( 'Too many codes were sent', $fourth->body );
		self::assertCount( 3, self::mail_to( $address ), 'the fourth send is refused' );

		// A new pending login shares the same allowance: the limit is per user.
		$again = $this->browser();
		$this->password( $again, $login, $pass );
		$this->verify_post( $again, 'email', array( 'mdmfa_send' => '1' ) );
		self::assertCount( 3, self::mail_to( $address ) );

		// The third code still works.
		$ok = $this->verify_post( $browser, 'email', array( 'mdmfa_code' => self::mailed_code( $address ) ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	public function test_trusted_device_skips_the_challenge_until_the_password_changes(): void {
		self::author_settings();
		list( $id, $login, $pass ) = self::user( 'author' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();

		$this->password( $browser, $login, $pass );
		$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
		self::assertStringContainsString( 'name="mdmfa_trust"', $screen->body );
		self::assertStringContainsString( 'for 30 days', $screen->body );
		$done = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_code' => self::code( $secret ), 'mdmfa_trust' => '1' ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		$cookie = implode( '', array_filter( $done->set_cookies, static fn ( string $c ): bool => str_starts_with( $c, 'mdmfa_td=' ) ) );
		self::assertNotSame( '', $cookie, 'the trusted-device cookie is set' );
		self::assertStringContainsStringIgnoringCase( 'httponly', $cookie );
		self::assertStringContainsStringIgnoringCase( 'samesite=lax', $cookie );
		$device = $browser->cookies['mdmfa_td'];

		// Same device, new sign-in: straight in, and the session says how.
		$return                      = $this->browser();
		$return->cookies['mdmfa_td'] = $device;
		$logins                      = self::counter( 'e2e_wp_login' );
		$in                          = $this->password( $return, $login, $pass );
		self::assertTrue( $in->sets_cookie_prefix( 'wordpress_logged_in_' ), 'no challenge on a trusted device' );
		self::assertStringNotContainsString( 'mdmfa-verify', $in->location() );
		self::assertSame( $logins + 1, self::counter( 'e2e_wp_login' ) );
		self::assertContains( 'trusted', array_column( array_filter( self::stamps( $id ) ), 'factor' ) );

		// A trusted sign-in is not a fresh verification: sensitive changes still ask.
		$this->account_op( $return, 'totp_remove' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ), 'step-up is still needed' );
		self::assertStringContainsString( '1 device skips the second step', $return->get( self::ACCOUNT )->body );

		// Another browser without the cookie is challenged.
		$other = $this->browser();
		self::assertStringContainsString( 'action=mdmfa-verify', $this->password( $other, $login, $pass )->location() );

		// A wrong password with the cookie gets nowhere.
		$wrong                      = $this->browser();
		$wrong->cookies['mdmfa_td'] = $device;
		self::assertNoAuthCookie( $this->password( $wrong, $login, 'not-the-password' ) );

		// The password changes (a reset, a profile edit, anything): every device is forgotten.
		$new = bin2hex( random_bytes( 12 ) );
		self::wp( 'user', 'update', (string) $id, '--user_pass=' . $new, '--skip-email' );
		$after                      = $this->browser();
		$after->cookies['mdmfa_td'] = $device;
		$challenged                 = $this->password( $after, $login, $new );
		self::assertStringContainsString( 'action=mdmfa-verify', $challenged->location(), 'the old cookie no longer skips the challenge' );
		self::assertNoAuthCookie( $challenged );
		self::assertSame( '0', self::eval( sprintf( 'echo MaxtDesign\Mfa\Auth\TrustedDevice::count( %d );', $id ) ) );
	}

	public function test_trusted_devices_are_not_offered_unless_the_role_allows_them(): void {
		list( $id, $login, $pass ) = self::user( 'author' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );

		$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
		self::assertStringNotContainsString( 'mdmfa_trust', $screen->body );
		$done = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_code' => self::code( $secret ), 'mdmfa_trust' => '1' ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertFalse( $done->sets_cookie_prefix( 'mdmfa_td=' ), 'a forged checkbox does nothing' );
	}

	public function test_forgetting_and_factor_removal_revoke_trusted_devices(): void {
		self::author_settings();
		list( $id, $login, $pass ) = self::user( 'author' );
		$secret                    = self::enroll( $id );
		self::enroll_email( $id );
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );
		$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
		$browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_code' => self::code( $secret ), 'mdmfa_trust' => '1' ) );
		self::assertSame( '1', self::eval( sprintf( 'echo MaxtDesign\Mfa\Auth\TrustedDevice::count( %d );', $id ) ) );

		$this->account_op( $browser, 'email_remove' );
		self::assertSame( '0', self::eval( sprintf( 'echo MaxtDesign\Mfa\Auth\TrustedDevice::count( %d );', $id ) ), 'removing a factor forgets trusted devices' );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\EmailCode::has( %d ) ? "true" : "false";', $id ) ) );
	}

	public function test_email_recovery_resets_factors_after_the_link_is_confirmed(): void {
		self::author_settings();
		list( $id, $login, $pass ) = self::user( 'author' );
		self::enroll( $id );
		$address = $login . '@example.com';
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );

		$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
		self::assertStringContainsString( 'Lost access? Reset by email', $screen->body );
		$asked = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		self::assertStringContainsString( 'We emailed you a link', $asked->body );
		self::assertNoAuthCookie( $asked );

		$mail = self::mail_to( $address );
		self::assertCount( 1, $mail );
		self::assertSame( 1, preg_match( '#https?://\S+admin-post\.php\?\S+#', $mail[0]['message'], $m ) );
		$link = $m[0];
		self::assertStringNotContainsString( self::$login, $mail[0]['message'], 'the link is not on the login address' );
		self::assertStringNotContainsString( 'wp-login.php', $link );

		// Opening the link changes nothing (mail scanners open links).
		$stranger = $this->browser();
		$confirm  = $stranger->get( $link );
		self::assertSame( 200, $confirm->status );
		self::assertSame( 'no-referrer', $confirm->headers['referrer-policy'] ?? '' );
		self::assertStringContainsString( 'Yes, reset it', $confirm->body );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );

		// A forged confirmation without the form token fails.
		parse_str( (string) parse_url( $link, PHP_URL_QUERY ), $query );
		$forged = $stranger->post( 'wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => str_repeat( '0', 64 ) ) );
		self::assertSame( 403, $forged->status );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );

		$confirm = $stranger->get( $link );
		$done    = $stranger->post( 'wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => $confirm->form_token() ) );
		self::assertSame( 200, $done->status );
		self::assertStringContainsString( 'was reset for your account', $done->body );
		self::assertNoAuthCookie( $done, 'recovery never signs anyone in' );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );
		self::assertSame( '0', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\RecoveryCodes::remaining( %d );', $id ) ) );
		self::assertContains( 'recovery_reset', array_column( self::log_events( $id ), 'event' ) );
		self::assertCount( 2, self::mail_to( $address ), 'the user is told' );

		// Single use.
		self::assertSame( 403, $stranger->get( $link )->status );

		// The role is Optional, so the password alone signs in now.
		self::assertTrue( $this->password( $this->browser(), $login, $pass )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	public function test_email_recovery_waits_for_staff_and_a_real_sign_in_cancels_it(): void {
		self::settings( array( 'roles' => array( 'editor' => array( 'email_recovery' => true ) ) ) );
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$address                   = $login . '@example.com';

		$request = function () use ( $login, $pass, $address ): void {
			$browser = $this->browser();
			$this->password( $browser, $login, $pass );
			$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
			$browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
			$mail = self::mail_to( $address );
			self::assertSame( 1, preg_match( '#https?://\S+admin-post\.php\?\S+#', end( $mail )['message'], $m ) );
			parse_str( (string) parse_url( $m[0], PHP_URL_QUERY ), $query );
			$confirm = $this->browser()->get( $m[0] );
			$done    = $this->browser()->post( 'wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => $confirm->form_token() ) );
			self::assertStringContainsString( 'will be reset in', $done->body );
		};

		$request();
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ), 'staff wait 24 hours' );
		$ready = (int) self::eval( sprintf( 'echo (int) get_user_meta( %d, "mdmfa_recovery_pending", true );', $id ) );
		self::assertEqualsWithDelta( time() + 24 * 3600, $ready, 120 );
		self::assertNotSame( array(), self::mail_to( 'admin@example.com' ), 'the site admin is told about a staff recovery' );
		self::assertStringContainsString( 'action=mdmfa-verify', $this->password( $this->browser(), $login, $pass )->location(), 'still challenged while waiting' );

		// The owner signs in with the real second step: the reset is cancelled.
		$owner = $this->browser();
		$this->password( $owner, $login, $pass );
		self::assertTrue( $this->submit_code( $owner, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( '', self::eval( sprintf( 'echo get_user_meta( %d, "mdmfa_recovery_pending", true );', $id ) ) );
		self::assertContains( 'recovery_cancelled', array_column( self::log_events( $id ), 'event' ) );

		// A second request, and this time the waiting period passes.
		self::eval( sprintf( 'delete_user_meta( %d, "mdmfa_email_sends" );', $id ) );
		$request();
		self::eval( sprintf( 'update_user_meta( %d, "mdmfa_recovery_pending", time() - 1 );', $id ) );
		$after = $this->password( $this->browser(), $login, $pass );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ), 'the reset takes effect at the next password sign-in' );
		self::assertStringContainsString( 'action=mdmfa-enroll', $after->location(), 'a Required role sets up again, with a fresh grace period' );
		self::assertNoAuthCookie( $after );
	}

	public function test_email_recovery_is_not_offered_to_staff_by_default(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::enroll( $id );
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );

		$screen = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
		self::assertStringNotContainsString( 'Reset by email', $screen->body );
		$browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		self::assertSame( array(), self::mail_to( $login . '@example.com' ), 'a forged request sends nothing' );
	}
}
