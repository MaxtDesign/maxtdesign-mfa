<?php
/**
 * A host's access gate in front of the site (staging finding, 2026-10-02): every request of
 * a browser that is not logged in must carry a WordPress user's credentials as HTTP Basic
 * authentication. The gate calls wp_authenticate() on plugins_loaded, before any login form
 * exists, and starts the session itself. The plugin used to refuse that login for every
 * account that needs a second step, and the gate answered 401: staff could not get in at
 * all. Both must hold now: nobody passes the gate without a correct password, and nobody
 * gets a session without the second step.
 *
 * Runs against the fixture's stand-in gate, or against a real gate plugin when
 * MDMFA_E2E_GATE_PLUGIN names one that is installed (for example
 * "hosting-basic-authentication/hosting-basic-authentication.php").
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

use MaxtDesign\Mfa\Support\Base32;

// phpcs:ignoreFile

final class HttpAuthGateTest extends E2eTestCase {

	private const CODES = '/<li><code>[A-Z2-7]{4}(-[A-Z2-7]{4}){3}<\/code><\/li>/';

	protected function setUp(): void {
		parent::setUp();
		self::eval( 'delete_option( "e2e_mail" );' );
		self::gate( true );
	}

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::gate( false );
			self::reset_settings();
		}
		parent::tearDown();
	}

	private static function gate( bool $on ): void {
		$plugin = (string) getenv( 'MDMFA_E2E_GATE_PLUGIN' );
		if ( '' !== $plugin ) {
			self::wp( 'plugin', $on ? 'activate' : 'deactivate', $plugin );
			return;
		}
		$on ? self::wp( 'option', 'update', 'e2e_http_gate', '1' ) : self::eval( 'delete_option( "e2e_http_gate" );' );
	}

	/**
	 * A browser that answers the gate's prompt with these credentials on every request.
	 */
	private function gated( string $login, string $pass ): Browser {
		$browser        = $this->browser();
		$browser->basic = $login . ':' . $pass;
		return $browser;
	}

	private static function has_totp( int $user_id ): bool {
		return 'true' === self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $user_id ) );
	}

	/**
	 * Whether a response is a page served to a signed-in user.
	 */
	private static function signed_in( Browser $browser ): bool {
		$profile = $browser->get( 'wp-admin/profile.php' );
		return 200 === $profile->status && str_contains( $profile->body, 'id="your-profile"' );
	}

	public function test_the_gate_still_keeps_out_anyone_without_a_correct_password(): void {
		list( $id, $login ) = self::user( 'administrator' );
		self::enroll( $id );

		foreach ( array( '', 'sample-page/', 'wp-admin/', self::lp(), self::lp( 'action=mdmfa-verify' ), self::lp( 'action=mdmfa-enroll' ), 'wp-admin/admin-post.php?action=mdmfa_recover&t=x' ) as $path ) {
			$anonymous = $this->browser()->get( $path );
			self::assertSame( 401, $anonymous->status, "anonymous /{$path}" );
			self::assertStringContainsString( 'Basic', $anonymous->headers['www-authenticate'] ?? '' );
			self::assertSame( array(), $anonymous->set_cookies, "anonymous /{$path} gets no cookie" );

			$wrong = $this->gated( $login, 'not-the-password' )->get( $path );
			self::assertSame( 401, $wrong->status, "wrong password on /{$path}" );
			self::assertFalse( $wrong->sets_cookie_prefix( 'mdmfa_pending=' ), "wrong password on /{$path} starts no sign-in" );
			self::assertNoAuthCookie( $wrong );
		}
		self::assertSame( 401, $this->gated( 'nobody-' . bin2hex( random_bytes( 3 ) ), 'x' )->get( '' )->status );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_an_account_that_needs_no_second_step_passes_the_gate_as_before(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->gated( $login, $pass );

		$home = $browser->get( '' );

		self::assertSame( 200, $home->status );
		self::assertTrue( $home->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 1, self::sessions( $id ) );
	}

	public function test_fresh_staff_reach_setup_through_the_gate_and_get_a_session_only_after_it(): void {
		// A new administrator: Required, nothing set up, in the setup period.
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$browser                   = $this->gated( $login, $pass );

		$first = $browser->get( 'wp-admin/index.php' );
		self::assertSame( 302, $first->status, 'not 401: the password is right, so the browser is sent to the second step' );
		self::assertStringContainsString( 'action=mdmfa-enroll', $first->location() );
		self::assertTrue( $first->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertNoAuthCookie( $first );
		self::assertSame( 0, self::sessions( $id ) );

		$grace = $browser->get( $first->location() );
		self::assertSame( 200, $grace->status, substr( strip_tags( $grace->body ), 0, 300 ) );
		self::assertStringContainsString( 'days left to set it up', $grace->body );
		self::assertNoAuthCookie( $grace, 'the gate started no session on the setup screen' );
		self::assertSame( 0, self::sessions( $id ) );
		self::assertFalse( self::signed_in( $browser ), 'and the browser cannot use wp-admin yet' );

		// Set it up now.
		$setup = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $grace->form_token() ) );
		self::assertSame( 1, preg_match( '/<code class="mdmfa-secret">([A-Z2-7 ]+)<\/code>/', $setup->body, $m ), substr( strip_tags( $setup->body ), 0, 300 ) );
		$secret = (string) Base32::decode( $m[1] );
		$codes  = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $setup->form_token(), 'mdmfa_code' => self::code( $secret ) ) );
		self::assertSame( 10, preg_match_all( self::CODES, $codes->body ), 'recovery codes shown' );
		self::assertNoAuthCookie( $codes );
		self::assertSame( 0, self::sessions( $id ), 'no session until the codes are acknowledged' );

		$done = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $codes->form_token(), 'mdmfa_saved' => '1' ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ), substr( strip_tags( $done->body ), 0, 300 ) );
		self::assertStringContainsString( 'wp-admin/index.php', $done->location(), 'back to the page the gate interrupted' );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );
		self::assertTrue( self::signed_in( $browser ) );

		// The next visit, in a new browser: the password passes the gate, the code signs in.
		$next  = $this->gated( $login, $pass );
		$again = $next->get( 'wp-admin/index.php' );
		self::assertStringContainsString( 'action=mdmfa-verify', $again->location() );
		self::assertNoAuthCookie( $again );
		$page = $next->get( $again->location() );
		self::assertSame( 200, $page->status );
		$ok = $next->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_code' => self::code( $secret, 1 ) ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ), substr( strip_tags( $ok->body ), 0, 300 ) );
		self::assertSame( 2, self::sessions( $id ) );
	}

	public function test_a_correct_password_alone_never_becomes_a_session_for_enrolled_staff(): void {
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->gated( $login, $pass );

		$first = $browser->get( 'sample-page/?from=gate' );
		self::assertSame( 302, $first->status );
		self::assertStringContainsString( 'action=mdmfa-verify', $first->location() );
		self::assertTrue( $first->sets_cookie_prefix( 'mdmfa_pending=' ) );
		$page = $browser->get( $first->location() );
		self::assertSame( 200, $page->status );
		self::assertStringContainsString( 'name="mdmfa_code"', $page->body );

		// Everything else the browser asks for meanwhile leads back to the second step, with
		// the same pending sign-in: nothing is served, no cookie, no session.
		$near_misses = array( '?action=mdmfa-verify', self::lp( 'action=MDMFA-VERIFY' ), self::lp( 'action=mdmfa-verify&key=abc' ), self::lp( 'action=mdmfa-verify&checkemail=confirm' ), 'wp-admin/admin-post.php?action=MDMFA_RECOVER', 'wp-admin/admin-post.php?action=mdmfa_login' );
		foreach ( $near_misses as $path ) {
			$miss = $browser->get( $path );
			self::assertSame( 302, $miss->status, "/{$path} is not one of the second step's pages, so nothing is served" );
			self::assertStringContainsString( 'action=mdmfa-verify', $miss->location() );
		}
		foreach ( array_merge( $near_misses, array( '', 'wp-admin/', 'wp-admin/profile.php', 'wp-admin/admin-ajax.php?action=heartbeat', 'favicon.ico', 'wp-json/wp/v2/users/me', self::lp() ) ) as $path ) {
			$other = $browser->get( $path );
			self::assertNoAuthCookie( $other, "/{$path}" );
			self::assertFalse( $other->sets_cookie_prefix( 'mdmfa_pending=' ), "/{$path} keeps the pending sign-in" );
			self::assertStringNotContainsString( 'id="your-profile"', $other->body );
			self::assertStringNotContainsString( 'id="wpadminbar"', $other->body, "/{$path} is not served as the user" );
		}
		self::assertSame( 0, self::sessions( $id ) );
		self::assertFalse( self::signed_in( $browser ) );

		$wrong = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_code' => self::wrong_code( $secret ) ) );
		self::assertStringContainsString( 'That code is not valid', $wrong->body, 'the form from before those requests still works' );
		self::assertNoAuthCookie( $wrong );
		self::assertSame( 0, self::sessions( $id ) );

		$ok = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $wrong->form_token(), 'mdmfa_code' => self::code( $secret ) ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ), substr( strip_tags( $ok->body ), 0, 300 ) );
		self::assertStringContainsString( 'sample-page/?from=gate', $ok->location(), 'back to the page the gate interrupted' );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );
		self::assertTrue( self::signed_in( $browser ) );
		$events = array_column( self::log_events( $id ), 'event' );
		self::assertNotContains( 'bypass_blocked', $events, 'the gate is not logged as a bypass on every request' );
		self::assertCount( 1, array_keys( $events, 'gate_password', true ), 'one log row for the password the gate accepted' );
	}

	public function test_staff_past_the_setup_period_cannot_skip_setup_through_the_gate(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::wp( 'user', 'meta', 'update', (string) $id, 'mdmfa_grace_started', (string) ( time() - 8 * 86400 ) );
		$browser = $this->gated( $login, $pass );

		$first = $browser->get( '' );
		self::assertStringContainsString( 'action=mdmfa-enroll', $first->location() );
		$page = $browser->get( $first->location() );
		self::assertSame( 200, $page->status );
		self::assertStringNotContainsString( 'mdmfa_skip', $page->body );
		$skip = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_skip' => '1' ) );
		self::assertNoAuthCookie( $skip );
		self::assertSame( 0, self::sessions( $id ) );
		self::assertFalse( self::signed_in( $browser ) );
	}

	public function test_logging_out_ends_the_session_and_the_next_visit_needs_the_second_step_again(): void {
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->gated( $login, $pass );
		$first                     = $browser->get( '' );
		$page                      = $browser->get( $first->location() );
		$browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_code' => self::code( $secret ) ) );
		self::assertSame( 1, self::sessions( $id ) );

		$profile = $browser->get( 'wp-admin/profile.php' );
		self::assertSame( 1, preg_match( "/href=[\"']([^\"']*action=logout[^\"']*)[\"']/", $profile->body, $m ), 'the admin bar has a log out link' );
		$logout = html_entity_decode( $m[1] );
		self::assertStringContainsString( 'basic-auth-logout=1', $logout, 'the gate\'s own logout' );

		$out = $browser->get( $logout );
		self::assertSame( 401, $out->status );
		self::assertSame( 0, self::sessions( $id ), 'the session is gone' );

		$next = $this->gated( $login, $pass );
		$back = $next->get( 'wp-admin/' );
		self::assertStringContainsString( 'action=mdmfa-verify', $back->location(), 'signing in again asks for the code again' );
		self::assertNoAuthCookie( $back );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_email_recovery_works_behind_the_gate_and_signs_nobody_in(): void {
		self::settings( array( 'roles' => array( 'author' => array( 'email_recovery' => true, 'recovery_wait_hours' => 0 ) ) ) );
		list( $id, $login, $pass ) = self::user( 'author' );
		self::enroll( $id );
		$address = $login . '@example.com';
		$browser = $this->gated( $login, $pass );

		$first  = $browser->get( '' );
		$screen = $browser->get( $first->location() );
		self::assertStringContainsString( 'Lost access? Reset by email', $screen->body );
		$asked = $browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		self::assertStringContainsString( 'We emailed you a link', $asked->body );
		$mail = self::mail_to( $address );
		self::assertSame( 1, preg_match( '#https?://\S+admin-post\.php\?\S+#', end( $mail )['message'], $m ) );
		parse_str( (string) parse_url( $m[0], PHP_URL_QUERY ), $query );

		// The link opened without the password does not get past the gate.
		self::assertSame( 401, $this->browser()->get( $m[0] )->status );

		// Opened in another browser, which answers the gate: the confirmation page, no session.
		$other   = $this->gated( $login, $pass );
		$confirm = $other->get( $m[0] );
		self::assertSame( 200, $confirm->status, $confirm->location() );
		self::assertStringContainsString( 'Yes, reset it', $confirm->body );
		self::assertNoAuthCookie( $confirm );
		self::assertTrue( self::has_totp( $id ), 'opening the link changes nothing' );

		$done = $other->post( 'wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => $confirm->form_token() ) );
		self::assertSame( 200, $done->status );
		self::assertStringContainsString( 'was reset for your account', $done->body );
		self::assertNoAuthCookie( $done, 'recovery never signs anyone in' );
		self::assertFalse( self::has_totp( $id ) );
		self::assertSame( 0, self::sessions( $id ) );

		// Authors are Optional: with nothing set up any more, the password passes the gate.
		self::assertTrue( $this->gated( $login, $pass )->get( '' )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	public function test_a_gate_nobody_vouched_for_is_refused_as_before(): void {
		if ( '' !== (string) getenv( 'MDMFA_E2E_GATE_PLUGIN' ) ) {
			self::markTestSkipped( 'Needs the fixture gate, which can run without being vouched for.' );
		}
		// Any other code that authenticates Basic credentials on a page request gets the old
		// answer, on every page, including the second step's own: fail closed.
		self::wp( 'option', 'update', 'e2e_http_gate', 'unlisted' );
		list( $id, $login, $pass ) = self::user( 'administrator' );
		self::enroll( $id );
		$browser = $this->gated( $login, $pass );

		foreach ( array( '', 'wp-admin/', self::lp( 'action=mdmfa-verify' ), 'wp-admin/admin-post.php?action=mdmfa_recover&t=x' ) as $path ) {
			$response = $browser->get( $path );
			self::assertSame( 401, $response->status, "/{$path}" );
			self::assertNoAuthCookie( $response );
			self::assertFalse( $response->sets_cookie_prefix( 'mdmfa_pending=' ) );
		}
		self::assertSame( 0, self::sessions( $id ) );
		self::assertContains( 'noninteractive_blocked', array_column( self::log_events( $id ), 'event' ) );

		// Accounts that need no second step still pass it.
		list( , $plain, $plain_pass ) = self::user( 'subscriber' );
		self::assertTrue( $this->gated( $plain, $plain_pass )->get( '' )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	public function test_without_a_gate_basic_credentials_on_a_page_request_mean_nothing(): void {
		self::gate( false );
		list( $id, $login, $pass ) = self::user( 'administrator' );
		self::enroll( $id );
		$browser = $this->gated( $login, $pass );

		$home = $browser->get( '' );
		self::assertSame( 200, $home->status );
		self::assertSame( array(), $home->set_cookies, 'nothing authenticates, so nothing is started' );
		self::assertSame( 200, $browser->get( self::lp( 'action=mdmfa-verify' ) )->status );
		self::assertSame( 0, self::sessions( $id ) );
		self::assertFalse( self::signed_in( $browser ) );

		// The normal login form is what it was.
		$plain = $this->browser();
		$step1 = $this->password( $plain, $login, $pass );
		self::assertStringContainsString( 'action=mdmfa-verify', $step1->location() );
		self::assertNoAuthCookie( $step1 );
	}
}
