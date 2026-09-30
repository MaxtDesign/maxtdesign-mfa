<?php
/**
 * P2 definition of done (plan section 14), against real WordPress over HTTP.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class LoginFlowTest extends E2eTestCase {

	public function test_optional_unenrolled_user_signs_in_with_password_only(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->browser();

		$response = $this->password( $browser, $login, $pass );

		self::assertSame( 302, $response->status );
		self::assertStringNotContainsString( 'mdmfa', $response->location() );
		self::assertTrue( $response->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 1, self::sessions( $id ) );
	}

	public function test_correct_password_creates_no_session_until_the_second_factor(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$logins                    = self::counter( 'e2e_wp_login' );
		$failures                  = self::counter( 'e2e_wp_login_failed' );

		$response = $this->password( $browser, $login, $pass );

		self::assertSame( 302, $response->status );
		self::assertStringContainsString( 'action=mdmfa-verify', $response->location() );
		self::assertTrue( $response->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertNoAuthCookie( $response );
		self::assertSame( 0, self::sessions( $id ), 'no session after a correct password' );
		self::assertSame( $logins, self::counter( 'e2e_wp_login' ), 'wp_login must not fire yet' );
		self::assertSame( $failures, self::counter( 'e2e_wp_login_failed' ), 'a correct password is not a failure' );

		$wrong = $this->submit_code( $browser, self::wrong_code( $secret ) );
		self::assertSame( 200, $wrong->status );
		self::assertStringContainsString( 'That code is not valid', $wrong->body );
		self::assertNoAuthCookie( $wrong );

		$ok = $this->submit_code( $browser, self::code( $secret ) );
		self::assertSame( 302, $ok->status, substr( strip_tags( $ok->body ), 0, 400 ) );
		self::assertStringContainsString( '/wp-admin/', $ok->location() );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null, 'the session carries the mdmfa stamp' );
		self::assertSame( $logins + 1, self::counter( 'e2e_wp_login' ), 'wp_login fires exactly once, at completion' );
		self::assertFalse( $browser->has_cookie_prefix( 'mdmfa_pending' ), 'pending cookie cleared' );

		$admin = $browser->get( 'wp-admin/' );
		self::assertSame( 200, $admin->status, 'the new session works' );
	}

	public function test_pending_record_is_single_use_under_two_concurrent_requests(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$logins                    = self::counter( 'e2e_wp_login' );

		$this->password( $browser, $login, $pass );
		$token = $browser->get( 'wp-login.php?action=mdmfa-verify' )->form_token();
		$form  = array(
			'mdmfa_form' => $token,
			'mdmfa_code' => self::code( $secret ),
		);

		$responses = $browser->post_concurrently(
			array(
				array( 'wp-login.php?action=mdmfa-verify&method=totp', $form ),
				array( 'wp-login.php?action=mdmfa-verify&method=totp', $form ),
			)
		);

		$winners = array_filter( $responses, static fn ( Response $r ): bool => $r->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertCount( 1, $winners, 'exactly one request may finish the login' );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertSame( $logins + 1, self::counter( 'e2e_wp_login' ) );
	}

	public function test_fifth_wrong_code_burns_the_record_and_the_sixth_attempt_fails(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );

		for ( $i = 1; $i <= 5; $i++ ) {
			$response = $this->submit_code( $browser, self::wrong_code( $secret ) );
		}
		self::assertStringContainsString( 'Too many wrong codes. For your security, please log in again.', $response->body );

		$sixth = $browser->get( 'wp-login.php?action=mdmfa-verify' );
		self::assertStringContainsString( 'Your sign-in expired', $sixth->body, 'the record is gone: even a correct code cannot be used' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_twentieth_consecutive_failure_locks_the_second_factor(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		// 19 earlier failures, backoff long over.
		self::wp( 'user', 'meta', 'update', (string) $id, 'mdmfa_failures', '{"count":19,"last_fail":0,"locked_until":0,"lock_level":0}', '--format=json' );

		$browser = $this->browser();
		$this->password( $browser, $login, $pass );
		$this->submit_code( $browser, self::wrong_code( $secret ) );

		$locked_until = (int) self::eval( sprintf( '$f = get_user_meta( %d, "mdmfa_failures", true ); echo (int) $f["locked_until"];', $id ) );
		self::assertGreaterThan( time() + 3500, $locked_until, 'locked for an hour' );
		self::assertContains( 'locked', array_column( self::log_events( $id ), 'event' ) );

		$again = $this->browser();
		$this->password( $again, $login, $pass );
		$response = $this->submit_code( $again, self::code( $secret ) );
		self::assertStringContainsString( 'Too many wrong codes. Try again in', $response->body );
		self::assertNoAuthCookie( $response );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_a_totp_code_cannot_be_replayed(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$code                      = self::code( $secret );

		$first = $this->browser();
		$this->password( $first, $login, $pass );
		self::assertTrue( $this->submit_code( $first, $code )->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		$second = $this->browser();
		$this->password( $second, $login, $pass );
		$replay = $this->submit_code( $second, $code );
		self::assertStringContainsString( 'That code is not valid', $replay->body );
		self::assertSame( 1, self::sessions( $id ) );
	}

	public function test_recovery_code_signs_in_once(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::enroll( $id );
		$codes = (array) json_decode( self::eval( sprintf( 'echo wp_json_encode( MaxtDesign\\Mfa\\Factors\\RecoveryCodes::generate( %d ) );', $id ) ), true );

		$browser = $this->browser();
		$this->password( $browser, $login, $pass );
		$ok = $this->submit_code( $browser, strtolower( (string) $codes[2] ), 'recovery' );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ), substr( strip_tags( $ok->body ), 0, 400 ) );
		self::assertSame( 'recovery', self::stamps( $id )[0]['factor'] ?? null );
		self::assertSame( '9', self::eval( sprintf( 'echo MaxtDesign\\Mfa\\Factors\\RecoveryCodes::remaining( %d );', $id ) ) );

		$again = $this->browser();
		$this->password( $again, $login, $pass );
		self::assertStringContainsString( 'That code is not valid', $this->submit_code( $again, (string) $codes[2], 'recovery' )->body );
	}

	public function test_bypass_guard_blocks_a_direct_auth_cookie_and_sends_the_user_to_the_challenge(): void {
		list( $id, , ) = self::user( 'editor' );
		$secret        = self::enroll( $id );
		$browser       = $this->browser();

		$response = $browser->post(
			'',
			array(
				'mdmfa_e2e' => 'direct_login',
				'user'      => $id,
			)
		);

		self::assertSame( 302, $response->status );
		self::assertStringContainsString( 'action=mdmfa-verify', $response->location(), 'the caller\'s redirect is rewritten to the challenge' );
		self::assertNoAuthCookie( $response, 'send_auth_cookies must stop the cookie' );
		self::assertTrue( $response->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertSame( 0, self::sessions( $id ), 'the direct session is destroyed' );
		$blocked = array_values( array_filter( self::log_events( $id ), static fn ( array $e ): bool => 'bypass_blocked' === $e['event'] ) );
		self::assertSame( 'mdmfa_e2e_direct_login', $blocked[0]['detail'] ?? null );

		$ok = $this->submit_code( $browser, self::code( $secret ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertStringContainsString( 'wp-admin/profile.php', $ok->location(), 'after the challenge the user lands where the caller wanted' );
	}

	public function test_bypass_guard_allows_cores_cookie_reissue_on_password_change(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );
		$this->submit_code( $browser, self::code( $secret ) );
		self::assertSame( 1, self::sessions( $id ) );

		$response = $browser->post(
			'',
			array(
				'mdmfa_e2e' => 'change_password',
				'pass'      => bin2hex( random_bytes( 12 ) ),
			)
		);

		self::assertSame( 'changed', trim( $response->body ) );
		self::assertTrue( $response->sets_cookie_prefix( 'wordpress_logged_in_' ), 'core re-issued the cookie for the existing, stamped session' );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertNotContains( 'bypass_blocked', array_column( self::log_events( $id ), 'event' ) );
		self::assertSame( 200, $browser->get( 'wp-admin/' )->status );
	}

	public function test_interim_login_completes_with_the_core_success_page(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();

		$response = $this->password( $browser, $login, $pass, array( 'interim-login' => '1' ) );
		self::assertStringContainsString( 'action=mdmfa-verify', $response->location() );

		$page = $browser->get( 'wp-login.php?action=mdmfa-verify' );
		self::assertStringContainsString( 'interim-login', $page->body );

		$ok = $browser->post(
			'wp-login.php?action=mdmfa-verify&method=totp',
			array(
				'mdmfa_form' => $page->form_token(),
				'mdmfa_code' => self::code( $secret ),
			)
		);
		self::assertSame( 200, $ok->status );
		self::assertStringContainsString( 'interim-login-success', $ok->body );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	public function test_required_user_in_grace_can_skip_once_without_a_stamp(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$browser                   = $this->browser();

		$response = $this->password( $browser, $login, $pass );
		self::assertStringContainsString( 'action=mdmfa-enroll', $response->location() );
		self::assertNoAuthCookie( $response );

		$page = $browser->get( 'wp-login.php?action=mdmfa-enroll' );
		self::assertStringContainsString( 'days left to set it up', $page->body );

		$skip = $browser->post(
			'wp-login.php?action=mdmfa-enroll',
			array(
				'mdmfa_form' => $page->form_token(),
				'mdmfa_skip' => '1',
			)
		);
		self::assertTrue( $skip->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertNull( self::stamps( $id )[0] ?? null, 'a skipped login is not MFA-verified' );
		self::assertNotSame( '', self::wp( 'user', 'meta', 'get', (string) $id, 'mdmfa_grace_started' ) );
	}

	public function test_required_user_past_grace_must_enroll_before_the_session_starts(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::wp( 'user', 'meta', 'update', (string) $id, 'mdmfa_grace_started', (string) ( time() - 8 * 86400 ) );
		$browser = $this->browser();

		$this->password( $browser, $login, $pass );
		$page = $browser->get( 'wp-login.php?action=mdmfa-enroll' );
		self::assertStringContainsString( '<svg', $page->body, 'QR code rendered inline' );
		self::assertStringNotContainsString( 'mdmfa_skip', $page->body, 'no skip once grace is over' );
		self::assertSame( 1, preg_match( '/<code class="mdmfa-secret">([A-Z2-7 ]+)<\/code>/', $page->body, $m ) );
		$secret = (string) \MaxtDesign\Mfa\Support\Base32::decode( $m[1] );

		$codes = $browser->post(
			'wp-login.php?action=mdmfa-enroll',
			array(
				'mdmfa_form' => $page->form_token(),
				'mdmfa_code' => self::code( $secret ),
			)
		);
		self::assertSame( 10, preg_match_all( '/<li><code>[A-Z2-7]{4}(-[A-Z2-7]{4}){3}<\/code><\/li>/', $codes->body ) );
		self::assertNoAuthCookie( $codes, 'no session until the codes are acknowledged' );

		$done = $browser->post(
			'wp-login.php?action=mdmfa-enroll',
			array(
				'mdmfa_form'  => $codes->form_token(),
				'mdmfa_saved' => '1',
			)
		);
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ), substr( strip_tags( $done->body ), 0, 400 ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\\Mfa\\Factors\\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );
	}

	public function test_xmlrpc_password_auth_is_refused_for_an_enrolled_user(): void {
		list( $id, $login, $pass )      = self::user( 'editor' );
		self::enroll( $id );
		list( , $plain_login, $plain )  = self::user( 'subscriber' );
		$call = static fn ( string $u, string $p ): string => '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>' . $u . '</string></value></param><param><value><string>' . $p . '</string></value></param></params></methodCall>';

		$client  = curl_init( rtrim( self::$url, '/' ) . '/xmlrpc.php' );
		curl_setopt_array( $client, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => $call( $login, $pass ), CURLOPT_HTTPHEADER => array( 'Content-Type: text/xml' ) ) );
		$refused = (string) curl_exec( $client );
		curl_setopt( $client, CURLOPT_POSTFIELDS, $call( $plain_login, $plain ) );
		$allowed = (string) curl_exec( $client );

		self::assertStringContainsString( '<int>403</int>', $refused );
		self::assertStringNotContainsString( 'faultCode', $allowed, 'password-only users are unaffected' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_escape_hatch_restores_password_only_login(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::enroll( $id );
		self::wp( 'config', 'set', 'MDMFA_DISABLE', 'true', '--raw', '--type=constant' );
		try {
			$response = $this->password( $this->browser(), $login, $pass );
			self::assertTrue( $response->sets_cookie_prefix( 'wordpress_logged_in_' ) );
			self::assertFalse( $response->sets_cookie_prefix( 'mdmfa_pending=' ) );
		} finally {
			self::wp( 'config', 'delete', 'MDMFA_DISABLE', '--type=constant' );
		}
		self::assertSame( 1, self::sessions( $id ) );
	}

	public function test_front_end_pages_carry_nothing_from_the_plugin(): void {
		$home = $this->browser()->get( '' );

		self::assertSame( 200, $home->status );
		self::assertStringNotContainsString( 'mdmfa', $home->body );
		self::assertStringNotContainsString( 'maxtdesign-mfa', $home->body );
		foreach ( $home->set_cookies as $cookie ) {
			self::assertStringNotContainsString( 'mdmfa', $cookie );
		}
	}
}
