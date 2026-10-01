<?php
/**
 * P8: one test per exploitable finding of the security audits and the lanes review
 * (docs/security-audit-auth-p8.md, docs/security-audit-admin-p8.md, docs/review-p8.md).
 * Each reproduces the reported request and expects it to fail.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class AuditRegressionTest extends E2eTestCase {

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::reset_settings();
			self::eval( '$o = get_option( "mdmfa_login" ); $o["public_login"] = "auto"; $o["public_page"] = 0; update_option( "mdmfa_login", $o, true );' );
		}
		parent::tearDown();
	}

	private static function app_password( int $user_id ): string {
		return self::eval( sprintf( '$r = WP_Application_Passwords::create_new_application_password( %d, array( "name" => "e2e" ) ); echo $r[0];', $user_id ) );
	}

	private static function xml_login_call( string $method, string $login, string $secret ): string {
		return '<methodCall><methodName>' . $method . '</methodName><params><param><value><string>' . $login . '</string></value></param><param><value><string>' . $secret . '</string></value></param></params></methodCall>';
	}

	/**
	 * Auth audit H1: an application password authenticated the attacker; the victim's
	 * account password in the same request must still be refused.
	 */
	public function test_someone_elses_application_password_does_not_exempt_a_victims_password(): void {
		list( $attacker, $attacker_login ) = self::user( 'subscriber' );
		$attacker_secret                   = self::app_password( $attacker );
		list( $victim, $victim_login, $victim_pass ) = self::user( 'subscriber' );
		self::enroll( $victim );
		$basic = 'Authorization: Basic ' . base64_encode( $attacker_login . ':' . $attacker_secret );

		// Variant 1: attacker's Basic header, victim's password in the XML body.
		$body    = '<?xml version="1.0"?>' . self::xml_login_call( 'wp.getUsersBlogs', $victim_login, $victim_pass );
		$refused = $this->browser()->raw( 'POST', 'xmlrpc.php', $body, array( 'Content-Type: text/xml', $basic ) );
		self::assertStringContainsString( '<int>403</int>', $refused->body, 'the victim is not exempt' );
		self::assertStringNotContainsString( 'isAdmin', $refused->body );

		// Variant 2: system.multicall, attacker first, victim second.
		$call  = static fn ( string $login, string $secret ): string => '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>' . $login . '</string></value><value><string>' . $secret . '</string></value></data></array></value></member></struct></value>';
		$multi = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>' . $call( $attacker_login, $attacker_secret ) . $call( $victim_login, $victim_pass ) . '</data></array></value></param></params></methodCall>';
		$both  = $this->browser()->raw( 'POST', 'xmlrpc.php', $multi, array( 'Content-Type: text/xml' ) )->body;
		self::assertSame( 1, substr_count( $both, 'isAdmin' ), 'only the attacker\'s own call succeeds' );
		self::assertStringContainsString( '<int>403</int>', $both );

		// Variant 3: a REST password endpoint with the attacker's Basic header.
		$token = $this->browser()->raw( 'POST', 'wp-json/mdmfa-e2e/v1/token', (string) json_encode( array( 'username' => $victim_login, 'password' => $victim_pass ) ), array( 'Content-Type: application/json', $basic ) );
		self::assertSame( 403, $token->status );
		self::assertSame( 'mdmfa_required', json_decode( $token->body, true )['code'] ?? null );
		self::assertSame( 0, self::sessions( $victim ) );

		// The attacker's own application password still works for the attacker.
		self::assertSame( 200, $this->browser()->raw( 'GET', 'wp-json/wp/v2/users/me', '', array( $basic ) )->status );
	}

	/**
	 * Auth audit M1: wp-login.php runs a different action than the one in the request.
	 */
	public function test_wp_login_php_cannot_be_reached_through_action_confusion(): void {
		$get = $this->browser()->get( 'wp-login.php?action=confirmaction&request_id=1&confirm_key=x&key=y' );
		self::assertSame( 404, $get->status, '?key= turns the action into resetpass' );
		self::assertStringNotContainsString( self::$login, $get->location() );
		self::assertStringNotContainsString( self::$login, $get->body );

		$check = $this->browser()->get( 'wp-login.php?action=confirmaction&request_id=1&confirm_key=x&checkemail=confirm' );
		self::assertSame( 404, $check->status );
		self::assertStringNotContainsString( self::$login, $check->body );

		$post = $this->browser()->post( 'wp-login.php?rm_token=1&rm_key=1', array( 'action' => 'enter_recovery_mode', 'log' => 'admin', 'pwd' => 'x' ) );
		self::assertSame( 404, $post->status, 'a POSTed action does not open the old login form' );
		self::assertStringNotContainsString( self::$login, $post->body );
		self::assertStringNotContainsString( 'name="log"', $post->body );

		// The real uses still work.
		self::assertNotSame( 404, $this->browser()->get( 'wp-login.php?action=confirmaction&request_id=1&confirm_key=x' )->status );
	}

	/**
	 * Auth audit M2 and review 7: the neutral login handler must not hand the login
	 * address to an anonymous visitor when the owner chose a public login page.
	 */
	public function test_a_failed_front_end_login_does_not_reveal_the_login_address(): void {
		$page = (int) self::wp( 'post', 'create', '--post_type=page', '--post_status=publish', '--post_title=Sign in', '--porcelain' );
		self::eval( sprintf( '$o = get_option( "mdmfa_login" ); $o["public_login"] = "page"; $o["public_page"] = %d; update_option( "mdmfa_login", $o, true );', $page ) );

		$failed = $this->browser()->post( 'wp-admin/admin-post.php?action=mdmfa_login', array( 'log' => 'nobody', 'pwd' => 'wrong' ) );
		self::assertSame( 302, $failed->status );
		self::assertStringNotContainsString( self::$login, $failed->location() );
		self::assertStringContainsString( self::eval( sprintf( 'echo get_permalink( %d );', $page ) ), $failed->location() );

		// And login links keep the page to return to.
		$link = self::eval( 'echo wp_login_url( home_url( "/sample-page/" ) );' );
		self::assertStringContainsString( self::$login, $link, 'WP-CLI is an insider and sees the real address' );
		$front = $this->browser()->get( '?mdmfa_e2e_form=1' );
		self::assertStringNotContainsString( self::$login, $front->body );
	}

	/**
	 * Admin audit M1: the step-up check on application-password creation matched the
	 * route by a case-sensitive pattern.
	 */
	public function test_application_password_creation_is_guarded_whatever_the_route_looks_like(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );
		$this->submit_code( $browser, self::code( $secret ) );
		self::assertSame( 1, preg_match( '/var wpApiSettings = \{[^}]*"nonce":"([a-f0-9]+)"/', $browser->get( 'wp-admin/profile.php' )->body, $m ) );
		self::age_sessions( $id );

		foreach ( array( 'wp-json/wp/v2/Users/me/application-passwords', 'wp-json/WP/V2/USERS/ME/APPLICATION-PASSWORDS', '?rest_route=/wp/v2/users/' . $id . '/Application-Passwords' ) as $route ) {
			$created = $browser->raw( 'POST', $route, (string) json_encode( array( 'name' => 'sneaky' ) ), array( 'Content-Type: application/json', 'X-WP-Nonce: ' . $m[1] ) );
			self::assertNotSame( 201, $created->status, $route );
		}
		self::assertSame( '0', self::eval( sprintf( 'echo count( WP_Application_Passwords::get_user_application_passwords( %d ) );', $id ) ) );

		// Admin audit L2: the authorize screen's POST is refused too.
		$authorize = $browser->post( 'wp-admin/authorize-application.php', array( 'app_name' => 'sneaky', 'approve' => '1' ) );
		self::assertSame( 403, $authorize->status );
		self::assertSame( '0', self::eval( sprintf( 'echo count( WP_Application_Passwords::get_user_application_passwords( %d ) );', $id ) ) );
	}

	/**
	 * Admin audit M2: changing the account's email must not redirect the second step.
	 */
	public function test_changing_the_email_address_switches_email_codes_off_and_closes_recovery(): void {
		self::settings( array( 'roles' => array( 'author' => array( 'factors' => array( 'email' => true ), 'email_recovery' => true, 'recovery_wait_hours' => 0, 'trusted_devices' => true ) ) ) );
		list( $id, $login, $pass ) = self::user( 'author' );
		$secret                    = self::enroll( $id );
		self::enroll_email( $id );
		self::eval( sprintf( 'MaxtDesign\Mfa\Auth\TrustedDevice::issue( get_userdata( %d ) );', $id ) );
		self::eval( 'delete_option( "e2e_mail" );' );

		self::wp( 'user', 'update', (string) $id, '--user_email=attacker-' . $login . '@evil.example', '--skip-email' );

		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\EmailCode::has( %d ) ? "true" : "false";', $id ) ), 'the email factor waits for the new address to be confirmed' );
		self::assertSame( '0', self::eval( sprintf( 'echo MaxtDesign\Mfa\Auth\TrustedDevice::count( %d );', $id ) ) );
		self::assertContains( 'email_changed', array_column( self::log_events( $id ), 'event' ) );

		// The challenge offers no emailed code and no email recovery to the new mailbox.
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );
		$screen = $browser->get( self::lp( 'action=mdmfa-verify' ) );
		self::assertStringNotContainsString( 'Email me a code', $screen->body );
		self::assertStringNotContainsString( 'Reset by email', $screen->body );
		$browser->post( self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		$browser->post( self::lp( 'action=mdmfa-verify&method=email' ), array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_send' => '1' ) );
		self::assertSame( array(), self::mail_to( 'attacker-' . $login . '@evil.example' ), 'nothing is sent to the new address' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );

		// The authenticator still signs the owner in.
		self::assertTrue( $this->submit_code( $browser, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	/**
	 * Auth audit M3 and review 10: parallel wrong codes on separate pending logins must
	 * each count. Needs a server with several workers (CI); with one worker the requests
	 * are serial and the test still passes.
	 */
	public function test_parallel_wrong_codes_all_count_toward_the_lockout(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );
		$requests                  = array();
		for ( $i = 0; $i < 4; $i++ ) {
			$browser = $this->browser();
			$this->password( $browser, $login, $pass );
			$page       = $browser->get( self::lp( 'action=mdmfa-verify&method=totp' ) );
			$requests[] = array( $browser, self::lp( 'action=mdmfa-verify&method=totp' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_code' => self::wrong_code( $secret ) ) );
		}

		$responses = Browser::race( $requests );

		foreach ( $responses as $response ) {
			self::assertNoAuthCookie( $response );
		}
		$count  = (int) self::eval( sprintf( '$f = get_user_meta( %d, "mdmfa_failures", true ); echo is_array( $f ) ? (int) $f["count"] : 0;', $id ) );
		$failed = count( array_filter( $responses, static fn ( Response $r ): bool => str_contains( $r->body, 'That code is not valid' ) ) );
		$busy   = count( array_filter( $responses, static fn ( Response $r ): bool => str_contains( $r->body, 'in progress' ) ) );
		self::assertSame( 4, $failed + $busy, 'every request was either counted or turned away' );
		self::assertSame( $failed, $count, 'no failure was lost to a parallel write' );
	}

	/**
	 * Review 2: first activation tells the owners where the login went, and a site on
	 * plain permalinks keeps its login where it is.
	 */
	public function test_install_emails_the_address_and_never_moves_the_login_on_plain_permalinks(): void {
		$probe = 'delete_option( "e2e_mail" ); $saved = array( get_option( "mdmfa_login" ), get_option( "mdmfa_notices" ), get_option( "permalink_structure" ) );'
			. ' delete_option( "mdmfa_login" ); delete_option( "mdmfa_notices" ); %s'
			. ' MaxtDesign\Mfa\Install\Installer::install(); $made = get_option( "mdmfa_login" ); $mail = get_option( "e2e_mail", array() ); $notices = get_option( "mdmfa_notices" );'
			. ' update_option( "mdmfa_login", $saved[0], true ); update_option( "mdmfa_notices", $saved[1], false ); update_option( "permalink_structure", $saved[2] );'
			. ' echo wp_json_encode( array( "enabled" => $made["enabled"], "slug" => $made["slug"], "mail" => $mail, "notices" => array_keys( (array) $notices ) ) );';

		$pretty = (array) json_decode( self::eval( sprintf( $probe, '' ) ), true );
		self::assertTrue( $pretty['enabled'] );
		self::assertNotSame( array(), $pretty['mail'], 'administrators are emailed on first activation' );
		self::assertStringContainsString( $pretty['slug'], $pretty['mail'][0]['message'] );
		self::assertStringContainsString( 'MDMFA_DISABLE_LOGIN_LOCATION', $pretty['mail'][0]['message'], 'with the way back' );

		$plain = (array) json_decode( self::eval( sprintf( $probe, 'update_option( "permalink_structure", "" );' ) ), true );
		self::assertFalse( $plain['enabled'], 'plain permalinks: the address might not load, so the login stays put' );
		self::assertSame( array(), $plain['mail'] );
		self::assertSame( array( 'location_off' ), $plain['notices'] );

		self::assertSame( rtrim( self::$url, '/' ) . '/' . self::$login, self::wp( 'mdmfa', 'slug', 'get' ), 'the test left the real address alone' );
	}

	/**
	 * Review 3: defining MDMFA_ENCRYPTION_KEY must not make authenticators unreadable.
	 */
	public function test_key_commands_keep_authenticators_working_when_the_key_is_pinned_or_replaced(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );

		$line = self::wp( 'mdmfa', 'key', 'export-define' );
		self::assertSame( 1, preg_match( "/^define\( 'MDMFA_ENCRYPTION_KEY', '([A-Za-z0-9+\/=]{44})' \);$/", $line, $m ) );
		self::assertStringContainsString( 'current: ', self::wp( 'mdmfa', 'key', 'status' ) );

		// Pinning the current key changes nothing.
		self::wp( 'config', 'set', 'MDMFA_ENCRYPTION_KEY', $m[1], '--type=constant' );
		try {
			self::assertSame( 'current', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::key_state( %d );', $id ) ) );
			$browser = $this->browser();
			$this->password( $browser, $login, $pass );
			self::assertTrue( $this->submit_code( $browser, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );

			// A brand new key: secrets written under the salts are still readable and convert.
			self::wp( 'config', 'set', 'MDMFA_ENCRYPTION_KEY', base64_encode( random_bytes( 32 ) ), '--type=constant' );
			self::assertSame( 'older key', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::key_state( %d );', $id ) ) );
			self::assertTrue( (bool) self::mfa_status()['key_migrating'] );
			self::assertStringContainsString( 'Re-encrypted', self::wp( 'mdmfa', 'key', 'rewrap' ) );
			self::assertSame( 'current', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::key_state( %d );', $id ) ) );
			$again = $this->browser();
			$this->password( $again, $login, $pass );
			self::assertTrue( $this->submit_code( $again, self::code( $secret, 1 ) )->sets_cookie_prefix( 'wordpress_logged_in_' ), 'the same authenticator still works under the new key' );
		} finally {
			// Other tests' secrets are under the salts-derived key: put this user's back too.
			self::wp( 'user', 'meta', 'delete', (string) $id, 'mdmfa_totp' );
			self::wp( 'config', 'delete', 'MDMFA_ENCRYPTION_KEY', '--type=constant' );
			self::eval( 'delete_transient( "mdmfa_status_cache" ); $k = MaxtDesign\Mfa\Crypto\KeyProvider::from_environment(); update_option( "mdmfa_key_check", array( "kid" => $k->kid(), "source" => $k->source() ), false );' );
		}

		self::assertSame( '', self::wp( 'mdmfa', 'recovery-codes', (string) self::user( 'subscriber' )[0], '--yes' ), 'no codes for a user without a second step' );
		list( $owner ) = self::user( 'subscriber' );
		self::enroll( $owner );
		$printed = self::wp( 'mdmfa', 'recovery-codes', (string) $owner, '--yes' );
		self::assertSame( 10, preg_match_all( '/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/m', $printed ), 'a locked-out owner with server access gets a fresh set' );
		self::assertSame( '10', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\RecoveryCodes::remaining( %d );', $owner ) ) );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function mfa_status(): array {
		return (array) json_decode( self::wp( 'mdmfa', 'status', '--fresh', '--format=json' ), true );
	}
}
