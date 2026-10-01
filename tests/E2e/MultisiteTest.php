<?php
/**
 * P8: behaviour on a network (subdirectory multisite, plugin network-active). Sessions are
 * network-wide, so no single site may decide alone. Skipped on a single site; CI job
 * "e2e-multisite" runs it.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class MultisiteTest extends E2eTestCase {

	private static ?bool $network = null;
	private static string $shop   = '';
	private static string $shop_login = '';

	protected function setUp(): void {
		parent::setUp();
		if ( null === self::$network ) {
			self::$network = '1' === self::eval( 'echo is_multisite() ? "1" : "0";' );
		}
		if ( ! self::$network ) {
			self::markTestSkipped( 'Not a multisite (CI job "e2e-multisite" runs this).' );
		}
		if ( '' === self::$shop ) {
			$existing = self::eval( '$s = get_sites( array( "path" => "/shop/" ) ); echo $s ? get_site_url( (int) $s[0]->blog_id ) : "";' );
			if ( '' === $existing ) {
				self::wp( 'site', 'create', '--slug=shop', '--title=Shop' );
				$existing = rtrim( self::$url, '/' ) . '/shop';
			}
			self::$shop       = rtrim( $existing, '/' ) . '/';
			self::$shop_login = 'shop/' . basename( self::shop_wp( 'mdmfa', 'slug', 'get' ) );
		}
	}

	protected function tearDown(): void {
		if ( self::$network ) {
			self::shop_wp( 'option', 'delete', 'mdmfa_settings' );
			self::reset_settings();
		}
		parent::tearDown();
	}

	/**
	 * WP-CLI in the context of the second site.
	 */
	private static function shop_wp( string ...$args ): string {
		return self::wp( '--url=' . self::$shop, ...$args );
	}

	private function shop_password( Browser $browser, string $login, string $pass ): Response {
		return $browser->post( self::$shop_login, array( 'log' => $login, 'pwd' => $pass, 'wp-submit' => 'Log In' ) );
	}

	public function test_each_site_has_its_own_login_address_and_hides_wp_login_php(): void {
		self::assertNotSame( self::$login, basename( self::$shop_login ), 'the second site got its own address' );
		self::assertSame( 200, $this->browser()->get( self::lp() )->status );
		self::assertSame( 200, $this->browser()->get( self::$shop_login )->status );
		self::assertSame( 404, $this->browser()->get( 'wp-login.php' )->status );
		self::assertSame( 404, $this->browser()->get( 'shop/wp-login.php' )->status );
		self::assertSame( 404, $this->browser()->get( 'shop/' . self::$login )->status, 'one site\'s address is not another\'s' );

		// A login URL built on site 1 for site 2 carries site 2's address.
		$cross = self::eval( 'echo get_site_url( (int) get_sites( array( "path" => "/shop/" ) )[0]->blog_id, "wp-login.php", "login" );' );
		self::assertStringEndsWith( '/' . self::$shop_login, $cross );
		self::assertStringNotContainsString( 'wp-login.php', $cross );

		self::assertSame( 'true', self::eval( 'echo is_plugin_active_for_network( plugin_basename( MDMFA_FILE ) ) ? "true" : "false";' ) );
	}

	public function test_a_required_role_on_one_site_cannot_be_dodged_by_signing_in_on_another(): void {
		// Editor on site 1 (Required), past the setup period, nothing set up. No role on site 2.
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::wp( 'user', 'meta', 'update', (string) $id, 'mdmfa_grace_started', (string) ( time() - 30 * 86400 ) );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"roles":{"subscriber":{"policy":"off"}}}', '--format=json' );

		$response = $this->shop_password( $this->browser(), $login, $pass );

		self::assertNoAuthCookie( $response, 'a password alone gets no network-wide session through the lenient site' );
		self::assertStringContainsString( 'action=mdmfa-enroll', $response->location() );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_an_enrolled_account_is_challenged_on_a_site_whose_policy_is_off(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"roles":{"subscriber":{"policy":"off"}},"unlisted_role":{"policy":"off"}}', '--format=json' );
		self::settings( array( 'roles' => array( 'subscriber' => array( 'policy' => 'off' ) ), 'unlisted_role' => array( 'policy' => 'off' ) ) );

		$browser  = $this->browser();
		$response = $this->shop_password( $browser, $login, $pass );

		self::assertNoAuthCookie( $response );
		self::assertStringContainsString( 'action=mdmfa-verify', $response->location() );
		$page = $browser->get( self::$shop_login . '?action=mdmfa-verify&method=totp' );
		$done = $browser->post( self::$shop_login . '?action=mdmfa-verify&method=totp', array( 'mdmfa_form' => $page->form_token(), 'mdmfa_code' => self::code( $secret ) ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ), 'and the second step still completes there' );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );
	}

	public function test_a_super_admin_is_required_everywhere(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		self::wp( 'super-admin', 'add', $login );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"roles":{"administrator":{"policy":"off"}},"unlisted_role":{"policy":"off"}}', '--format=json' );
		try {
			$response = $this->shop_password( $this->browser(), $login, $pass );
			self::assertNoAuthCookie( $response );
			self::assertStringContainsString( 'action=mdmfa-enroll', $response->location(), 'setup is asked for before the session starts' );
		} finally {
			self::wp( 'super-admin', 'remove', $login );
		}
	}

	/*
	 * Independent review 2026-10-01, finding F1: the strictest site used to raise the policy
	 * mode only. Recovery, grace and application passwords still came from the site being
	 * visited, so a lenient site was a way round a strict one. The tests below use a staff
	 * membership on site 1 and a lenient membership on the shop, and go through both sites.
	 */

	private const LENIENT = '{"roles":{"subscriber":{"policy":"optional","email_recovery":true,"recovery_wait_hours":0,"app_passwords":true,"trusted_devices":true,"factors":{"email":true}}}}';

	/**
	 * What the plugin answers for a user on a request to one site.
	 *
	 * @return array<string, mixed>
	 */
	private static function answers( int $user_id, bool $on_shop ): array {
		$php = sprintf(
			'$u = get_userdata( %d ); $e = MaxtDesign\Mfa\Policy\Policy::effective( $u ); echo wp_json_encode( array('
			. ' "policy" => $e["policy"], "grace_days" => $e["grace_days"], "recovery_wait_hours" => $e["recovery_wait_hours"],'
			. ' "email_recovery" => MaxtDesign\Mfa\Flow\EmailRecovery::allowed( $u ),'
			. ' "app_passwords" => wp_is_application_passwords_available_for_user( $u ),'
			. ' "trusted_devices" => MaxtDesign\Mfa\Auth\TrustedDevice::allowed( $u ),'
			. ' "email_codes" => MaxtDesign\Mfa\Factors\EmailCode::allowed( $u ),'
			. ' "decision" => MaxtDesign\Mfa\Policy\Policy::decide( $u ) ) );',
			$user_id
		);
		return (array) json_decode( $on_shop ? self::wp( '--url=' . self::$shop, 'eval', $php ) : self::eval( $php ), true );
	}

	/**
	 * Mail captured on the shop (each site keeps its own capture).
	 *
	 * @return array<int, array{subject: string, message: string}>
	 */
	private static function shop_mail_to( string $address ): array {
		$all = (array) json_decode( self::wp( '--url=' . self::$shop, 'eval', 'echo wp_json_encode( get_option( "e2e_mail", array() ) );' ), true );
		return array_values( array_filter( $all, static fn ( array $m ): bool => $m['to'] === $address ) );
	}

	private static function has_totp( int $user_id ): bool {
		return 'true' === self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $user_id ) );
	}

	/**
	 * Password, then the verify screen, on one site. Returns the browser and the screen.
	 *
	 * @return array{Browser, Response, string}
	 */
	private function challenge( bool $on_shop, string $login, string $pass ): array {
		$browser = $this->browser();
		$first   = $on_shop ? $this->shop_password( $browser, $login, $pass ) : $this->password( $browser, $login, $pass );
		self::assertNoAuthCookie( $first );
		self::assertStringContainsString( 'action=mdmfa-verify', $first->location() );
		$path = ( $on_shop ? self::$shop_login : self::lp() ) . '?action=mdmfa-verify&method=totp';
		return array( $browser, $browser->get( $path ), $path );
	}

	private function rest_me( bool $on_shop, string $login, string $secret ): Response {
		return $this->browser()->raw( 'GET', ( $on_shop ? 'shop/' : '' ) . 'wp-json/wp/v2/users/me?context=edit', '', array( 'Authorization: Basic ' . base64_encode( $login . ':' . $secret ) ) );
	}

	private function xmlrpc( bool $on_shop, string $login, string $secret ): string {
		$body = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>' . $login . '</string></value></param><param><value><string>' . $secret . '</string></value></param></params></methodCall>';
		return $this->browser()->raw( 'POST', ( $on_shop ? 'shop/' : '' ) . 'xmlrpc.php', $body, array( 'Content-Type: text/xml' ) )->body;
	}

	public function test_a_lenient_site_cannot_weaken_recovery_grace_or_application_passwords_for_another_sites_staff(): void {
		// Site 1: administrators Required, no email recovery, no setup period, no application
		// passwords. The shop: immediate email recovery, seven days, application passwords.
		self::settings( array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) ) );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', self::LENIENT, '--format=json' );
		list( $id, $login, $pass ) = self::user( 'administrator' );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );
		self::enroll( $id );

		$expected = array(
			'policy'              => 'required',
			'grace_days'          => 0,
			'recovery_wait_hours' => 24,
			'email_recovery'      => false,
			'app_passwords'       => false,
			'trusted_devices'     => false,
			'email_codes'         => false,
			'decision'            => 'challenge',
		);
		self::assertSame( $expected, self::answers( $id, true ), 'on a request to the shop' );
		self::assertSame( $expected, self::answers( $id, false ), 'on a request to site 1' );

		// The fixture really is lenient: someone who only belongs to the shop gets all of it.
		list( $only, $only_login, $only_pass ) = self::user( 'subscriber' );
		self::shop_wp( 'user', 'set-role', (string) $only, 'subscriber' );
		// On a network this removes the user from site 1 only (remove_user_from_blog).
		self::wp( 'user', 'delete', (string) $only, '--yes' );
		self::enroll( $only );
		$lenient = self::answers( $only, true );
		self::assertSame( array( 'optional', true, true, true, 0 ), array( $lenient['policy'], $lenient['email_recovery'], $lenient['app_passwords'], $lenient['email_codes'], $lenient['recovery_wait_hours'] ) );

		// Recovery over HTTP, through both sites: not offered, and a forged request mails nothing.
		self::eval( 'delete_option( "e2e_mail" );' );
		self::shop_wp( 'option', 'delete', 'e2e_mail' );
		foreach ( array( true, false ) as $on_shop ) {
			list( $browser, $screen, $path ) = $this->challenge( $on_shop, $login, $pass );
			self::assertStringNotContainsString( 'Reset by email', $screen->body, $on_shop ? 'shop' : 'site 1' );
			$forged = $browser->post( $path, array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
			self::assertNoAuthCookie( $forged );
		}
		self::assertSame( array(), self::mail_to( $login . '@example.com' ) );
		self::assertSame( array(), self::shop_mail_to( $login . '@example.com' ) );
		self::assertTrue( self::has_totp( $id ), 'the factors are untouched' );
		self::assertNotContains( 'recovery_requested', array_column( self::log_events( $id ), 'event' ) );

		// The shop-only member does get recovery there, and it resets at once.
		list( $browser, $screen, $path ) = $this->challenge( true, $only_login, $only_pass );
		self::assertStringContainsString( 'Lost access? Reset by email', $screen->body );
		$browser->post( $path, array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		$mail = self::shop_mail_to( $only_login . '@example.com' );
		self::assertSame( 1, preg_match( '#https?://\S+admin-post\.php\?\S+#', end( $mail )['message'], $m ) );
		parse_str( (string) parse_url( $m[0], PHP_URL_QUERY ), $query );
		$confirm = $this->browser()->get( $m[0] );
		$done    = $this->browser()->post( 'shop/wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => $confirm->form_token() ) );
		self::assertStringContainsString( 'was reset for your account', $done->body );
		self::assertFalse( self::has_totp( $only ) );

		// Application passwords are one credential for the whole network.
		$secret = self::eval( sprintf( '$r = WP_Application_Passwords::create_new_application_password( %d, array( "name" => "e2e" ) ); echo is_wp_error( $r ) ? "error:" . $r->get_error_code() : $r[0];', $id ) );
		self::assertStringStartsNotWith( 'error:', $secret );
		self::assertSame( 401, $this->rest_me( true, $login, $secret )->status, 'refused on the lenient shop' );
		self::assertSame( 401, $this->rest_me( false, $login, $secret )->status, 'and on site 1' );
		$own = self::eval( sprintf( '$r = WP_Application_Passwords::create_new_application_password( %d, array( "name" => "e2e" ) ); echo is_wp_error( $r ) ? "error:" . $r->get_error_code() : $r[0];', $only ) );
		self::assertSame( 200, $this->rest_me( true, $only_login, $own )->status, 'the shop-only member uses one on the shop' );

		// The shop turning them on for everybody changes nothing for site 1's administrator.
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"application_passwords":"on"}', '--format=json' );
		self::assertSame( 401, $this->rest_me( true, $login, $secret )->status );
		self::assertSame( 401, $this->rest_me( false, $login, $secret )->status );

		// The same for account passwords over XML-RPC: the shop accepts them, site 1 does not.
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"xmlrpc":"allow"}', '--format=json' );
		self::enroll( $only );
		self::assertStringContainsString( '<int>403</int>', $this->xmlrpc( true, $login, $pass ), 'the password alone is refused on the shop' );
		self::assertStringContainsString( '<int>403</int>', $this->xmlrpc( false, $login, $pass ) );
		self::assertStringNotContainsString( 'faultCode', $this->xmlrpc( true, $only_login, $only_pass ), 'the shop-only member follows the shop' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_a_lenient_site_gives_no_setup_period_to_another_sites_staff(): void {
		// Not enrolled. Site 1 allows no setup period; the shop is Optional with seven days.
		self::settings( array( 'roles' => array( 'administrator' => array( 'grace_days' => 0 ) ) ) );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', self::LENIENT, '--format=json' );
		list( $id, $login, $pass ) = self::user( 'administrator' );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );

		foreach ( array( true, false ) as $on_shop ) {
			$where    = $on_shop ? 'shop' : 'site 1';
			$browser  = $this->browser();
			$response = $on_shop ? $this->shop_password( $browser, $login, $pass ) : $this->password( $browser, $login, $pass );
			self::assertNoAuthCookie( $response, $where );
			self::assertStringContainsString( 'action=mdmfa-enroll', $response->location(), $where );
			$enroll = ( $on_shop ? self::$shop_login : self::lp() ) . '?action=mdmfa-enroll';
			$page   = $browser->get( $enroll );
			self::assertStringNotContainsString( 'name="mdmfa_skip"', $page->body, "{$where}: setup cannot be skipped" );
			$skip = $browser->post( $enroll, array( 'mdmfa_form' => $page->form_token(), 'mdmfa_skip' => '1' ) );
			self::assertNoAuthCookie( $skip, "{$where}: a forged skip starts no session" );
		}
		self::assertSame( 0, self::sessions( $id ) );
		self::assertSame( 'enroll', self::answers( $id, true )['decision'] );
	}

	public function test_two_sites_that_both_require_keep_each_others_restrictions(): void {
		// Equal rank. Site 1: editors may recover by email after 48 hours, 0 days of grace.
		// The shop: subscribers Required, immediate recovery, 10 days, application passwords.
		self::settings( array( 'roles' => array( 'editor' => array( 'email_recovery' => true, 'recovery_wait_hours' => 48, 'grace_days' => 0, 'app_passwords' => false ) ) ) );
		self::shop_wp( 'option', 'update', 'mdmfa_settings', '{"roles":{"subscriber":{"policy":"required","email_recovery":true,"recovery_wait_hours":0,"grace_days":10,"app_passwords":true}}}', '--format=json' );
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );
		self::enroll( $id );

		$expected = array(
			'policy'              => 'required',
			'grace_days'          => 0,
			'recovery_wait_hours' => 48,
			'email_recovery'      => true,
			'app_passwords'       => false,
			'trusted_devices'     => false,
			'email_codes'         => false,
			'decision'            => 'challenge',
		);
		self::assertSame( $expected, self::answers( $id, true ) );
		self::assertSame( $expected, self::answers( $id, false ) );

		// Recovery completed through the shop waits site 1's 48 hours; nothing is reset yet.
		self::shop_wp( 'option', 'delete', 'e2e_mail' );
		list( $browser, $screen, $path ) = $this->challenge( true, $login, $pass );
		self::assertStringContainsString( 'Lost access? Reset by email', $screen->body, 'both sites allow it, so it is offered' );
		$browser->post( $path, array( 'mdmfa_form' => $screen->form_token(), 'mdmfa_recover' => '1' ) );
		$mail = self::shop_mail_to( $login . '@example.com' );
		self::assertNotSame( array(), $mail );
		self::assertSame( 1, preg_match( '#https?://\S+admin-post\.php\?\S+#', end( $mail )['message'], $m ) );
		parse_str( (string) parse_url( $m[0], PHP_URL_QUERY ), $query );
		$confirm = $this->browser()->get( $m[0] );
		$done    = $this->browser()->post( 'shop/wp-admin/admin-post.php', array( 'action' => 'mdmfa_recover', 't' => (string) $query['t'], 'mdmfa_form' => $confirm->form_token() ) );
		self::assertStringContainsString( 'will be reset in', $done->body );
		self::assertTrue( self::has_totp( $id ), 'no immediate reset through the site with no waiting period' );
		self::assertEqualsWithDelta( time() + 48 * 3600, (int) self::eval( sprintf( 'echo (int) get_user_meta( %d, "mdmfa_recovery_pending", true );', $id ) ), 120 );
		self::assertStringContainsString( 'action=mdmfa-verify', $this->shop_password( $this->browser(), $login, $pass )->location(), 'still challenged while waiting' );

		// When the wait is over the reset applies, and the setup period that restarts is
		// site 1's (none), not the shop's ten days.
		self::eval( sprintf( 'update_user_meta( %d, "mdmfa_recovery_pending", time() - 1 );', $id ) );
		$browser = $this->browser();
		$after   = $this->shop_password( $browser, $login, $pass );
		self::assertFalse( self::has_totp( $id ) );
		self::assertNoAuthCookie( $after );
		self::assertStringContainsString( 'action=mdmfa-enroll', $after->location() );
		self::assertStringNotContainsString( 'name="mdmfa_skip"', $browser->get( self::$shop_login . '?action=mdmfa-enroll' )->body, 'no fresh setup period from the lenient site' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_removing_a_user_from_one_site_keeps_their_passkeys(): void {
		list( $id )    = self::user( 'subscriber' );
		$authenticator = new \MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator();
		self::seed_passkey( $id, $authenticator );
		self::shop_wp( 'user', 'set-role', (string) $id, 'subscriber' );

		// On a network this removes the user from the site only (remove_user_from_blog).
		self::shop_wp( 'user', 'delete', (string) $id, '--yes' );

		self::assertSame( 1, self::passkey_count( $id ), 'the account still exists on the network, so its passkeys stay' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Policy\Policy::is_enrolled( %d ) ? "true" : "false";', $id ) ) );
	}
}
