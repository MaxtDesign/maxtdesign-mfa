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
