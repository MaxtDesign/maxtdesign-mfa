<?php
/**
 * P3 definition of done (plan section 14) against real WordPress + WooCommerce over HTTP
 * (CI job "e2e-wc"): customers finish their second step on My Account and never load
 * wp-login.php; a password-reset auto-login becomes a challenge; checkout login returns to
 * checkout with the cart; new-account checkout still logs in; zero plugin CSS/JS.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2eWc;

use MaxtDesign\Mfa\Tests\E2e\Browser;
use MaxtDesign\Mfa\Tests\E2e\E2eTestCase;
use MaxtDesign\Mfa\Tests\E2e\Response;

// phpcs:ignoreFile

final class CustomerPathTest extends E2eTestCase {

	private static string $account  = '';
	private static string $checkout = '';
	private static int $product     = 0;

	protected function setUp(): void {
		parent::setUp();
		if ( '' === self::$account ) {
			self::$account  = self::eval( 'echo wc_get_page_permalink( "myaccount" );' );
			self::$checkout = self::eval( 'echo wc_get_page_permalink( "checkout" );' );
			self::$product  = (int) self::eval( 'echo (int) get_option( "mdmfa_e2e_product" );' );
		}
	}

	/**
	 * Logs in through the My Account form. Returns the password-step response.
	 */
	private function account_login( Browser $browser, string $login, string $pass ): Response {
		$page = $browser->get( self::$account );
		return $browser->post(
			self::$account,
			array(
				'username'                => $login,
				'password'                => $pass,
				'login'                   => 'Log in',
				'woocommerce-login-nonce' => $page->input( 'woocommerce-login-nonce' ),
			)
		);
	}

	/**
	 * Submits a code on the My Account challenge.
	 */
	private function account_code( Browser $browser, string $code, string $method = 'totp' ): Response {
		$url  = add_query( self::$account, 'mdmfa_method', $method );
		$page = $browser->get( $url );
		return $browser->post(
			$url,
			array(
				'mdmfa_wc'   => '1',
				'mdmfa_form' => $page->form_token(),
				'mdmfa_code' => $code,
			)
		);
	}

	private static function assertNeverWpLogin( Browser $browser ): void {
		foreach ( $browser->history as $url ) {
			self::assertStringNotContainsString( 'wp-login.php', $url, 'a customer flow touched wp-login.php' );
		}
	}

	private static function assertNoPluginAssets( Response $response ): void {
		self::assertSame( 0, preg_match( '/<(script|link|style)\b[^>]*(mdmfa|maxtdesign-mfa)/i', $response->body ), 'plugin CSS/JS found' );
	}

	public function test_customer_second_step_happens_on_my_account_not_wp_login(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();

		$step1 = $this->account_login( $browser, $login, $pass );
		self::assertSame( 302, $step1->status );
		self::assertSame( self::$account, $step1->location() );
		self::assertTrue( $step1->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertNoAuthCookie( $step1 );
		self::assertSame( 0, self::sessions( $id ) );

		$challenge = $browser->get( self::$account );
		self::assertStringContainsString( 'woocommerce-form-login', $challenge->body );
		self::assertStringContainsString( 'name="mdmfa_code"', $challenge->body );
		self::assertStringNotContainsString( 'name="password"', $challenge->body, 'the password form is swapped out' );
		self::assertNoPluginAssets( $challenge );

		$wrong = $this->account_code( $browser, self::wrong_code( $secret ) );
		self::assertSame( 200, $wrong->status );
		self::assertStringContainsString( 'That code is not valid', $wrong->body );

		$done = $this->account_code( $browser, self::code( $secret ) );
		self::assertSame( 302, $done->status, substr( strip_tags( $done->body ), 0, 400 ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null );
		self::assertStringContainsString( 'Log out', $browser->get( self::$account )->body, 'My Account dashboard after login' );
		self::assertNeverWpLogin( $browser );
	}

	public function test_recovery_code_and_start_over_on_my_account(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		self::enroll( $id );
		$codes   = (array) json_decode( self::eval( sprintf( 'echo wp_json_encode( MaxtDesign\\Mfa\\Factors\\RecoveryCodes::generate( %d ) );', $id ) ), true );
		$browser = $this->browser();

		$this->account_login( $browser, $login, $pass );
		$page = $browser->get( self::$account );
		self::assertSame( 1, preg_match( '/href="([^"]*mdmfa_cancel=[0-9a-f]{64}[^"]*)"/', $page->body, $m ) );
		$browser->get( html_entity_decode( $m[1] ) );
		self::assertFalse( $browser->has_cookie_prefix( 'mdmfa_pending' ), 'start over clears the pending login' );
		self::assertStringContainsString( 'name="password"', $browser->get( self::$account )->body );

		$this->account_login( $browser, $login, $pass );
		$done = $this->account_code( $browser, (string) $codes[0], 'recovery' );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 'recovery', self::stamps( $id )[0]['factor'] ?? null );
		self::assertNeverWpLogin( $browser );
	}

	public function test_password_reset_auto_login_becomes_a_challenge_not_a_session(): void {
		list( $id, $login, ) = self::user( 'customer' );
		$secret              = self::enroll( $id );
		$key                 = self::eval( sprintf( 'echo get_password_reset_key( get_userdata( %d ) );', $id ) );
		$lost                = self::eval( 'echo wc_lostpassword_url();' );
		$browser             = $this->browser();

		// WooCommerce's emailed link: stores the key in a cookie, then shows the form.
		$link = $browser->get( add_query( add_query( $lost, 'key', $key ), 'id', (string) $id ) );
		self::assertSame( 302, $link->status );
		$form = $browser->get( $link->location() );
		$new  = bin2hex( random_bytes( 10 ) ) . 'Aa1!';

		$reset = $browser->post(
			$form->location() ?: $link->location(),
			array(
				'password_1'                       => $new,
				'password_2'                       => $new,
				'reset_key'                        => $form->input( 'reset_key' ),
				'reset_login'                      => $form->input( 'reset_login' ),
				'wc_reset_password'                => 'true',
				'woocommerce-reset-password-nonce' => $form->input( 'woocommerce-reset-password-nonce' ),
			)
		);

		self::assertSame( 302, $reset->status, substr( strip_tags( $reset->body ), 0, 400 ) );
		self::assertSame( self::$account, $reset->location(), 'WooCommerce\'s redirect is sent to the challenge' );
		self::assertNoAuthCookie( $reset, 'the reset must not log an enrolled user in' );
		self::assertTrue( $reset->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertSame( 0, self::sessions( $id ) );
		$blocked = array_values( array_filter( self::log_events( $id ), static fn ( array $e ): bool => 'bypass_blocked' === $e['event'] ) );
		self::assertSame( 'wc_set_customer_auth_cookie', $blocked[0]['detail'] ?? null );

		$done = $this->account_code( $browser, self::code( $secret ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertStringContainsString( 'password-reset=true', $done->location(), 'then on to where WooCommerce was going' );
		self::assertNeverWpLogin( $browser );
	}

	public function test_checkout_login_returns_to_checkout_with_the_cart(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();

		$browser->get( add_query( self::$checkout, 'add-to-cart', (string) self::$product ) );
		$checkout = $browser->get( self::$checkout );
		self::assertStringContainsString( 'MFA E2E Product', $checkout->body );
		self::assertNoPluginAssets( $checkout );

		$step1 = $browser->post(
			self::$checkout,
			array(
				'username'                => $login,
				'password'                => $pass,
				'login'                   => 'Login',
				'redirect'                => $checkout->input( 'redirect' ),
				'woocommerce-login-nonce' => $checkout->input( 'woocommerce-login-nonce' ),
			)
		);
		self::assertSame( self::$account, $step1->location() );
		self::assertNoAuthCookie( $step1 );

		$done = $this->account_code( $browser, self::code( $secret ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( self::$checkout, $done->location(), 'back to checkout' );

		$after = $browser->get( self::$checkout );
		self::assertStringContainsString( 'MFA E2E Product', $after->body, 'the cart survived the login' );
		self::assertNeverWpLogin( $browser );
	}

	public function test_new_account_checkout_still_logs_in(): void {
		$browser = $this->browser();
		$email   = 'e2e' . bin2hex( random_bytes( 4 ) ) . '@example.com';

		$browser->get( add_query( self::$checkout, 'add-to-cart', (string) self::$product ) );
		$checkout = $browser->get( self::$checkout );
		$result   = $browser->post(
			add_query( home_url_of( self::$checkout ), 'wc-ajax', 'checkout' ),
			array(
				'billing_first_name'                  => 'Test',
				'billing_last_name'                   => 'Buyer',
				'billing_country'                     => 'US',
				'billing_address_1'                   => '1 Main St',
				'billing_city'                        => 'Austin',
				'billing_state'                       => 'TX',
				'billing_postcode'                    => '78701',
				'billing_phone'                       => '5125550100',
				'billing_email'                       => $email,
				'createaccount'                       => '1',
				'payment_method'                      => 'cod',
				'woocommerce-process-checkout-nonce' => $checkout->input( 'woocommerce-process-checkout-nonce' ),
				'_wp_http_referer'                    => '/?wc-ajax=update_order_review',
			)
		);

		$json = (array) json_decode( $result->body, true );
		self::assertSame( 'success', $json['result'] ?? null, substr( $result->body, 0, 600 ) );
		self::assertTrue( $result->sets_cookie_prefix( 'wordpress_logged_in_' ), 'a new, not-yet-enrolled customer is logged in as before' );
		self::assertNeverWpLogin( $browser );
	}

	public function test_front_end_login_form_posts_to_the_neutral_handler(): void {
		$form = $this->browser()->get( '?mdmfa_e2e_form=1' );
		self::assertSame( 1, preg_match( '/<form[^>]*action="([^"]+)"/', $form->body, $m ) );
		$action = html_entity_decode( $m[1] );
		self::assertStringContainsString( 'admin-post.php?action=mdmfa_login', $action );

		list( $id, $login, $pass ) = self::user( 'customer' );
		self::enroll( $id );
		$mfa = $this->browser();
		$r   = $mfa->post( $action, array( 'log' => $login, 'pwd' => $pass, 'redirect_to' => home_url_of( self::$account ) . '?landed=1' ) );
		self::assertSame( self::$account, $r->location(), 'enrolled: challenge on My Account' );
		self::assertNoAuthCookie( $r );
		self::assertNeverWpLogin( $mfa );

		list( , $plain_login, $plain_pass ) = self::user( 'customer' );
		$plain                             = $this->browser();
		$r                                 = $plain->post( $action, array( 'log' => $plain_login, 'pwd' => $plain_pass, 'redirect_to' => home_url_of( self::$account ) . '?landed=1' ) );
		self::assertStringContainsString( 'landed=1', $r->location(), 'not enrolled: straight to redirect_to' );
		self::assertTrue( $r->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		$bad = $this->browser()->post( $action, array( 'log' => $plain_login, 'pwd' => 'wrong' ) );
		self::assertStringContainsString( 'mdmfa_login=failed', $bad->location() );
		self::assertStringNotContainsString( 'wp-login.php', $bad->location() );
	}

	public function test_another_plugins_form_post_goes_to_the_challenge(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		self::enroll( $id );

		$r = $this->browser()->post( '', array( 'mdmfa_e2e' => 'custom_login', 'log' => $login, 'pwd' => $pass ) );

		self::assertSame( self::$account, $r->location() );
		self::assertNoAuthCookie( $r );
		self::assertTrue( $r->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_ajax_login_gets_an_error_with_a_link_and_no_session(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		self::enroll( $id );

		$r    = $this->browser()->post( 'wp-admin/admin-ajax.php', array( 'action' => 'mdmfa_e2e_login', 'log' => $login, 'pwd' => $pass ) );
		$json = (array) json_decode( $r->body, true );

		self::assertStringContainsString( 'Continue to verification', (string) ( $json['error'] ?? '' ) );
		self::assertStringContainsString( self::$account, html_entity_decode( (string) ( $json['error'] ?? '' ) ) );
		self::assertTrue( $r->sets_cookie_prefix( 'mdmfa_pending=' ) );
		self::assertNoAuthCookie( $r );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_security_tab_turns_on_two_step_verification(): void {
		list( $id, $login, $pass ) = self::user( 'customer' );
		$browser                   = $this->browser();
		$this->account_login( $browser, $login, $pass );
		$tab = self::eval( 'echo wc_get_account_endpoint_url( "mdmfa-security" );' );

		$page = $browser->get( $tab );
		self::assertSame( 200, $page->status );
		self::assertStringContainsString( 'Set up authenticator app', $page->body );
		self::assertNoPluginAssets( $page );

		$begin = $browser->post( $tab, array( 'mdmfa_op' => 'totp_begin', '_wpnonce' => $page->input( '_wpnonce' ) ) );
		self::assertSame( 302, $begin->status );
		$setup = $browser->get( $begin->location() );
		self::assertSame( 1, preg_match( '/<code class="mdmfa-secret">([A-Z2-7 ]+)<\/code>/', $setup->body, $m ) );
		$secret = (string) \MaxtDesign\Mfa\Support\Base32::decode( $m[1] );

		$confirm = $browser->post( $tab, array( 'mdmfa_op' => 'totp_confirm', '_wpnonce' => $setup->input( '_wpnonce' ), 'mdmfa_code' => self::code( $secret ) ) );
		self::assertSame( 200, $confirm->status );
		self::assertSame( 10, preg_match_all( '/<li><code>[A-Z2-7]{4}(-[A-Z2-7]{4}){3}<\/code><\/li>/', $confirm->body ), 'first recovery codes shown once' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\\Mfa\\Factors\\TotpStore::has( %d ) ? "true" : "false";', $id ) ) );
		self::assertSame( 'totp', self::stamps( $id )[0]['factor'] ?? null, 'the session is stamped after proving the factor' );

		$remove = $browser->post( $tab, array( 'mdmfa_op' => 'totp_remove', '_wpnonce' => $confirm->input( '_wpnonce' ) ) );
		self::assertSame( 302, $remove->status );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\\Mfa\\Factors\\TotpStore::has( %d ) ? "true" : "false";', $id ) ), 'fresh step-up from setup allows removal' );
		self::assertNeverWpLogin( $browser );
	}
}

function add_query( string $url, string $key, string $value ): string {
	return $url . ( str_contains( $url, '?' ) ? '&' : '?' ) . rawurlencode( $key ) . '=' . rawurlencode( $value );
}

function home_url_of( string $url ): string {
	$parts = parse_url( $url );
	return ( $parts['scheme'] ?? 'http' ) . '://' . ( $parts['host'] ?? '' ) . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' ) . '/';
}
