<?php
/**
 * P5 definition of done (plan section 14): passkeys over HTTP against real WordPress, with a
 * software authenticator standing in for the browser and the device.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator;

// phpcs:ignoreFile

final class PasskeyTest extends E2eTestCase {

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::eval( 'delete_option( "mdmfa_settings" ); global $wpdb; $wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE \'%mdmfa_ipthrottle%\'" );' );
		}
		parent::tearDown();
	}

	/**
	 * Lets authors sign in with a passkey alone.
	 */
	private static function allow_passwordless( string $role = 'author' ): void {
		self::wp( 'option', 'update', 'mdmfa_settings', (string) json_encode( array( 'roles' => array( $role => array( 'passwordless' => true ) ) ) ), '--format=json' );
	}

	/**
	 * The passwordless control on the login page.
	 *
	 * @return array{action: string, fields: array<string, string>, config: array<string, mixed>}
	 */
	private function passwordless_form( Browser $browser ): array {
		$page  = $browser->get( self::lp() );
		$forms = $page->passkey_forms();
		self::assertCount( 1, $forms, 'one passwordless control on the login page' );
		self::assertSame( 'mdmfa_passwordless', $forms[0]['config']['field'] );
		self::assertSame( 'user_login', $forms[0]['config']['conditional'] ?? null, 'autofill (conditional mediation) targets the username field' );
		self::assertSame( array(), $forms[0]['config']['options']['allowCredentials'] ?? null, 'discoverable: no credential list before a user is known' );
		self::assertSame( 'required', $forms[0]['config']['options']['userVerification'] ?? null );
		return $forms[0];
	}

	private static function assertPasskeyRefused( Response $response, string $code, int $user_id, string $message ): void {
		self::assertSame( 302, $response->status, $message );
		self::assertStringContainsString( 'mdmfa_passkey=' . $code, $response->location(), $message );
		self::assertNoAuthCookie( $response, $message );
		self::assertSame( 0, self::sessions( $user_id ), $message );
	}

	public function test_passkey_added_on_my_security_then_used_as_the_second_factor(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->browser();
		self::assertTrue( $this->password( $browser, $login, $pass )->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		$page = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		self::assertSame( 200, $page->status );
		self::assertPasskeyModule( $page, true, 'the security page offers a passkey, so it loads the module' );
		$forms = $page->passkey_forms();
		self::assertCount( 1, $forms );
		self::assertSame( 'create', $forms[0]['config']['mode'] );
		$options = $forms[0]['config']['options'];
		self::assertSame( parse_url( self::$url, PHP_URL_HOST ), $options['rp']['id'] );
		self::assertSame( array( -7, -257, -8 ), array_column( $options['pubKeyCredParams'], 'alg' ) );
		self::assertSame( 'none', $options['attestation'] );
		self::assertNotSame( base64_encode( (string) $id ), $options['user']['id'], 'the user handle is random, never the user ID' );

		$authenticator = new VirtualAuthenticator();
		$added         = $this->submit_passkey( $browser, $forms[0], $authenticator->create( $options, self::origin() ), array( 'mdmfa_passkey_name' => 'Work laptop' ) );
		self::assertContains( $added->status, array( 200, 302 ) );
		self::assertSame( 1, self::passkey_count( $id ) );
		self::assertSame( 'Work laptop', self::eval( sprintf( 'global $wpdb; echo $wpdb->get_var( $wpdb->prepare( "SELECT name FROM %%i WHERE user_id = %%d", $wpdb->base_prefix . "mdmfa_credentials", %d ) );', $id ) ) );
		self::assertContains( 'enrolled', array_column( self::log_events( $id ), 'event' ) );

		// The same response cannot be registered twice (the challenge was consumed).
		$this->submit_passkey( $browser, $forms[0], $authenticator->create( $options, self::origin() ) );
		self::assertSame( 1, self::passkey_count( $id ), 'a replayed registration adds nothing' );

		// Next sign-in: the passkey is the second factor, offered first.
		$authenticator->counts = true;
		$next                  = $this->browser();
		$first                 = $this->password( $next, $login, $pass );
		self::assertStringContainsString( 'action=mdmfa-verify', $first->location() );
		self::assertNoAuthCookie( $first );
		$verify = $next->get( $first->location() );
		self::assertPasskeyModule( $verify, true );
		$forms = $verify->passkey_forms();
		self::assertCount( 1, $forms, 'the verify screen leads with the passkey' );
		self::assertSame( 'get', $forms[0]['config']['mode'] );
		self::assertSame( array( Base64Url::encode( $authenticator->credential_id ) ), array_column( $forms[0]['config']['options']['allowCredentials'], 'id' ) );

		// A wrong signature is refused and does not start a session.
		$bad = $this->submit_passkey( $next, $forms[0], $authenticator->get( $forms[0]['config']['options'], self::origin(), array( 'tamper_signature' => true ) ) );
		self::assertNoAuthCookie( $bad );
		self::assertSame( 1, self::sessions( $id ), 'only the first browser session exists' );

		$verify = $next->get( self::lp( 'action=mdmfa-verify&method=passkey' ) );
		$forms  = $verify->passkey_forms();
		$ok     = $this->submit_passkey( $next, $forms[0], $authenticator->get( $forms[0]['config']['options'], self::origin() ) );
		self::assertSame( 302, $ok->status, substr( strip_tags( $ok->body ), 0, 400 ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertSame( 2, self::sessions( $id ) );
		self::assertContains( 'passkey', array_column( array_filter( self::stamps( $id ) ), 'factor' ) );
		self::assertSame( '0', self::eval( sprintf( 'global $wpdb; echo (int) $wpdb->get_var( $wpdb->prepare( "SELECT flagged FROM %%i WHERE user_id = %%d", $wpdb->base_prefix . "mdmfa_credentials", %d ) );', $id ) ) );
	}

	public function test_adding_a_passkey_to_an_enrolled_account_needs_a_recent_verification(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );
		self::assertTrue( $this->submit_code( $browser, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		// Age the session's verification past the 10-minute window.
		self::eval( sprintf( '$t = get_user_meta( %1$d, "session_tokens", true ); foreach ( $t as $k => $s ) { $t[ $k ]["mdmfa"]["verified_at"] = time() - 3600; } update_user_meta( %1$d, "session_tokens", $t );', $id ) );

		$page  = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		$forms = array_values( array_filter( $page->passkey_forms(), static fn ( array $f ): bool => 'create' === $f['config']['mode'] ) );
		self::assertCount( 1, $forms );
		$authenticator = new VirtualAuthenticator();
		$this->submit_passkey( $browser, $forms[0], $authenticator->create( $forms[0]['config']['options'], self::origin() ) );
		self::assertSame( 0, self::passkey_count( $id ), 'a stale session cannot add a factor' );

		// After a fresh step-up the same page adds it.
		$page = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		$browser->post(
			'wp-admin/profile.php?page=mdmfa-account',
			array(
				'_wpnonce'     => $page->input( '_wpnonce' ),
				'mdmfa_op'     => 'stepup',
				'mdmfa_method' => 'totp',
				'mdmfa_code'   => self::code( $secret, 1 ),
			)
		);
		$page  = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		$forms = array_values( array_filter( $page->passkey_forms(), static fn ( array $f ): bool => 'create' === $f['config']['mode'] ) );
		$this->submit_passkey( $browser, $forms[0], $authenticator->create( $forms[0]['config']['options'], self::origin() ) );
		self::assertSame( 1, self::passkey_count( $id ) );
	}

	public function test_passwordless_sign_in_when_the_role_allows_it_and_replay_fails(): void {
		self::allow_passwordless();
		list( $id ) = self::user( 'author' );
		$authenticator         = new VirtualAuthenticator( -8 );
		$authenticator->counts = true;
		self::seed_passkey( $id, $authenticator );
		$logins = self::counter( 'e2e_wp_login' );

		$browser = $this->browser();
		$form    = $this->passwordless_form( $browser );
		$json    = $authenticator->get( $form['config']['options'], self::origin() );
		$ok      = $this->submit_passkey( $browser, $form, $json );

		self::assertSame( 302, $ok->status, substr( strip_tags( $ok->body ), 0, 400 ) );
		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		self::assertStringContainsString( '/wp-admin/', $ok->location() );
		self::assertSame( 1, self::sessions( $id ) );
		self::assertSame( 'passkey', self::stamps( $id )[0]['factor'] ?? null );
		self::assertSame( $logins + 1, self::counter( 'e2e_wp_login' ), 'wp_login fires once' );
		self::assertContains( 'passwordless_ok', array_column( self::log_events( $id ), 'event' ) );

		$replay = $this->submit_passkey( $this->browser(), $form, $json );
		self::assertSame( 302, $replay->status );
		self::assertStringContainsString( 'mdmfa_passkey=', $replay->location() );
		self::assertNoAuthCookie( $replay, 'a captured assertion cannot be replayed' );
		self::assertSame( 1, self::sessions( $id ) );
	}

	public function test_passwordless_refusals(): void {
		self::allow_passwordless();
		list( $author ) = self::user( 'author' );
		$authenticator  = new VirtualAuthenticator();
		$authenticator->counts = true;
		self::seed_passkey( $author, $authenticator );

		$form = $this->passwordless_form( $this->browser() );
		self::assertPasskeyRefused(
			$this->submit_passkey( $this->browser(), $form, $authenticator->get( $form['config']['options'], self::origin(), array( 'uv' => false ) ) ),
			'mdmfa_passkey_failed',
			$author,
			'user verification is required for passwordless'
		);

		$form = $this->passwordless_form( $this->browser() );
		self::assertPasskeyRefused(
			$this->submit_passkey( $this->browser(), $form, $authenticator->get( $form['config']['options'], self::origin(), array( 'user_handle' => random_bytes( 32 ) ) ) ),
			'mdmfa_passkey_failed',
			$author,
			'the userHandle must be the credential owner\'s'
		);

		$form = $this->passwordless_form( $this->browser() );
		self::assertPasskeyRefused(
			$this->submit_passkey( $this->browser(), $form, $authenticator->get( $form['config']['options'], self::origin(), array( 'origin' => 'http://evil.example' ) ) ),
			'mdmfa_passkey_failed',
			$author,
			'a foreign origin is refused'
		);

		list( $subscriber ) = self::user( 'subscriber' );
		$other              = new VirtualAuthenticator();
		self::seed_passkey( $subscriber, $other );
		$form = $this->passwordless_form( $this->browser() );
		self::assertPasskeyRefused(
			$this->submit_passkey( $this->browser(), $form, $other->get( $form['config']['options'], self::origin() ) ),
			'mdmfa_passwordless_off',
			$subscriber,
			'a role without passwordless must use its password first'
		);
		$page = $this->browser()->get( self::lp( 'mdmfa_passkey=mdmfa_passwordless_off' ) );
		self::assertStringContainsString( 'Passkey-only sign-in is not enabled for your account.', $page->body );
	}

	public function test_counter_anomaly_is_flagged_and_logged_but_not_blocked_by_default(): void {
		self::allow_passwordless();
		list( $id )    = self::user( 'author' );
		$authenticator = new VirtualAuthenticator();
		$authenticator->counter = 5;
		self::seed_passkey( $id, $authenticator, 10 );

		$browser = $this->browser();
		$form    = $this->passwordless_form( $browser );
		$ok      = $this->submit_passkey( $browser, $form, $authenticator->get( $form['config']['options'], self::origin() ) );

		self::assertTrue( $ok->sets_cookie_prefix( 'wordpress_logged_in_' ), 'counter_anomaly_block is off by default' );
		self::assertSame( '1', self::eval( sprintf( 'global $wpdb; echo (int) $wpdb->get_var( $wpdb->prepare( "SELECT flagged FROM %%i WHERE user_id = %%d", $wpdb->base_prefix . "mdmfa_credentials", %d ) );', $id ) ) );
		self::assertContains( 'counter_anomaly', array_column( self::log_events( $id ), 'event' ) );

		$page = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		self::assertStringContainsString( 'reported an unexpected counter', $page->body, 'the owner is warned' );
	}

	public function test_passkey_module_loads_only_where_a_passkey_is_offered(): void {
		$browser = $this->browser();
		self::assertPasskeyModule( $browser->get( self::lp() ), false, 'no passwordless role: the login page stays asset-free' );
		self::assertPasskeyModule( $browser->get( '' ), false, 'never on the front end' );

		self::allow_passwordless();
		self::assertPasskeyModule( $browser->get( self::lp() ), true, 'passwordless on: the login page offers it' );
		self::assertPasskeyModule( $browser->get( self::lp( 'action=lostpassword' ) ), false, 'not on other login actions' );
		self::assertPasskeyModule( $browser->get( '' ), false, 'still never on the front end' );

		// A TOTP-only user never meets the module on the verify screen.
		self::wp( 'option', 'delete', 'mdmfa_settings' );
		list( $id, $login, $pass ) = self::user( 'editor' );
		self::enroll( $id );
		$this->password( $browser, $login, $pass );
		self::assertPasskeyModule( $browser->get( self::lp( 'action=mdmfa-verify' ) ), false );
	}
}
