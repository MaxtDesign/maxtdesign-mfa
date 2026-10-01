<?php
/**
 * P6 definition of done: the side-door rows of plan 4.3 (application passwords, XML-RPC,
 * non-interactive password logins) and step-up on creating an application password.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class SideDoorTest extends E2eTestCase {

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::reset_settings();
		}
		parent::tearDown();
	}

	private static function app_password( int $user_id ): string {
		return self::eval( sprintf( '$r = WP_Application_Passwords::create_new_application_password( %d, array( "name" => "e2e" ) ); echo is_wp_error( $r ) ? "error:" . $r->get_error_code() : $r[0];', $user_id ) );
	}

	private function rest_me( string $login, string $secret ): Response {
		return $this->browser()->raw( 'GET', 'wp-json/wp/v2/users/me?context=edit', '', array( 'Authorization: Basic ' . base64_encode( $login . ':' . $secret ) ) );
	}

	private function xmlrpc( string $login, string $secret ): string {
		$body = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>' . $login . '</string></value></param><param><value><string>' . $secret . '</string></value></param></params></methodCall>';
		return $this->browser()->raw( 'POST', 'xmlrpc.php', $body, array( 'Content-Type: text/xml' ) )->body;
	}

	private function token( string $login, string $pass ): Response {
		return $this->browser()->raw( 'POST', 'wp-json/mdmfa-e2e/v1/token', (string) json_encode( array( 'username' => $login, 'password' => $pass ) ), array( 'Content-Type: application/json' ) );
	}

	public function test_application_passwords_follow_the_role_and_skip_the_second_step(): void {
		list( $subscriber, $sub_login ) = self::user( 'subscriber' );
		self::enroll( $subscriber );
		list( $editor, $editor_login ) = self::user( 'editor' );
		self::enroll( $editor );
		$sub_secret = self::app_password( $subscriber );

		$ok = $this->rest_me( $sub_login, $sub_secret );
		self::assertSame( 200, $ok->status, 'an enrolled user in an Optional role uses an application password with no second step' );
		self::assertSame( $subscriber, json_decode( $ok->body, true )['id'] ?? null );
		self::assertSame( 0, self::sessions( $subscriber ), 'and it creates no browser session' );
		self::assertContains( 'app_password_used', array_column( self::log_events( $subscriber ), 'event' ) );

		self::assertSame( 'false', self::eval( sprintf( 'echo wp_is_application_passwords_available_for_user( %d ) ? "true" : "false";', $editor ) ), 'Required roles have no application passwords by default' );
		$editor_secret = self::app_password( $editor );
		self::assertSame( 401, $this->rest_me( $editor_login, $editor_secret )->status, 'so an existing one does not authenticate' );

		// The owner allows them for editors: the same password now works.
		self::settings( array( 'roles' => array( 'editor' => array( 'app_passwords' => true ) ) ) );
		self::assertSame( 200, $this->rest_me( $editor_login, $editor_secret )->status );

		// Back to the default: it stops working again.
		self::reset_settings();
		self::assertSame( 401, $this->rest_me( $editor_login, $editor_secret )->status );

		// Off for the whole site.
		self::settings( array( 'application_passwords' => 'off' ) );
		self::assertSame( 401, $this->rest_me( $sub_login, $sub_secret )->status );
	}

	public function test_an_account_password_never_works_as_basic_auth(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		self::enroll( $id );

		self::assertSame( 401, $this->rest_me( $login, $pass )->status, 'core REST takes application passwords only' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_a_rest_password_endpoint_is_refused_for_users_with_a_second_step(): void {
		list( $id, $login, $pass )      = self::user( 'subscriber' );
		self::enroll( $id );
		list( $plain, $plain_login, $plain_pass ) = self::user( 'subscriber' );

		$refused = $this->token( $login, $pass );
		self::assertSame( 403, $refused->status );
		self::assertSame( 'mdmfa_required', json_decode( $refused->body, true )['code'] ?? null );
		self::assertFalse( $refused->sets_cookie_prefix( 'mdmfa_pending=' ), 'no pending login is opened for a machine client' );
		self::assertContains( 'noninteractive_blocked', array_column( self::log_events( $id ), 'event' ) );

		$allowed = $this->token( $plain_login, $plain_pass );
		self::assertSame( 200, $allowed->status, 'password-only users are unaffected' );
		self::assertSame( $plain, json_decode( $allowed->body, true )['user'] ?? null );

		$wrong = $this->token( $login, 'not-the-password' );
		self::assertSame( 403, $wrong->status );
		self::assertNotSame( 'mdmfa_required', json_decode( $wrong->body, true )['code'] ?? null, 'a wrong password does not reveal that the account has a second step' );
	}

	public function test_xmlrpc_modes(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		self::enroll( $id );
		$secret = self::app_password( $id );

		$refused = $this->xmlrpc( $login, $pass );
		self::assertStringContainsString( '<int>403</int>', $refused );
		self::assertStringContainsString( 'application password', $refused, 'the error says what to use instead' );
		self::assertStringNotContainsString( 'faultCode', $this->xmlrpc( $login, $secret ), 'an application password works over XML-RPC' );

		self::settings( array( 'xmlrpc' => 'allow' ) );
		self::assertStringNotContainsString( 'faultCode', $this->xmlrpc( $login, $pass ), 'the owner can allow passwords' );
		self::assertContains( 'xmlrpc_password', array_column( self::log_events( $id ), 'event' ), 'and each use is logged' );

		self::settings( array( 'xmlrpc' => 'off' ) );
		self::assertStringContainsString( '<int>405</int>', $this->xmlrpc( $login, $secret ), 'off disables every authenticated method' );
		self::assertSame( 0, self::sessions( $id ) );
	}

	public function test_creating_an_application_password_needs_a_recent_verification(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$secret                    = self::enroll( $id );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );
		self::assertTrue( $this->submit_code( $browser, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		$profile = $browser->get( 'wp-admin/profile.php' );
		self::assertSame( 1, preg_match( '/var wpApiSettings = \{[^}]*"nonce":"([a-f0-9]+)"/', $profile->body, $m ), 'REST nonce on the profile screen' );
		$create = static fn ( Browser $b ): Response => $b->raw( 'POST', 'wp-json/wp/v2/users/me/application-passwords', (string) json_encode( array( 'name' => 'from the profile screen' ) ), array( 'Content-Type: application/json', 'X-WP-Nonce: ' . $m[1] ) );

		$fresh = $create( $browser );
		self::assertSame( 201, $fresh->status, 'right after signing in the verification is recent: ' . $fresh->body );

		self::age_sessions( $id );
		$stale = $create( $browser );
		self::assertSame( 403, $stale->status );
		self::assertSame( 'mdmfa_stepup_required', json_decode( $stale->body, true )['code'] ?? null );
		self::assertSame( '1', self::eval( sprintf( 'echo count( WP_Application_Passwords::get_user_application_passwords( %d ) );', $id ) ) );

		// Step up on My security, then it works again.
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
		self::assertSame( 201, $create( $browser )->status );

		// An application password cannot mint more application passwords.
		$first = self::app_password( $id );
		$via   = $this->browser()->raw( 'POST', 'wp-json/wp/v2/users/me/application-passwords', (string) json_encode( array( 'name' => 'self-made' ) ), array( 'Content-Type: application/json', 'Authorization: Basic ' . base64_encode( $login . ':' . $first ) ) );
		self::assertSame( 403, $via->status );
	}

	public function test_users_without_a_second_step_create_application_passwords_as_before(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );
		$profile = $browser->get( 'wp-admin/profile.php' );
		self::assertSame( 1, preg_match( '/var wpApiSettings = \{[^}]*"nonce":"([a-f0-9]+)"/', $profile->body, $m ) );

		$created = $browser->raw( 'POST', 'wp-json/wp/v2/users/me/application-passwords', (string) json_encode( array( 'name' => 'plain' ) ), array( 'Content-Type: application/json', 'X-WP-Nonce: ' . $m[1] ) );
		self::assertSame( 201, $created->status, $created->body );
	}
}
