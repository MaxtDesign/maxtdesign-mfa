<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\HttpAuth;
use MaxtDesign\Mfa\Settings\LoginSlug;
use MaxtDesign\Mfa\Settings\Options;
use PHPUnit\Framework\TestCase;

// phpcs:ignoreFile

final class HttpAuthTest extends TestCase {

	private string $slug = '';

	protected function setUp(): void {
		mdmfa_test_reset();
		$this->slug = LoginSlug::generate();
		$GLOBALS['mdmfa_test']['options'][ Options::LOGIN ] = array( 'enabled' => true, 'slug' => $this->slug );
		$_GET  = array();
		$_POST = array();
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['REQUEST_URI'], $_SERVER['SCRIPT_NAME'], $_SERVER['REQUEST_METHOD'] );
	}

	protected function tearDown(): void {
		$_GET  = array();
		$_POST = array();
		unset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'], $_SERVER['REQUEST_URI'], $_SERVER['SCRIPT_NAME'], $_SERVER['REQUEST_METHOD'] );
	}

	/**
	 * @param array<string, string> $get
	 * @param array<string, string> $post
	 */
	private function request( string $script, string $uri, array $get = array(), array $post = array() ): void {
		$_SERVER['SCRIPT_NAME'] = $script;
		$_SERVER['REQUEST_URI'] = $uri;
		$_GET                   = $get;
		$_POST                  = $post;
	}

	public function test_only_the_requests_own_basic_credentials_count(): void {
		self::assertFalse( HttpAuth::matches( 'alice', 'secret' ), 'no Basic credentials in the request' );

		$_SERVER['PHP_AUTH_USER'] = 'alice';
		$_SERVER['PHP_AUTH_PW']   = 'secret';
		self::assertTrue( HttpAuth::matches( 'alice', 'secret' ) );
		self::assertFalse( HttpAuth::matches( 'bob', 'secret' ), 'another account being authenticated in the same request' );
		self::assertFalse( HttpAuth::matches( 'alice', 'other' ), 'another password, for example from a form' );
		self::assertFalse( HttpAuth::matches( '', '' ) );
		self::assertFalse( HttpAuth::matches( null, array() ) );

		// WordPress slashes $_SERVER; a gate may hand the password on either way.
		$_SERVER['PHP_AUTH_PW'] = "it\\'s";
		self::assertTrue( HttpAuth::matches( 'alice', "it\\'s" ) );
		self::assertTrue( HttpAuth::matches( 'alice', "it's" ) );

		$_SERVER['PHP_AUTH_PW'] = '';
		self::assertFalse( HttpAuth::matches( 'alice', '' ) );
	}

	public function test_only_the_second_steps_own_pages_are_flow_requests(): void {
		$slug = '/' . $this->slug;
		$v    = array( 'action' => 'mdmfa-verify' );
		$e    = array( 'action' => 'mdmfa-enroll' );
		$yes  = array(
			array( '/index.php', $slug . '?action=mdmfa-verify', $v ),
			array( '/index.php', $slug . '/?action=mdmfa-enroll&method=totp', $e + array( 'method' => 'totp' ) ),
			array( $slug, $slug . '?action=mdmfa-verify', $v ),
			array( '/wp-login.php', '/wp-login.php?action=mdmfa-verify', $v ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php?action=mdmfa_recover&t=x', array( 'action' => 'mdmfa_recover', 't' => 'x' ) ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php', array(), array( 'action' => 'mdmfa_recover', 't' => 'x' ) ),
		);
		$no   = array(
			array( '/index.php', '/' ),
			array( '/index.php', '/?action=mdmfa-verify', $v ),
			array( '/index.php', '/sample-page/?action=mdmfa-enroll', $e ),
			array( '/index.php', $slug ),
			array( '/index.php', $slug . '?action=login', array( 'action' => 'login' ) ),
			array( '/index.php', $slug . '?action=lostpassword', array( 'action' => 'lostpassword' ) ),
			array( '/index.php', $slug . 'x?action=mdmfa-verify', $v ),
			array( '/wp-admin/index.php', '/wp-admin/?action=mdmfa-verify', $v ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php?action=mdmfa_login', array( 'action' => 'mdmfa_login' ) ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php?action=mdmfa-verify', $v ),
			array( '/wp-admin/admin-ajax.php', '/wp-admin/admin-ajax.php?action=mdmfa_recover', array( 'action' => 'mdmfa_recover' ) ),
			// Core does not normalise the action, so a near miss runs another screen.
			array( '/index.php', $slug . '?action=MDMFA-VERIFY', array( 'action' => 'MDMFA-VERIFY' ) ),
			array( '/index.php', $slug . '?action=mdmfa-verify!', array( 'action' => 'mdmfa-verify!' ) ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php?action=MDMFA_RECOVER', array( 'action' => 'MDMFA_RECOVER' ) ),
			// wp-login.php swaps the action when these are present.
			array( '/index.php', $slug . '?action=mdmfa-verify&key=abc', $v + array( 'key' => 'abc' ) ),
			array( '/index.php', $slug . '?action=mdmfa-verify&checkemail=confirm', $v + array( 'checkemail' => 'confirm' ) ),
			// A posted action wins, as it does in core.
			array( '/index.php', $slug . '?action=mdmfa-verify', $v, array( 'action' => 'login' ) ),
			array( '/wp-admin/admin-post.php', '/wp-admin/admin-post.php?action=mdmfa_recover', array( 'action' => 'mdmfa_recover' ), array( 'action' => 'other' ) ),
		);
		foreach ( $yes as $case ) {
			$this->request( ...$case );
			self::assertTrue( HttpAuth::is_flow_request(), $case[1] );
		}
		foreach ( $no as $case ) {
			$this->request( ...$case );
			self::assertFalse( HttpAuth::is_flow_request(), $case[1] . ' ' . json_encode( array_slice( $case, 2 ) ) );
		}

		// With the login left at wp-login.php, the slug means nothing.
		$GLOBALS['mdmfa_test']['options'][ Options::LOGIN ]['enabled'] = false;
		$this->request( '/index.php', $slug . '?action=mdmfa-verify', $v );
		self::assertFalse( HttpAuth::is_flow_request() );
	}

	public function test_only_a_known_gate_calling_wp_authenticate_counts(): void {
		require_once dirname( __DIR__, 2 ) . '/Support/gate-callers.php';
		$GLOBALS['mdmfa_test']['authenticate'] = static fn (): bool => HttpAuth::from_gate();

		self::assertTrue( ( new \Pressable_Basic_Auth() )->force_basic_authentication(), 'the gate hosts put on staging sites' );
		self::assertFalse( \Some_Export_Plugin::run(), 'any other code that authenticates Basic credentials' );
		self::assertFalse( \mdmfa_test_other_gate() );
		self::assertFalse( HttpAuth::from_gate(), 'not inside wp_authenticate() at all' );

		// A site owner can vouch for another gate, by class or by function.
		add_filter( 'mdmfa_http_auth_gates', static fn ( array $gates ): array => array_merge( $gates, array( 'mdmfa_test_other_gate' ) ) );
		self::assertTrue( \mdmfa_test_other_gate() );
		self::assertTrue( ( new \Pressable_Basic_Auth() )->force_basic_authentication() );
		self::assertFalse( \Some_Export_Plugin::run() );

		// And can switch the integration off.
		mdmfa_test_reset();
		add_filter( 'mdmfa_http_auth_gates', static fn (): array => array() );
		$GLOBALS['mdmfa_test']['authenticate'] = static fn (): bool => HttpAuth::from_gate();
		self::assertFalse( ( new \Pressable_Basic_Auth() )->force_basic_authentication() );
	}

	public function test_the_return_target_is_this_sites_own_page_for_a_get_only(): void {
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['REQUEST_URI']    = '/sample-page/?a=1';
		self::assertSame( 'https://example.test/sample-page/?a=1', HttpAuth::target() );

		$_SERVER['REQUEST_URI'] = '//evil.example/path';
		self::assertSame( '', HttpAuth::target(), 'never a protocol-relative address' );

		$_SERVER['REQUEST_URI']    = '/sample-page/';
		$_SERVER['REQUEST_METHOD'] = 'POST';
		self::assertSame( '', HttpAuth::target() );
	}

	public function test_a_pass_is_for_one_user_and_ends_with_release(): void {
		HttpAuth::release();
		self::assertFalse( HttpAuth::passed( 5 ) );
		HttpAuth::pass( new \WP_User( 5, array( 'administrator' ) ) );
		self::assertTrue( HttpAuth::passed( 5 ) );
		self::assertFalse( HttpAuth::passed( 6 ) );
		self::assertFalse( HttpAuth::passed( 0 ) );
		HttpAuth::release();
		self::assertFalse( HttpAuth::passed( 5 ) );
	}
}
