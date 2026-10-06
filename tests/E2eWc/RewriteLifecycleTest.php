<?php
/**
 * Endpoint recovery after an inactive rewrite rebuild, on a site or network.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2eWc;

use MaxtDesign\Mfa\Tests\E2e\E2eTestCase;
use MaxtDesign\Mfa\Tests\E2e\Browser;

// phpcs:ignoreFile

final class RewriteLifecycleTest extends E2eTestCase {
	private ?Browser $admin = null;
	private int $admin_id = 0;

	protected function setUp(): void {
		parent::setUp();
		if ( '1' !== self::eval( 'echo function_exists("WC") ? "1" : "0";' ) ) {
			self::markTestSkipped( 'WooCommerce is required.' );
		}
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$this->admin_id = $id;
		if ( '1' === self::eval( 'echo is_multisite() ? "1" : "0";' ) ) {
			self::wp( 'super-admin', 'add', $login );
		}
		$secret = self::enroll( $id );
		$this->admin = $this->browser();
		$this->password( $this->admin, $login, $pass );
		self::assertTrue( $this->submit_code( $this->admin, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
	}

	protected function tearDown(): void {
		if ( $this->admin_id ) {
			self::eval( 'require_once ABSPATH."wp-admin/includes/user.php"; if(is_multisite()){require_once ABSPATH."wp-admin/includes/ms.php"; wpmu_delete_user(' . $this->admin_id . ');}else{wp_delete_user(' . $this->admin_id . ');}' );
		}
		parent::tearDown();
	}

	public function test_partial_cli_boot_and_shoppers_do_not_consume_pending_repair(): void {
		self::wp( 'option', 'update', 'e2e_foreign_route', '1' );
		try {
			$hash = self::eval( '$r=(array)get_option("rewrite_rules");$r=["^e2e-theme-route/?$"=>"index.php?e2e_theme_route=1"]+$r;update_option("rewrite_rules",$r);delete_option("mdmfa_rewrite_version");echo hash("sha256",serialize($r));' );
			// E2eTestCase runs every CLI command with --skip-themes, exactly the incident.
			self::wp( 'option', 'get', 'blogname' );
			self::assertSame( $hash, self::eval( 'echo hash("sha256",serialize(get_option("rewrite_rules")));' ) );
			$this->browser()->get( '' );
			self::assertSame( $hash, self::eval( 'echo hash("sha256",serialize(get_option("rewrite_rules")));' ) );
			self::assertSame( 'missing', self::eval( 'echo get_option("mdmfa_rewrite_version", "missing");' ) );
			self::assertSame( 200, $this->admin->get( 'wp-admin/profile.php' )->status );
			self::assertSame( '1', self::eval( '$r=get_option("rewrite_rules");echo isset($r["^e2e-theme-route/?$"])?"1":"0";' ) );
			self::assertSame( '1', self::eval( 'echo !empty(get_option("mdmfa_rewrite_version")["rule"])?"1":"0";' ) );
		} finally {
			self::eval( 'delete_option("e2e_foreign_route");delete_option("mdmfa_rewrite_version");' );
			$this->admin->get( 'wp-admin/profile.php' );
		}
	}

	public function test_a_rebuild_that_finds_no_endpoint_rule_is_not_repeated_on_every_request(): void {
		if ( '1' !== self::eval( 'echo function_exists("WC") ? "1" : "0";' ) ) {
			self::markTestSkipped( 'WooCommerce is required.' );
		}
		self::wp( 'option', 'update', 'e2e_drop_endpoint_rule', '1' );
		try {
			self::eval( 'delete_option( "mdmfa_rewrite_version" ); update_option( "e2e_rewrite_flushes", 0, false );' );
			for ( $i = 0; $i < 4; $i++ ) {
				$this->browser()->get( '' );
			}
			self::assertSame( '0', self::eval( 'echo (int) get_option( "e2e_rewrite_flushes" );' ), 'Shopper and CLI requests never repair.' );
			for ( $i = 0; $i < 4; $i++ ) {
				$this->admin->get( 'wp-admin/profile.php' );
			}
			self::assertSame( '1', self::eval( 'echo (int) get_option( "e2e_rewrite_flushes" );' ), 'one rebuild, then no more while the rule cannot appear' );
			$marker = (array) json_decode( self::wp( 'option', 'get', 'mdmfa_rewrite_version', '--format=json' ), true );
			self::assertSame( '', $marker['rule'] ?? null );
			self::assertEqualsWithDelta( time(), (int) ( $marker['checked'] ?? 0 ), 120 );

			// A day later it tries once more.
			self::eval( '$m = get_option( "mdmfa_rewrite_version" ); $m["checked"] = time() - DAY_IN_SECONDS - 1; update_option( "mdmfa_rewrite_version", $m, true );' );
			$this->admin->get( 'wp-admin/profile.php' );
			$this->admin->get( 'wp-admin/profile.php' );
			self::assertSame( '2', self::eval( 'echo (int) get_option( "e2e_rewrite_flushes" );' ) );
		} finally {
			self::eval( 'delete_option( "e2e_drop_endpoint_rule" ); delete_option( "e2e_rewrite_flushes" ); delete_option( "mdmfa_rewrite_version" );' );
			$this->admin->get( 'wp-admin/profile.php' );
		}
		// With the filter gone the next request repairs the rule and records it.
		self::assertSame( 200, $this->browser()->get( self::eval( 'echo wc_get_account_endpoint_url( "mdmfa-security" );' ) )->status );
		$marker = (array) json_decode( self::wp( 'option', 'get', 'mdmfa_rewrite_version', '--format=json' ), true );
		self::assertNotSame( '', (string) ( $marker['rule'] ?? '' ) );
	}

	public function test_existing_sites_repair_missing_rules_after_reactivation(): void {
		if ( '1' !== self::eval( 'echo function_exists("WC") ? "1" : "0";' ) ) {
			self::markTestSkipped( 'WooCommerce is required.' );
		}
		$network = '1' === self::eval( 'echo is_multisite() ? "1" : "0";' );
		$sites   = $network
			? json_decode( self::eval( 'echo wp_json_encode(array_map(static fn($s)=>get_site_url((int)$s->blog_id),get_sites()));' ), true )
			: array( rtrim( self::$url, '/' ) );
		$flags   = $network ? array( '--network' ) : array();
		$urls    = array();
		foreach ( $sites as $site ) {
			self::wp( '--url=' . $site, 'eval', 'WC_Install::create_pages(); update_option("permalink_structure","/%postname%/");' );
			$this->admin->get( rtrim( $site, '/' ) . '/wp-admin/profile.php' );
			$urls[ $site ] = self::wp( '--url=' . $site, 'eval', 'echo wc_get_account_endpoint_url("mdmfa-security");' );
			self::assertSame( 200, $this->browser()->get( $urls[ $site ] )->status );
		}

		try {
			self::wp( 'plugin', 'deactivate', 'maxtdesign-mfa', ...$flags );
			foreach ( $sites as $site ) {
				$result = self::wp( '--url=' . $site, 'eval', 'flush_rewrite_rules(false); $n=0; foreach((array)get_option("rewrite_rules") as $k=>$v){if(str_contains($k,"login-security"))$n++;} echo $n;' );
				self::assertSame( '0', $result, 'The inactive rebuild must actually remove the endpoint.' );
			}
		} finally {
			self::wp( 'plugin', 'activate', 'maxtdesign-mfa', ...$flags );
		}

		foreach ( $sites as $site ) {
			// An authorized HTTP admin visit repairs each subsite; never CLI or shoppers.
			self::assertSame( 200, $this->admin->get( rtrim( $site, '/' ) . '/wp-admin/profile.php' )->status );
			self::assertSame( 200, $this->browser()->get( $urls[ $site ] )->status, $site );
			$marker = self::wp( '--url=' . $site, 'option', 'get', 'mdmfa_rewrite_version', '--format=json' );
			self::assertIsArray( json_decode( $marker, true ) );
			self::assertSame( 200, $this->browser()->get( $urls[ $site ] )->status );
			self::assertSame( $marker, self::wp( '--url=' . $site, 'option', 'get', 'mdmfa_rewrite_version', '--format=json' ) );
			self::assertSame( '0', self::wp( '--url=' . $site, 'eval', '$n=0; add_action("generate_rewrite_rules",static function()use(&$n){$n++;}); MaxtDesign\\Mfa\\WooCommerce\\SecurityEndpoint::maybe_flush(); MaxtDesign\\Mfa\\WooCommerce\\SecurityEndpoint::maybe_flush(); echo $n;' ), 'An intact rule must not trigger another flush.' );
		}
	}
}
