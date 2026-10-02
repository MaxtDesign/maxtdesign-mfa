<?php
/**
 * Endpoint recovery after an inactive rewrite rebuild, on a site or network.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2eWc;

use MaxtDesign\Mfa\Tests\E2e\E2eTestCase;

// phpcs:ignoreFile

final class RewriteLifecycleTest extends E2eTestCase {

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
			// HTTP is the first request to each subsite after activation; no CLI repair.
			self::assertSame( 200, $this->browser()->get( $urls[ $site ] )->status, $site );
			$marker = self::wp( '--url=' . $site, 'option', 'get', 'mdmfa_rewrite_version', '--format=json' );
			self::assertIsArray( json_decode( $marker, true ) );
			self::assertSame( 200, $this->browser()->get( $urls[ $site ] )->status );
			self::assertSame( $marker, self::wp( '--url=' . $site, 'option', 'get', 'mdmfa_rewrite_version', '--format=json' ) );
			self::assertSame( '0', self::wp( '--url=' . $site, 'eval', '$n=0; add_action("generate_rewrite_rules",static function()use(&$n){$n++;}); MaxtDesign\\Mfa\\WooCommerce\\SecurityEndpoint::maybe_flush(); MaxtDesign\\Mfa\\WooCommerce\\SecurityEndpoint::maybe_flush(); echo $n;' ), 'An intact rule must not trigger another flush.' );
		}
	}
}
