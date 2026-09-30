<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Location;

use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Settings\LoginSlug;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LoginLocationTest extends TestCase {

	/**
	 * @return iterable<string, array{string, string, bool}>
	 */
	public static function requests(): iterable {
		yield 'exact' => array( '/abc123def456', '/', true );
		yield 'trailing slash' => array( '/abc123def456/', '/', true );
		yield 'with query' => array( '/abc123def456?action=mdmfa-verify&method=totp', '/', true );
		yield 'upper case' => array( '/ABC123DEF456', '/', true );
		yield 'subdirectory install' => array( '/blog/abc123def456', '/blog/', true );
		yield 'subdirectory, missing base' => array( '/abc123def456', '/blog/', false );
		yield 'deeper path' => array( '/abc123def456/extra', '/', false );
		yield 'prefix only' => array( '/abc123def45', '/', false );
		yield 'longer' => array( '/abc123def4567', '/', false );
		yield 'home' => array( '/', '/', false );
		yield 'query holds the slug' => array( '/?p=abc123def456', '/', false );
	}

	#[DataProvider( 'requests' )]
	public function test_request_matching( string $uri, string $home, bool $expected ): void {
		self::assertSame( $expected, LoginLocation::matches( $uri, $home, 'abc123def456' ) );
	}

	public function test_empty_slug_never_matches(): void {
		self::assertFalse( LoginLocation::matches( '/', '/', '' ) );
	}

	public function test_well_formed_slugs(): void {
		foreach ( array( 'abcd', 'team-access', 'a1b2c3d4e5f6', str_repeat( 'a', 64 ) ) as $ok ) {
			self::assertTrue( LoginSlug::well_formed( $ok ), $ok );
		}
		foreach ( array( '', 'abc', str_repeat( 'a', 65 ), 'Team', 'team_access', 'team--access', '-team', 'team-', 'te am', 'café', 'a/b' ) as $bad ) {
			self::assertFalse( LoginSlug::well_formed( $bad ), $bad );
		}
	}

	public function test_generated_slugs_are_well_formed(): void {
		for ( $i = 0; $i < 100; $i++ ) {
			self::assertTrue( LoginSlug::well_formed( LoginSlug::generate() ) );
		}
	}

	public function test_validate_rejects_format_and_reserved_before_touching_the_database(): void {
		foreach ( array( 'ab', 'bad slug', 'UPPER_case' ) as $bad ) {
			$result = LoginSlug::validate( $bad );
			self::assertInstanceOf( \WP_Error::class, $result, $bad );
			self::assertSame( 'mdmfa_slug_format', $result->get_error_code() );
		}
		foreach ( array( 'login', 'wp-admin', 'wp-anything', 'dashboard', 'checkout', 'my-account' ) as $reserved ) {
			$result = LoginSlug::validate( $reserved );
			self::assertInstanceOf( \WP_Error::class, $result, $reserved );
			self::assertSame( 'mdmfa_slug_reserved', $result->get_error_code(), $reserved );
		}
	}
}
