<?php
/**
 * Guards the version triple and floors that the deliverables gate also checks, so a
 * mismatch fails in PHPUnit before it reaches the commit hook.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class ReleaseMetadataTest extends TestCase {

	private static function header( string $field ): string {
		$main = (string) file_get_contents( dirname( __DIR__, 2 ) . '/maxtdesign-mfa.php' );
		preg_match( '/^\s*\*\s*' . preg_quote( $field, '/' ) . ':\s*(.+)$/mi', $main, $m );
		return trim( $m[1] ?? '' );
	}

	private static function readme( string $field ): string {
		$readme = (string) file_get_contents( dirname( __DIR__, 2 ) . '/readme.txt' );
		preg_match( '/^' . preg_quote( $field, '/' ) . ':\s*(.+)$/mi', $readme, $m );
		return trim( $m[1] ?? '' );
	}

	public function test_version_triple_is_equal(): void {
		$main = (string) file_get_contents( dirname( __DIR__, 2 ) . '/maxtdesign-mfa.php' );
		preg_match( "/define\(\s*'MDMFA_VERSION',\s*'([^']+)'/", $main, $m );

		self::assertNotSame( '', self::header( 'Version' ) );
		self::assertSame( self::header( 'Version' ), $m[1] ?? null, 'MDMFA_VERSION' );
		self::assertSame( self::header( 'Version' ), self::readme( 'Stable tag' ), 'Stable tag' );
	}

	public function test_floors_match_the_plan(): void {
		self::assertSame( '8.3', self::header( 'Requires PHP' ) );
		self::assertSame( '8.3', self::readme( 'Requires PHP' ) );
		self::assertSame( '7.0', self::header( 'Requires at least' ) );
		self::assertSame( '7.0', self::readme( 'Requires at least' ) );
		self::assertSame( '7.1', self::readme( 'Tested up to' ) );
		self::assertSame( '11.0', self::header( 'WC requires at least' ) );
		self::assertSame( '11.1', self::header( 'WC tested up to' ) );
	}

	public function test_changelog_has_an_entry_for_the_version(): void {
		$readme = (string) file_get_contents( dirname( __DIR__, 2 ) . '/readme.txt' );

		self::assertStringContainsString( '= ' . self::header( 'Version' ) . ' =', $readme );
	}
}
