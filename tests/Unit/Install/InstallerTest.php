<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Install;

use MaxtDesign\Mfa\Install\Installer;
use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use PHPUnit\Framework\TestCase;

final class InstallerTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_activation_creates_three_tables_and_seeds_options(): void {
		Installer::activate();

		$created = array_map(
			static fn ( string $sql ): string => (string) preg_replace( '/^CREATE TABLE (\S+) .*/s', '$1', $sql ),
			$GLOBALS['mdmfa_test']['dbdelta']
		);
		self::assertSame( array( 'wp_mdmfa_credentials', 'wp_mdmfa_pending', 'wp_mdmfa_log' ), $created );

		$options = $GLOBALS['mdmfa_test']['options'];
		self::assertSame( Schema::VERSION, $options[ Options::DB_VERSION ] );
		self::assertSame( Settings::defaults(), $options[ Options::SETTINGS ] );
		self::assertMatchesRegularExpression( '/^[a-z0-9]{12}$/', $options[ Options::LOGIN ]['slug'] );
		self::assertIsInt( $options[ Options::ACTIVATED_AT ] );
		self::assertSame( 'db', $options[ Options::KEY_CHECK ]['source'], 'no salt constants in the test process' );
		self::assertMatchesRegularExpression( '/^[0-9a-f]{16}$/', $options[ Options::KEY_CHECK ]['kid'] );
	}

	public function test_autoload_flags_match_the_registry(): void {
		Installer::activate();

		foreach ( Options::all() as $option => $autoload ) {
			if ( in_array( $option, array( Options::NOTICES, Options::REWRITE ), true ) ) {
				continue; // Created on demand, not at activation.
			}
			self::assertSame( $autoload, $GLOBALS['mdmfa_test']['autoload'][ $option ], $option );
		}
	}

	public function test_reactivation_never_overwrites_owner_values(): void {
		Installer::activate();
		$slug = $GLOBALS['mdmfa_test']['options'][ Options::LOGIN ]['slug'];
		$GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] = array( 'log_retention_days' => 30 );

		Installer::activate();

		self::assertSame( $slug, $GLOBALS['mdmfa_test']['options'][ Options::LOGIN ]['slug'] );
		self::assertSame( array( 'log_retention_days' => 30 ), $GLOBALS['mdmfa_test']['options'][ Options::SETTINGS ] );
	}

	public function test_maybe_upgrade_is_a_no_op_when_schema_is_current(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::DB_VERSION ] = Schema::VERSION;

		Installer::maybe_upgrade();

		self::assertSame( array(), $GLOBALS['mdmfa_test']['dbdelta'] );
	}

	public function test_maybe_upgrade_installs_when_schema_differs(): void {
		$GLOBALS['mdmfa_test']['options'][ Options::DB_VERSION ] = '0';

		Installer::maybe_upgrade();

		self::assertCount( 3, $GLOBALS['mdmfa_test']['dbdelta'] );
		self::assertSame( Schema::VERSION, $GLOBALS['mdmfa_test']['options'][ Options::DB_VERSION ] );
	}
}

