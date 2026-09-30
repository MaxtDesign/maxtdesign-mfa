<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Install;

use MaxtDesign\Mfa\Install\Uninstaller;
use MaxtDesign\Mfa\Settings\Options;
use PHPUnit\Framework\TestCase;

final class UninstallerTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	/**
	 * @return string[]
	 */
	private function queries(): array {
		return $GLOBALS['wpdb']->queries;
	}

	public function test_single_site_drops_all_three_tables(): void {
		Uninstaller::run();

		$drops = array_values( array_filter( $this->queries(), static fn ( string $q ): bool => str_starts_with( $q, 'DROP TABLE' ) ) );
		self::assertSame(
			array(
				'DROP TABLE IF EXISTS `wp_mdmfa_pending`',
				'DROP TABLE IF EXISTS `wp_mdmfa_log`',
				'DROP TABLE IF EXISTS `wp_mdmfa_credentials`',
			),
			$drops
		);
	}

	public function test_options_are_deleted_and_swept_with_escaped_like(): void {
		foreach ( array_keys( Options::all() ) as $option ) {
			$GLOBALS['mdmfa_test']['options'][ $option ] = 'x';
		}
		$GLOBALS['mdmfa_test']['options']['unrelated'] = 'keep';

		Uninstaller::run();

		self::assertSame( array( 'unrelated' => 'keep' ), $GLOBALS['mdmfa_test']['options'] );
		$sweep = implode( "\n", $this->queries() );
		self::assertStringContainsString( "DELETE FROM `wp_options` WHERE option_name LIKE 'mdmfa\\\_%'", $sweep );
		self::assertStringContainsString( "'\\\_transient\\\_timeout\\\_mdmfa\\\_%'", $sweep );
		self::assertStringContainsString( "DELETE FROM `wp_usermeta` WHERE meta_key LIKE 'mdmfa\\\_%'", $sweep );
		self::assertStringNotContainsString( 'wp_sitemeta', $sweep, 'single site has no sitemeta' );
	}

	public function test_every_user_meta_key_is_deleted_for_all_users(): void {
		Uninstaller::run();

		$deleted = array_map( static fn ( array $d ): string => $d[2], $GLOBALS['mdmfa_test']['deleted_meta'] );
		self::assertSame( Options::user_meta_keys(), $deleted );
		foreach ( $GLOBALS['mdmfa_test']['deleted_meta'] as $call ) {
			self::assertSame( array( 'user', 0 ), array( $call[0], $call[1] ) );
			self::assertTrue( $call[3], 'delete_all must be true' );
		}
	}

	public function test_cron_is_cleared(): void {
		Uninstaller::run();

		self::assertSame( array( 'mdmfa_purge@wp_' ), $GLOBALS['mdmfa_test']['cleared_cron'] );
	}

	public function test_multisite_cleans_every_site_and_the_network_once(): void {
		$GLOBALS['mdmfa_test']['multisite'] = true;
		$GLOBALS['mdmfa_test']['sites']     = array( 1, 2, 5 );

		Uninstaller::run();

		$drops = array_values( array_filter( $this->queries(), static fn ( string $q ): bool => str_starts_with( $q, 'DROP TABLE' ) ) );
		self::assertSame(
			array(
				'DROP TABLE IF EXISTS `wp_mdmfa_pending`',
				'DROP TABLE IF EXISTS `wp_mdmfa_log`',
				'DROP TABLE IF EXISTS `wp_2_mdmfa_pending`',
				'DROP TABLE IF EXISTS `wp_2_mdmfa_log`',
				'DROP TABLE IF EXISTS `wp_5_mdmfa_pending`',
				'DROP TABLE IF EXISTS `wp_5_mdmfa_log`',
				'DROP TABLE IF EXISTS `wp_mdmfa_credentials`',
			),
			$drops
		);
		self::assertSame( array( 'mdmfa_purge@wp_', 'mdmfa_purge@wp_2_', 'mdmfa_purge@wp_5_' ), $GLOBALS['mdmfa_test']['cleared_cron'] );
		$all = implode( "\n", $this->queries() );
		self::assertStringContainsString( 'DELETE FROM `wp_2_options`', $all );
		self::assertStringContainsString( "DELETE FROM `wp_sitemeta` WHERE meta_key LIKE 'mdmfa\\\_%'", $all );
	}
}
