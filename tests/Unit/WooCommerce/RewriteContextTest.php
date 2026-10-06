<?php
/** Regression: partial CLI boots must not destroy another component's routes. */
declare(strict_types=1);
namespace MaxtDesign\Mfa\Tests\Unit\WooCommerce;

use MaxtDesign\Mfa\WooCommerce\SecurityEndpoint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

// phpcs:ignoreFile
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class RewriteContextTest extends TestCase {
	private const FOREIGN = array( '^vehicles/([^/]+)/([^/]+)/?$' => 'index.php?vehicle_model=$matches[2]' );
	private const ENDPOINT = array( '(.?.+?)/login-security(/(.*))?/?$' => 'index.php?pagename=$matches[1]&login-security=$matches[3]' );

	protected function setUp(): void {
		mdmfa_test_reset();
		require dirname( __DIR__, 2 ) . '/Support/rewrite-shims.php';
		$GLOBALS['mdmfa_test']['is_admin'] = true;
		$GLOBALS['mdmfa_test']['authorized'] = true;
		$GLOBALS['mdmfa_test']['flushes'] = 0;
		$GLOBALS['mdmfa_test']['generated_rules'] = self::ENDPOINT;
		$GLOBALS['mdmfa_test']['actions'][] = array( 'wp_loaded' );
		update_option( 'permalink_structure', '/%postname%/' );
		update_option( 'rewrite_rules', self::FOREIGN );
	}

	public static function unsafe_contexts(): array {
		return array(
			'CLI without theme' => array( 'cli' ),
			'CLI constant defined false' => array( 'cli_false' ),
			'shopper request' => array( 'frontend' ),
			'installation' => array( 'installing' ),
			'unauthorized admin entry' => array( 'unauthorized' ),
			'admin AJAX' => array( 'ajax' ),
			'before complete bootstrap' => array( 'early' ),
		);
	}

	#[DataProvider('unsafe_contexts')]
	public function test_incomplete_or_public_requests_preserve_foreign_routes( string $context ): void {
		if ( str_starts_with( $context, 'cli' ) ) {
			define( 'WP_CLI', 'cli' === $context );
		} elseif ( 'frontend' === $context ) {
			$GLOBALS['mdmfa_test']['is_admin'] = false;
		} elseif ( 'unauthorized' === $context ) {
			$GLOBALS['mdmfa_test']['authorized'] = false;
		} elseif ( 'early' === $context ) {
			$GLOBALS['mdmfa_test']['actions'] = array();
		} else {
			$GLOBALS['mdmfa_test'][ $context ] = true;
		}
		SecurityEndpoint::register();
		SecurityEndpoint::maybe_flush(); // Also protected if called directly.
		self::assertSame( 0, $GLOBALS['mdmfa_test']['flushes'] );
		self::assertSame( self::FOREIGN, get_option( 'rewrite_rules' ) );
		self::assertFalse( get_option( 'mdmfa_rewrite_version' ) );
	}

	public function test_admin_repair_keeps_registered_foreign_routes_and_runs_once(): void {
		$GLOBALS['mdmfa_test']['generated_rules'] = self::FOREIGN + self::ENDPOINT;
		SecurityEndpoint::maybe_flush();
		SecurityEndpoint::maybe_flush();
		self::assertSame( 1, $GLOBALS['mdmfa_test']['flushes'] );
		self::assertSame( self::FOREIGN + self::ENDPOINT, get_option( 'rewrite_rules' ) );
		self::assertNotEmpty( get_option( 'mdmfa_rewrite_version' )['rule'] );
	}

	public function test_failed_admin_repair_is_not_retried_on_every_visit(): void {
		$GLOBALS['mdmfa_test']['generated_rules'] = self::FOREIGN;
		SecurityEndpoint::maybe_flush();
		SecurityEndpoint::maybe_flush();
		self::assertSame( 1, $GLOBALS['mdmfa_test']['flushes'] );
		self::assertSame( self::FOREIGN, get_option( 'rewrite_rules' ) );
	}
}
