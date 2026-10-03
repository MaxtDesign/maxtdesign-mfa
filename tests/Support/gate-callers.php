<?php
/**
 * Callers of wp_authenticate() for HttpAuthTest: a class with the name of the host's gate,
 * and callers nobody has vouched for.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:ignoreFile

if ( ! function_exists( 'wp_authenticate' ) ) {
	/**
	 * Runs the test's stand-in for the authenticate filter.
	 */
	function wp_authenticate( string $username, string $password ): mixed {
		return ( $GLOBALS['mdmfa_test']['authenticate'] )( $username, $password );
	}
}

final class Pressable_Basic_Auth {
	public function force_basic_authentication(): mixed {
		return wp_authenticate( 'alice', 'secret' );
	}
}

final class Some_Export_Plugin {
	public static function run(): mixed {
		return wp_authenticate( 'alice', 'secret' );
	}
}

function mdmfa_test_other_gate(): mixed {
	return wp_authenticate( 'alice', 'secret' );
}
