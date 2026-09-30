<?php
/**
 * CI-only must-use plugin for the end-to-end suite. Copied into wp-content/mu-plugins by
 * .github/workflows/ci.yml and active only when MDMFA_E2E_FIXTURES is defined. Never
 * shipped: /tests is in .distignore.
 *
 * @package MaxtDesign\Mfa
 */

// phpcs:ignoreFile

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'MDMFA_E2E_FIXTURES' ) || ! MDMFA_E2E_FIXTURES ) {
	return;
}

// No mail transport on the runner; the suite does not assert on mail.
add_filter( 'pre_wp_mail', '__return_true' );

add_action(
	'wp_login',
	static function (): void {
		update_option( 'e2e_wp_login', (int) get_option( 'e2e_wp_login', 0 ) + 1, false );
	}
);
add_action(
	'wp_login_failed',
	static function (): void {
		update_option( 'e2e_wp_login_failed', (int) get_option( 'e2e_wp_login_failed', 0 ) + 1, false );
	}
);

add_action(
	'init',
	static function (): void {
		$op = isset( $_POST['mdmfa_e2e'] ) ? (string) $_POST['mdmfa_e2e'] : '';
		if ( 'direct_login' === $op ) {
			mdmfa_e2e_direct_login( (int) $_POST['user'] );
		}
		if ( 'change_password' === $op ) {
			if ( ! is_user_logged_in() ) {
				status_header( 403 );
				exit( 'not logged in' );
			}
			wp_update_user(
				array(
					'ID'        => get_current_user_id(),
					'user_pass' => (string) $_POST['pass'],
				)
			);
			exit( 'changed' );
		}
	},
	1
);

/**
 * Logs a user in the way WooCommerce's reset auto-login and Jetpack SSO do: a direct
 * wp_set_auth_cookie() followed by a redirect.
 */
function mdmfa_e2e_direct_login( int $user_id ): void {
	wp_set_auth_cookie( $user_id );
	wp_safe_redirect( admin_url( 'profile.php' ) );
	exit;
}
