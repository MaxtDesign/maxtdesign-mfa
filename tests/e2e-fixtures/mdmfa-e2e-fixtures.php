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

// No mail transport on the runner: capture every message instead (newest last).
add_filter(
	'pre_wp_mail',
	static function ( $short_circuit, $atts ) {
		$mail   = (array) get_option( 'e2e_mail', array() );
		$mail[] = array(
			'to'      => is_array( $atts['to'] ) ? implode( ',', $atts['to'] ) : (string) $atts['to'],
			'subject' => (string) $atts['subject'],
			'message' => (string) $atts['message'],
		);
		update_option( 'e2e_mail', array_slice( $mail, -20 ), false );
		return true;
	},
	10,
	2
);

// Records the suite purge signal maxtdesign-cache would act on.
add_action(
	'md_suite_content_changed',
	static function ( $payload ): void {
		$urls   = (array) get_option( 'e2e_purged', array() );
		$urls[] = is_array( $payload ) && isset( $payload['url'] ) ? (string) $payload['url'] : 'full';
		update_option( 'e2e_purged', $urls, false );
	}
);

// Reports is_login() on the login screen (plan 5.1: SCRIPT_NAME set on the slug).
add_action(
	'login_init',
	static function (): void {
		header( 'X-E2E-Is-Login: ' . ( is_login() ? '1' : '0' ) );
		header( 'X-E2E-Pagenow: ' . $GLOBALS['pagenow'] );
	}
);

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

// A token endpoint of the kind JWT plugins add: a username and password over REST
// (plan 4.3 "rest" context, a non-interactive password login).
add_action(
	'rest_api_init',
	static function (): void {
		register_rest_route(
			'mdmfa-e2e/v1',
			'/token',
			array(
				'methods'             => 'POST',
				'permission_callback' => '__return_true',
				'callback'            => static function ( WP_REST_Request $request ) {
					$user = wp_authenticate( (string) $request['username'], (string) $request['password'] );
					return is_wp_error( $user ) ? new WP_Error( $user->get_error_code(), 'denied', array( 'status' => 403 ) ) : array( 'user' => $user->ID );
				},
			)
		);
	}
);

// Another plugin's AJAX login (plan 4.3 "ajax" context).
add_action(
	'wp_ajax_nopriv_mdmfa_e2e_login',
	static function (): void {
		$user = wp_signon();
		wp_send_json( is_wp_error( $user ) ? array( 'error' => $user->get_error_message() ) : array( 'ok' => true ) );
	}
);

add_action(
	'init',
	static function (): void {
		// A page that prints the core front-end login form.
		if ( isset( $_GET['mdmfa_e2e_form'] ) ) {
			echo wp_login_form( array( 'echo' => false, 'redirect' => home_url( '/?landed=1' ) ) );
			exit;
		}
		$op = isset( $_POST['mdmfa_e2e'] ) ? (string) $_POST['mdmfa_e2e'] : '';
		// Another plugin's own login form posting to an arbitrary page ("unknown-post").
		if ( 'custom_login' === $op ) {
			$user = wp_signon();
			if ( is_wp_error( $user ) ) {
				exit( 'error: ' . $user->get_error_code() );
			}
			wp_safe_redirect( home_url( '/?custom=1' ) );
			exit;
		}
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
