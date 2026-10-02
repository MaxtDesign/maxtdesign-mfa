<?php
/**
 * WordPress and WooCommerce stand-ins for PresenterDispatchTest, loaded inside its separate
 * process only. Nonces behave like WordPress's: valid for one action, not for another.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:ignoreFile

/**
 * Stands in for exit after a redirect, and for wp_die().
 */
final class Mdmfa_Test_Halt extends RuntimeException {}

function mdmfa_test_nonce( string $action ): string {
	return 'nonce-for-' . $action;
}

function wp_verify_nonce( mixed $nonce, mixed $action = -1 ): int|false {
	return is_string( $nonce ) && mdmfa_test_nonce( (string) $action ) === $nonce ? 1 : false;
}

function check_admin_referer( mixed $action = -1, string $query_arg = '_wpnonce' ): int {
	if ( false === wp_verify_nonce( $_REQUEST[ $query_arg ] ?? '', $action ) ) {
		throw new Mdmfa_Test_Halt( 'die:nonce' );
	}
	return 1;
}

function is_user_logged_in(): bool {
	return get_current_user_id() > 0;
}

function wp_get_current_user(): WP_User {
	$user = get_userdata( get_current_user_id() );
	return $user instanceof WP_User ? $user : new WP_User( 0, array() );
}

function wp_get_session_token(): string {
	return '';
}

function current_user_can( string $capability ): bool {
	return true;
}

function absint( mixed $value ): int {
	return abs( (int) $value );
}

function esc_html( string $text ): string {
	return $text;
}

function esc_html__( string $text, string $domain = 'default' ): string {
	return $text;
}

function wc_add_notice( string $message, string $type = 'success' ): void {
	$GLOBALS['mdmfa_test']['wc_notices'][] = array( $type, $message );
}

function admin_url( string $path = '' ): string {
	return 'https://example.test/wp-admin/' . $path;
}

function wc_get_account_endpoint_url( string $endpoint ): string {
	return 'https://example.test/my-account/login-security/';
}

function add_query_arg( mixed ...$args ): string {
	if ( is_array( $args[0] ) ) {
		list( $pairs, $url ) = $args;
	} else {
		$pairs = array( $args[0] => $args[1] );
		$url   = $args[2];
	}
	return array() === $pairs ? (string) $url : $url . ( str_contains( (string) $url, '?' ) ? '&' : '?' ) . http_build_query( $pairs );
}

function wp_safe_redirect( string $location, int $status = 302 ): bool {
	throw new Mdmfa_Test_Halt( 'redirect:' . $location );
}
