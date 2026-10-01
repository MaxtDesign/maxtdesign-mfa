<?php
/**
 * Where a login is happening (plan 4.2). Set by hooks earlier in the same request, never
 * from client input.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Login context detection.
 */
final class Context {

	public const CORE         = 'core';
	public const WC           = 'wc';
	public const FRONTEND     = 'frontend';
	public const XMLRPC       = 'xmlrpc';
	public const REST         = 'rest';
	public const APPPASS      = 'apppass';
	public const CLI          = 'cli';
	public const AJAX         = 'ajax';
	public const UNKNOWN_POST = 'unknown-post';
	public const UNKNOWN      = 'unknown';

	/**
	 * Flags raised by earlier hooks in this request.
	 *
	 * @var array<string, bool>
	 */
	private static array $flags = array();

	/**
	 * User an application password authenticated in this request (0 = none).
	 *
	 * @var int
	 */
	private static int $apppass_user = 0;

	/**
	 * Raises a context flag (wc, frontend, apppass).
	 *
	 * @param string $context Context constant.
	 */
	public static function mark( string $context ): void {
		self::$flags[ $context ] = true;
	}

	/**
	 * Filter callback for woocommerce_login_credentials: marks the WC login form.
	 *
	 * @param mixed $credentials Credentials, returned unchanged.
	 * @return mixed
	 */
	public static function mark_wc( mixed $credentials ): mixed {
		self::mark( self::WC );

		return $credentials;
	}

	/**
	 * Action callback for application_password_did_authenticate. The exemption belongs to
	 * that user only: another account's password in the same request is a password login.
	 *
	 * @param mixed $user User the application password authenticated.
	 */
	public static function mark_apppass( mixed $user = null ): void {
		if ( $user instanceof \WP_User ) {
			self::$apppass_user = $user->ID;
		}
	}

	/**
	 * Clears flags (tests).
	 */
	public static function reset(): void {
		self::$flags        = array();
		self::$apppass_user = 0;
	}

	/**
	 * The current context.
	 *
	 * @param int $user_id User whose login is being decided.
	 */
	public static function detect( int $user_id = 0 ): string {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return self::CLI;
		}
		if ( $user_id > 0 && self::$apppass_user === $user_id ) {
			return self::APPPASS;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return self::XMLRPC;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return self::REST;
		}
		if ( did_action( 'login_form_login' ) ) {
			return self::CORE;
		}
		if ( ! empty( self::$flags[ self::WC ] ) ) {
			return self::WC;
		}
		if ( ! empty( self::$flags[ self::FRONTEND ] ) ) {
			return self::FRONTEND;
		}
		if ( wp_doing_ajax() ) {
			return self::AJAX;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';

		return 'post' === $method ? self::UNKNOWN_POST : self::UNKNOWN;
	}

	/**
	 * Contexts where a browser can follow a redirect to the challenge screen.
	 *
	 * @param string $context Context constant.
	 */
	public static function is_interactive( string $context ): bool {
		return in_array( $context, array( self::CORE, self::WC, self::FRONTEND, self::UNKNOWN_POST ), true );
	}
}
