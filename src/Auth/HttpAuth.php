<?php
/**
 * A site access gate that checks WordPress credentials sent as HTTP Basic authentication
 * (for example a host's staging barrier). It calls wp_authenticate() on every page request
 * of a browser that is not logged in, before any login form exists, and then issues the
 * session itself.
 *
 * The gate keeps doing its job: a wrong or missing password never gets past it. What it
 * may not do is turn the password into a session. A correct password for an account that
 * needs the second step sends the browser to that step; while the browser is on the second
 * step's own pages the gate is let through, and the session it then tries to start is
 * refused (BypassGuard). The only way to a session is Completion.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Location\LoginLocation;

defined( 'ABSPATH' ) || exit;

/**
 * HTTP Basic credentials as a login context.
 */
final class HttpAuth {

	/**
	 * User whose password a gate may check in this request without starting a session.
	 *
	 * @var int
	 */
	private static int $passed = 0;

	/**
	 * Whether the credentials being authenticated are the request's HTTP Basic credentials.
	 *
	 * @param mixed $username Username wp_authenticate() was given.
	 * @param mixed $password Password wp_authenticate() was given.
	 */
	public static function matches( mixed $username, mixed $password ): bool {
		if ( ! is_string( $username ) || ! is_string( $password ) || '' === $username || '' === $password
			|| ! isset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) || ! is_string( $_SERVER['PHP_AUTH_USER'] ) || ! is_string( $_SERVER['PHP_AUTH_PW'] ) ) {
			return false;
		}
		$sent_user = sanitize_user( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) );
		// A password is compared, never stored or changed. Core slashes $_SERVER; a caller may pass either form.
		$sent_pass = $_SERVER['PHP_AUTH_PW']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared in constant time below.

		return '' !== $sent_user && sanitize_user( $username ) === $sent_user
			&& ( hash_equals( trim( $sent_pass ), $password ) || hash_equals( trim( wp_unslash( $sent_pass ) ), $password ) );
	}

	/**
	 * Whether this request is one of the second step's own pages: the challenge and setup
	 * screens of the login page, and the emailed recovery link. Decided from the request
	 * itself, because a gate runs before WordPress has routed anything.
	 */
	public static function is_flow_request(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing only.
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		$script = isset( $_SERVER['SCRIPT_NAME'] ) && is_string( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( 'admin-post.php' === $script ) {
			return EmailRecovery::ACTION === $action;
		}
		if ( ! in_array( $action, array( ChallengeUrl::ACTION_VERIFY, ChallengeUrl::ACTION_ENROLL ), true ) ) {
			return false;
		}

		return 'wp-login.php' === $script
			|| ( LoginLocation::enabled() && LoginLocation::matches( $uri, LoginLocation::home_path(), LoginLocation::slug() ) );
	}

	/**
	 * Lets a gate's password check succeed for this user in this request, with no session:
	 * the user never becomes the current user, and BypassGuard refuses the cookie.
	 *
	 * @param \WP_User $user User whose password was correct.
	 */
	public static function pass( \WP_User $user ): void {
		if ( 0 === self::$passed ) {
			add_action( 'set_current_user', array( self::class, 'keep_signed_out' ), PHP_INT_MAX );
		}
		self::$passed = $user->ID;
	}

	/**
	 * Whether pass() was given for this user in this request.
	 *
	 * @param int $user_id User ID.
	 */
	public static function passed( int $user_id ): bool {
		return $user_id > 0 && self::$passed === $user_id;
	}

	/**
	 * Ends the pass: the second step was completed in this request.
	 */
	public static function release(): void {
		self::$passed = 0;
	}

	/**
	 * Action set_current_user: a gate that calls wp_set_current_user() after its password
	 * check does not get to act as the user for the rest of the request.
	 */
	public static function keep_signed_out(): void {
		if ( self::$passed > 0 && get_current_user_id() === self::$passed ) {
			wp_set_current_user( 0 );
		}
	}

	/**
	 * The page the browser asked for, to return to after the second step ('' for anything
	 * but a GET). Validated as a redirect target when it is used.
	 */
	public static function target(): string {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		if ( 'GET' !== $method || ! isset( $_SERVER['REQUEST_URI'] ) || ! is_string( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}
		$uri  = wp_sanitize_redirect( wp_unslash( $_SERVER['REQUEST_URI'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_sanitize_redirect() sanitizes it.
		$home = wp_parse_url( home_url( '/' ) );
		if ( ! is_array( $home ) || ! isset( $home['host'] ) || ! str_starts_with( $uri, '/' ) || str_starts_with( $uri, '//' ) ) {
			return '';
		}

		return ( $home['scheme'] ?? 'https' ) . '://' . $home['host'] . ( isset( $home['port'] ) ? ':' . $home['port'] : '' ) . $uri;
	}
}
