<?php
/**
 * Catches code that logs a user in without the login form (plan 4.6): WooCommerce's
 * auto-login after a My Account password reset, Jetpack SSO, Jetpack's leaked-password
 * flow, and anything else that calls wp_set_auth_cookie() directly.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * On set_auth_cookie: if the user must have passed MFA, the call is not from Completion,
 * and the session behind the token carries no mdmfa stamp, the session is destroyed, no
 * cookie leaves the server (send_auth_cookies returns false), a pending record is created
 * and the caller's next redirect is sent to the challenge instead. Core's own cookie
 * re-issue after a password change passes the existing, stamped token and is allowed.
 */
final class BypassGuard {

	/**
	 * Session tokens whose cookies must not be sent in this request.
	 *
	 * @var array<string, true>
	 */
	private static array $blocked = array();

	/**
	 * Pending record hash whose redirect target is still to be captured.
	 *
	 * @var string|null
	 */
	private static ?string $pending_hash = null;

	/**
	 * Decision for the pending record created by the last block.
	 *
	 * @var string
	 */
	private static string $decision = Policy::CHALLENGE;

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'set_auth_cookie', array( self::class, 'inspect' ), PHP_INT_MAX, 6 );
		add_filter( 'send_auth_cookies', array( self::class, 'filter_send' ), PHP_INT_MAX, 6 );
	}

	/**
	 * Inspects every auth cookie WordPress is about to issue.
	 *
	 * @param mixed $auth_cookie Cookie value (unused).
	 * @param mixed $expire      Cookie expiry (0 = session cookie).
	 * @param mixed $expiration  Auth expiration (unused).
	 * @param mixed $user_id     User ID.
	 * @param mixed $scheme      auth or secure_auth.
	 * @param mixed $token       Session token.
	 */
	public static function inspect( mixed $auth_cookie, mixed $expire, mixed $expiration, mixed $user_id, mixed $scheme, mixed $token ): void {
		unset( $auth_cookie, $expiration );
		if ( Completion::is_blessed() || ! is_numeric( $user_id ) || ! is_string( $token ) || '' === $token ) {
			return;
		}
		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		// A user who only ever arrives through a direct cookie issuer (SSO, a reset
		// auto-login) still gets a setup period that ends.
		Policy::maybe_start_grace( $user );
		// An access gate whose password check was let through on the second step's own pages
		// (HttpAuth): no session, whatever the policy, and the pending sign-in stays as it is.
		if ( HttpAuth::passed( $user->ID ) ) {
			\WP_Session_Tokens::get_instance( $user->ID )->destroy( $token );
			self::$blocked[ $token ] = true;
			if ( get_current_user_id() === $user->ID ) {
				wp_set_current_user( 0 );
			}

			return;
		}
		if ( ! Policy::is_subject( $user ) ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		$session = $manager->get( $token );
		if ( is_array( $session ) && isset( $session['mdmfa'] ) && is_array( $session['mdmfa'] ) && ! empty( $session['mdmfa']['verified_at'] ) ) {
			return;
		}

		$source = self::source();
		if ( true === apply_filters( 'mdmfa_allow_direct_auth_cookie', false, $user, $source ) ) {
			return;
		}

		$manager->destroy( $token );
		self::$blocked[ $token ] = true;
		if ( get_current_user_id() === $user->ID ) {
			wp_set_current_user( 0 );
		}

		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! headers_sent() ) {
			self::$decision = Policy::decide( $user );
			$pending        = PendingStore::create(
				$user->ID,
				PendingStore::KIND_LOGIN,
				array(
					'context'      => 'guard',
					'decision'     => self::$decision,
					'redirect_to'  => '',
					'remember'     => is_numeric( $expire ) && (int) $expire > 0,
					'secure'       => 'secure_auth' === $scheme,
					'interim'      => false,
					'first_factor' => 'guard:' . $source,
				)
			);
			PendingCookie::set( $pending );
			self::$pending_hash = PendingStore::hash( $pending );
			add_filter( 'wp_redirect', array( self::class, 'rewrite_redirect' ), PHP_INT_MAX, 1 );
		}

		Logger::log( 'bypass_blocked', $user->ID, '', 'guard', null, $source );
		do_action( 'mdmfa_bypass_blocked', $user, $source );
	}

	/**
	 * Keeps blocked cookies on the server.
	 *
	 * @param mixed $send       Whether to send.
	 * @param mixed $expire     Unused.
	 * @param mixed $expiration Unused.
	 * @param mixed $user_id    Unused.
	 * @param mixed $scheme     Unused.
	 * @param mixed $token      Session token.
	 * @return mixed
	 */
	public static function filter_send( mixed $send, mixed $expire = 0, mixed $expiration = 0, mixed $user_id = 0, mixed $scheme = '', mixed $token = '' ): mixed {
		unset( $expire, $expiration, $user_id, $scheme );

		return is_string( $token ) && isset( self::$blocked[ $token ] ) ? false : $send;
	}

	/**
	 * One-shot: sends the caller's next redirect to the challenge, keeping the original
	 * target as the post-verification destination.
	 *
	 * @param mixed $location Redirect target.
	 * @return mixed
	 */
	public static function rewrite_redirect( mixed $location ): mixed {
		remove_filter( 'wp_redirect', array( self::class, 'rewrite_redirect' ), PHP_INT_MAX );
		$token = PendingCookie::get();
		if ( null === self::$pending_hash || null === $token || PendingStore::hash( $token ) !== self::$pending_hash ) {
			return $location;
		}
		$record = PendingStore::find( $token );
		if ( null !== $record && is_string( $location ) ) {
			PendingStore::update_payload( $record, array_merge( $record->payload, array( 'redirect_to' => substr( wp_sanitize_redirect( $location ), 0, 2048 ) ) ) );
		}

		return ChallengeUrl::for_decision( self::$decision, 'guard', is_string( $location ) ? $location : '' );
	}

	/**
	 * Name of the function that called wp_set_auth_cookie(), for the log.
	 */
	private static function source(): string {
		$frames = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 16 ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- identifies the direct cookie issuer for the security log.
		foreach ( $frames as $index => $frame ) {
			if ( 'wp_set_auth_cookie' === $frame['function'] ) {
				$caller = $frames[ $index + 1 ] ?? array();
				$name   = ( isset( $caller['class'] ) ? $caller['class'] . '::' : '' ) . ( $caller['function'] ?? 'unknown' );

				return substr( (string) preg_replace( '/[^A-Za-z0-9_:\\\\-]/', '', $name ), 0, 64 );
			}
		}

		return 'unknown';
	}
}
