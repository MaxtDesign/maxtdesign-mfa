<?php
/**
 * Stops a correct password from becoming a session (plan 4.2).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Hooks authenticate at PHP_INT_MAX, after every other plugin has voted. When the verdict
 * is a WP_User who needs a second factor, the request never returns to wp_signon(), so
 * wp_set_auth_cookie() (and the session it creates), wp_login and wp_login_failed never
 * run. Interactive contexts are redirected to the challenge; the rest get a WP_Error.
 */
final class Interceptor {

	/**
	 * Secure-cookie flag wp_signon() resolved for this request.
	 *
	 * @var bool
	 */
	private static bool $secure = false;

	/**
	 * "Remember me" as wp_signon() normalised it.
	 *
	 * @var bool
	 */
	private static bool $remember = false;

	/**
	 * Whether wp_signon() ran in this request (a plugin may call wp_authenticate() alone).
	 *
	 * @var bool
	 */
	private static bool $captured = false;

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'secure_signon_cookie', array( self::class, 'capture_signon' ), PHP_INT_MAX, 2 );
		add_filter( 'authenticate', array( self::class, 'authenticate' ), PHP_INT_MAX, 1 );
		add_filter( 'woocommerce_login_credentials', array( Context::class, 'mark_wc' ), PHP_INT_MAX );
		add_action( 'application_password_did_authenticate', array( Context::class, 'mark_apppass' ) );
	}

	/**
	 * Records wp_signon()'s final secure flag and remember choice (user.php, the
	 * secure_signon_cookie filter runs before wp_authenticate()). Returns it unchanged.
	 *
	 * @param mixed $secure      Secure flag.
	 * @param mixed $credentials Sign-on credentials.
	 * @return mixed
	 */
	public static function capture_signon( mixed $secure, mixed $credentials = array() ): mixed {
		self::$captured = true;
		self::$secure   = (bool) $secure;
		self::$remember = is_array( $credentials ) && ! empty( $credentials['remember'] );

		return $secure;
	}

	/**
	 * The final authenticate verdict.
	 *
	 * @param mixed $user WP_User, WP_Error or null.
	 * @return mixed
	 */
	public static function authenticate( mixed $user ): mixed {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}

		$context = Context::detect( $user->ID );
		// App passwords are a revocable scoped credential, exempt by design (plan 4.3).
		// WP-CLI and cron never create browser sessions.
		if ( Context::APPPASS === $context || Context::CLI === $context ) {
			return $user;
		}
		// A logged-in user re-checking their own password is not a new login (plan risk 3).
		// On a login form it is one: the form issues a fresh session, which must be earned.
		if ( ! Context::is_interactive( $context ) && is_user_logged_in() && get_current_user_id() === $user->ID ) {
			return $user;
		}

		// A confirmed email recovery whose waiting period is over takes effect now.
		EmailRecovery::maybe_apply( $user );
		Policy::maybe_start_grace( $user );
		$decision = Policy::decide( $user );
		if ( Policy::NONE === $decision ) {
			return $user;
		}

		if ( ! Context::is_interactive( $context ) ) {
			// On a network: only when every site the user belongs to allows it.
			if ( Context::XMLRPC === $context && ! empty( Policy::effective( $user )['xmlrpc_password'] ) ) {
				Logger::log( 'xmlrpc_password', $user->ID, '', $context );
				return $user;
			}
			if ( true === apply_filters( 'mdmfa_allow_noninteractive_password', false, $user, $context ) ) {
				return $user;
			}
			if ( Context::AJAX === $context && ! headers_sent() ) {
				$token = PendingStore::create( $user->ID, PendingStore::KIND_LOGIN, self::payload( $context, $decision ) );
				PendingCookie::set( $token );
				do_action( 'mdmfa_challenge_started', $user, $context );

				return new \WP_Error(
					'mdmfa_required',
					sprintf(
						/* translators: %s: URL of the verification screen. */
						__( 'Two-step verification is required. <a href="%s">Continue to verification</a>.', 'maxtdesign-mfa' ),
						esc_url( ChallengeUrl::for_decision( $decision, $context ) )
					)
				);
			}
			Logger::log( 'noninteractive_blocked', $user->ID, '', $context );

			return new \WP_Error( 'mdmfa_required', __( 'Two-step verification is required for this account. Sign in through the login page.', 'maxtdesign-mfa' ) );
		}

		$token = PendingStore::create( $user->ID, PendingStore::KIND_LOGIN, self::payload( $context, $decision ) );

		// A trusted device skips the challenge, never enrollment (plan 4.3).
		if ( Policy::CHALLENGE === $decision && TrustedDevice::valid( $user ) ) {
			$record = PendingStore::find( $token );
			if ( null !== $record && Completion::complete( $user, TrustedDevice::FACTOR, $record ) ) {
				Completion::redirect( $user, $record );
			}
		}

		PendingCookie::set( $token );
		do_action( 'mdmfa_challenge_started', $user, $context );

		nocache_headers();
		wp_safe_redirect( ChallengeUrl::for_decision( $decision, $context ) );
		exit;
	}

	/**
	 * Everything the completion step needs, kept server side rather than in the URL.
	 *
	 * @param string $context  Login context.
	 * @param string $decision Policy decision.
	 * @return array<string, mixed>
	 */
	private static function payload( string $context, string $decision ): array {
		// phpcs:disable WordPress.Security.NonceVerification -- the login forms carry no nonce (core reads the same fields); values are only stored and validated at use.
		$redirect = '';
		if ( Context::WC === $context ) {
			// WC_Form_Handler::process_login() order: posted redirect, then referer.
			if ( isset( $_POST['redirect'] ) && is_string( $_POST['redirect'] ) && '' !== $_POST['redirect'] ) {
				$redirect = wp_sanitize_redirect( wp_unslash( $_POST['redirect'] ) );
			} elseif ( isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) && '' !== $_GET['redirect_to'] ) {
				// Login links rewritten to My Account carry the page to return to.
				$redirect = wp_sanitize_redirect( wp_unslash( $_GET['redirect_to'] ) );
			} elseif ( function_exists( 'wc_get_raw_referer' ) ) {
				$redirect = (string) wc_get_raw_referer();
			}
		} elseif ( isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ) {
			$redirect = wp_sanitize_redirect( wp_unslash( $_REQUEST['redirect_to'] ) );
		}
		$interim = Context::CORE === $context && isset( $_REQUEST['interim-login'] );
		// phpcs:enable

		return array(
			'context'      => $context,
			'decision'     => $decision,
			'redirect_to'  => substr( wp_sanitize_redirect( $redirect ), 0, 2048 ),
			'remember'     => self::$remember,
			// Without wp_signon() nobody resolved the flag: never issue a non-Secure cookie on https.
			'secure'       => self::$captured ? self::$secure : is_ssl(),
			'interim'      => $interim,
			'first_factor' => 'password',
		);
	}
}
