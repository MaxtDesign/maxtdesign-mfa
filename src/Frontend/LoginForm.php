<?php
/**
 * Front-end login forms (plan 4.3, decision 9): wp_login_form() and the Login/out block
 * post to site_url( 'wp-login.php', 'login_post' ) (general-template.php). Outside the
 * login screen that URL is rewritten to a neutral handler,
 * admin-post.php?action=mdmfa_login, so a front-end login never lands on wp-login.php and
 * its second step can happen on My Account.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Frontend;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Auth\Context;
use MaxtDesign\Mfa\Location\LoginLocation;

defined( 'ABSPATH' ) || exit;

/**
 * Neutral login handler.
 */
final class LoginForm {

	public const ACTION = 'mdmfa_login';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'site_url', array( self::class, 'rewrite_form_action' ), 10, 3 );
		add_action( 'admin_post_nopriv_' . self::ACTION, array( self::class, 'handle' ) );
		add_action( 'admin_post_' . self::ACTION, array( self::class, 'handle_logged_in' ) );
	}

	/**
	 * Rewrites the plain `wp-login.php` login_post URL everywhere except wp-login.php.
	 *
	 * @param mixed $url    URL.
	 * @param mixed $path   Requested path.
	 * @param mixed $scheme URL scheme context.
	 * @return mixed
	 */
	public static function rewrite_form_action( mixed $url, mixed $path = '', mixed $scheme = null ): mixed {
		if ( 'login_post' !== $scheme || 'wp-login.php' !== ltrim( (string) $path, '/' ) ) {
			return $url;
		}
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return $url;
		}

		return add_query_arg( 'action', self::ACTION, admin_url( 'admin-post.php' ) );
	}

	/**
	 * Logged-out submission: sign on as the core form would. A user who needs a second
	 * factor is redirected to the challenge by the Interceptor and never returns here.
	 */
	public static function handle(): void {
		Context::mark( Context::FRONTEND );
		$user   = wp_signon();
		$target = self::target();

		if ( is_wp_error( $user ) ) {
			$account = ChallengeUrl::account();
			// The public login page, never the address itself unless that is the public page.
			$public = LoginLocation::enabled() ? add_query_arg( 'redirect_to', rawurlencode( $target ), LoginLocation::public_url() ) : wp_login_url( $target );
			$retry  = '' !== $account ? add_query_arg( 'mdmfa_login', 'failed', $account ) : $public;
			wp_safe_redirect( $retry );
			exit;
		}

		wp_safe_redirect( $target );
		exit;
	}

	/**
	 * Already logged in: just continue.
	 */
	public static function handle_logged_in(): void {
		wp_safe_redirect( self::target() );
		exit;
	}

	/**
	 * Where to go next: the form's redirect_to, else the referring page, else home.
	 */
	private static function target(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core login forms carry no nonce; the value is validated below.
		$requested = isset( $_POST['redirect_to'] ) && is_string( $_POST['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_POST['redirect_to'] ) ) : '';
		$fallback  = wp_get_referer();

		return wp_validate_redirect( $requested, false !== $fallback ? $fallback : home_url( '/' ) );
	}
}
