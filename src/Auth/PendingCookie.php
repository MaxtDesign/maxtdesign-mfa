<?php
/**
 * Browser side of the pending login (plan 4.5).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * The mdmfa_pending cookie: HttpOnly, SameSite=Lax, Secure when the login URL is https, session
 * lifetime, path COOKIEPATH. Strictly necessary for signing in.
 */
final class PendingCookie {

	public const NAME = 'mdmfa_pending';

	/**
	 * Sets the cookie for this response and the rest of this request.
	 *
	 * @param string $token Raw token.
	 */
	public static function set( string $token ): void {
		self::send( $token, 0 );
		$_COOKIE[ self::NAME ] = $token;
	}

	/**
	 * Raw token from the request, or null when absent or malformed.
	 */
	public static function get(): ?string {
		if ( ! isset( $_COOKIE[ self::NAME ] ) || ! is_string( $_COOKIE[ self::NAME ] ) ) {
			return null;
		}
		$token = sanitize_text_field( wp_unslash( $_COOKIE[ self::NAME ] ) );

		return 1 === preg_match( PendingStore::TOKEN_PATTERN, $token ) ? $token : null;
	}

	/**
	 * Expires the cookie.
	 */
	public static function clear(): void {
		self::send( '', time() - YEAR_IN_SECONDS );
		unset( $_COOKIE[ self::NAME ] );
	}

	/**
	 * Emits Set-Cookie.
	 *
	 * @param string $value   Value.
	 * @param int    $expires Expiry (0 = session).
	 */
	private static function send( string $value, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			self::NAME,
			$value,
			array(
				'expires'  => $expires,
				'path'     => defined( 'COOKIEPATH' ) && '' !== COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => str_starts_with( site_url( 'wp-login.php', 'login' ), 'https://' ),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}
}
