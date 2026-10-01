<?php
/**
 * Login location state (plan section 5): whether the moved login is on, its slug, and the
 * URLs built from it. Honest framing: the slug removes scanner noise; it is not a security
 * boundary. MFA is.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Settings\LoginSlug;
use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Read side of the login location. All reads use the autoloaded mdmfa_login option.
 */
final class LoginLocation {

	/**
	 * Whether the moved login is active for this site.
	 * Off under MDMFA_DISABLE, MDMFA_DISABLE_LOGIN_LOCATION, or the option's enabled flag.
	 */
	public static function enabled(): bool {
		if ( Plugin::is_disabled() || ( defined( 'MDMFA_DISABLE_LOGIN_LOCATION' ) && (bool) constant( 'MDMFA_DISABLE_LOGIN_LOCATION' ) ) ) {
			return false;
		}
		$option = get_option( Options::LOGIN );

		return is_array( $option ) && ! empty( $option['enabled'] ) && '' !== self::slug();
	}

	/**
	 * The effective slug: MDMFA_LOGIN_SLUG (lost-slug recovery, plan 5.5) wins over the option.
	 */
	public static function slug(): string {
		if ( defined( 'MDMFA_LOGIN_SLUG' ) ) {
			$forced = strtolower( trim( (string) constant( 'MDMFA_LOGIN_SLUG' ) ) );
			if ( LoginSlug::well_formed( $forced ) ) {
				return $forced;
			}
		}
		$option = get_option( Options::LOGIN );
		$slug   = is_array( $option ) && isset( $option['slug'] ) && is_string( $option['slug'] ) ? $option['slug'] : '';

		return LoginSlug::well_formed( $slug ) ? $slug : '';
	}

	/**
	 * Path of home_url(), always with a trailing slash ('/' or '/blog/').
	 */
	public static function home_path(): string {
		$path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );

		return '/' . ltrim( trailingslashit( '' !== $path ? $path : '/' ), '/' );
	}

	/**
	 * Request path of the slug ('/blog/abc123').
	 */
	public static function slug_path(): string {
		return self::home_path() . self::slug();
	}

	/**
	 * Absolute URL of the login page, with an optional query string.
	 *
	 * @param string $query Query string without the leading '?'.
	 */
	public static function url( string $query = '' ): string {
		$url = set_url_scheme( home_url( '/' . self::slug() ), 'login' );

		return '' !== $query ? $url . '?' . $query : $url;
	}

	/**
	 * The URL wp-login.php really lives at, bypassing every URL filter. Used for the
	 * allow-listed actions that must stay there (postpass, confirmaction, recovery mode).
	 *
	 * @param string $query Query string without the leading '?'.
	 */
	public static function raw_core_url( string $query = '' ): string {
		$url = set_url_scheme( trailingslashit( (string) get_option( 'siteurl' ) ) . 'wp-login.php', 'login' );

		return '' !== $query ? $url . '?' . $query : $url;
	}

	/**
	 * Where logged-out visitors are sent to log in (plan 5.3, decision 8): WooCommerce My
	 * Account when present, else the slug; or a published page the owner chose. Filter:
	 * mdmfa_public_login_url.
	 */
	public static function public_url(): string {
		$option  = get_option( Options::LOGIN );
		$mode    = is_array( $option ) && isset( $option['public_login'] ) && is_string( $option['public_login'] ) ? $option['public_login'] : 'auto';
		$account = ChallengeUrl::account();
		$url     = ( 'slug' !== $mode && '' !== $account ) ? $account : self::url();
		if ( 'page' === $mode ) {
			$page = is_array( $option ) && isset( $option['public_page'] ) ? (int) $option['public_page'] : 0;
			$link = $page > 0 && 'publish' === get_post_status( $page ) ? get_permalink( $page ) : false;
			$url  = is_string( $link ) && '' !== $link ? $link : $url;
		}
		$url = apply_filters( 'mdmfa_public_login_url', $url );

		return is_string( $url ) && '' !== $url ? $url : self::url();
	}

	/**
	 * Whether the given request URI is the slug.
	 *
	 * @param string $request_uri REQUEST_URI.
	 * @param string $home_path   Home path with trailing slash.
	 * @param string $slug        Slug.
	 */
	public static function matches( string $request_uri, string $home_path, string $slug ): bool {
		if ( '' === $slug ) {
			return false;
		}
		$path = (string) wp_parse_url( $request_uri, PHP_URL_PATH );
		if ( ! str_starts_with( strtolower( $path ), strtolower( $home_path ) ) ) {
			return false;
		}

		return strtolower( trim( substr( $path, strlen( $home_path ) ), '/' ) ) === $slug;
	}
}
