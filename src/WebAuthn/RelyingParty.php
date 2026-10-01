<?php
/**
 * Relying party identity (plan 12, eval 5.2): the RP ID is the host of home_url() and the
 * allowed origins are the exact scheme + host + port of site_url() and home_url(). Never
 * derived from HTTP_HOST or X-Forwarded-*, so a proxy or a forged Host header cannot pick
 * them. Filters: mdmfa_webauthn_rp_id, mdmfa_webauthn_origins.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * RP configuration.
 */
final class RelyingParty {

	/** Hosts where WebAuthn may run over plain http (development). */
	private const LOOPBACK = array( 'localhost', '127.0.0.1', '[::1]', '::1' );

	/**
	 * RP ID.
	 */
	public static function id(): string {
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$id   = apply_filters( 'mdmfa_webauthn_rp_id', $host );

		return is_string( $id ) && '' !== $id ? strtolower( $id ) : $host;
	}

	/**
	 * RP display name.
	 */
	public static function name(): string {
		$name = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		return '' !== trim( $name ) ? $name : self::id();
	}

	/**
	 * Allowed origins.
	 *
	 * @return string[]
	 */
	public static function origins(): array {
		$origins = array_values( array_unique( array_filter( array( self::origin( home_url() ), self::origin( site_url() ) ) ) ) );
		$origins = apply_filters( 'mdmfa_webauthn_origins', $origins );

		return is_array( $origins ) ? array_values( array_filter( $origins, 'is_string' ) ) : array();
	}

	/**
	 * Whether passkeys can work on this site: openssl present and a secure context
	 * (https, or a loopback host in development).
	 */
	public static function available(): bool {
		if ( ! function_exists( 'openssl_verify' ) ) {
			return false;
		}
		$scheme = (string) wp_parse_url( home_url(), PHP_URL_SCHEME );
		$host   = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );

		return 'https' === $scheme || in_array( $host, self::LOOPBACK, true ) || str_ends_with( $host, '.localhost' );
	}

	/**
	 * Origin string (scheme://host[:port]) of a URL; default ports are omitted, as browsers do.
	 *
	 * @param string $url URL.
	 */
	public static function origin( string $url ): string {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$scheme  = strtolower( $parts['scheme'] );
		$port    = isset( $parts['port'] ) ? (int) $parts['port'] : 0;
		$default = ( 'https' === $scheme && 443 === $port ) || ( 'http' === $scheme && 80 === $port ) || 0 === $port;

		return $scheme . '://' . strtolower( $parts['host'] ) . ( $default ? '' : ':' . $port );
	}
}
