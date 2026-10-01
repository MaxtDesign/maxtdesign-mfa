<?php
/**
 * Best-effort per-IP soft throttle (plan 11.1) for endpoints that run before any user is
 * known (passwordless finish). Transients, so an object-cache eviction can reset it; the
 * authoritative limits are per user and per pending record.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Throttle.
 */
final class IpThrottle {

	public const LIMIT  = 30;
	public const WINDOW = 600;

	/**
	 * Counts one attempt from the client address; false once over the limit.
	 *
	 * @param string $bucket What is being throttled.
	 */
	public static function allow( string $bucket ): bool {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		// Behind a proxy or CDN every visitor shares REMOTE_ADDR. Forwarded headers are
		// client-controlled, so only the owner can say which one to trust.
		$filtered = apply_filters( 'mdmfa_client_ip', $ip );
		$ip       = is_string( $filtered ) ? $filtered : $ip;
		$key      = 'mdmfa_ipthrottle_' . substr( hash( 'sha256', $bucket . '|' . $ip . '|' . wp_salt( 'nonce' ) ), 0, 32 );
		$hit      = (int) get_transient( $key );
		if ( $hit >= self::LIMIT ) {
			return false;
		}
		set_transient( $key, $hit + 1, self::WINDOW );

		return true;
	}
}
