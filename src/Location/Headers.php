<?php
/**
 * Response headers and cache signals for login responses (plan 5.2, 5.6, 10.4).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps login, challenge and 404 responses out of every cache.
 */
final class Headers {

	/**
	 * Sends no-store, same-origin referrers and noindex, and sets the page-cache opt-outs
	 * common caches honour.
	 */
	public static function no_store(): void {
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Referrer-Policy: same-origin' );
			header( 'X-Robots-Tag: noindex, nofollow' );
		}
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- the page-cache convention WP Super Cache, W3TC and others read.
		}
		if ( has_action( 'litespeed_control_set_nocache' ) ) {
			do_action( 'litespeed_control_set_nocache', 'maxtdesign-mfa login' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- LiteSpeed Cache's documented API.
		}
	}
}
