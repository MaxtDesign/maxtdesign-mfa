<?php
/**
 * Page caches (plan 5.6). The slug and challenge responses are no-store; on top of that:
 * maxtdesign-cache gets the slug in exclude_paths and a per-URL purge on every slug change
 * (a 404 cached at a path before it became the slug would otherwise shadow the login),
 * and WP Rocket gets the slug in its reject list.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

defined( 'ABSPATH' ) || exit;

/**
 * Cache plugin integration through their public hooks only.
 */
final class CacheBridge {

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'md_cache_config', array( self::class, 'cache_config' ) );
		add_filter( 'rocket_cache_reject_uri', array( self::class, 'rocket_reject' ) );
	}

	/**
	 * Adds the slug path to maxtdesign-cache's exclude_paths (prefix match on the request
	 * path). Takes effect when that plugin next regenerates its config.
	 *
	 * @param mixed $config Cache config.
	 * @return mixed
	 */
	public static function cache_config( mixed $config ): mixed {
		if ( ! is_array( $config ) || ! LoginLocation::enabled() ) {
			return $config;
		}
		$paths                   = isset( $config['exclude_paths'] ) && is_array( $config['exclude_paths'] ) ? $config['exclude_paths'] : array();
		$paths[]                 = LoginLocation::slug_path();
		$config['exclude_paths'] = array_values( array_unique( $paths ) );

		return $config;
	}

	/**
	 * WP Rocket never caches the slug.
	 *
	 * @param mixed $uris URI patterns.
	 * @return mixed
	 */
	public static function rocket_reject( mixed $uris ): mixed {
		if ( ! is_array( $uris ) || ! LoginLocation::enabled() ) {
			return $uris;
		}
		$uris[] = LoginLocation::slug_path() . '(.*)';

		return $uris;
	}

	/**
	 * Purges URLs through the suite signal maxtdesign-cache listens to, and asks it to
	 * regenerate its config when it offers the (requested) public hook.
	 *
	 * @param string[] $urls URLs.
	 */
	public static function purge( array $urls ): void {
		foreach ( $urls as $url ) {
			do_action( 'md_suite_content_changed', array( 'url' => $url ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- the MaxtDesign suite's shared purge signal.
		}
		if ( has_action( 'md_cache_regenerate_config' ) ) {
			do_action( 'md_cache_regenerate_config' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- maxtdesign-cache's hook, requested in the plan.
		}
	}
}
