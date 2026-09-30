<?php
/**
 * Login slug generation and validation (plan 5.4).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Random slug, format rules and collision checks.
 */
final class LoginSlug {

	public const LENGTH   = 12;
	public const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
	public const MIN      = 4;
	public const MAX      = 64;

	/** Paths WordPress, common plugins and scanners already use. */
	public const RESERVED = array(
		'wp-admin',
		'wp-content',
		'wp-includes',
		'wp-json',
		'wp-login',
		'wp-signup',
		'wp-activate',
		'wp-cron',
		'wp-sitemap',
		'xmlrpc',
		'login',
		'admin',
		'dashboard',
		'register',
		'signin',
		'sign-in',
		'logout',
		'feed',
		'rss',
		'rss2',
		'atom',
		'rdf',
		'embed',
		'trackback',
		'comments',
		'search',
		'page',
		'author',
		'category',
		'tag',
		'type',
		'attachment',
		'robots',
		'favicon',
		'sitemap',
		'shop',
		'cart',
		'checkout',
		'my-account',
		'wc-api',
		'wc-auth',
	);

	/**
	 * A bare random token (about 62 bits) with no fixed prefix, so a scanner learns
	 * nothing from its shape.
	 */
	public static function generate(): string {
		$max  = strlen( self::ALPHABET ) - 1;
		$slug = '';
		for ( $i = 0; $i < self::LENGTH; $i++ ) {
			$slug .= self::ALPHABET[ random_int( 0, $max ) ];
		}

		return $slug;
	}

	/**
	 * Format only: 4-64 of [a-z0-9], single hyphens between groups.
	 *
	 * @param string $slug Candidate.
	 */
	public static function well_formed( string $slug ): bool {
		$length = strlen( $slug );

		return $length >= self::MIN && $length <= self::MAX && 1 === preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $slug );
	}

	/**
	 * Full validation for an owner-chosen slug. Returns the normalised slug or an error.
	 *
	 * @param string $raw Owner input.
	 * @return string|\WP_Error
	 */
	public static function validate( string $raw ): string|\WP_Error {
		$slug = strtolower( trim( $raw, " \t\n\r\0\x0B/" ) );
		if ( ! self::well_formed( $slug ) || sanitize_title( $slug ) !== $slug ) {
			return new \WP_Error( 'mdmfa_slug_format', __( 'Use 4 to 64 lowercase letters, numbers and single hyphens.', 'maxtdesign-mfa' ) );
		}
		if ( in_array( $slug, self::RESERVED, true ) || str_starts_with( $slug, 'wp-' ) ) {
			return new \WP_Error( 'mdmfa_slug_reserved', __( 'That address is reserved. Choose another.', 'maxtdesign-mfa' ) );
		}
		$collision = self::collision( $slug );
		if ( '' !== $collision ) {
			return new \WP_Error(
				'mdmfa_slug_taken',
				sprintf(
					/* translators: %s: what already uses the address, for example "a page". */
					__( 'That address is already used by %s. Choose another.', 'maxtdesign-mfa' ),
					$collision
				)
			);
		}

		return $slug;
	}

	/**
	 * What already uses the slug as a path on this site, or ''.
	 *
	 * @param string $slug Well-formed slug.
	 */
	public static function collision( string $slug ): string {
		$public_types = get_post_types( array( 'public' => true ) );
		if ( null !== get_page_by_path( $slug, OBJECT, array_values( $public_types ) ) ) {
			return __( 'a page or post', 'maxtdesign-mfa' );
		}
		foreach ( $public_types as $type ) {
			$object = get_post_type_object( $type );
			if ( null === $object ) {
				continue;
			}
			$rewrite = is_array( $object->rewrite ) && isset( $object->rewrite['slug'] ) ? (string) $object->rewrite['slug'] : '';
			$archive = is_string( $object->has_archive ) ? $object->has_archive : '';
			if ( $slug === $rewrite || $slug === $archive ) {
				return __( 'a content type', 'maxtdesign-mfa' );
			}
		}
		foreach ( get_taxonomies( array( 'public' => true ), 'objects' ) as $taxonomy ) {
			$rewrite = is_array( $taxonomy->rewrite ) && isset( $taxonomy->rewrite['slug'] ) ? (string) $taxonomy->rewrite['slug'] : '';
			if ( $slug === $rewrite ) {
				return __( 'a taxonomy', 'maxtdesign-mfa' );
			}
		}
		if ( null !== term_exists( $slug ) ) {
			return __( 'a category or tag', 'maxtdesign-mfa' );
		}
		global $wp_rewrite;
		if ( $wp_rewrite instanceof \WP_Rewrite ) {
			foreach ( array_keys( (array) $wp_rewrite->wp_rewrite_rules() ) as $regex ) {
				// Only rules that start with a literal path segment can collide.
				if ( 1 === preg_match( '#^([a-z0-9-]+)(/|\(|\?|$)#', (string) $regex, $m ) && $m[1] === $slug ) {
					return __( 'another plugin or the theme', 'maxtdesign-mfa' );
				}
			}
		}

		return '';
	}
}
