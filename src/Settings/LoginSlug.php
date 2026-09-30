<?php
/**
 * Login slug generation (plan 5.4). Routing and validation arrive in P4.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Random login slug.
 */
final class LoginSlug {

	public const LENGTH   = 12;
	public const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

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
}
