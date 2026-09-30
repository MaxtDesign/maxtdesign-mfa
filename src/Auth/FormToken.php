<?php
/**
 * CSRF binding for logged-out challenge forms (plan 4.5).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * The form token is HMAC(key, token_hash | purpose). WordPress nonces are shared by every
 * anonymous visitor, so they are weak before login; this token is bound to one pending
 * record and one form.
 */
final class FormToken {

	/**
	 * Token for a record and purpose.
	 *
	 * @param string $token_hash Pending record hash.
	 * @param string $purpose    Form purpose.
	 */
	public static function make( string $token_hash, string $purpose ): string {
		return hash_hmac( 'sha256', $token_hash . '|' . $purpose, self::key() );
	}

	/**
	 * Constant-time check.
	 *
	 * @param mixed  $given      Submitted value.
	 * @param string $token_hash Pending record hash.
	 * @param string $purpose    Form purpose.
	 */
	public static function check( mixed $given, string $token_hash, string $purpose ): bool {
		return is_string( $given ) && hash_equals( self::make( $token_hash, $purpose ), $given );
	}

	/**
	 * HMAC key derived from the site's auth salt.
	 */
	private static function key(): string {
		return hash_hkdf( 'sha256', wp_salt( 'auth' ), 32, 'mdmfa-form-v1' );
	}
}
