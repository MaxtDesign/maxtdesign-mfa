<?php
/**
 * Trusted devices (plan 4.3, decision 15): after a verified sign-in the user may let this
 * browser skip the second step for a while. Off for every role at install.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Cookie mdmfa_td = selector:validator. The server keeps the selector and a hash of the
 * validator (wp_fast_hash) in user meta, at most 10 per user. Every password change and
 * every factor removal revokes them all.
 */
final class TrustedDevice {

	public const COOKIE = 'mdmfa_td';
	public const META   = 'mdmfa_trusted';
	public const MAX    = 10;

	/** Session stamp of a sign-in that skipped the challenge. Never counts as a fresh verification. */
	public const FACTOR = 'trusted';

	private const PATTERN = '/^([A-Za-z0-9_-]{16}):([A-Za-z0-9_-]{43})$/';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		// Fires for wp_set_password() and for a password changed through wp_insert_user().
		add_action( 'wp_set_password', array( self::class, 'password_changed' ), 10, 2 );
	}

	/**
	 * Revokes every trusted device when the password changes.
	 *
	 * @param mixed $password New password (unused).
	 * @param mixed $user_id  User ID.
	 */
	public static function password_changed( mixed $password, mixed $user_id = 0 ): void {
		unset( $password );
		if ( is_numeric( $user_id ) && (int) $user_id > 0 ) {
			self::revoke_all( (int) $user_id );
		}
	}

	/**
	 * Whether the user's role allows trusted devices.
	 *
	 * @param \WP_User $user User.
	 */
	public static function allowed( \WP_User $user ): bool {
		return ! empty( Policy::effective( $user )['trusted_devices'] );
	}

	/**
	 * Lifetime of a new trusted device in seconds.
	 *
	 * @param \WP_User $user User.
	 */
	public static function lifetime( \WP_User $user ): int {
		$days     = Settings::get()['trusted_device_days'];
		$lifetime = apply_filters( 'mdmfa_trusted_device_lifetime', ( is_int( $days ) ? max( 1, $days ) : 30 ) * DAY_IN_SECONDS, $user );

		return is_int( $lifetime ) && $lifetime > 0 ? $lifetime : 30 * DAY_IN_SECONDS;
	}

	/**
	 * Whether this request carries a live trusted-device cookie for the user.
	 *
	 * @param \WP_User $user User.
	 */
	public static function valid( \WP_User $user ): bool {
		if ( ! self::allowed( $user ) ) {
			return false;
		}
		$parts = self::cookie();
		if ( null === $parts ) {
			return false;
		}
		foreach ( self::devices( $user->ID ) as $device ) {
			if ( hash_equals( $device['selector'], $parts[0] ) ) {
				return wp_verify_fast_hash( $parts[1], $device['validator_hash'] );
			}
		}

		return false;
	}

	/**
	 * Records this browser as trusted and returns the cookie value.
	 *
	 * @param \WP_User $user User.
	 * @return array{value: string, expires: int}
	 */
	public static function issue( \WP_User $user ): array {
		$selector  = Base64Url::random( 12 );
		$validator = Base64Url::random( 32 );
		$expires   = Clock::now() + self::lifetime( $user );
		$agent     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		$devices   = self::devices( $user->ID );
		$devices[] = array(
			'selector'       => $selector,
			'validator_hash' => wp_fast_hash( $validator ),
			'expires'        => $expires,
			'ua_label'       => substr( $agent, 0, 64 ),
		);
		update_user_meta( $user->ID, self::META, array_slice( $devices, -self::MAX ) );

		return array(
			'value'   => $selector . ':' . $validator,
			'expires' => $expires,
		);
	}

	/**
	 * Trusts this browser: stores the device and sends the cookie.
	 *
	 * @param \WP_User $user User.
	 */
	public static function remember( \WP_User $user ): void {
		if ( ! self::allowed( $user ) || headers_sent() ) {
			return;
		}
		$cookie = self::issue( $user );
		setcookie(
			self::COOKIE,
			$cookie['value'],
			array(
				'expires'  => $cookie['expires'],
				'path'     => defined( 'COOKIEPATH' ) && '' !== COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => str_starts_with( site_url( 'wp-login.php', 'login' ), 'https://' ),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Number of live trusted devices.
	 *
	 * @param int $user_id User ID.
	 */
	public static function count( int $user_id ): int {
		return count( self::devices( $user_id ) );
	}

	/**
	 * Forgets every trusted device of a user. Their cookies stop working at once.
	 *
	 * @param int $user_id User ID.
	 */
	public static function revoke_all( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
	}

	/**
	 * Unexpired devices.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, array{selector: string, validator_hash: string, expires: int, ua_label: string}>
	 */
	private static function devices( int $user_id ): array {
		$stored  = get_user_meta( $user_id, self::META, true );
		$devices = array();
		foreach ( is_array( $stored ) ? $stored : array() as $device ) {
			if ( is_array( $device ) && isset( $device['selector'], $device['validator_hash'], $device['expires'] )
				&& is_string( $device['selector'] ) && is_string( $device['validator_hash'] ) && is_int( $device['expires'] ) && $device['expires'] > Clock::now() ) {
				$devices[] = array(
					'selector'       => $device['selector'],
					'validator_hash' => $device['validator_hash'],
					'expires'        => $device['expires'],
					'ua_label'       => isset( $device['ua_label'] ) && is_string( $device['ua_label'] ) ? $device['ua_label'] : '',
				);
			}
		}

		return $devices;
	}

	/**
	 * Selector and validator from the request cookie, or null.
	 *
	 * @return array{string, string}|null
	 */
	private static function cookie(): ?array {
		$raw = isset( $_COOKIE[ self::COOKIE ] ) && is_string( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 !== preg_match( self::PATTERN, $raw, $m ) ) {
			return null;
		}

		return array( $m[1], $m[2] );
	}
}
