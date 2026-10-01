<?php
/**
 * Emailed one-time code (plan 11.1, 11.3): an 8-digit code, valid 10 minutes, 5 tries,
 * sent at most 3 times per 15 minutes and 10 times per day per user. Off for staff roles
 * by default (NIST SP 800-63B-4 does not accept email as an out-of-band authenticator).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Notify\Mailer;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Codes are stored hashed in user meta, keyed by purpose, so a code issued for one
 * pending login cannot finish another.
 */
final class EmailCode {

	/** User meta: {enabled: bool, confirmed_at: int, address: sha256 of the confirmed address}. */
	public const META = 'mdmfa_email';

	/** User meta: purpose => {hash, expires, attempts}. */
	public const CODES = 'mdmfa_email_code';

	/** User meta: send timestamps of the last day. */
	public const SENDS = 'mdmfa_email_sends';

	/** User meta: unix time of the last change of the account's email address. */
	public const CHANGED = 'mdmfa_email_changed';

	public const DIGITS       = 8;
	public const TTL          = 600;
	public const MAX_ATTEMPTS = 5;

	public const SENT    = 'sent';
	public const LIMITED = 'limited';
	public const FAILED  = 'failed';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'profile_update', array( self::class, 'address_changed' ), 10, 2 );
	}

	/**
	 * A changed address is an unproven mailbox: the email factor goes off until it is
	 * confirmed again, trusted devices are forgotten and any waiting recovery is dropped.
	 * Email recovery then stays closed for a day (EmailRecovery::allowed()).
	 *
	 * @param mixed $user_id  User ID.
	 * @param mixed $old_user User data before the update.
	 */
	public static function address_changed( mixed $user_id, mixed $old_user = null ): void {
		$user = is_numeric( $user_id ) ? get_userdata( (int) $user_id ) : false;
		if ( ! $user instanceof \WP_User || ! $old_user instanceof \WP_User || strtolower( $old_user->user_email ) === strtolower( $user->user_email ) ) {
			return;
		}
		update_user_meta( $user->ID, self::CHANGED, Clock::now() );
		$had = self::stored( $user->ID );
		self::remove( $user->ID );
		Reset::after_change( $user->ID );
		delete_user_meta( $user->ID, EmailRecovery::META );
		Logger::log( 'email_changed', $user->ID, $had ? 'email' : '', 'account', get_current_user_id() > 0 ? get_current_user_id() : null );
	}

	/**
	 * Whether the role lets this user use an emailed code.
	 *
	 * @param \WP_User $user User.
	 */
	public static function allowed( \WP_User $user ): bool {
		return Policy::allows( $user, 'email' ) && false !== is_email( $user->user_email );
	}

	/**
	 * Whether the user turned the emailed code on and may still use it.
	 *
	 * @param int $user_id User ID.
	 */
	public static function has( int $user_id ): bool {
		if ( ! self::stored( $user_id ) ) {
			return false;
		}
		$meta = get_user_meta( $user_id, self::META, true );
		$user = get_userdata( $user_id );

		// Only for the address the user proved they can read.
		return $user instanceof \WP_User && self::allowed( $user )
			&& is_array( $meta ) && isset( $meta['address'] ) && is_string( $meta['address'] )
			&& hash_equals( $meta['address'], self::address_hash( $user->user_email ) );
	}

	/**
	 * Whether the factor is switched on in storage (whatever the role or address now say).
	 *
	 * @param int $user_id User ID.
	 */
	private static function stored( int $user_id ): bool {
		$meta = get_user_meta( $user_id, self::META, true );

		return is_array( $meta ) && ! empty( $meta['enabled'] );
	}

	/**
	 * Fingerprint of an address.
	 *
	 * @param string $email Address.
	 */
	private static function address_hash( string $email ): string {
		return hash( 'sha256', strtolower( trim( $email ) ) );
	}

	/**
	 * Turns the factor on (after the user proved they receive the mail).
	 *
	 * @param int $user_id User ID.
	 */
	public static function enable( int $user_id ): void {
		$user = get_userdata( $user_id );
		update_user_meta(
			$user_id,
			self::META,
			array(
				'enabled'      => true,
				'confirmed_at' => Clock::now(),
				'address'      => $user instanceof \WP_User ? self::address_hash( $user->user_email ) : '',
			)
		);
	}

	/**
	 * Turns the factor off and drops any live code.
	 *
	 * @param int $user_id User ID.
	 */
	public static function remove( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
		delete_user_meta( $user_id, self::CODES );
	}

	/**
	 * Takes one slot of the user's send allowance (shared by codes and recovery links).
	 * False when the 15-minute or daily limit is reached.
	 *
	 * @param int $user_id User ID.
	 */
	public static function take_send_slot( int $user_id ): bool {
		$now    = Clock::now();
		$stored = get_user_meta( $user_id, self::SENDS, true );
		$sends  = array();
		foreach ( is_array( $stored ) ? $stored : array() as $at ) {
			if ( is_int( $at ) && $at > $now - DAY_IN_SECONDS ) {
				$sends[] = $at;
			}
		}
		$limits = Settings::get()['email_code_limits'];
		$short  = is_array( $limits ) && isset( $limits['per_15_minutes'] ) && is_int( $limits['per_15_minutes'] ) ? $limits['per_15_minutes'] : 3;
		$day    = is_array( $limits ) && isset( $limits['per_day'] ) && is_int( $limits['per_day'] ) ? $limits['per_day'] : 10;
		$recent = count( array_filter( $sends, static fn ( int $at ): bool => $at > $now - 15 * MINUTE_IN_SECONDS ) );
		if ( $recent >= $short || count( $sends ) >= $day ) {
			return false;
		}
		$sends[] = $now;
		update_user_meta( $user_id, self::SENDS, $sends );

		return true;
	}

	/**
	 * Issues and mails a code for a purpose, replacing any earlier code for it.
	 *
	 * @param \WP_User $user    User.
	 * @param string   $purpose What the code unlocks (login:{record}, setup, stepup).
	 * @return string SENT, LIMITED or FAILED.
	 */
	public static function send( \WP_User $user, string $purpose ): string {
		if ( false === is_email( $user->user_email ) ) {
			return self::FAILED;
		}
		if ( ! self::take_send_slot( $user->ID ) ) {
			return self::LIMITED;
		}
		$code              = str_pad( (string) random_int( 0, 10 ** self::DIGITS - 1 ), self::DIGITS, '0', STR_PAD_LEFT );
		$codes             = self::live( $user->ID );
		$codes[ $purpose ] = array(
			'hash'     => self::hash( $user->ID, $purpose, $code ),
			'expires'  => Clock::now() + self::TTL,
			'attempts' => 0,
		);
		update_user_meta( $user->ID, self::CODES, $codes );

		return Mailer::email_code( $user, $code ) ? self::SENT : self::FAILED;
	}

	/**
	 * Whether a live code exists for the purpose (the screen then shows the code field).
	 *
	 * @param int    $user_id User ID.
	 * @param string $purpose Purpose.
	 */
	public static function issued( int $user_id, string $purpose ): bool {
		return isset( self::live( $user_id )[ $purpose ] );
	}

	/**
	 * Checks a submitted code. A match consumes it; the fifth miss destroys it.
	 *
	 * @param int    $user_id User ID.
	 * @param string $purpose Purpose.
	 * @param string $input   Submitted code.
	 */
	public static function check( int $user_id, string $purpose, string $input ): bool {
		$codes = self::live( $user_id );
		if ( ! isset( $codes[ $purpose ] ) ) {
			return false;
		}
		$digits = (string) preg_replace( '/\D+/', '', $input );
		$ok     = self::DIGITS === strlen( $digits ) && hash_equals( $codes[ $purpose ]['hash'], self::hash( $user_id, $purpose, $digits ) );
		++$codes[ $purpose ]['attempts'];
		if ( $ok || $codes[ $purpose ]['attempts'] >= self::MAX_ATTEMPTS ) {
			unset( $codes[ $purpose ] );
		}
		if ( array() === $codes ) {
			delete_user_meta( $user_id, self::CODES );
		} else {
			update_user_meta( $user_id, self::CODES, $codes );
		}

		return $ok;
	}

	/**
	 * An address with the local part masked, for "we sent a code to ...".
	 *
	 * @param string $email Address.
	 */
	public static function masked( string $email ): string {
		$at = strrpos( $email, '@' );
		if ( false === $at || 0 === $at ) {
			return '';
		}

		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	/**
	 * Unexpired codes by purpose.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, array{hash: string, expires: int, attempts: int}>
	 */
	private static function live( int $user_id ): array {
		$stored = get_user_meta( $user_id, self::CODES, true );
		$live   = array();
		foreach ( is_array( $stored ) ? $stored : array() as $purpose => $entry ) {
			if ( is_string( $purpose ) && is_array( $entry ) && isset( $entry['hash'], $entry['expires'], $entry['attempts'] )
				&& is_string( $entry['hash'] ) && is_int( $entry['expires'] ) && is_int( $entry['attempts'] ) && $entry['expires'] > Clock::now() ) {
				$live[ $purpose ] = array(
					'hash'     => $entry['hash'],
					'expires'  => $entry['expires'],
					'attempts' => $entry['attempts'],
				);
			}
		}

		return $live;
	}

	/**
	 * Keyed hash of a code, bound to the user and the purpose.
	 *
	 * @param int    $user_id User ID.
	 * @param string $purpose Purpose.
	 * @param string $code    The digits.
	 */
	private static function hash( int $user_id, string $purpose, string $code ): string {
		return hash_hmac( 'sha256', $user_id . '|' . $purpose . '|' . $code, wp_salt( 'auth' ) );
	}
}
