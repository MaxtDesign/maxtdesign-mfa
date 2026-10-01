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

use MaxtDesign\Mfa\Auth\StepUp;
use MaxtDesign\Mfa\Auth\TrustedDevice;
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

	/**
	 * Whether this request's own-address change was refused for want of a fresh verification.
	 *
	 * @var bool
	 */
	private static bool $refused_change = false;

	public const SENT    = 'sent';
	public const LIMITED = 'limited';
	public const FAILED  = 'failed';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'profile_update', array( self::class, 'address_changed' ), 10, 2 );
		// Before core's own handler, which mails a confirmation link to the new address.
		add_action( 'personal_options_update', array( self::class, 'guard_profile_request' ), 0, 1 );
		add_action( 'user_profile_update_errors', array( self::class, 'guard_profile_change' ), 10, 3 );
		add_action( 'woocommerce_save_account_details_errors', array( self::class, 'guard_wc_change' ), 10, 2 );
	}

	/**
	 * A changed address is an unproven mailbox: no code is sent to it until it is confirmed
	 * again on the security screen, trusted devices are forgotten and any waiting recovery
	 * is dropped. Email recovery then stays closed for a day (EmailRecovery::allowed()).
	 *
	 * The account stays enrolled (Policy::is_enrolled() counts a stored email factor), so
	 * it is still challenged, with its other methods or a recovery code. Switching the
	 * factor off here would hand a password-only login to whoever changed the address.
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
		delete_user_meta( $user->ID, self::CODES );
		TrustedDevice::revoke_all( $user->ID );
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
		if ( ! $user instanceof \WP_User || ! is_array( $meta ) || ! self::allowed( $user ) ) {
			return false;
		}
		// An enrollment stored before addresses were recorded: bind it to the address the
		// account has now. Treating it as absent would drop the account to password-only.
		if ( ! isset( $meta['address'] ) || ! is_string( $meta['address'] ) || '' === $meta['address'] ) {
			$meta['address'] = self::address_hash( $user->user_email );
			update_user_meta( $user_id, self::META, $meta );
		}

		// Only for the address the user proved they can read.
		return hash_equals( $meta['address'], self::address_hash( $user->user_email ) );
	}

	/**
	 * Whether the user turned email codes on and the role still allows them, whatever
	 * address the account has now. This is what "enrolled" means for the policy: an
	 * unconfirmed new address stops codes being sent, it does not remove the second step.
	 *
	 * @param int $user_id User ID.
	 */
	public static function enrolled( int $user_id ): bool {
		$user = self::stored( $user_id ) ? get_userdata( $user_id ) : false;

		return $user instanceof \WP_User && Policy::allows( $user, 'email' );
	}

	/**
	 * Changing your own email address on an account with two-step verification needs a
	 * recent verification: wp-admin profile form.
	 *
	 * @param mixed $errors Errors to add to.
	 * @param mixed $update Whether this is an update.
	 * @param mixed $user   Submitted user data.
	 */
	public static function guard_profile_change( mixed $errors, mixed $update = true, mixed $user = null ): void {
		$new = is_object( $user ) && isset( $user->user_email ) && is_string( $user->user_email ) ? $user->user_email : '';
		$id  = is_object( $user ) && isset( $user->ID ) ? (int) $user->ID : 0;
		if ( $errors instanceof \WP_Error && $update && ( self::$refused_change || self::change_needs_stepup( $id, $new ) ) ) {
			$errors->add( 'mdmfa_stepup_required', esc_html( self::stepup_message() ) );
		}
	}

	/**
	 * The wp-admin profile form posts a new address to core, which mails a confirmation
	 * link to it before any validation hook runs. When the change is not allowed, the
	 * posted address is put back to the current one, so no link is sent, and the refusal
	 * is reported by guard_profile_change().
	 *
	 * @param mixed $user_id User whose profile is being saved (always the current user here).
	 */
	public static function guard_profile_request( mixed $user_id ): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- core verified the profile nonce before firing this action.
		$new = isset( $_POST['email'] ) && is_string( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		if ( is_numeric( $user_id ) && self::change_needs_stepup( (int) $user_id, $new ) ) {
			$user                 = get_userdata( (int) $user_id );
			$_POST['email']       = $user instanceof \WP_User ? $user->user_email : '';
			self::$refused_change = true;
		}
		// phpcs:enable
	}

	/**
	 * The same rule for WooCommerce My Account, Account details.
	 *
	 * @param mixed $errors Errors to add to.
	 * @param mixed $user   Submitted user data.
	 */
	public static function guard_wc_change( mixed $errors, mixed $user = null ): void {
		$new = is_object( $user ) && isset( $user->user_email ) && is_string( $user->user_email ) ? $user->user_email : '';
		$id  = is_object( $user ) && isset( $user->ID ) ? (int) $user->ID : 0;
		if ( $errors instanceof \WP_Error && self::change_needs_stepup( $id, $new ) ) {
			$errors->add( 'mdmfa_stepup_required', esc_html( self::stepup_message() ) );
		}
	}

	/**
	 * Whether the current user is changing their own address without a fresh verification.
	 * An administrator editing someone else is not held to the other person's second step.
	 *
	 * @param int    $user_id User being edited.
	 * @param string $address Submitted address.
	 */
	private static function change_needs_stepup( int $user_id, string $address ): bool {
		$user = $user_id > 0 && get_current_user_id() === $user_id ? get_userdata( $user_id ) : false;

		return $user instanceof \WP_User && '' !== $address
			&& strtolower( $address ) !== strtolower( $user->user_email )
			&& Policy::is_enrolled( $user_id ) && ! StepUp::is_fresh( $user_id );
	}

	/**
	 * Message shown when the address change is refused.
	 */
	private static function stepup_message(): string {
		return __( 'To change your email address, first confirm it is you on your security page, then make the change within 10 minutes.', 'maxtdesign-mfa' );
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
