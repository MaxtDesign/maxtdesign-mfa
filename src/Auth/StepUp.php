<?php
/**
 * Step-up (plan 4.3): sensitive actions need a factor verified on this session within the
 * last 10 minutes, read from the session's mdmfa stamp.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Session freshness and re-verification.
 */
final class StepUp {

	public const WINDOW = 600;

	/**
	 * Whether the current session verified a factor within WINDOW seconds.
	 *
	 * @param int $user_id User ID (must be the current user).
	 */
	public static function is_fresh( int $user_id ): bool {
		$session = self::session( $user_id );
		$stamp   = is_array( $session ) && isset( $session['mdmfa'] ) && is_array( $session['mdmfa'] ) ? $session['mdmfa'] : array();
		$at      = isset( $stamp['verified_at'] ) ? (int) $stamp['verified_at'] : 0;

		return $at > 0 && $at >= Clock::now() - self::WINDOW;
	}

	/**
	 * Stamps the current session as verified now.
	 *
	 * @param int    $user_id User ID (must be the current user).
	 * @param string $factor  Factor that passed.
	 */
	public static function mark( int $user_id, string $factor ): void {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( ! is_array( $session ) ) {
			return;
		}
		$session['mdmfa'] = array(
			'verified_at' => Clock::now(),
			'factor'      => $factor,
		);
		$manager->update( $token, $session );
	}

	/**
	 * Verifies a factor for step-up, with the same lockout as the login challenge.
	 *
	 * @param int    $user_id User ID.
	 * @param string $method  totp, recovery or passkey.
	 * @param string $code    Submitted code, or the credential JSON for a passkey.
	 * @return string 'ok', 'wait' or 'invalid'.
	 */
	public static function verify( int $user_id, string $method, string $code ): string {
		if ( Lockout::blocked_until( $user_id ) > 0 ) {
			return 'wait';
		}
		if ( 'passkey' === $method ) {
			$user      = get_userdata( $user_id );
			$challenge = Passkeys::take_session_challenge( $user_id, 'stepup' );
			$ok        = $user instanceof \WP_User && null !== $challenge && Passkeys::verify_for_user( $user, $code, $challenge, false );
		} elseif ( 'recovery' === $method ) {
			$ok = null !== RecoveryCodes::consume( $user_id, $code );
		} else {
			$ok = TotpStore::verify( $user_id, $code );
		}

		if ( ! $ok ) {
			Lockout::record_failure( $user_id );
			Logger::log( 'stepup_fail', $user_id, $method, 'admin' );

			return 'invalid';
		}
		Lockout::reset( $user_id );
		self::mark( $user_id, $method );
		Logger::log( 'stepup_ok', $user_id, $method, 'admin' );

		return 'ok';
	}

	/**
	 * The current session's data.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, mixed>|null
	 */
	private static function session( int $user_id ): ?array {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return null;
		}
		$session = \WP_Session_Tokens::get_instance( $user_id )->get( $token );

		return is_array( $session ) ? $session : null;
	}
}
