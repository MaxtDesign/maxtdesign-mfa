<?php
/**
 * Self-service operations on the current user's own factors, shared by Users > My
 * security and the WooCommerce My Account Security tab. Callers verify the nonce first.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Account;

use MaxtDesign\Mfa\Auth\StepUp;
use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Operations. Each returns a notice code, recovery codes to show once, and a view.
 *
 * @phpstan-type Result array{notice: string, codes: string[], view: string}
 */
final class SecurityActions {

	public const NONCE = 'mdmfa_account';

	/**
	 * Operation names a form may post.
	 */
	public const OPS = array( 'totp_begin', 'totp_confirm', 'totp_remove', 'recovery_generate', 'stepup' );

	/**
	 * Runs an operation for the user.
	 *
	 * @param string   $op     Operation.
	 * @param \WP_User $user   Current user (never another user).
	 * @param string   $code   Submitted code, if any.
	 * @param string   $method totp or recovery (step-up).
	 * @param string   $source account or wc, for the log.
	 * @return Result
	 */
	public static function run( string $op, \WP_User $user, string $code, string $method, string $source ): array {
		switch ( $op ) {
			case 'totp_begin':
				if ( TotpStore::has( $user->ID ) || ! Policy::allows( $user, 'totp' ) ) {
					return self::result( 'not_allowed' );
				}
				try {
					TotpStore::begin_pending( $user->ID );
				} catch ( InvalidKeyException $e ) {
					return self::result( 'key_invalid' );
				}
				return self::result( '', array(), 'totp' );

			case 'totp_confirm':
				$secret = TotpStore::pending( $user->ID );
				if ( null === $secret || TotpStore::has( $user->ID ) ) {
					return self::result( 'setup_expired' );
				}
				$step = Totp::match( $secret, Totp::normalize( $code ), Clock::now() );
				if ( null === $step ) {
					return self::result( 'code_invalid', array(), 'totp' );
				}
				try {
					TotpStore::save( $user->ID, $secret, $step );
				} catch ( InvalidKeyException $e ) {
					return self::result( 'key_invalid' );
				}
				update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
				// The user just proved the factor: stamp this session as verified (it then
				// also survives core's cookie re-issue on a password change).
				StepUp::mark( $user->ID, 'totp' );
				Logger::log( 'enrolled', $user->ID, 'totp', $source, $user->ID );
				do_action( 'mdmfa_enrolled', $user, 'totp' );
				if ( 0 === RecoveryCodes::remaining( $user->ID ) ) {
					return self::result( 'totp_on', RecoveryCodes::generate( $user->ID ) );
				}
				return self::result( 'totp_on' );

			case 'totp_remove':
				if ( ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				TotpStore::remove( $user->ID );
				if ( ! Policy::is_enrolled( $user->ID ) ) {
					delete_user_meta( $user->ID, 'mdmfa_enrolled' );
					RecoveryCodes::remove( $user->ID );
				}
				Logger::log( 'factor_removed', $user->ID, 'totp', $source, $user->ID );
				do_action( 'mdmfa_factor_removed', $user, 'totp', $user->ID );
				return self::result( 'totp_off' );

			case 'recovery_generate':
				if ( ! Policy::is_enrolled( $user->ID ) ) {
					return self::result( 'not_allowed' );
				}
				if ( ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				Logger::log( 'recovery_regenerated', $user->ID, 'recovery', $source, $user->ID );
				return self::result( 'codes_new', RecoveryCodes::generate( $user->ID ) );

			case 'stepup':
				$outcome = StepUp::verify( $user->ID, 'recovery' === $method ? 'recovery' : 'totp', $code );
				return self::result( 'ok' === $outcome ? 'stepup_ok' : ( 'wait' === $outcome ? 'stepup_wait' : 'code_invalid' ) );
		}

		return self::result( '' );
	}

	/**
	 * Human-readable notices by code: [type, message].
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function notices(): array {
		return array(
			'totp_on'       => array( 'success', __( 'Two-step verification is on.', 'maxtdesign-mfa' ) ),
			'totp_off'      => array( 'success', __( 'Authenticator app removed.', 'maxtdesign-mfa' ) ),
			'codes_new'     => array( 'success', __( 'New recovery codes created. The old ones no longer work.', 'maxtdesign-mfa' ) ),
			'stepup_ok'     => array( 'success', __( 'Confirmed. You can make changes for the next 10 minutes.', 'maxtdesign-mfa' ) ),
			'stepup_needed' => array( 'error', __( 'Confirm it is you with a code first.', 'maxtdesign-mfa' ) ),
			'stepup_wait'   => array( 'error', __( 'Too many wrong codes. Wait a few minutes and try again.', 'maxtdesign-mfa' ) ),
			'code_invalid'  => array( 'error', __( 'That code is not valid.', 'maxtdesign-mfa' ) ),
			'setup_expired' => array( 'error', __( 'Setup expired. Start again.', 'maxtdesign-mfa' ) ),
			'not_allowed'   => array( 'error', __( 'That option is not available for your account.', 'maxtdesign-mfa' ) ),
			'key_invalid'   => array( 'error', __( 'The site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' ) ),
		);
	}

	/**
	 * Builds a result.
	 *
	 * @param string   $notice Notice code.
	 * @param string[] $codes  Recovery codes to show once.
	 * @param string   $view   View to return to.
	 * @return Result
	 */
	private static function result( string $notice, array $codes = array(), string $view = '' ): array {
		return array(
			'notice' => $notice,
			'codes'  => $codes,
			'view'   => $view,
		);
	}
}
