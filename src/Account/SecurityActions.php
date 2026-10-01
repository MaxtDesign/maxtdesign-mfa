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
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\Reset;
use MaxtDesign\Mfa\Factors\Passkeys;
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
 * @phpstan-type Input array{code: string, method: string, credential: string, name: string, id: int}
 */
final class SecurityActions {

	public const NONCE = 'mdmfa_account';

	/**
	 * Operation names a form may post.
	 */
	public const OPS = array( 'totp_begin', 'totp_confirm', 'totp_remove', 'recovery_generate', 'stepup', 'stepup_send', 'passkey_add', 'passkey_remove', 'email_begin', 'email_confirm', 'email_remove', 'trusted_forget' );

	/**
	 * Runs an operation for the user.
	 *
	 * @param string               $op     Operation.
	 * @param \WP_User             $user   Current user (never another user).
	 * @param array<string, mixed> $input  Posted values (see input()).
	 * @param string               $source account or wc, for the log.
	 * @phpstan-param Input $input
	 * @return Result
	 */
	public static function run( string $op, \WP_User $user, array $input, string $source ): array {
		$code   = $input['code'];
		$method = $input['method'];
		switch ( $op ) {
			case 'totp_begin':
				if ( TotpStore::has( $user->ID ) || ! Policy::allows( $user, 'totp' ) ) {
					return self::result( 'not_allowed' );
				}
				// Adding a second method to an enrolled account is as sensitive as removing one.
				if ( Policy::is_enrolled( $user->ID ) && ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
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
				// Another session of the same user must not finish a setup this one began.
				if ( Policy::is_enrolled( $user->ID ) && ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
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
				Reset::after_change( $user->ID );
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

			case 'stepup_send':
				if ( ! EmailCode::has( $user->ID ) ) {
					return self::result( 'not_allowed' );
				}
				return self::result( EmailCode::SENT === EmailCode::send( $user, 'stepup' ) ? 'email_sent' : 'email_limited' );

			case 'stepup':
				$chosen  = in_array( $method, array( 'recovery', 'passkey', 'email' ), true ) ? $method : 'totp';
				$outcome = StepUp::verify( $user->ID, $chosen, 'passkey' === $chosen ? $input['credential'] : $code );
				return self::result( 'ok' === $outcome ? 'stepup_ok' : ( 'wait' === $outcome ? 'stepup_wait' : 'code_invalid' ) );

			case 'passkey_add':
				if ( Policy::is_enrolled( $user->ID ) && ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				$challenge = Passkeys::take_session_challenge( $user->ID, 'add' );
				if ( null === $challenge ) {
					return self::result( 'setup_expired' );
				}
				$added = Passkeys::register( $user, $input['credential'], $challenge, $input['name'] );
				if ( $added instanceof \WP_Error ) {
					return self::result( 'passkey_invalid' );
				}
				StepUp::mark( $user->ID, 'passkey' );
				if ( 0 === RecoveryCodes::remaining( $user->ID ) ) {
					return self::result( 'passkey_on', RecoveryCodes::generate( $user->ID ) );
				}
				return self::result( 'passkey_on' );

			case 'passkey_remove':
				if ( ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				if ( ! PasskeyStore::delete( $user->ID, $input['id'] ) ) {
					return self::result( 'not_allowed' );
				}
				Reset::after_change( $user->ID );
				Logger::log( 'factor_removed', $user->ID, 'passkey', $source, $user->ID );
				do_action( 'mdmfa_factor_removed', $user, 'passkey', $user->ID );
				return self::result( 'passkey_off' );

			case 'email_begin':
				if ( EmailCode::has( $user->ID ) || ! EmailCode::allowed( $user ) ) {
					return self::result( 'not_allowed' );
				}
				if ( Policy::is_enrolled( $user->ID ) && ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				return EmailCode::SENT === EmailCode::send( $user, 'setup' ) ? self::result( 'email_sent', array(), 'email' ) : self::result( 'email_limited' );

			case 'email_confirm':
				if ( EmailCode::has( $user->ID ) || ! EmailCode::allowed( $user ) ) {
					return self::result( 'not_allowed' );
				}
				if ( ! EmailCode::issued( $user->ID, 'setup' ) ) {
					return self::result( 'setup_expired' );
				}
				if ( Policy::is_enrolled( $user->ID ) && ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				if ( ! EmailCode::check( $user->ID, 'setup', $code ) ) {
					return self::result( 'code_invalid', array(), 'email' );
				}
				EmailCode::enable( $user->ID );
				update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
				StepUp::mark( $user->ID, 'email' );
				Logger::log( 'enrolled', $user->ID, 'email', $source, $user->ID );
				do_action( 'mdmfa_enrolled', $user, 'email' );
				if ( 0 === RecoveryCodes::remaining( $user->ID ) ) {
					return self::result( 'email_on', RecoveryCodes::generate( $user->ID ) );
				}
				return self::result( 'email_on' );

			case 'email_remove':
				if ( ! StepUp::is_fresh( $user->ID ) ) {
					return self::result( 'stepup_needed' );
				}
				EmailCode::remove( $user->ID );
				Reset::after_change( $user->ID );
				Logger::log( 'factor_removed', $user->ID, 'email', $source, $user->ID );
				do_action( 'mdmfa_factor_removed', $user, 'email', $user->ID );
				return self::result( 'email_off' );

			case 'trusted_forget':
				// Forgetting devices only removes access, so it needs no step-up.
				TrustedDevice::revoke_all( $user->ID );
				Logger::log( 'trusted_revoked', $user->ID, '', $source, $user->ID );
				return self::result( 'trusted_off' );
		}

		return self::result( '' );
	}

	/**
	 * Posted values for an operation, read once and sanitized. Callers verify the nonce first.
	 *
	 * @return Input
	 */
	public static function input(): array {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- the caller verified the nonce.
		return array(
			'code'       => isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '',
			'method'     => isset( $_POST['mdmfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mdmfa_method'] ) ) : 'totp',
			'credential' => isset( $_POST['mdmfa_credential'] ) && is_string( $_POST['mdmfa_credential'] ) ? wp_unslash( $_POST['mdmfa_credential'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON; CredentialJson validates it strictly.
			'name'       => isset( $_POST['mdmfa_passkey_name'] ) && is_string( $_POST['mdmfa_passkey_name'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_passkey_name'] ) ) : '',
			'id'         => isset( $_POST['mdmfa_passkey_id'] ) ? absint( wp_unslash( $_POST['mdmfa_passkey_id'] ) ) : 0,
		);
		// phpcs:enable
	}

	/**
	 * Human-readable notices by code: [type, message].
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function notices(): array {
		return array(
			'totp_on'         => array( 'success', __( 'Two-step verification is on.', 'maxtdesign-mfa' ) ),
			'totp_off'        => array( 'success', __( 'Authenticator app removed.', 'maxtdesign-mfa' ) ),
			'passkey_on'      => array( 'success', __( 'Passkey added.', 'maxtdesign-mfa' ) ),
			'passkey_off'     => array( 'success', __( 'Passkey removed.', 'maxtdesign-mfa' ) ),
			'passkey_invalid' => array( 'error', __( 'That passkey could not be added. Please try again.', 'maxtdesign-mfa' ) ),
			'email_sent'      => array( 'success', __( 'We emailed you a code. It works for 10 minutes.', 'maxtdesign-mfa' ) ),
			'email_limited'   => array( 'error', __( 'The code could not be sent. Too many were sent recently; wait a few minutes.', 'maxtdesign-mfa' ) ),
			'email_on'        => array( 'success', __( 'Email codes are on.', 'maxtdesign-mfa' ) ),
			'email_off'       => array( 'success', __( 'Email codes are off.', 'maxtdesign-mfa' ) ),
			'trusted_off'     => array( 'success', __( 'Trusted devices forgotten. Every device will be asked for the second step again.', 'maxtdesign-mfa' ) ),
			'codes_new'       => array( 'success', __( 'New recovery codes created. The old ones no longer work.', 'maxtdesign-mfa' ) ),
			'stepup_ok'       => array( 'success', __( 'Confirmed. You can make changes for the next 10 minutes.', 'maxtdesign-mfa' ) ),
			'stepup_needed'   => array( 'error', __( 'Confirm it is you with a code first.', 'maxtdesign-mfa' ) ),
			'stepup_wait'     => array( 'error', __( 'Too many wrong codes. Wait a few minutes and try again.', 'maxtdesign-mfa' ) ),
			'code_invalid'    => array( 'error', __( 'That code is not valid.', 'maxtdesign-mfa' ) ),
			'setup_expired'   => array( 'error', __( 'Setup expired. Start again.', 'maxtdesign-mfa' ) ),
			'not_allowed'     => array( 'error', __( 'That option is not available for your account.', 'maxtdesign-mfa' ) ),
			'key_invalid'     => array( 'error', __( 'The site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' ) ),
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
