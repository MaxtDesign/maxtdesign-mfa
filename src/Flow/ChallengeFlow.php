<?php
/**
 * The second-step state machine (plan 4.1-4.5), shared by every place a user can finish a
 * login: the core login screen and WooCommerce My Account. It decides the screen,
 * verifies codes, enforces the attempt cap and lockout, and completes the login. It never
 * prints and never redirects: presenters do that from the returned FlowState.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Flow;

use MaxtDesign\Mfa\Auth\Completion;
use MaxtDesign\Mfa\Auth\FormToken;
use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\PendingCookie;
use MaxtDesign\Mfa\Auth\PendingRecord;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Challenge, grace, enrollment and acknowledgement.
 *
 * @phpstan-type Input array{post: bool, token: mixed, code: string, skip: bool, saved: bool, method: string}
 */
final class ChallengeFlow {

	private const STAGE_TOTP     = 'totp';
	private const STAGE_RECOVERY = 'recovery';

	/**
	 * Request input, read once and sanitized. Logged-out forms are CSRF-bound by FormToken,
	 * which each handler checks before any state change.
	 *
	 * @return Input
	 */
	public static function input(): array {
		// phpcs:disable WordPress.Security.NonceVerification -- FormToken (HMAC over the pending record) is verified by the handler before any state change.
		$method = '';
		foreach ( array( 'mdmfa_method', 'method' ) as $key ) {
			if ( '' === $method && isset( $_REQUEST[ $key ] ) && is_string( $_REQUEST[ $key ] ) ) {
				$method = sanitize_key( wp_unslash( $_REQUEST[ $key ] ) );
			}
		}
		$input = array(
			'post'   => isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ),
			'token'  => isset( $_POST['mdmfa_form'] ) && is_string( $_POST['mdmfa_form'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_form'] ) ) : null,
			'code'   => isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '',
			'skip'   => isset( $_POST['mdmfa_skip'] ),
			'saved'  => ! empty( $_POST['mdmfa_saved'] ),
			'method' => $method,
		);
		// phpcs:enable

		return $input;
	}

	/**
	 * Runs the flow for the pending login in the request cookie.
	 *
	 * @param array<string, mixed> $input Request input.
	 * @phpstan-param Input $input
	 */
	public static function run( array $input ): FlowState {
		$token  = PendingCookie::get();
		$record = null === $token ? null : PendingStore::find( $token );
		$user   = null === $record ? false : get_userdata( $record->user_id );
		if ( null === $record || ! $user instanceof \WP_User ) {
			return FlowState::expired( __( 'Your sign-in expired. Please log in again.', 'maxtdesign-mfa' ) );
		}

		$stage    = $record->string( 'stage' );
		$decision = Policy::decide( $user );

		if ( Policy::NONE === $decision && self::STAGE_RECOVERY !== $stage ) {
			// Policy relaxed (or MFA removed) since the password step: plain login, no stamp.
			return self::complete( $user, null, $record );
		}
		if ( self::STAGE_RECOVERY === $stage ) {
			return self::recovery_ack( $record, $user, $input );
		}
		if ( Policy::CHALLENGE === $decision ) {
			return self::verify( $record, $user, $input );
		}
		if ( Policy::GRACE === $decision && self::STAGE_TOTP !== $stage ) {
			return self::grace( $record, $user, $input );
		}

		return self::enroll( $record, $user, $input );
	}

	/**
	 * Cancels the pending login ("start over") when the link carries the right token.
	 *
	 * @param mixed $given Token from the link.
	 */
	public static function cancel( mixed $given ): bool {
		$token  = PendingCookie::get();
		$record = null === $token ? null : PendingStore::find( $token );
		if ( null === $record || ! FormToken::check( $given, $record->token_hash, 'cancel' ) ) {
			return false;
		}
		PendingStore::delete( $record );
		PendingCookie::clear();

		return true;
	}

	/**
	 * The challenge for enrolled users.
	 *
	 * @param PendingRecord        $record Pending record.
	 * @param \WP_User             $user   User.
	 * @param array<string, mixed> $input Request input.
	 * @phpstan-param Input $input
	 */
	private static function verify( PendingRecord $record, \WP_User $user, array $input ): FlowState {
		$method = ( 'recovery' === $input['method'] || null === TotpStore::secret( $user->ID ) ) ? 'recovery' : 'totp';
		$errors = new \WP_Error();
		$state  = static fn (): FlowState => new FlowState( FlowState::VERIFY, $record, $user, $errors, $method );

		if ( ! $input['post'] ) {
			return $state();
		}
		if ( ! FormToken::check( $input['token'], $record->token_hash, 'verify' ) ) {
			$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please enter your code again.', 'maxtdesign-mfa' ) );
			return $state();
		}
		$until = Lockout::blocked_until( $user->ID );
		if ( $until > 0 ) {
			$errors->add(
				'mdmfa_wait',
				esc_html(
					sprintf(
						/* translators: %s: human-readable time, for example "5 mins". */
						__( 'Too many wrong codes. Try again in %s.', 'maxtdesign-mfa' ),
						human_time_diff( Clock::now(), $until )
					)
				)
			);
			return $state();
		}
		if ( ! PendingStore::reserve_attempt( $record ) ) {
			return self::burn( $record, $user );
		}

		$remaining = null;
		if ( 'recovery' === $method ) {
			$remaining = RecoveryCodes::consume( $user->ID, $input['code'] );
			$ok        = null !== $remaining;
		} else {
			$ok = TotpStore::verify( $user->ID, $input['code'] );
		}

		if ( $ok ) {
			do_action( 'mdmfa_factor_verified', $user, $method, $record->context() );
			if ( null !== $remaining ) {
				Logger::log( 'recovery_used', $user->ID, 'recovery', $record->context(), null, (string) $remaining );
				do_action( 'mdmfa_recovery_code_used', $user, $remaining );
			}
			return self::complete( $user, $method, $record );
		}

		Lockout::record_failure( $user->ID );
		Logger::log( 'challenge_fail', $user->ID, $method, $record->context() );
		do_action( 'mdmfa_factor_failed', $user, $method, 'invalid_code' );

		$left = PendingStore::MAX_ATTEMPTS - ( $record->attempts + 1 );
		if ( $left <= 0 ) {
			return self::burn( $record, $user );
		}
		$errors->add(
			'mdmfa_invalid',
			esc_html(
				sprintf(
					/* translators: %d: attempts left before the sign-in must restart. */
					_n( 'That code is not valid. %d attempt left.', 'That code is not valid. %d attempts left.', $left, 'maxtdesign-mfa' ),
					$left
				)
			)
		);

		return $state();
	}

	/**
	 * Required role in grace: set up now, or skip this time.
	 *
	 * @param PendingRecord        $record Pending record.
	 * @param \WP_User             $user   User.
	 * @param array<string, mixed> $input Request input.
	 * @phpstan-param Input $input
	 */
	private static function grace( PendingRecord $record, \WP_User $user, array $input ): FlowState {
		$errors = new \WP_Error();
		if ( $input['post'] ) {
			if ( ! FormToken::check( $input['token'], $record->token_hash, 'grace' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please choose again.', 'maxtdesign-mfa' ) );
			} elseif ( $input['skip'] ) {
				return self::complete( $user, null, $record );
			} else {
				$record = PendingStore::update_payload( $record, array_merge( $record->payload, array( 'stage' => self::STAGE_TOTP ) ) );
				return self::enroll( $record, $user, array_merge( $input, array( 'post' => false ) ) );
			}
		}
		$days = max( 1, (int) ceil( Policy::grace_remaining( $user ) / DAY_IN_SECONDS ) );

		return new FlowState( FlowState::GRACE, $record, $user, $errors, 'totp', null, array(), '', $days );
	}

	/**
	 * Authenticator setup inside the pending login.
	 *
	 * @param PendingRecord        $record Pending record.
	 * @param \WP_User             $user   User.
	 * @param array<string, mixed> $input Request input.
	 * @phpstan-param Input $input
	 */
	private static function enroll( PendingRecord $record, \WP_User $user, array $input ): FlowState {
		if ( ! Policy::allows( $user, 'totp' ) ) {
			return FlowState::expired( __( 'Your account needs two-step verification, but no setup method is available for it. Please contact the site administrator.', 'maxtdesign-mfa' ) );
		}
		$key_error = __( 'Two-step verification cannot be set up because the site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' );

		try {
			$sealed = isset( $record->payload['enroll_secret'] ) && is_array( $record->payload['enroll_secret'] ) ? $record->payload['enroll_secret'] : null;
			$secret = null !== $sealed ? TotpStore::open_for_login( $user->ID, $sealed ) : null;
			if ( null === $secret ) {
				$secret = Totp::generate_secret();
				$record = PendingStore::update_payload(
					$record,
					array_merge(
						$record->payload,
						array(
							'stage'         => self::STAGE_TOTP,
							'enroll_secret' => TotpStore::seal_for_login( $user->ID, $secret ),
						)
					)
				);
			}
		} catch ( InvalidKeyException $e ) {
			return FlowState::expired( $key_error );
		}

		$errors = new \WP_Error();
		if ( $input['post'] ) {
			if ( ! FormToken::check( $input['token'], $record->token_hash, 'enroll-totp' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please enter the code again.', 'maxtdesign-mfa' ) );
			} else {
				if ( ! PendingStore::reserve_attempt( $record ) ) {
					return self::burn( $record, $user );
				}
				$step = Totp::match( $secret, Totp::normalize( $input['code'] ), Clock::now() );
				if ( null !== $step ) {
					try {
						TotpStore::save( $user->ID, $secret, $step );
					} catch ( InvalidKeyException $e ) {
						return FlowState::expired( $key_error );
					}
					return self::finish_enrollment( $record, $user );
				}
				Logger::log( 'enroll_fail', $user->ID, 'totp', $record->context() );
				if ( PendingStore::MAX_ATTEMPTS - ( $record->attempts + 1 ) <= 0 ) {
					return self::burn( $record, $user );
				}
				$errors->add( 'mdmfa_invalid', esc_html__( 'That code did not match. Check the time on your phone and try the newest code.', 'maxtdesign-mfa' ) );
			}
		}

		return new FlowState( FlowState::ENROLL, $record, $user, $errors, 'totp', $secret );
	}

	/**
	 * Issues recovery codes after a confirmed setup; they are shown once.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 */
	private static function finish_enrollment( PendingRecord $record, \WP_User $user ): FlowState {
		$codes   = RecoveryCodes::generate( $user->ID );
		$payload = $record->payload;
		unset( $payload['enroll_secret'] );
		$payload['stage'] = self::STAGE_RECOVERY;
		$record           = PendingStore::update_payload( $record, $payload );

		update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
		Logger::log( 'enrolled', $user->ID, 'totp', $record->context() );
		do_action( 'mdmfa_enrolled', $user, 'totp' );

		return new FlowState( FlowState::RECOVERY, $record, $user, new \WP_Error(), 'totp', null, $codes );
	}

	/**
	 * Confirming the codes were saved finishes the login, stamped as TOTP-verified: the
	 * user just proved the authenticator works.
	 *
	 * @param PendingRecord        $record Pending record.
	 * @param \WP_User             $user   User.
	 * @param array<string, mixed> $input Request input.
	 * @phpstan-param Input $input
	 */
	private static function recovery_ack( PendingRecord $record, \WP_User $user, array $input ): FlowState {
		$errors = new \WP_Error();
		if ( $input['post'] ) {
			if ( ! FormToken::check( $input['token'], $record->token_hash, 'enroll-ack' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please confirm again.', 'maxtdesign-mfa' ) );
			} elseif ( ! $input['saved'] ) {
				$errors->add( 'mdmfa_saved', esc_html__( 'Please confirm that you saved your recovery codes.', 'maxtdesign-mfa' ) );
			} else {
				return self::complete( $user, 'totp', $record );
			}
		}

		return new FlowState( FlowState::RECOVERY, $record, $user, $errors );
	}

	/**
	 * Completes the login, or reports that a concurrent request already did.
	 *
	 * @param \WP_User      $user   User.
	 * @param string|null   $factor Factor, or null for a skip.
	 * @param PendingRecord $record Pending record.
	 */
	private static function complete( \WP_User $user, ?string $factor, PendingRecord $record ): FlowState {
		if ( ! Completion::complete( $user, $factor, $record ) ) {
			return FlowState::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
		}

		return new FlowState( FlowState::DONE, $record, $user, new \WP_Error() );
	}

	/**
	 * Burns a record after too many attempts.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 */
	private static function burn( PendingRecord $record, \WP_User $user ): FlowState {
		PendingStore::delete( $record );
		PendingCookie::clear();
		Logger::log( 'pending_burned', $user->ID, '', $record->context() );

		return FlowState::expired( __( 'Too many wrong codes. For your security, please log in again.', 'maxtdesign-mfa' ) );
	}
}
