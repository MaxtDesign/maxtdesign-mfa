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
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\Passkeys;
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
 * @phpstan-type Input array{post: bool, token: mixed, code: string, skip: bool, saved: bool, method: string, credential: string, name: string, send: bool, trust: bool, recover: bool}
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
			'post'       => isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ),
			'token'      => isset( $_POST['mdmfa_form'] ) && is_string( $_POST['mdmfa_form'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_form'] ) ) : null,
			'code'       => isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '',
			'skip'       => isset( $_POST['mdmfa_skip'] ),
			'saved'      => ! empty( $_POST['mdmfa_saved'] ),
			'method'     => $method,
			// Strict JSON, parsed and size-limited by CredentialJson before any use.
			'credential' => isset( $_POST['mdmfa_credential'] ) && is_string( $_POST['mdmfa_credential'] ) ? wp_unslash( $_POST['mdmfa_credential'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON from the passkey module; CredentialJson validates it strictly.
			'name'       => isset( $_POST['mdmfa_passkey_name'] ) && is_string( $_POST['mdmfa_passkey_name'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_passkey_name'] ) ) : '',
			'send'       => isset( $_POST['mdmfa_send'] ),
			'trust'      => ! empty( $_POST['mdmfa_trust'] ),
			'recover'    => isset( $_POST['mdmfa_recover'] ),
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
		$methods = self::methods( $user );
		$method  = in_array( $input['method'], $methods, true ) ? $input['method'] : ( $methods[0] ?? 'recovery' );
		$errors  = new \WP_Error();
		$purpose = self::email_purpose( $record );
		$state   = static function () use ( &$record, $user, &$errors, $method, $methods, $purpose ): FlowState {
			$options = array();
			if ( 'passkey' === $method ) {
				list( $record, $challenge ) = Passkeys::pending_challenge( $record, 'verify' );
				$options                    = Passkeys::request_options( $user, $challenge );
			}
			return new FlowState(
				FlowState::VERIFY,
				$record,
				$user,
				$errors,
				$method,
				null,
				array(),
				'',
				0,
				$options,
				$methods,
				'email' === $method && EmailCode::issued( $user->ID, $purpose ),
				TrustedDevice::allowed( $user ),
				EmailRecovery::allowed( $user )
			);
		};

		if ( ! $input['post'] ) {
			return $state();
		}
		if ( ! FormToken::check( $input['token'], $record->token_hash, 'verify' ) ) {
			$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please try again.', 'maxtdesign-mfa' ) );
			return $state();
		}
		// Asking for a recovery link is not a guess: it works during a lock, and is
		// capped by the send limits.
		if ( $input['recover'] ) {
			$errors->add(
				'mdmfa_recover',
				esc_html(
					EmailRecovery::request( $user, $record->context() )
						? __( 'We emailed you a link to reset two-step verification. It works for one hour.', 'maxtdesign-mfa' )
						: __( 'A recovery email cannot be sent right now. Try again later.', 'maxtdesign-mfa' )
				),
				'message'
			);
			return $state();
		}

		// One attempt at a time per user: the lock and backoff counters stay exact under
		// parallel requests.
		$result = Lockout::with_lock(
			$user->ID,
			static function () use ( &$record, $user, $input, $method, $purpose, $errors, $state ): FlowState {
				return self::attempt( $record, $user, $input, $method, $purpose, $errors, $state );
			}
		);
		if ( null === $result ) {
			$errors->add( 'mdmfa_busy', esc_html__( 'Another sign-in attempt for this account is in progress. Try again in a moment.', 'maxtdesign-mfa' ) );
			return $state();
		}

		return $result;
	}

	/**
	 * One verification attempt, run under the per-user lock.
	 *
	 * @param PendingRecord        $record  Pending record (replaced when its payload changes).
	 * @param \WP_User             $user    User.
	 * @param array<string, mixed> $input   Request input.
	 * @param string               $method  Chosen method.
	 * @param string               $purpose Email-code purpose of this pending login.
	 * @param \WP_Error            $errors  Messages for the screen.
	 * @param callable():FlowState $state   Builds the verify screen.
	 * @phpstan-param Input $input
	 */
	private static function attempt( PendingRecord &$record, \WP_User $user, array $input, string $method, string $purpose, \WP_Error $errors, callable $state ): FlowState {
		// The record as it is now: a request that waited for the lock may hold a copy
		// whose passkey challenge or attempt count another request already used.
		$current = PendingStore::find( (string) PendingCookie::get() );
		if ( null === $current || $current->user_id !== $user->ID ) {
			return FlowState::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
		}
		$record = $current;
		$until  = Lockout::blocked_until( $user->ID );
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
		// Sending a code takes no attempt and is capped by the send limits instead.
		if ( 'email' === $method && ( $input['send'] || '' === $input['code'] ) ) {
			$sent = EmailCode::send( $user, $purpose );
			if ( EmailCode::SENT === $sent ) {
				/* translators: %s: masked email address. */
				$errors->add( 'mdmfa_sent', esc_html( sprintf( __( 'We sent a code to %s.', 'maxtdesign-mfa' ), EmailCode::masked( $user->user_email ) ) ), 'message' );
			} else {
				$errors->add(
					'mdmfa_send',
					esc_html(
						EmailCode::LIMITED === $sent
							? __( 'Too many codes were sent. Wait a few minutes, or use another method.', 'maxtdesign-mfa' )
							: __( 'The email could not be sent. Use another method.', 'maxtdesign-mfa' )
					)
				);
			}
			return $state();
		}
		if ( ! PendingStore::reserve_attempt( $record ) ) {
			return self::burn( $record, $user );
		}
		$attempts_used = $record->attempts + 1;

		$remaining = null;
		if ( 'passkey' === $method ) {
			$challenge = Passkeys::take_pending_challenge( $record, 'verify' );
			$record    = PendingStore::find( (string) PendingCookie::get() ) ?? $record;
			$ok        = null !== $challenge && '' !== $input['credential'] && Passkeys::verify_for_user( $user, $input['credential'], $challenge, false );
		} elseif ( 'email' === $method ) {
			$ok = EmailCode::check( $user->ID, $purpose, $input['code'] );
		} elseif ( 'recovery' === $method ) {
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
			$done = self::complete( $user, $method, $record );
			if ( FlowState::DONE === $done->screen && $input['trust'] ) {
				TrustedDevice::remember( $user );
			}
			return $done;
		}

		Lockout::record_failure( $user->ID );
		Logger::log( 'challenge_fail', $user->ID, $method, $record->context() );
		do_action( 'mdmfa_factor_failed', $user, $method, 'passkey' === $method ? 'invalid_passkey' : 'invalid_code' );

		$left = PendingStore::MAX_ATTEMPTS - $attempts_used;
		if ( $left <= 0 ) {
			return self::burn( $record, $user );
		}
		$message = 'passkey' === $method
			/* translators: %d: attempts left before the sign-in must restart. */
			? _n( 'That passkey did not work. %d attempt left.', 'That passkey did not work. %d attempts left.', $left, 'maxtdesign-mfa' )
			/* translators: %d: attempts left before the sign-in must restart. */
			: _n( 'That code is not valid. %d attempt left.', 'That code is not valid. %d attempts left.', $left, 'maxtdesign-mfa' );
		$errors->add( 'mdmfa_invalid', esc_html( sprintf( $message, $left ) ) );

		return $state();
	}

	/**
	 * Verification methods the user can use, strongest first: passkey (phishing-resistant),
	 * authenticator app, emailed code, recovery code.
	 *
	 * @param \WP_User $user User.
	 * @return string[]
	 */
	private static function methods( \WP_User $user ): array {
		$methods = array();
		if ( Passkeys::has( $user->ID ) ) {
			$methods[] = 'passkey';
		}
		if ( null !== TotpStore::secret( $user->ID ) ) {
			$methods[] = 'totp';
		}
		if ( EmailCode::has( $user->ID ) ) {
			$methods[] = 'email';
		}
		if ( RecoveryCodes::remaining( $user->ID ) > 0 || array() === $methods ) {
			$methods[] = 'recovery';
		}

		return $methods;
	}

	/**
	 * Email-code purpose of a pending login: a code issued for one login cannot finish
	 * another.
	 *
	 * @param PendingRecord $record Pending record.
	 */
	private static function email_purpose( PendingRecord $record ): string {
		return 'login:' . substr( $record->token_hash, 0, 16 );
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
		$totp    = Policy::allows( $user, 'totp' );
		$passkey = Passkeys::allowed( $user );
		if ( ! $totp && ! $passkey ) {
			return FlowState::expired( __( 'Your account needs two-step verification, but no setup method is available for it. Please contact the site administrator.', 'maxtdesign-mfa' ) );
		}
		$key_error = __( 'Two-step verification cannot be set up because the site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' );

		$secret = null;
		if ( $totp ) {
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
				if ( ! $passkey ) {
					return FlowState::expired( $key_error );
				}
				$secret = null;
			}
		}

		$errors = new \WP_Error();
		if ( $input['post'] ) {
			$is_passkey = '' !== $input['credential'];
			$purpose    = $is_passkey ? 'enroll-passkey' : 'enroll-totp';
			if ( ! FormToken::check( $input['token'], $record->token_hash, $purpose ) || ( $is_passkey && ! $passkey ) || ( ! $is_passkey && null === $secret ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please try again.', 'maxtdesign-mfa' ) );
			} else {
				if ( ! PendingStore::reserve_attempt( $record ) ) {
					return self::burn( $record, $user );
				}
				$attempts_used = $record->attempts + 1;
				if ( $is_passkey ) {
					$challenge = Passkeys::take_pending_challenge( $record, 'enroll' );
					$record    = PendingStore::find( (string) PendingCookie::get() ) ?? $record;
					$result    = null === $challenge ? null : Passkeys::register( $user, $input['credential'], $challenge, $input['name'] );
					if ( null !== $result && ! $result instanceof \WP_Error ) {
						return self::finish_enrollment( $record, $user, 'passkey' );
					}
					$errors->add( 'mdmfa_invalid', esc_html( $result instanceof \WP_Error ? $result->get_error_message() : __( 'That passkey could not be set up. Please try again.', 'maxtdesign-mfa' ) ) );
				} else {
					$step = Totp::match( (string) $secret, Totp::normalize( $input['code'] ), Clock::now() );
					if ( null !== $step ) {
						try {
							TotpStore::save( $user->ID, (string) $secret, $step );
						} catch ( InvalidKeyException $e ) {
							return FlowState::expired( $key_error );
						}
						return self::finish_enrollment( $record, $user, 'totp' );
					}
					Logger::log( 'enroll_fail', $user->ID, 'totp', $record->context() );
					$errors->add( 'mdmfa_invalid', esc_html__( 'That code did not match. Check the time on your phone and try the newest code.', 'maxtdesign-mfa' ) );
				}
				if ( PendingStore::MAX_ATTEMPTS - $attempts_used <= 0 ) {
					return self::burn( $record, $user );
				}
			}
		}

		$options = array();
		if ( $passkey ) {
			list( $record, $challenge ) = Passkeys::pending_challenge( $record, 'enroll' );
			$options                    = Passkeys::creation_options( $user, $challenge );
		}

		return new FlowState( FlowState::ENROLL, $record, $user, $errors, 'totp', $secret, array(), '', 0, $options );
	}

	/**
	 * Issues recovery codes after a confirmed setup; they are shown once.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @param string        $factor Factor just enrolled.
	 */
	private static function finish_enrollment( PendingRecord $record, \WP_User $user, string $factor ): FlowState {
		$codes   = RecoveryCodes::generate( $user->ID );
		$payload = $record->payload;
		unset( $payload['enroll_secret'], $payload['wa'] );
		$payload['stage']           = self::STAGE_RECOVERY;
		$payload['enrolled_factor'] = $factor;
		$record                     = PendingStore::update_payload( $record, $payload );

		update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
		if ( 'totp' === $factor ) {
			// Passkeys::register() logs and fires mdmfa_enrolled for passkeys itself.
			Logger::log( 'enrolled', $user->ID, 'totp', $record->context() );
			do_action( 'mdmfa_enrolled', $user, 'totp' );
		}

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
				return self::complete( $user, '' !== $record->string( 'enrolled_factor' ) ? $record->string( 'enrolled_factor' ) : 'totp', $record );
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
