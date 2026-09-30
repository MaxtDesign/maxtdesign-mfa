<?php
/**
 * Second-step screens on wp-login.php (plan 4.3, core login path): verify, grace prompt,
 * enrollment. Custom login actions are admitted by core because a login_form_{action}
 * callback exists for them (wp-login.php). Rendered with core login_header() and
 * login_footer(): core styles only, zero plugin CSS or JavaScript.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Screens;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
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
 * Login-flow screens. Logged-out POSTs are bound to the pending record by FormToken, not
 * by WordPress nonces (plan 4.5).
 *
 * phpcs:disable WordPress.Security.NonceVerification.Missing -- logged-out forms are CSRF-bound with FormToken (HMAC over the pending record), checked before any state change.
 */
final class LoginScreens {

	private const STAGE_TOTP     = 'totp';
	private const STAGE_RECOVERY = 'recovery';

	/**
	 * Registers the login actions.
	 */
	public static function register(): void {
		add_action( 'login_form_' . ChallengeUrl::ACTION_VERIFY, array( self::class, 'verify' ) );
		add_action( 'login_form_' . ChallengeUrl::ACTION_ENROLL, array( self::class, 'enroll' ) );
	}

	/**
	 * The challenge for enrolled users.
	 */
	public static function verify(): void {
		list( $record, $user ) = self::load();

		$decision = Policy::decide( $user );
		if ( Policy::CHALLENGE !== $decision ) {
			self::route( $decision, $user, $record );
		}

		$method = self::method( $user );
		$errors = new \WP_Error();
		if ( self::is_post() ) {
			if ( ! FormToken::check( $_POST['mdmfa_form'] ?? null, $record->token_hash, 'verify' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please enter your code again.', 'maxtdesign-mfa' ) );
			} else {
				self::attempt( $record, $user, $method, $errors );
			}
		}

		self::render_verify( $record, $method, $errors );
	}

	/**
	 * Grace prompt, TOTP enrollment and the recovery-code acknowledgement.
	 */
	public static function enroll(): void {
		list( $record, $user ) = self::load();

		$stage    = $record->string( 'stage' );
		$decision = Policy::decide( $user );
		if ( self::STAGE_RECOVERY !== $stage && Policy::CHALLENGE === $decision ) {
			self::route( $decision, $user, $record );
		}
		if ( Policy::NONE === $decision ) {
			self::route( $decision, $user, $record );
		}

		if ( self::STAGE_RECOVERY === $stage ) {
			self::recovery_ack( $record, $user );
		}
		if ( Policy::GRACE === $decision && self::STAGE_TOTP !== $stage ) {
			self::grace_prompt( $record, $user );
		}
		self::totp_enrollment( $record, $user );
	}

	/**
	 * One verification attempt. Exits on success.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @param string        $method totp or recovery.
	 * @param \WP_Error     $errors Collects messages.
	 */
	private static function attempt( PendingRecord $record, \WP_User $user, string $method, \WP_Error $errors ): void {
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
			return;
		}
		if ( ! PendingStore::reserve_attempt( $record ) ) {
			self::burn( $record, $user );
		}

		$input     = isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '';
		$remaining = null;
		if ( 'recovery' === $method ) {
			$remaining = RecoveryCodes::consume( $user->ID, $input );
			$ok        = null !== $remaining;
		} else {
			$ok = TotpStore::verify( $user->ID, $input );
		}

		if ( $ok ) {
			do_action( 'mdmfa_factor_verified', $user, $method, $record->context() );
			if ( null !== $remaining ) {
				Logger::log( 'recovery_used', $user->ID, 'recovery', $record->context(), null, (string) $remaining );
				do_action( 'mdmfa_recovery_code_used', $user, $remaining );
			}
			if ( ! Completion::complete( $user, $method, $record ) ) {
				self::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
			}
			Completion::redirect( $user, $record );
		}

		Lockout::record_failure( $user->ID );
		Logger::log( 'challenge_fail', $user->ID, $method, $record->context() );
		do_action( 'mdmfa_factor_failed', $user, $method, 'invalid_code' );

		$left = PendingStore::MAX_ATTEMPTS - ( $record->attempts + 1 );
		if ( $left <= 0 ) {
			self::burn( $record, $user );
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
	}

	/**
	 * Renders the verification form and exits.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param string        $method totp or recovery.
	 * @param \WP_Error     $errors Messages.
	 * @return never
	 */
	private static function render_verify( PendingRecord $record, string $method, \WP_Error $errors ): void {
		self::prepare_page( $record );
		$recovery = 'recovery' === $method;
		$intro    = $recovery
			? __( 'Enter one of your recovery codes.', 'maxtdesign-mfa' )
			: __( 'Enter the 6-digit code from your authenticator app.', 'maxtdesign-mfa' );

		login_header( __( 'Two-step verification', 'maxtdesign-mfa' ), '<p class="message">' . esc_html( $intro ) . '</p>', $errors );
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_VERIFY, array( 'method' => $method ) ), 'verify', $record );
		echo Fragments::code_field( 'mdmfa_code', $recovery ? __( 'Recovery code', 'maxtdesign-mfa' ) : __( 'Authentication code', 'maxtdesign-mfa' ), $recovery ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		self::form_close( __( 'Verify', 'maxtdesign-mfa' ) );

		$other = $recovery
			? array( 'totp', __( 'Use your authenticator app', 'maxtdesign-mfa' ) )
			: array( 'recovery', __( 'Use a recovery code', 'maxtdesign-mfa' ) );
		printf(
			'<p id="nav"><a href="%1$s">%2$s</a> | <a href="%3$s">%4$s</a></p>',
			esc_url( ChallengeUrl::core( ChallengeUrl::ACTION_VERIFY, array( 'method' => $other[0] ) ) ),
			esc_html( $other[1] ),
			esc_url( wp_login_url() ),
			esc_html__( 'Start over', 'maxtdesign-mfa' )
		);
		login_footer();
		exit;
	}

	/**
	 * Required role, still in grace: set up now or skip.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @return never
	 */
	private static function grace_prompt( PendingRecord $record, \WP_User $user ): void {
		$errors = new \WP_Error();
		if ( self::is_post() ) {
			if ( ! FormToken::check( $_POST['mdmfa_form'] ?? null, $record->token_hash, 'grace' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please choose again.', 'maxtdesign-mfa' ) );
			} elseif ( isset( $_POST['mdmfa_skip'] ) ) {
				if ( ! Completion::complete( $user, null, $record ) ) {
					self::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
				}
				Completion::redirect( $user, $record );
			} else {
				PendingStore::update_payload( $record, array_merge( $record->payload, array( 'stage' => self::STAGE_TOTP ) ) );
				wp_safe_redirect( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ) );
				exit;
			}
		}

		$days = max( 1, (int) ceil( Policy::grace_remaining( $user ) / DAY_IN_SECONDS ) );
		self::prepare_page( $record );
		login_header(
			__( 'Set up two-step verification', 'maxtdesign-mfa' ),
			'<p class="message">' . esc_html(
				sprintf(
					/* translators: %d: days left to set up two-step verification. */
					_n( 'Your account needs two-step verification. You have %d day left to set it up.', 'Your account needs two-step verification. You have %d days left to set it up.', $days, 'maxtdesign-mfa' ),
					$days
				)
			) . '</p>',
			$errors
		);
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), 'grace', $record );
		echo '<p>' . esc_html__( 'It takes about a minute with an authenticator app on your phone.', 'maxtdesign-mfa' ) . '</p>';
		printf(
			'<p class="submit"><input type="submit" name="mdmfa_enroll" class="button button-primary button-large" value="%1$s"> <input type="submit" name="mdmfa_skip" class="button button-large" value="%2$s"></p></form>',
			esc_attr__( 'Set up now', 'maxtdesign-mfa' ),
			esc_attr__( 'Skip for now', 'maxtdesign-mfa' )
		);
		login_footer();
		exit;
	}

	/**
	 * Authenticator enrollment inside the pending login.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @return never
	 */
	private static function totp_enrollment( PendingRecord $record, \WP_User $user ): void {
		if ( ! Policy::allows( $user, 'totp' ) ) {
			self::expired( __( 'Your account needs two-step verification, but no setup method is available for it. Please contact the site administrator.', 'maxtdesign-mfa' ) );
		}

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
			self::expired( __( 'Two-step verification cannot be set up because the site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' ) );
		}

		$errors = new \WP_Error();
		if ( self::is_post() ) {
			if ( ! FormToken::check( $_POST['mdmfa_form'] ?? null, $record->token_hash, 'enroll-totp' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please enter the code again.', 'maxtdesign-mfa' ) );
			} else {
				if ( ! PendingStore::reserve_attempt( $record ) ) {
					self::burn( $record, $user );
				}
				$input = isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '';
				$step  = Totp::match( $secret, Totp::normalize( $input ), Clock::now() );
				if ( null !== $step ) {
					self::finish_enrollment( $record, $user, $secret, $step );
				}
				Logger::log( 'enroll_fail', $user->ID, 'totp', $record->context() );
				$left = PendingStore::MAX_ATTEMPTS - ( $record->attempts + 1 );
				if ( $left <= 0 ) {
					self::burn( $record, $user );
				}
				$errors->add( 'mdmfa_invalid', esc_html__( 'That code did not match. Check the time on your phone and try the newest code.', 'maxtdesign-mfa' ) );
			}
		}

		self::prepare_page( $record );
		login_header( __( 'Set up two-step verification', 'maxtdesign-mfa' ), '', $errors );
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), 'enroll-totp', $record );
		echo Fragments::totp_setup( $secret, $user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally.
		echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		self::form_close( __( 'Confirm', 'maxtdesign-mfa' ) );
		printf( '<p id="nav"><a href="%1$s">%2$s</a></p>', esc_url( wp_login_url() ), esc_html__( 'Start over', 'maxtdesign-mfa' ) );
		login_footer();
		exit;
	}

	/**
	 * Saves the confirmed secret, issues recovery codes and shows them once.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @param string        $secret Raw secret.
	 * @param int           $step   Step used to confirm (cannot be replayed).
	 * @return never
	 */
	private static function finish_enrollment( PendingRecord $record, \WP_User $user, string $secret, int $step ): void {
		try {
			TotpStore::save( $user->ID, $secret, $step );
		} catch ( InvalidKeyException $e ) {
			self::expired( __( 'Two-step verification cannot be set up because the site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' ) );
		}
		$codes   = RecoveryCodes::generate( $user->ID );
		$payload = $record->payload;
		unset( $payload['enroll_secret'] );
		$payload['stage'] = self::STAGE_RECOVERY;
		$record           = PendingStore::update_payload( $record, $payload );

		update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
		Logger::log( 'enrolled', $user->ID, 'totp', $record->context() );
		do_action( 'mdmfa_enrolled', $user, 'totp' );

		self::render_recovery_ack( $record, $codes, new \WP_Error() );
	}

	/**
	 * The acknowledgement step after enrollment. Completing here stamps the session as
	 * verified with TOTP: the user just proved the authenticator works.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @return never
	 */
	private static function recovery_ack( PendingRecord $record, \WP_User $user ): void {
		$errors = new \WP_Error();
		if ( self::is_post() ) {
			if ( ! FormToken::check( $_POST['mdmfa_form'] ?? null, $record->token_hash, 'enroll-ack' ) ) {
				$errors->add( 'mdmfa_form', esc_html__( 'This form expired. Please confirm again.', 'maxtdesign-mfa' ) );
			} elseif ( empty( $_POST['mdmfa_saved'] ) ) {
				$errors->add( 'mdmfa_saved', esc_html__( 'Please confirm that you saved your recovery codes.', 'maxtdesign-mfa' ) );
			} else {
				if ( ! Completion::complete( $user, 'totp', $record ) ) {
					self::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
				}
				Completion::redirect( $user, $record );
			}
		}

		self::render_recovery_ack( $record, array(), $errors );
	}

	/**
	 * Recovery codes (on the first render only) plus the confirmation form.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param string[]      $codes  Codes to show, or none after the first render.
	 * @param \WP_Error     $errors Messages.
	 * @return never
	 */
	private static function render_recovery_ack( PendingRecord $record, array $codes, \WP_Error $errors ): void {
		self::prepare_page( $record );
		login_header( __( 'Recovery codes', 'maxtdesign-mfa' ), '<p class="message">' . esc_html__( 'Two-step verification is on.', 'maxtdesign-mfa' ) . '</p>', $errors );
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), 'enroll-ack', $record );
		if ( array() !== $codes ) {
			echo Fragments::recovery_codes( $codes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		} else {
			echo '<p>' . esc_html__( 'Your recovery codes were shown once. If you did not save them, create new ones under Users, My security after you sign in.', 'maxtdesign-mfa' ) . '</p>';
		}
		printf(
			'<p><label><input type="checkbox" name="mdmfa_saved" value="1" required> %s</label></p>',
			esc_html__( 'I have saved my recovery codes', 'maxtdesign-mfa' )
		);
		self::form_close( __( 'Continue', 'maxtdesign-mfa' ) );
		login_footer();
		exit;
	}

	/**
	 * Sends a record whose decision changed to the right place.
	 *
	 * @param string        $decision Current decision.
	 * @param \WP_User      $user     User.
	 * @param PendingRecord $record   Pending record.
	 * @return never
	 */
	private static function route( string $decision, \WP_User $user, PendingRecord $record ): void {
		if ( Policy::NONE === $decision ) {
			// Policy relaxed (or MFA removed) since the password step: plain login, no stamp.
			if ( ! Completion::complete( $user, null, $record ) ) {
				self::expired( __( 'This sign-in was already completed or has expired. Please log in again.', 'maxtdesign-mfa' ) );
			}
			Completion::redirect( $user, $record );
		}
		$action = Policy::CHALLENGE === $decision ? ChallengeUrl::ACTION_VERIFY : ChallengeUrl::ACTION_ENROLL;
		wp_safe_redirect( ChallengeUrl::core( $action ) );
		exit;
	}

	/**
	 * Pending record and user from the cookie; renders "expired" and exits otherwise.
	 *
	 * @return array{0: PendingRecord, 1: \WP_User}
	 */
	private static function load(): array {
		$token  = PendingCookie::get();
		$record = null === $token ? null : PendingStore::find( $token );
		$user   = null === $record ? false : get_userdata( $record->user_id );
		if ( null === $record || ! $user instanceof \WP_User ) {
			self::expired( __( 'Your sign-in expired. Please log in again.', 'maxtdesign-mfa' ) );
		}

		return array( $record, $user );
	}

	/**
	 * Which factor the form asks for.
	 *
	 * @param \WP_User $user User.
	 */
	private static function method( \WP_User $user ): string {
		$requested = isset( $_GET['method'] ) ? sanitize_key( wp_unslash( $_GET['method'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display choice only.
		if ( 'recovery' === $requested || null === TotpStore::secret( $user->ID ) ) {
			return 'recovery';
		}

		return 'totp';
	}

	/**
	 * Burns a record after too many attempts and exits.
	 *
	 * @param PendingRecord $record Pending record.
	 * @param \WP_User      $user   User.
	 * @return never
	 */
	private static function burn( PendingRecord $record, \WP_User $user ): void {
		PendingStore::delete( $record );
		Logger::log( 'pending_burned', $user->ID, '', $record->context() );
		self::expired( __( 'Too many wrong codes. For your security, please log in again.', 'maxtdesign-mfa' ) );
	}

	/**
	 * Renders a dead-end message with a link back to the login form, and exits.
	 *
	 * @param string $message Plain-text message.
	 * @return never
	 */
	private static function expired( string $message ): void {
		PendingCookie::clear();
		self::prepare_page( null );
		login_header( __( 'Two-step verification', 'maxtdesign-mfa' ), '', new \WP_Error( 'mdmfa_expired', esc_html( $message ) ) );
		printf( '<p id="nav"><a href="%1$s">%2$s</a></p>', esc_url( wp_login_url() ), esc_html__( 'Log in', 'maxtdesign-mfa' ) );
		login_footer();
		exit;
	}

	/**
	 * Headers for every screen, and the interim-login global (wp-login.php only sets it
	 * after login_form_{action} has fired).
	 *
	 * @param PendingRecord|null $record Pending record.
	 */
	private static function prepare_page( ?PendingRecord $record ): void {
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Referrer-Policy: same-origin' );
			header( 'X-Robots-Tag: noindex, nofollow' );
		}
		if ( null !== $record && $record->flag( 'interim' ) ) {
			$GLOBALS['interim_login'] = true; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own global; login_header() reads it.
		}
	}

	/**
	 * Opens a login form bound to the record.
	 *
	 * @param string        $action  Form action URL.
	 * @param string        $purpose FormToken purpose.
	 * @param PendingRecord $record  Pending record.
	 */
	private static function form_open( string $action, string $purpose, PendingRecord $record ): void {
		printf(
			'<form name="mdmfaform" id="loginform" action="%1$s" method="post"><input type="hidden" name="mdmfa_form" value="%2$s">',
			esc_url( $action ),
			esc_attr( FormToken::make( $record->token_hash, $purpose ) )
		);
	}

	/**
	 * Submit button and form end.
	 *
	 * @param string $label Button label.
	 */
	private static function form_close( string $label ): void {
		printf( '<p class="submit"><input type="submit" class="button button-primary button-large" value="%s"></p></form>', esc_attr( $label ) );
	}

	/**
	 * Whether this is a form submission.
	 */
	private static function is_post(): bool {
		return isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
	}
}
