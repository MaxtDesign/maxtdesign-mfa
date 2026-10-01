<?php
/**
 * Second-step screens on wp-login.php (plan 4.3, core login path). Custom login actions
 * are admitted by core because a login_form_{action} callback exists for them
 * (wp-login.php). Rendered with core login_header() and login_footer(): core styles
 * only, zero plugin CSS or JavaScript. All decisions come from ChallengeFlow.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Screens;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Auth\Completion;
use MaxtDesign\Mfa\Auth\PendingCookie;
use MaxtDesign\Mfa\Flow\ChallengeFlow;
use MaxtDesign\Mfa\Flow\FlowState;

defined( 'ABSPATH' ) || exit;

/**
 * Core-login presenter.
 */
final class LoginScreens {

	/**
	 * Registers the login actions. Both run the same flow; the action only names the URL.
	 */
	public static function register(): void {
		add_action( 'login_form_' . ChallengeUrl::ACTION_VERIFY, array( self::class, 'handle' ) );
		add_action( 'login_form_' . ChallengeUrl::ACTION_ENROLL, array( self::class, 'handle' ) );
	}

	/**
	 * Runs the flow and renders the result, then exits.
	 */
	public static function handle(): void {
		$state = ChallengeFlow::run( ChallengeFlow::input() );

		if ( FlowState::DONE === $state->screen && null !== $state->user && null !== $state->record ) {
			Completion::redirect( $state->user, $state->record );
		}
		if ( FlowState::EXPIRED === $state->screen ) {
			self::expired( $state->message );
		}

		self::prepare_page( $state );
		switch ( $state->screen ) {
			case FlowState::VERIFY:
				self::render_verify( $state );
				break;
			case FlowState::GRACE:
				self::render_grace( $state );
				break;
			case FlowState::ENROLL:
				self::render_enroll( $state );
				break;
			default:
				self::render_recovery( $state );
		}
		login_footer();
		exit;
	}

	/**
	 * Verification: passkey, authenticator code or recovery code.
	 *
	 * @param FlowState $state Flow state.
	 */
	private static function render_verify( FlowState $state ): void {
		$intros = array(
			'passkey'  => __( 'Use your passkey to finish signing in.', 'maxtdesign-mfa' ),
			'recovery' => __( 'Enter one of your recovery codes.', 'maxtdesign-mfa' ),
			'email'    => __( 'Use a code we send to your email address.', 'maxtdesign-mfa' ),
			'totp'     => __( 'Enter the 6-digit code from your authenticator app.', 'maxtdesign-mfa' ),
		);
		login_header( __( 'Two-step verification', 'maxtdesign-mfa' ), '<p class="message">' . esc_html( $intros[ $state->method ] ?? $intros['totp'] ) . '</p>', $state->errors );
		$action = ChallengeUrl::core( ChallengeUrl::ACTION_VERIFY, array( 'method' => $state->method ) );
		self::form_open( $action, $state );
		if ( 'passkey' === $state->method ) {
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'get',
					'options' => $state->passkey,
					'field'   => 'mdmfa_credential',
				),
				__( 'Use your passkey', 'maxtdesign-mfa' ),
				'button button-primary button-large'
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo Fragments::trust_field( $state ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo '</form>';
		} elseif ( 'email' === $state->method && ! $state->email_sent ) {
			echo '<input type="hidden" name="mdmfa_send" value="1">';
			self::form_close( __( 'Email me a code', 'maxtdesign-mfa' ) );
		} else {
			$recovery = 'recovery' === $state->method;
			$label    = __( 'Authentication code', 'maxtdesign-mfa' );
			if ( $recovery ) {
				$label = __( 'Recovery code', 'maxtdesign-mfa' );
			} elseif ( 'email' === $state->method ) {
				$label = __( 'Code from the email', 'maxtdesign-mfa' );
			}
			echo Fragments::code_field( 'mdmfa_code', $label, $recovery ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo Fragments::trust_field( $state ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			self::form_close( __( 'Verify', 'maxtdesign-mfa' ) );
			if ( 'email' === $state->method ) {
				echo Fragments::mail_form( $action, $state, 'mdmfa_send', __( 'Send a new code', 'maxtdesign-mfa' ), 'button' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			}
		}
		if ( $state->can_recover ) {
			echo Fragments::mail_form( $action, $state, 'mdmfa_recover', __( 'Lost access? Reset by email', 'maxtdesign-mfa' ), 'button-link' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		}

		$links = array();
		foreach ( $state->methods as $method ) {
			if ( $method !== $state->method ) {
				$links[] = sprintf( '<a href="%1$s">%2$s</a>', esc_url( ChallengeUrl::core( ChallengeUrl::ACTION_VERIFY, array( 'method' => $method ) ) ), esc_html( self::method_label( $method ) ) );
			}
		}
		$links[] = sprintf( '<a href="%1$s">%2$s</a>', esc_url( wp_login_url() ), esc_html__( 'Start over', 'maxtdesign-mfa' ) );
		echo '<p id="nav">' . implode( ' | ', $links ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each link is escaped above.
	}

	/**
	 * Link text for switching to a method.
	 *
	 * @param string $method Method.
	 */
	public static function method_label( string $method ): string {
		switch ( $method ) {
			case 'passkey':
				return __( 'Use a passkey', 'maxtdesign-mfa' );
			case 'recovery':
				return __( 'Use a recovery code', 'maxtdesign-mfa' );
			case 'email':
				return __( 'Email me a code', 'maxtdesign-mfa' );
			default:
				return __( 'Use your authenticator app', 'maxtdesign-mfa' );
		}
	}

	/**
	 * Grace prompt.
	 *
	 * @param FlowState $state Flow state.
	 */
	private static function render_grace( FlowState $state ): void {
		login_header(
			__( 'Set up two-step verification', 'maxtdesign-mfa' ),
			'<p class="message">' . esc_html( Fragments::grace_message( $state->grace_days ) ) . '</p>',
			$state->errors
		);
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), $state );
		echo '<p>' . esc_html__( 'It takes about a minute with an authenticator app on your phone.', 'maxtdesign-mfa' ) . '</p>';
		printf(
			'<p class="submit"><input type="submit" name="mdmfa_enroll" class="button button-primary button-large" value="%1$s"> <input type="submit" name="mdmfa_skip" class="button button-large" value="%2$s"></p></form>',
			esc_attr__( 'Set up now', 'maxtdesign-mfa' ),
			esc_attr__( 'Skip for now', 'maxtdesign-mfa' )
		);
	}

	/**
	 * Authenticator setup.
	 *
	 * @param FlowState $state Flow state.
	 */
	private static function render_enroll( FlowState $state ): void {
		login_header( __( 'Set up two-step verification', 'maxtdesign-mfa' ), '', $state->errors );
		if ( array() !== $state->passkey ) {
			printf(
				'<form name="mdmfapasskey" action="%1$s" method="post"><input type="hidden" name="mdmfa_form" value="%2$s"><p><strong>%3$s</strong><br>%4$s</p>',
				esc_url( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ) ),
				esc_attr( $state->token_for( 'enroll-passkey' ) ),
				esc_html__( 'Use a passkey', 'maxtdesign-mfa' ),
				esc_html__( 'Sign in with your fingerprint, face or screen lock. Nothing to type.', 'maxtdesign-mfa' )
			);
			echo Fragments::passkey_name_field(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'create',
					'options' => $state->passkey,
					'field'   => 'mdmfa_credential',
				),
				__( 'Create a passkey', 'maxtdesign-mfa' ),
				'button button-primary button-large'
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo '</form>';
		}
		if ( null !== $state->secret && null !== $state->user ) {
			self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), $state );
			if ( array() !== $state->passkey ) {
				echo '<p><strong>' . esc_html__( 'Or use an authenticator app', 'maxtdesign-mfa' ) . '</strong></p>';
			}
			echo Fragments::totp_setup( $state->secret, $state->user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally.
			echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			self::form_close( __( 'Confirm', 'maxtdesign-mfa' ) );
		}
		printf( '<p id="nav"><a href="%1$s">%2$s</a></p>', esc_url( wp_login_url() ), esc_html__( 'Start over', 'maxtdesign-mfa' ) );
	}

	/**
	 * Recovery codes (first render only) and the confirmation.
	 *
	 * @param FlowState $state Flow state.
	 */
	private static function render_recovery( FlowState $state ): void {
		login_header( __( 'Recovery codes', 'maxtdesign-mfa' ), '<p class="message">' . esc_html__( 'Two-step verification is on.', 'maxtdesign-mfa' ) . '</p>', $state->errors );
		self::form_open( ChallengeUrl::core( ChallengeUrl::ACTION_ENROLL ), $state );
		echo Fragments::recovery_block( $state->codes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		self::form_close( __( 'Continue', 'maxtdesign-mfa' ) );
	}

	/**
	 * Dead end with a link back to the login form, and exits.
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
	 * Headers for every screen, and the interim-login global (wp-login.php sets it only
	 * after login_form_{action} has fired).
	 *
	 * @param FlowState|null $state Flow state.
	 */
	private static function prepare_page( ?FlowState $state ): void {
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Referrer-Policy: same-origin' );
			header( 'X-Robots-Tag: noindex, nofollow' );
		}
		if ( null !== $state && null !== $state->record && $state->record->flag( 'interim' ) ) {
			$GLOBALS['interim_login'] = true; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own global; login_header() reads it.
		}
	}

	/**
	 * Opens a login form bound to the flow state.
	 *
	 * @param string    $action Form action URL.
	 * @param FlowState $state  Flow state.
	 */
	private static function form_open( string $action, FlowState $state ): void {
		printf(
			'<form name="mdmfaform" id="loginform" action="%1$s" method="post"><input type="hidden" name="mdmfa_form" value="%2$s">',
			esc_url( $action ),
			esc_attr( $state->token() )
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
}
