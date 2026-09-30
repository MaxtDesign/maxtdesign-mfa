<?php
/**
 * My security (plan section 8): the logged-in user's own factors. P2 covers the
 * authenticator app and recovery codes. Server-rendered with core admin classes; no
 * plugin CSS or JavaScript.
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
use MaxtDesign\Mfa\Screens\Fragments;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Users -> My security (or Profile -> My security for users without list_users).
 */
final class AccountPage {

	public const SLUG  = 'mdmfa-account';
	public const NONCE = 'mdmfa_account';

	/**
	 * Recovery codes generated in this request, rendered once in the response.
	 *
	 * @var string[]
	 */
	private static array $codes = array();

	/**
	 * Registers hooks (admin requests only).
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'show_user_profile', array( self::class, 'profile_summary' ) );
	}

	/**
	 * Adds the page and its load handler.
	 */
	public static function menu(): void {
		$hook = add_users_page(
			__( 'My security', 'maxtdesign-mfa' ),
			__( 'My security', 'maxtdesign-mfa' ),
			'read',
			self::SLUG,
			array( self::class, 'render' )
		);
		if ( is_string( $hook ) && '' !== $hook ) {
			add_action( 'load-' . $hook, array( self::class, 'handle' ) );
		}
	}

	/**
	 * Handles form posts before any output.
	 */
	public static function handle(): void {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return;
		}
		check_admin_referer( self::NONCE );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		$op = isset( $_POST['mdmfa_op'] ) ? sanitize_key( wp_unslash( $_POST['mdmfa_op'] ) ) : '';

		switch ( $op ) {
			case 'totp_begin':
				self::totp_begin( $user );
				break;
			case 'totp_confirm':
				self::totp_confirm( $user );
				break;
			case 'totp_remove':
				self::totp_remove( $user );
				break;
			case 'recovery_generate':
				self::recovery_generate( $user );
				break;
			case 'stepup':
				self::stepup( $user );
				break;
		}
	}

	/**
	 * Starts authenticator setup.
	 *
	 * @param \WP_User $user Current user.
	 */
	private static function totp_begin( \WP_User $user ): void {
		if ( TotpStore::has( $user->ID ) || ! Policy::allows( $user, 'totp' ) ) {
			self::back( 'not_allowed' );
		}
		try {
			TotpStore::begin_pending( $user->ID );
		} catch ( InvalidKeyException $e ) {
			self::back( 'key_invalid' );
		}
		self::back( '', array( 'view' => 'totp' ) );
	}

	/**
	 * Confirms authenticator setup with a code from the app.
	 *
	 * @param \WP_User $user Current user.
	 */
	private static function totp_confirm( \WP_User $user ): void {
		$secret = TotpStore::pending( $user->ID );
		if ( null === $secret || TotpStore::has( $user->ID ) ) {
			self::back( 'setup_expired' );
		}
		$input = isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in handle().
		$step  = Totp::match( $secret, Totp::normalize( $input ), Clock::now() );
		if ( null === $step ) {
			self::back( 'code_invalid', array( 'view' => 'totp' ) );
		}
		try {
			TotpStore::save( $user->ID, $secret, $step );
		} catch ( InvalidKeyException $e ) {
			self::back( 'key_invalid' );
		}
		update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
		// The user just proved the factor: stamp this session so it counts as verified
		// (and survives core's cookie re-issue on a password change).
		StepUp::mark( $user->ID, 'totp' );
		Logger::log( 'enrolled', $user->ID, 'totp', 'account', $user->ID );
		do_action( 'mdmfa_enrolled', $user, 'totp' );

		if ( 0 === RecoveryCodes::remaining( $user->ID ) ) {
			self::$codes = RecoveryCodes::generate( $user->ID );
			return;
		}
		self::back( 'totp_on' );
	}

	/**
	 * Removes the authenticator (step-up required).
	 *
	 * @param \WP_User $user Current user.
	 */
	private static function totp_remove( \WP_User $user ): void {
		if ( ! StepUp::is_fresh( $user->ID ) ) {
			self::back( 'stepup_needed' );
		}
		TotpStore::remove( $user->ID );
		if ( ! Policy::is_enrolled( $user->ID ) ) {
			delete_user_meta( $user->ID, 'mdmfa_enrolled' );
			RecoveryCodes::remove( $user->ID );
		}
		Logger::log( 'factor_removed', $user->ID, 'totp', 'account', $user->ID );
		do_action( 'mdmfa_factor_removed', $user, 'totp', $user->ID );
		self::back( 'totp_off' );
	}

	/**
	 * Issues a new set of recovery codes (step-up required).
	 *
	 * @param \WP_User $user Current user.
	 */
	private static function recovery_generate( \WP_User $user ): void {
		if ( ! Policy::is_enrolled( $user->ID ) ) {
			self::back( 'not_allowed' );
		}
		if ( ! StepUp::is_fresh( $user->ID ) ) {
			self::back( 'stepup_needed' );
		}
		self::$codes = RecoveryCodes::generate( $user->ID );
		Logger::log( 'recovery_regenerated', $user->ID, 'recovery', 'account', $user->ID );
	}

	/**
	 * Re-verifies a factor for step-up.
	 *
	 * @param \WP_User $user Current user.
	 */
	private static function stepup( \WP_User $user ): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in handle().
		$method = isset( $_POST['mdmfa_method'] ) && 'recovery' === $_POST['mdmfa_method'] ? 'recovery' : 'totp';
		$input  = isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '';
		// phpcs:enable
		$result = StepUp::verify( $user->ID, $method, $input );
		self::back( 'ok' === $result ? 'stepup_ok' : ( 'wait' === $result ? 'stepup_wait' : 'code_invalid' ) );
	}

	/**
	 * Renders the page.
	 */
	public static function render(): void {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		$enrolled  = Policy::is_enrolled( $user->ID );
		$policy    = Policy::policy( $user );
		$remaining = RecoveryCodes::remaining( $user->ID );
		$view      = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display choice only.

		echo '<div class="wrap"><h1>' . esc_html__( 'My security', 'maxtdesign-mfa' ) . '</h1>';
		self::notices();

		if ( array() !== self::$codes ) {
			echo '<div class="notice notice-warning">' . Fragments::recovery_codes( self::$codes ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		}

		$labels = array(
			Settings::POLICY_REQUIRED => __( 'Required for your account', 'maxtdesign-mfa' ),
			Settings::POLICY_OPTIONAL => __( 'Optional for your account', 'maxtdesign-mfa' ),
			Settings::POLICY_OFF      => __( 'Not used for your account', 'maxtdesign-mfa' ),
		);
		echo '<table class="form-table" role="presentation"><tbody>';
		printf( '<tr><th scope="row">%1$s</th><td>%2$s</td></tr>', esc_html__( 'Two-step verification', 'maxtdesign-mfa' ), esc_html( $enrolled ? __( 'On', 'maxtdesign-mfa' ) : __( 'Off', 'maxtdesign-mfa' ) ) );
		printf( '<tr><th scope="row">%1$s</th><td>%2$s</td></tr>', esc_html__( 'Site policy', 'maxtdesign-mfa' ), esc_html( $labels[ $policy ] ?? $policy ) );
		if ( $enrolled ) {
			printf(
				'<tr><th scope="row">%1$s</th><td>%2$s</td></tr>',
				esc_html__( 'Recovery codes left', 'maxtdesign-mfa' ),
				esc_html( (string) $remaining ) . ( $remaining <= RecoveryCodes::LOW ? ' <strong>' . esc_html__( 'Running low: create a new set.', 'maxtdesign-mfa' ) . '</strong>' : '' )
			);
		}
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'Authenticator app', 'maxtdesign-mfa' ) . '</h2>';
		if ( TotpStore::has( $user->ID ) ) {
			if ( null === TotpStore::secret( $user->ID ) ) {
				echo '<p>' . esc_html__( 'Your authenticator key cannot be read, most likely because the site\'s encryption key changed. Remove it and set it up again.', 'maxtdesign-mfa' ) . '</p>';
			} else {
				echo '<p>' . esc_html__( 'Your authenticator app is set up.', 'maxtdesign-mfa' ) . '</p>';
			}
			self::op_form( 'totp_remove', __( 'Remove authenticator app', 'maxtdesign-mfa' ), 'button-link-delete' );
		} elseif ( 'totp' === $view && null !== TotpStore::pending( $user->ID ) ) {
			$secret = (string) TotpStore::pending( $user->ID );
			echo Fragments::totp_setup( $secret, $user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally.
			self::form_start( 'totp_confirm' );
			echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ), false, 'regular-text' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			submit_button( __( 'Confirm and turn on', 'maxtdesign-mfa' ) );
			echo '</form>';
		} elseif ( Policy::allows( $user, 'totp' ) ) {
			echo '<p>' . esc_html__( 'Use an app on your phone to generate sign-in codes.', 'maxtdesign-mfa' ) . '</p>';
			self::op_form( 'totp_begin', __( 'Set up authenticator app', 'maxtdesign-mfa' ), 'button-primary' );
		} else {
			echo '<p>' . esc_html__( 'Authenticator apps are not available for your account.', 'maxtdesign-mfa' ) . '</p>';
		}

		if ( $enrolled ) {
			echo '<h2>' . esc_html__( 'Recovery codes', 'maxtdesign-mfa' ) . '</h2>';
			echo '<p>' . esc_html__( 'Creating a new set replaces every unused code.', 'maxtdesign-mfa' ) . '</p>';
			self::op_form( 'recovery_generate', __( 'Create new recovery codes', 'maxtdesign-mfa' ), 'button-secondary' );

			if ( ! StepUp::is_fresh( $user->ID ) ) {
				echo '<h2>' . esc_html__( 'Confirm it is you', 'maxtdesign-mfa' ) . '</h2>';
				echo '<p>' . esc_html__( 'Removing a method or creating new recovery codes needs a code verified in the last 10 minutes.', 'maxtdesign-mfa' ) . '</p>';
				self::form_start( 'stepup' );
				echo '<fieldset><label><input type="radio" name="mdmfa_method" value="totp" checked> ' . esc_html__( 'Authenticator code', 'maxtdesign-mfa' ) . '</label> ';
				echo '<label><input type="radio" name="mdmfa_method" value="recovery"> ' . esc_html__( 'Recovery code', 'maxtdesign-mfa' ) . '</label></fieldset>';
				printf(
					'<p><label for="mdmfa_stepup_code">%1$s</label><br><input type="text" name="mdmfa_code" id="mdmfa_stepup_code" class="regular-text" autocomplete="one-time-code" required></p>',
					esc_html__( 'Code', 'maxtdesign-mfa' )
				);
				submit_button( __( 'Confirm', 'maxtdesign-mfa' ), 'secondary' );
				echo '</form>';
			}
		}
		echo '</div>';
	}

	/**
	 * Status row on the user's own profile screen, linking to My security. No assets.
	 *
	 * @param \WP_User $user Profile owner (always the current user on show_user_profile).
	 */
	public static function profile_summary( \WP_User $user ): void {
		printf(
			'<h2>%1$s</h2><table class="form-table" role="presentation"><tr><th scope="row">%2$s</th><td>%3$s <a href="%4$s">%5$s</a></td></tr></table>',
			esc_html__( 'Login security', 'maxtdesign-mfa' ),
			esc_html__( 'Two-step verification', 'maxtdesign-mfa' ),
			esc_html( Policy::is_enrolled( $user->ID ) ? __( 'On.', 'maxtdesign-mfa' ) : __( 'Off.', 'maxtdesign-mfa' ) ),
			esc_url( self::page_url() ),
			esc_html__( 'Manage in My security', 'maxtdesign-mfa' )
		);
	}

	/**
	 * Notice from the query string (codes only, never raw text).
	 */
	private static function notices(): void {
		$code     = isset( $_GET['mdmfa_notice'] ) ? sanitize_key( wp_unslash( $_GET['mdmfa_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		$messages = array(
			'totp_on'       => array( 'success', __( 'Two-step verification is on.', 'maxtdesign-mfa' ) ),
			'totp_off'      => array( 'success', __( 'Authenticator app removed.', 'maxtdesign-mfa' ) ),
			'stepup_ok'     => array( 'success', __( 'Confirmed. You can make changes for the next 10 minutes.', 'maxtdesign-mfa' ) ),
			'stepup_needed' => array( 'warning', __( 'Confirm it is you with a code first.', 'maxtdesign-mfa' ) ),
			'stepup_wait'   => array( 'error', __( 'Too many wrong codes. Wait a few minutes and try again.', 'maxtdesign-mfa' ) ),
			'code_invalid'  => array( 'error', __( 'That code is not valid.', 'maxtdesign-mfa' ) ),
			'setup_expired' => array( 'error', __( 'Setup expired. Start again.', 'maxtdesign-mfa' ) ),
			'not_allowed'   => array( 'error', __( 'That option is not available for your account.', 'maxtdesign-mfa' ) ),
			'key_invalid'   => array( 'error', __( 'The site\'s encryption key is invalid. Please contact the site administrator.', 'maxtdesign-mfa' ) ),
		);
		if ( isset( $messages[ $code ] ) ) {
			printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( $messages[ $code ][0] ), esc_html( $messages[ $code ][1] ) );
		}
	}

	/**
	 * A one-button form for an operation.
	 *
	 * @param string $op        Operation.
	 * @param string $label     Button label.
	 * @param string $css_class Button class.
	 */
	private static function op_form( string $op, string $label, string $css_class ): void {
		self::form_start( $op );
		printf( '<p><button type="submit" class="button %1$s">%2$s</button></p></form>', esc_attr( $css_class ), esc_html( $label ) );
	}

	/**
	 * Opens a form posting to this page with the nonce and operation.
	 *
	 * @param string $op Operation.
	 */
	private static function form_start( string $op ): void {
		printf( '<form method="post" action="%s">', esc_url( self::page_url() ) );
		wp_nonce_field( self::NONCE );
		printf( '<input type="hidden" name="mdmfa_op" value="%s">', esc_attr( $op ) );
	}

	/**
	 * Raw URL of this page. add_users_page() hangs it under users.php for users who can
	 * edit_users and under profile.php otherwise (wp-admin/includes/plugin.php).
	 */
	private static function page_url(): string {
		return add_query_arg( 'page', self::SLUG, admin_url( current_user_can( 'edit_users' ) ? 'users.php' : 'profile.php' ) );
	}

	/**
	 * Redirects back to the page with a notice code (post/redirect/get), and exits.
	 *
	 * @param string                $notice Notice code, or ''.
	 * @param array<string, string> $args   Extra query args.
	 * @return never
	 */
	private static function back( string $notice, array $args = array() ): void {
		if ( '' !== $notice ) {
			$args['mdmfa_notice'] = $notice;
		}
		wp_safe_redirect( add_query_arg( $args, self::page_url() ) );
		exit;
	}
}
