<?php
/**
 * Passwordless passkey sign-in (plan 4.3) on the core login form and the WooCommerce login
 * form, shown only when some role allows it. The request options carry a stateless
 * challenge, so page views write nothing; the module fills a hidden field and submits the
 * same form, and this class finishes the login through Completion.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Frontend;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Auth\Completion;
use MaxtDesign\Mfa\Auth\Context;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Screens\Fragments;
use MaxtDesign\Mfa\Support\IpThrottle;
use MaxtDesign\Mfa\WebAuthn\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Passwordless controls and handler.
 *
 * phpcs:disable WordPress.Security.NonceVerification.Missing -- the posted assertion is itself the proof: a single-use, HMAC-bound challenge signed by the user's passkey.
 */
final class PasskeyLogin {

	public const FIELD = 'mdmfa_passwordless';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'login_form', array( self::class, 'core_control' ) );
		add_action( 'woocommerce_login_form', array( self::class, 'wc_control' ) );
		add_action( 'login_form_login', array( self::class, 'core_submit' ), 1 );
		add_action( 'wp_loaded', array( self::class, 'wc_submit' ), 14 );
		add_filter( 'wp_login_errors', array( self::class, 'core_errors' ) );
	}

	/**
	 * Control inside the core login form.
	 */
	public static function core_control(): void {
		self::control( 'user_login', 'button button-large' );
	}

	/**
	 * Control inside the WooCommerce login form.
	 */
	public static function wc_control(): void {
		$button = 'woocommerce-button button' . ( function_exists( 'wc_wp_theme_get_element_class_name' ) && wc_wp_theme_get_element_class_name( 'button' ) ? ' ' . wc_wp_theme_get_element_class_name( 'button' ) : '' );
		self::control( 'username', $button );
	}

	/**
	 * Core login form submission carrying an assertion.
	 */
	public static function core_submit(): void {
		if ( ! isset( $_POST[ self::FIELD ] ) || ! is_string( $_POST[ self::FIELD ] ) || '' === $_POST[ self::FIELD ] ) {
			return;
		}
		$result = self::verify( wp_unslash( $_POST[ self::FIELD ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON; CredentialJson validates it strictly.
		if ( $result instanceof \WP_Error ) {
			wp_safe_redirect( add_query_arg( 'mdmfa_passkey', rawurlencode( (string) $result->get_error_code() ), wp_login_url() ) );
			exit;
		}
		$redirect = isset( $_POST['redirect_to'] ) && is_string( $_POST['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_POST['redirect_to'] ) ) : '';
		self::finish( $result, Context::CORE, $redirect );
	}

	/**
	 * WooCommerce login form submission carrying an assertion (before WooCommerce's own
	 * handlers at wp_loaded 20).
	 */
	public static function wc_submit(): void {
		if ( is_user_logged_in() || ! isset( $_POST[ self::FIELD ] ) || ! is_string( $_POST[ self::FIELD ] ) || '' === $_POST[ self::FIELD ] || ! function_exists( 'WC' ) ) {
			return;
		}
		$result = self::verify( wp_unslash( $_POST[ self::FIELD ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON; CredentialJson validates it strictly.
		if ( $result instanceof \WP_Error ) {
			if ( function_exists( 'wc_add_notice' ) && null !== WC()->session ) {
				wc_add_notice( esc_html( $result->get_error_message() ), 'error' );
			}
			wp_safe_redirect( '' !== ChallengeUrl::account() ? ChallengeUrl::account() : home_url( '/' ) );
			exit;
		}
		$redirect = isset( $_POST['redirect'] ) && is_string( $_POST['redirect'] ) ? wp_sanitize_redirect( wp_unslash( $_POST['redirect'] ) ) : '';
		self::finish( $result, Context::WC, $redirect );
	}

	/**
	 * Shows the failure reason on the core login form after a redirect.
	 *
	 * @param mixed $errors Login errors.
	 * @return mixed
	 */
	public static function core_errors( mixed $errors ): mixed {
		$code = isset( $_GET['mdmfa_passkey'] ) ? sanitize_key( wp_unslash( $_GET['mdmfa_passkey'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		if ( '' === $code || ! $errors instanceof \WP_Error ) {
			return $errors;
		}
		$message = 'mdmfa_passwordless_off' === $code
			? __( 'Please sign in with your password first. Passkey-only sign-in is not enabled for your account.', 'maxtdesign-mfa' )
			: __( 'That passkey did not work. Try again, or sign in with your password.', 'maxtdesign-mfa' );
		$errors->add( 'mdmfa_passkey', esc_html( $message ) );

		return $errors;
	}

	/**
	 * Renders the passwordless control when any role allows it.
	 *
	 * @param string $username_id Username input id, for autofill (conditional mediation).
	 * @param string $css_class   Button class.
	 */
	private static function control( string $username_id, string $css_class ): void {
		if ( ! Passkeys::passwordless_offered() ) {
			return;
		}
		$mdmfa_passkey_html = Fragments::passkey_button(
			array(
				'mode'        => 'get',
				'options'     => Options::request( Passkeys::login_challenge(), array(), true ),
				'field'       => self::FIELD,
				'conditional' => $username_id,
			),
			__( 'Sign in with a passkey', 'maxtdesign-mfa' ),
			$css_class
		);
		echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
	}

	/**
	 * Throttles, then verifies.
	 *
	 * @param string $json Posted assertion.
	 * @return \WP_User|\WP_Error
	 */
	private static function verify( string $json ): \WP_User|\WP_Error {
		if ( ! IpThrottle::allow( 'passwordless' ) ) {
			return new \WP_Error( 'mdmfa_passkey_throttled', __( 'Too many attempts. Wait a few minutes and try again.', 'maxtdesign-mfa' ) );
		}

		return Passkeys::passwordless( $json );
	}

	/**
	 * Completes the login through the blessed routine, and redirects.
	 *
	 * @param \WP_User $user     User.
	 * @param string   $context  Login context.
	 * @param string   $redirect Requested destination.
	 * @return never
	 */
	private static function finish( \WP_User $user, string $context, string $redirect ): void {
		$token  = PendingStore::create(
			$user->ID,
			PendingStore::KIND_LOGIN,
			array(
				'context'      => $context,
				'redirect_to'  => substr( $redirect, 0, 2048 ),
				'remember'     => ! empty( $_POST['rememberme'] ),
				'secure'       => is_ssl(),
				'interim'      => false,
				'first_factor' => 'passkey',
			)
		);
		$record = PendingStore::find( $token );
		if ( null === $record || ! Completion::complete( $user, 'passkey', $record ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		Logger::log( 'passwordless_ok', $user->ID, 'passkey', $context );
		Completion::redirect( $user, $record );
	}
}
