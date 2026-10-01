<?php
/**
 * The second step on WooCommerce My Account (plan 4.3): while a pending login exists, the
 * logged-out login form is swapped (wc_get_template) for the challenge, styled by the
 * theme through WooCommerce's own classes. Zero plugin CSS or JavaScript.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WooCommerce;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Auth\Completion;
use MaxtDesign\Mfa\Auth\PendingCookie;
use MaxtDesign\Mfa\Flow\ChallengeFlow;
use MaxtDesign\Mfa\Flow\FlowState;

defined( 'ABSPATH' ) || exit;

/**
 * My Account presenter.
 */
final class AccountChallenge {

	/** Template WooCommerce renders for logged-out My Account visitors. */
	public const SWAPPED_TEMPLATE = 'myaccount/form-login.php';

	/** Theme override path: {theme}/maxtdesign-mfa/challenge.php. */
	public const THEME_TEMPLATE = 'maxtdesign-mfa/challenge.php';

	/**
	 * State to render in this request, set before any output.
	 *
	 * @var FlowState|null
	 */
	private static ?FlowState $state = null;

	/**
	 * Registers hooks. They do nothing until WooCommerce loads and a pending cookie exists.
	 */
	public static function register(): void {
		add_action( 'wp_loaded', array( self::class, 'handle_post' ), 15 );
		add_action( 'template_redirect', array( self::class, 'prepare' ), 5 );
		add_filter( 'wc_get_template', array( self::class, 'swap_template' ), 10, 2 );
		add_filter( 'woocommerce_login_redirect', array( self::class, 'honour_redirect' ), 5, 1 );
	}

	/**
	 * Login links that were sent to My Account instead of the login address carry the
	 * page to return to (UrlRewriter::login_url()). WooCommerce ignores it for a plain
	 * password login, so it is applied here; same-site targets only.
	 *
	 * @param mixed $redirect WooCommerce's redirect target.
	 * @return mixed
	 */
	public static function honour_redirect( mixed $redirect ): mixed {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a redirect target, validated below; WooCommerce verified the login nonce.
		$wanted = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_GET['redirect_to'] ) ) : '';
		if ( '' === $wanted || ! is_string( $redirect ) ) {
			return $redirect;
		}

		return wp_validate_redirect( $wanted, $redirect );
	}

	/**
	 * Challenge form posts, before WooCommerce's own handlers at wp_loaded 20.
	 */
	public static function handle_post(): void {
		// phpcs:disable WordPress.Security.NonceVerification -- the flow verifies FormToken (HMAC over the pending record) before any state change; the cancel link carries its own token.
		if ( is_user_logged_in() || null === PendingCookie::get() || ! function_exists( 'WC' ) ) {
			return;
		}
		if ( isset( $_GET['mdmfa_cancel'] ) ) {
			ChallengeFlow::cancel( sanitize_text_field( wp_unslash( $_GET['mdmfa_cancel'] ) ) );
			wp_safe_redirect( remove_query_arg( 'mdmfa_cancel' ) );
			exit;
		}
		if ( ! isset( $_POST['mdmfa_wc'] ) ) {
			return;
		}
		// phpcs:enable
		self::settle( ChallengeFlow::run( ChallengeFlow::input() ) );
	}

	/**
	 * GET on My Account: decide what to show before output starts, so a finished or
	 * expired login can still redirect or clear its cookie.
	 */
	public static function prepare(): void {
		if ( is_user_logged_in() || ! function_exists( 'is_account_page' ) || ! is_account_page() ) {
			return;
		}
		// A failed front-end login form (LoginForm) lands here. One generic message: it
		// must not reveal whether the account exists.
		if ( isset( $_GET['mdmfa_login'] ) && function_exists( 'wc_add_notice' ) && null !== WC()->session ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
			wc_add_notice( esc_html__( 'The username or password is incorrect.', 'maxtdesign-mfa' ), 'error' );
		}
		if ( null !== self::$state || null === PendingCookie::get() ) {
			return;
		}
		self::settle( ChallengeFlow::run( ChallengeFlow::input() ) );
		nocache_headers();
		if ( ! headers_sent() ) {
			header( 'Referrer-Policy: same-origin' );
			send_frame_options_header();
		}
	}

	/**
	 * Swaps the logged-out login form for the challenge while a login is pending.
	 *
	 * @param mixed $template      Resolved template path.
	 * @param mixed $template_name Template name.
	 * @return mixed
	 */
	public static function swap_template( mixed $template, mixed $template_name ): mixed {
		if ( self::SWAPPED_TEMPLATE !== $template_name || null === self::$state ) {
			return $template;
		}
		$theme = locate_template( self::THEME_TEMPLATE );

		return '' !== $theme ? $theme : MDMFA_DIR . '/templates/woocommerce/challenge.php';
	}

	/**
	 * State for the template.
	 */
	public static function state(): ?FlowState {
		return self::$state;
	}

	/**
	 * Form action for the current screen.
	 *
	 * @param FlowState $state Flow state.
	 */
	public static function form_action( FlowState $state ): string {
		$url = ChallengeUrl::account();

		return FlowState::VERIFY === $state->screen ? add_query_arg( 'mdmfa_method', $state->method, $url ) : $url;
	}

	/**
	 * Link that switches between the authenticator and a recovery code.
	 *
	 * @param string $method Method to switch to.
	 */
	public static function method_url( string $method ): string {
		return add_query_arg( 'mdmfa_method', $method, ChallengeUrl::account() );
	}

	/**
	 * "Start over" link.
	 *
	 * @param FlowState $state Flow state.
	 */
	public static function cancel_url( FlowState $state ): string {
		return add_query_arg( 'mdmfa_cancel', $state->cancel_token(), ChallengeUrl::account() );
	}

	/**
	 * Acts on a flow result: redirect when done, a notice when expired, else keep it for
	 * the template.
	 *
	 * @param FlowState $state Flow state.
	 */
	private static function settle( FlowState $state ): void {
		if ( FlowState::DONE === $state->screen && null !== $state->user && null !== $state->record ) {
			Completion::redirect( $state->user, $state->record );
		}
		if ( FlowState::EXPIRED === $state->screen ) {
			PendingCookie::clear();
			if ( function_exists( 'wc_add_notice' ) && null !== WC()->session ) {
				wc_add_notice( esc_html( $state->message ), 'error' );
			}
			self::$state = null;
			return;
		}
		self::$state = $state;
	}
}
