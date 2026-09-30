<?php
/**
 * My Account > Security (plan 4.3): customers manage their own factors on the site's
 * pages. Query-var key `mdmfa-security` (prefixed); URL slug `security`, filterable with
 * mdmfa_account_endpoint_slug. WooCommerce maps the slug back to the key
 * (WC_Query::parse_request), and the tab content fires on
 * woocommerce_account_mdmfa-security_endpoint.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WooCommerce;

use MaxtDesign\Mfa\Account\SecurityActions;
use MaxtDesign\Mfa\Account\SecurityView;
use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Security tab.
 */
final class SecurityEndpoint {

	public const KEY = 'mdmfa-security';

	/** Bump when the endpoint's rewrite rules change; rules are flushed once per value. */
	public const REWRITE_VERSION = '1';

	/**
	 * Recovery codes generated in this request, rendered once.
	 *
	 * @var string[]
	 */
	private static array $codes = array();

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'woocommerce_get_query_vars', array( self::class, 'query_vars' ) );
		add_filter( 'woocommerce_account_menu_items', array( self::class, 'menu_items' ) );
		add_filter( 'woocommerce_endpoint_' . self::KEY . '_title', array( self::class, 'title' ) );
		add_action( 'woocommerce_account_' . self::KEY . '_endpoint', array( self::class, 'render' ) );
		add_action( 'wp_loaded', array( self::class, 'handle_post' ), 20 );
		add_action( 'init', array( self::class, 'maybe_flush' ), 99 );
	}

	/**
	 * Adds the endpoint.
	 *
	 * @param mixed $vars Query vars (key => slug).
	 * @return mixed
	 */
	public static function query_vars( mixed $vars ): mixed {
		if ( ! is_array( $vars ) ) {
			return $vars;
		}
		$slug              = apply_filters( 'mdmfa_account_endpoint_slug', 'security' );
		$vars[ self::KEY ] = is_string( $slug ) && '' !== $slug ? sanitize_title( $slug ) : 'security';

		return $vars;
	}

	/**
	 * Adds the tab before Log out.
	 *
	 * @param mixed $items Menu items.
	 * @return mixed
	 */
	public static function menu_items( mixed $items ): mixed {
		if ( ! is_array( $items ) ) {
			return $items;
		}
		$logout = array_key_exists( 'customer-logout', $items ) ? array( 'customer-logout' => $items['customer-logout'] ) : array();
		unset( $items['customer-logout'] );

		return array_merge( $items, array( self::KEY => __( 'Security', 'maxtdesign-mfa' ) ), $logout );
	}

	/**
	 * Tab title.
	 */
	public static function title(): string {
		return __( 'Security', 'maxtdesign-mfa' );
	}

	/**
	 * Flushes rewrite rules once after the endpoint appears (WooCommerce registers its
	 * endpoints on init). Reads one autoloaded option otherwise.
	 */
	public static function maybe_flush(): void {
		if ( ! class_exists( 'WooCommerce' ) || self::REWRITE_VERSION === get_option( Options::REWRITE ) ) {
			return;
		}
		flush_rewrite_rules( false );
		update_option( Options::REWRITE, self::REWRITE_VERSION, true );
	}

	/**
	 * Handles tab form posts: own account only, nonce checked, then post/redirect/get
	 * unless recovery codes must be shown in this response.
	 */
	public static function handle_post(): void {
		if ( ! isset( $_POST['mdmfa_op'], $_POST['_wpnonce'] ) || ! is_user_logged_in() || ! function_exists( 'wc_add_notice' ) ) {
			return;
		}
		if ( false === wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), SecurityActions::NONCE ) ) {
			wc_add_notice( esc_html__( 'This form expired. Please try again.', 'maxtdesign-mfa' ), 'error' );
			return;
		}
		$op = sanitize_key( wp_unslash( $_POST['mdmfa_op'] ) );
		if ( ! in_array( $op, SecurityActions::OPS, true ) ) {
			return;
		}
		$result  = SecurityActions::run(
			$op,
			wp_get_current_user(),
			isset( $_POST['mdmfa_code'] ) && is_string( $_POST['mdmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_code'] ) ) : '',
			isset( $_POST['mdmfa_method'] ) ? sanitize_key( wp_unslash( $_POST['mdmfa_method'] ) ) : 'totp',
			'wc'
		);
		$notices = SecurityActions::notices();
		if ( isset( $notices[ $result['notice'] ] ) ) {
			wc_add_notice( esc_html( $notices[ $result['notice'] ][1] ), $notices[ $result['notice'] ][0] );
		}
		if ( array() !== $result['codes'] ) {
			self::$codes = $result['codes'];
			return;
		}
		wp_safe_redirect( add_query_arg( array_filter( array( 'view' => $result['view'] ) ), self::url() ) );
		exit;
	}

	/**
	 * Tab content.
	 */
	public static function render(): void {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		$view   = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display choice only.
		$button = 'woocommerce-Button button' . ( function_exists( 'wc_wp_theme_get_element_class_name' ) && wc_wp_theme_get_element_class_name( 'button' ) ? ' ' . wc_wp_theme_get_element_class_name( 'button' ) : '' );

		SecurityView::render(
			$user,
			self::url(),
			$view,
			self::$codes,
			array(
				'button'  => $button,
				'primary' => $button,
				'danger'  => $button,
				'input'   => 'woocommerce-Input woocommerce-Input--text input-text',
				'row'     => 'woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide',
			)
		);
	}

	/**
	 * URL of the tab.
	 */
	public static function url(): string {
		return function_exists( 'wc_get_account_endpoint_url' ) ? (string) wc_get_account_endpoint_url( self::KEY ) : home_url( '/' );
	}
}
