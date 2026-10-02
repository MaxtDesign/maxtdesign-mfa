<?php
/**
 * My Account > Security (plan 4.3): customers manage their own factors on the site's
 * pages. Query-var key `mdmfa-security` (prefixed); URL slug `login-security`, filterable with
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
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Security tab.
 */
final class SecurityEndpoint {

	public const KEY = 'mdmfa-security';

	/** Bump when the endpoint's rewrite rules change; rules are flushed once per value. */
	public const REWRITE_VERSION = '2';

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
		add_action( 'wp_loaded', array( self::class, 'maybe_flush' ), 10 );
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
		// Not plain "security": an endpoint claims that word under every page, which
		// would shadow a child page such as /company/security/.
		$slug              = apply_filters( 'mdmfa_account_endpoint_slug', 'login-security' );
		$vars[ self::KEY ] = is_string( $slug ) && '' !== $slug ? sanitize_title( $slug ) : 'login-security';

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
	 * Repairs missing endpoint rules after WooCommerce registers them on init.
	 * Runs on wp_loaded so a soft flush completes before its rule is recorded.
	 * Validate one saved rule in core's cached rules, including on existing subsites:
	 * a version alone cannot detect rules regenerated while this plugin was inactive.
	 */
	public static function maybe_flush(): void {
		if ( ! function_exists( 'WC' ) || '' === (string) get_option( 'permalink_structure' ) ) {
			return;
		}
		$slug = WC()->query->get_query_vars()[ self::KEY ] ?? '';
		if ( '' === $slug ) {
			return;
		}
		$rules  = (array) get_option( 'rewrite_rules', array() );
		$marker = get_option( Options::REWRITE );
		if ( is_array( $marker ) && self::REWRITE_VERSION === ( $marker['version'] ?? '' )
			&& ( $marker['slug'] ?? '' ) === $slug && isset( $marker['rule'], $marker['query'] )
			&& is_string( $marker['rule'] ) && ( $rules[ $marker['rule'] ] ?? null ) === $marker['query'] ) {
			return;
		}
		// A rebuild that produced no endpoint rule (another plugin filters the rules, or the
		// endpoint mask was changed) is retried once a day, never on every request.
		if ( is_array( $marker ) && self::REWRITE_VERSION === ( $marker['version'] ?? '' ) && ( $marker['slug'] ?? '' ) === $slug
			&& '' === ( $marker['rule'] ?? null ) && (int) ( $marker['checked'] ?? 0 ) > Clock::now() - DAY_IN_SECONDS ) {
			return;
		}
		flush_rewrite_rules( false );
		$found = array(
			'version' => self::REWRITE_VERSION,
			'slug'    => $slug,
			'rule'    => '',
			'query'   => '',
			'checked' => Clock::now(),
		);
		foreach ( (array) get_option( 'rewrite_rules', array() ) as $rule => $query ) {
			if ( is_string( $rule ) && is_string( $query ) && str_ends_with( $rule, $slug . '(/(.*))?/?$' )
				&& str_contains( $query, '&' . $slug . '=' ) ) {
				$found['rule']  = $rule;
				$found['query'] = $query;
				break;
			}
		}
		update_option( Options::REWRITE, $found, true );
	}

	/**
	 * Handles tab form posts: own account only, nonce checked, then post/redirect/get
	 * unless recovery codes must be shown in this response.
	 *
	 * This runs on wp_loaded, which also fires on wp-admin requests, before the admin
	 * page's own handler (Account\AccountPage, on load-{page}). Those posts are not this
	 * presenter's: it stays out of every admin request, and accepts only the nonce its own
	 * forms carry. WooCommerce not defining wc_add_notice() in wp-admin is no guard: it is
	 * defined there as soon as an extension calls wc_load_cart().
	 */
	public static function handle_post(): void {
		if ( is_admin() || ! isset( $_POST['mdmfa_op'], $_POST['_wpnonce'] ) || ! is_user_logged_in() || ! function_exists( 'wc_add_notice' ) ) {
			return;
		}
		if ( false === wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), SecurityActions::NONCE_WC ) ) {
			wc_add_notice( esc_html__( 'This form expired. Please try again.', 'maxtdesign-mfa' ), 'error' );
			return;
		}
		$op = sanitize_key( wp_unslash( $_POST['mdmfa_op'] ) );
		if ( ! in_array( $op, SecurityActions::OPS, true ) ) {
			return;
		}
		$result  = SecurityActions::run( $op, wp_get_current_user(), SecurityActions::input(), 'wc' );
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
			),
			SecurityActions::NONCE_WC
		);
	}

	/**
	 * URL of the tab.
	 */
	public static function url(): string {
		return function_exists( 'wc_get_account_endpoint_url' ) ? (string) wc_get_account_endpoint_url( self::KEY ) : home_url( '/' );
	}
}
