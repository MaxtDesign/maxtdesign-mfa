<?php
/**
 * Users > My security (plan section 8): the logged-in user's own factors in wp-admin.
 * Operations and markup are shared with the WooCommerce Security tab.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Account;

use MaxtDesign\Mfa\Policy\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Admin presenter (users.php, or profile.php for users without edit_users).
 */
final class AccountPage {

	public const SLUG = 'mdmfa-account';

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
	 * Handles form posts before any output: redirect with a notice (post/redirect/get),
	 * except when recovery codes must be shown, which render in this response.
	 */
	public static function handle(): void {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return;
		}
		// Only a form this page rendered: My Account's forms carry another nonce action.
		check_admin_referer( SecurityActions::NONCE_ADMIN );
		$user = wp_get_current_user();
		$op   = isset( $_POST['mdmfa_op'] ) ? sanitize_key( wp_unslash( $_POST['mdmfa_op'] ) ) : '';
		if ( ! $user->exists() || ! in_array( $op, SecurityActions::OPS, true ) ) {
			return;
		}
		$result = SecurityActions::run( $op, $user, SecurityActions::input(), 'account' );
		if ( array() !== $result['codes'] ) {
			self::$codes = $result['codes'];
			return;
		}
		$args = array_filter(
			array(
				'mdmfa_notice' => $result['notice'],
				'view'         => $result['view'],
			)
		);
		wp_safe_redirect( add_query_arg( $args, self::page_url() ) );
		exit;
	}

	/**
	 * Renders the page.
	 */
	public static function render(): void {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display choices only.
		$view   = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : '';
		$notice = isset( $_GET['mdmfa_notice'] ) ? sanitize_key( wp_unslash( $_GET['mdmfa_notice'] ) ) : '';
		// phpcs:enable
		$notices = SecurityActions::notices();

		echo '<div class="wrap"><h1>' . esc_html__( 'My security', 'maxtdesign-mfa' ) . '</h1>';
		if ( isset( $notices[ $notice ] ) ) {
			printf( '<div class="notice notice-%1$s"><p>%2$s</p></div>', esc_attr( $notices[ $notice ][0] ), esc_html( $notices[ $notice ][1] ) );
		}
		SecurityView::render(
			$user,
			self::page_url(),
			$view,
			self::$codes,
			array(
				'button'  => 'button button-secondary',
				'primary' => 'button button-primary',
				'danger'  => 'button button-link-delete',
				'input'   => 'regular-text',
				'row'     => '',
			),
			SecurityActions::NONCE_ADMIN
		);
		echo '</div>';
	}

	/**
	 * Status row on the user's own profile screen, linking here. No assets.
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
	 * Raw URL of this page. add_users_page() hangs it under users.php for users who can
	 * edit_users and under profile.php otherwise (wp-admin/includes/plugin.php).
	 */
	private static function page_url(): string {
		return add_query_arg( 'page', self::SLUG, admin_url( current_user_can( 'edit_users' ) ? 'users.php' : 'profile.php' ) );
	}
}
