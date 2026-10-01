<?php
/**
 * Serves the login at the slug and 404s the old paths (plan 5.1, 5.2). Early routing, not
 * a rewrite rule: no flushing, works whenever the server sends unknown paths to
 * index.php, and keeps $pagenow correct for core's wp-login.php checks.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

defined( 'ABSPATH' ) || exit;

/**
 * Request routing.
 */
final class Router {

	/** Entry points under wp-admin that must keep working logged out (plan 5.2). */
	private const ADMIN_EXEMPT = array( 'admin-ajax.php', 'admin-post.php', 'upgrade.php' );

	/** Actions that stay on wp-login.php (plan 5.2, and recovery mode). */
	private const CORE_ACTIONS = array( 'postpass', 'confirmaction', 'enter_recovery_mode' );

	/**
	 * Script WordPress resolved for this request before any routing (vars.php).
	 *
	 * @var string
	 */
	private static string $script = '';

	/**
	 * Whether this request is for the slug.
	 *
	 * @var bool
	 */
	private static bool $routed = false;

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'plugins_loaded', array( self::class, 'route' ), 1 );
		add_action( 'init', array( self::class, 'remove_shortcut_redirects' ) );
		add_action( 'wp_loaded', array( self::class, 'dispatch' ), PHP_INT_MAX );
		add_action( 'login_init', array( self::class, 'guard_resolved_action' ), 0 );
	}

	/**
	 * Second check, inside wp-login.php: by now core has resolved the action it will run
	 * (it rewrites it for ?key= and ?checkemail=, and falls back to `login`). On the old
	 * path only the allow-listed actions may proceed.
	 */
	public static function guard_resolved_action(): void {
		if ( ! LoginLocation::enabled() || self::$routed || 'wp-login.php' !== self::$script ) {
			return;
		}
		$action = isset( $GLOBALS['action'] ) && is_string( $GLOBALS['action'] ) ? $GLOBALS['action'] : '';
		if ( ! in_array( $action, self::CORE_ACTIONS, true ) ) {
			self::theme_404();
		}
	}

	/**
	 * Detects the slug. Runs before anything but mu-plugins could read $pagenow.
	 */
	public static function route(): void {
		self::$script = isset( $GLOBALS['pagenow'] ) && is_string( $GLOBALS['pagenow'] ) ? $GLOBALS['pagenow'] : '';
		if ( ! LoginLocation::enabled() || 'index.php' !== self::$script ) {
			return;
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( ! LoginLocation::matches( $uri, LoginLocation::home_path(), LoginLocation::slug() ) ) {
			return;
		}
		self::$routed       = true;
		$GLOBALS['pagenow'] = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- core's own checks (is_protected_endpoint, basic-auth, l10n, script loader) key on this.
		// is_login() compares wp_login_url() with SCRIPT_NAME (wp-includes/load.php).
		$_SERVER['SCRIPT_NAME'] = LoginLocation::slug_path();
	}

	/**
	 * Whether the current request is the slug.
	 */
	public static function is_routed(): bool {
		return self::$routed;
	}

	/**
	 * Core redirects /login, /admin, /dashboard and /wp-admin to the login URL
	 * (wp_redirect_admin_locations), which would publish the slug. They 404 instead.
	 */
	public static function remove_shortcut_redirects(): void {
		if ( LoginLocation::enabled() ) {
			remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
		}
	}

	/**
	 * After WordPress has loaded (blocks and theme included), before any wp-login.php or
	 * wp-admin code runs: serve the slug, or 404 the old paths.
	 */
	public static function dispatch(): void {
		if ( ! LoginLocation::enabled() ) {
			return;
		}
		if ( self::$routed ) {
			self::serve_login();
		}
		if ( 'wp-login.php' === self::$script ) {
			// After a valid recovery link core lands on wp-login.php; the login form for it
			// lives at the slug.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing only; recovery mode itself was verified by core.
			if ( isset( $_GET['action'] ) && 'entered_recovery_mode' === $_GET['action'] && wp_is_recovery_mode() ) {
				wp_safe_redirect( LoginLocation::url( 'action=entered_recovery_mode' ) );
				exit;
			}
			if ( ! self::core_action_allowed() ) {
				self::theme_404();
			}
		}
		if ( is_admin() && ! wp_doing_ajax() && ! is_user_logged_in() && ! self::admin_exempt() ) {
			self::admin_404();
		}
	}

	/**
	 * Runs core's login screen at the slug, and exits.
	 *
	 * @return never
	 */
	private static function serve_login(): void {
		Headers::no_store();
		// The functions wp-login.php defines read these as globals (wp-login.php:42, 326);
		// included from here, its top-level assignments must bind to the same globals.
		// phpcs:ignore Squiz.PHP.GlobalKeyword.NotAllowed -- required for including wp-login.php inside a method.
		global $error, $interim_login, $action, $user_login;
		require ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Whether a direct wp-login.php request is one of the actions that stay there.
	 */
	private static function core_action_allowed(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- routing decision only; core validates each action.
		// The query string only: core's recovery handler reads $_GET, and a POSTed action
		// would let the request through while wp-login.php runs something else.
		$action = isset( $_GET['action'] ) && is_string( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
		if ( ! in_array( $action, self::CORE_ACTIONS, true ) ) {
			return false;
		}
		// wp-login.php switches to resetpass or checkemail when these are present.
		if ( isset( $_GET['key'] ) || isset( $_GET['checkemail'] ) ) {
			return false;
		}
		if ( 'postpass' === $action ) {
			$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
			return 'POST' === $method;
		}
		if ( 'confirmaction' === $action ) {
			return isset( $_GET['request_id'], $_GET['confirm_key'] );
		}
		// enter_recovery_mode is handled by core before plugins load; reaching here means
		// it was invalid and core already stopped, but never 404 a recovery attempt.
		return isset( $_GET['rm_token'], $_GET['rm_key'] );
		// phpcs:enable
	}

	/**
	 * Whether a logged-out wp-admin request may proceed.
	 */
	private static function admin_exempt(): bool {
		if ( in_array( self::$script, self::ADMIN_EXEMPT, true ) ) {
			return true;
		}

		return 'repair.php' === self::$script && defined( 'WP_ALLOW_REPAIR' ) && WP_ALLOW_REPAIR;
	}

	/**
	 * The theme's 404 page for a direct wp-login.php request, and exits. Rendered through
	 * the normal template loader so it looks like any other missing URL.
	 *
	 * @return never
	 */
	private static function theme_404(): void {
		global $wp_query;

		$GLOBALS['pagenow'] = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- render as an ordinary front-end 404.
		if ( ! defined( 'WP_USE_THEMES' ) ) {
			define( 'WP_USE_THEMES', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- core's own switch for the template loader.
		}
		if ( $wp_query instanceof \WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		Headers::no_store();
		require ABSPATH . WPINC . '/template-loader.php';
		exit;
	}

	/**
	 * Minimal 404 for logged-out wp-admin (theme templates are unsafe while is_admin() is
	 * true), and exits. Filter: mdmfa_admin_404_html.
	 *
	 * @return never
	 */
	private static function admin_404(): void {
		status_header( 404 );
		Headers::no_store();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		$html = apply_filters(
			'mdmfa_admin_404_html',
			'<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>' . esc_html__( 'Page not found', 'maxtdesign-mfa' ) . '</title></head><body><h1>' . esc_html__( 'Page not found', 'maxtdesign-mfa' ) . '</h1></body></html>'
		);
		echo is_string( $html ) ? $html : ''; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above; the filter is the owner's own markup.
		exit;
	}
}
