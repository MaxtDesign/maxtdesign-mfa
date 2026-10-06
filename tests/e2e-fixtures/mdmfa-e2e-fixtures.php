<?php
/**
 * CI-only must-use plugin for the end-to-end suite. Copied into wp-content/mu-plugins by
 * .github/workflows/ci.yml and active only when MDMFA_E2E_FIXTURES is defined. Never
 * shipped: /tests is in .distignore.
 *
 * @package MaxtDesign\Mfa
 */

// phpcs:ignoreFile

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'MDMFA_E2E_FIXTURES' ) || ! MDMFA_E2E_FIXTURES ) {
	return;
}

// Represents a theme-owned route absent from partial CLI boots. Test sites only.
if ( get_option( 'e2e_foreign_route' ) && ! defined( 'WP_CLI' ) ) {
	add_action( 'init', static function (): void {
		add_rewrite_rule( '^e2e-theme-route/?$', 'index.php?e2e_theme_route=1', 'top' );
	} );
}

// No mail transport on the runner: capture every message instead (newest last).
add_filter(
	'pre_wp_mail',
	static function ( $short_circuit, $atts ) {
		$mail   = (array) get_option( 'e2e_mail', array() );
		$mail[] = array(
			'to'      => is_array( $atts['to'] ) ? implode( ',', $atts['to'] ) : (string) $atts['to'],
			'subject' => (string) $atts['subject'],
			'message' => (string) $atts['message'],
		);
		update_option( 'e2e_mail', array_slice( $mail, -20 ), false );
		return true;
	},
	10,
	2
);

// Footprint probe: with ?e2e_probe=1, records how often this request read the plugin's
// non-autoloaded settings and how many queries named a plugin table or option.
if ( isset( $_GET['e2e_probe'] ) ) {
	if ( ! defined( 'SAVEQUERIES' ) ) {
		define( 'SAVEQUERIES', true );
	}
	$GLOBALS['mdmfa_e2e_reads'] = 0;
	foreach ( array( 'pre_option_mdmfa_settings', 'default_option_mdmfa_settings', 'option_mdmfa_settings' ) as $mdmfa_e2e_hook ) {
		add_filter(
			$mdmfa_e2e_hook,
			static function ( $value ) {
				++$GLOBALS['mdmfa_e2e_reads'];
				return $value;
			}
		);
	}
	add_action(
		'shutdown',
		static function (): void {
			global $wpdb;
			$sql = array();
			foreach ( (array) $wpdb->queries as $query ) {
				if ( false !== stripos( $query[0], 'mdmfa' ) ) {
					$sql[] = substr( (string) preg_replace( '/\s+/', ' ', $query[0] ), 0, 160 );
				}
			}
			update_option( 'e2e_probe', array( 'reads' => $GLOBALS['mdmfa_e2e_reads'], 'sql' => $sql ), false );
		},
		PHP_INT_MAX
	);
}

// WooCommerce loads its notice functions on front-end requests only, so wc_add_notice() does
// not exist on a plain wp-admin page. It does as soon as any extension calls wc_load_cart()
// there (public API, "in all contexts"). With the option set, this fixture is that extension;
// every wp-admin response reports whether the function exists (SecurityPresentersTest).
if ( get_option( 'e2e_wc_cart_in_admin' ) ) {
	add_action(
		'woocommerce_init',
		static function (): void {
			if ( is_admin() && ! wp_doing_ajax() && function_exists( 'wc_load_cart' ) ) {
				wc_load_cart();
			}
		}
	);
}
add_action(
	'admin_init',
	static function (): void {
		if ( ! headers_sent() ) {
			header( 'X-E2E-Wc-Notices: ' . ( function_exists( 'wc_add_notice' ) ? '1' : '0' ) );
		}
	}
);

// A site access gate of the kind hosts put in front of staging sites (modelled on Hosting
// Basic Authentication 1.0.5): every page request of a browser that is not logged in must
// carry a WordPress user's credentials as HTTP Basic authentication. It checks them with
// wp_authenticate() on plugins_loaded priority 1, long before any login form exists, and
// then starts the session itself. HttpAuthGateTest turns it on with the option. With the
// value "unlisted" the gate runs but nobody has vouched for it (mdmfa_http_auth_gates).
final class Mdmfa_E2e_Gate {

	public static function register( bool $vouched ): void {
		add_action( 'plugins_loaded', array( self::class, 'force' ), 1 );
		add_action( 'init', array( self::class, 'logout' ), 1 );
		add_filter( 'logout_url', static fn ( $url ) => add_query_arg( 'basic-auth-logout', '1', $url ) );
		add_action( 'login_init', array( self::class, 'leave_login_page' ), 0 );
		if ( $vouched ) {
			add_filter( 'mdmfa_http_auth_gates', static fn ( $gates ) => array_merge( (array) $gates, array( self::class ) ) );
		}
	}

	private static function skip(): bool {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		return ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || 'cli' === php_sapi_name() || ( defined( 'WP_CLI' ) && WP_CLI )
			|| 'xmlrpc.php' === basename( (string) ( $_SERVER['SCRIPT_NAME'] ?? '' ) ) || 1 === preg_match( '#^/wp-json/wp/v2(/|\?|$)#', $uri );
	}

	private static function challenge(): void {
		header( 'WWW-Authenticate: Basic realm="Restricted Area"' );
		header( 'HTTP/1.1 401 Unauthorized' );
		echo '<h1>Authentication Required</h1>';
		exit;
	}

	public static function force(): void {
		if ( self::skip() || is_user_logged_in() ) {
			return;
		}
		$name = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : '';
		$pass = isset( $_SERVER['PHP_AUTH_PW'] ) ? $_SERVER['PHP_AUTH_PW'] : '';
		if ( '' === $name || '' === $pass ) {
			self::challenge();
		}
		$user = wp_authenticate( $name, $pass );
		if ( is_wp_error( $user ) ) {
			self::challenge();
		}
		if ( isset( $_GET['basic-auth-logout'] ) ) {
			return;
		}
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
	}

	public static function logout(): void {
		if ( ! self::skip() && isset( $_GET['basic-auth-logout'] ) ) {
			wp_logout();
			self::challenge();
		}
	}

	public static function leave_login_page(): void {
		if ( 'wp-login.php' === $GLOBALS['pagenow'] && ! empty( $_SERVER['PHP_AUTH_USER'] ) && ! empty( $_SERVER['PHP_AUTH_PW'] )
			&& ! isset( $_GET['action'] ) && ! isset( $_GET['loggedout'] ) && ! isset( $_POST['log'] ) && ! isset( $_GET['basic-auth-logout'] ) ) {
			wp_safe_redirect( home_url() );
			exit;
		}
	}
}
if ( get_option( 'e2e_http_gate' ) ) {
	Mdmfa_E2e_Gate::register( 'unlisted' !== get_option( 'e2e_http_gate' ) );
}

// Another plugin that filters the My Account Security endpoint's rules away, and a count
// of how often WordPress rebuilds its rules meanwhile (RewriteLifecycleTest).
if ( get_option( 'e2e_drop_endpoint_rule' ) ) {
	add_filter(
		'rewrite_rules_array',
		static fn ( $rules ) => is_array( $rules ) ? array_filter( $rules, static fn ( $key ) => ! str_contains( (string) $key, 'login-security' ), ARRAY_FILTER_USE_KEY ) : $rules,
		PHP_INT_MAX
	);
	add_action(
		'generate_rewrite_rules',
		static function (): void {
			update_option( 'e2e_rewrite_flushes', (int) get_option( 'e2e_rewrite_flushes', 0 ) + 1, false );
		}
	);
}

// Records the suite purge signal maxtdesign-cache would act on.
add_action(
	'md_suite_content_changed',
	static function ( $payload ): void {
		$urls   = (array) get_option( 'e2e_purged', array() );
		$urls[] = is_array( $payload ) && isset( $payload['url'] ) ? (string) $payload['url'] : 'full';
		update_option( 'e2e_purged', $urls, false );
	}
);

// Reports is_login() on the login screen (plan 5.1: SCRIPT_NAME set on the slug).
add_action(
	'login_init',
	static function (): void {
		header( 'X-E2E-Is-Login: ' . ( is_login() ? '1' : '0' ) );
		header( 'X-E2E-Pagenow: ' . $GLOBALS['pagenow'] );
	}
);

add_action(
	'wp_login',
	static function (): void {
		update_option( 'e2e_wp_login', (int) get_option( 'e2e_wp_login', 0 ) + 1, false );
	}
);
add_action(
	'wp_login_failed',
	static function (): void {
		update_option( 'e2e_wp_login_failed', (int) get_option( 'e2e_wp_login_failed', 0 ) + 1, false );
	}
);

// A token endpoint of the kind JWT plugins add: a username and password over REST
// (plan 4.3 "rest" context, a non-interactive password login).
add_action(
	'rest_api_init',
	static function (): void {
		register_rest_route(
			'mdmfa-e2e/v1',
			'/token',
			array(
				'methods'             => 'POST',
				'permission_callback' => '__return_true',
				'callback'            => static function ( WP_REST_Request $request ) {
					$user = wp_authenticate( (string) $request['username'], (string) $request['password'] );
					return is_wp_error( $user ) ? new WP_Error( $user->get_error_code(), 'denied', array( 'status' => 403 ) ) : array( 'user' => $user->ID );
				},
			)
		);
	}
);

// Another plugin's AJAX login (plan 4.3 "ajax" context).
add_action(
	'wp_ajax_nopriv_mdmfa_e2e_login',
	static function (): void {
		$user = wp_signon();
		wp_send_json( is_wp_error( $user ) ? array( 'error' => $user->get_error_message() ) : array( 'ok' => true ) );
	}
);

add_action(
	'init',
	static function (): void {
		// A page that prints the core front-end login form.
		if ( isset( $_GET['mdmfa_e2e_form'] ) ) {
			echo wp_login_form( array( 'echo' => false, 'redirect' => home_url( '/?landed=1' ) ) );
			exit;
		}
		$op = isset( $_POST['mdmfa_e2e'] ) ? (string) $_POST['mdmfa_e2e'] : '';
		// Another plugin's own login form posting to an arbitrary page ("unknown-post").
		if ( 'custom_login' === $op ) {
			$user = wp_signon();
			if ( is_wp_error( $user ) ) {
				exit( 'error: ' . $user->get_error_code() );
			}
			wp_safe_redirect( home_url( '/?custom=1' ) );
			exit;
		}
		if ( 'direct_login' === $op ) {
			mdmfa_e2e_direct_login( (int) $_POST['user'] );
		}
		if ( 'change_password' === $op ) {
			if ( ! is_user_logged_in() ) {
				status_header( 403 );
				exit( 'not logged in' );
			}
			wp_update_user(
				array(
					'ID'        => get_current_user_id(),
					'user_pass' => (string) $_POST['pass'],
				)
			);
			exit( 'changed' );
		}
	},
	1
);

/**
 * Logs a user in the way WooCommerce's reset auto-login and Jetpack SSO do: a direct
 * wp_set_auth_cookie() followed by a redirect.
 */
function mdmfa_e2e_direct_login( int $user_id ): void {
	wp_set_auth_cookie( $user_id );
	wp_safe_redirect( admin_url( 'profile.php' ) );
	exit;
}
