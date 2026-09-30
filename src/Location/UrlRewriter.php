<?php
/**
 * Generated URLs (plan 5.3): every wp-login.php link core builds points at the slug,
 * except the actions that must stay on wp-login.php. Logged-out front-end login links go
 * to the public login page, so pages visitors browse do not publish the slug.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * URL filters.
 */
final class UrlRewriter {

	/** Actions whose URLs stay on wp-login.php. */
	private const CORE_ACTIONS = array( 'postpass', 'confirmaction' );

	/**
	 * Registers hooks. Priority 20: after LoginForm (10) has moved front-end form posts
	 * to the neutral handler.
	 */
	public static function register(): void {
		add_filter( 'site_url', array( self::class, 'site_url' ), 20, 3 );
		add_filter( 'network_site_url', array( self::class, 'network_site_url' ), 20, 3 );
		add_filter( 'login_url', array( self::class, 'login_url' ), 20, 1 );
		add_filter( 'user_request_action_email_content', array( self::class, 'privacy_email' ), 20, 2 );
		add_filter( 'recovery_mode_begin_url', array( self::class, 'recovery_url' ), 20, 1 );
		add_filter( 'update_welcome_email', array( self::class, 'welcome_email' ), 20, 2 );
		add_filter( 'update_welcome_user_email', array( self::class, 'welcome_user_email' ), 20, 1 );
	}

	/**
	 * Current site's wp-login.php URLs.
	 *
	 * @param mixed $url    URL.
	 * @param mixed $path   Requested path.
	 * @param mixed $scheme Scheme context.
	 * @return mixed
	 */
	public static function site_url( mixed $url, mixed $path = '', mixed $scheme = null ): mixed {
		unset( $scheme );
		if ( ! is_string( $url ) || ! LoginLocation::enabled() ) {
			return $url;
		}

		return self::rewrite( $url, (string) $path, LoginLocation::url() );
	}

	/**
	 * Network wp-login.php URLs (password-reset and new-user emails use these). On a
	 * multisite subsite they belong to the main site's login.
	 *
	 * @param mixed $url    URL.
	 * @param mixed $path   Requested path.
	 * @param mixed $scheme Scheme context.
	 * @return mixed
	 */
	public static function network_site_url( mixed $url, mixed $path = '', mixed $scheme = null ): mixed {
		unset( $scheme );
		if ( ! is_string( $url ) ) {
			return $url;
		}
		if ( ! is_multisite() || is_main_site() ) {
			return LoginLocation::enabled() ? self::rewrite( $url, (string) $path, LoginLocation::url() ) : $url;
		}
		$main = self::main_site_login_url();

		return null === $main ? $url : self::rewrite( $url, (string) $path, $main );
	}

	/**
	 * Logged-out front-end visitors get the public login page; everyone else the slug
	 * (already produced by the site_url filter).
	 *
	 * @param mixed $login_url Login URL.
	 * @return mixed
	 */
	public static function login_url( mixed $login_url ): mixed {
		if ( ! is_string( $login_url ) || ! LoginLocation::enabled() ) {
			return $login_url;
		}
		$internal = is_admin() || is_user_logged_in() || Router::is_routed() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI );
		if ( $internal ) {
			return $login_url;
		}
		$public = LoginLocation::public_url();

		return LoginLocation::url() === $public ? $login_url : $public;
	}

	/**
	 * The privacy-request email links to wp-login.php?action=confirmaction, which is
	 * allow-listed, so the recipient (often not a user) never receives the slug. Core
	 * substitutes ###CONFIRM_URL### after this filter (wp-includes/user.php).
	 *
	 * @param mixed $content    Email body.
	 * @param mixed $email_data Email data.
	 * @return mixed
	 */
	public static function privacy_email( mixed $content, mixed $email_data = array() ): mixed {
		if ( ! is_string( $content ) || ! is_array( $email_data ) || ! isset( $email_data['confirm_url'] ) || ! LoginLocation::enabled() ) {
			return $content;
		}
		parse_str( (string) wp_parse_url( (string) $email_data['confirm_url'], PHP_URL_QUERY ), $args );
		if ( ! isset( $args['request_id'], $args['confirm_key'] ) || ! is_numeric( $args['request_id'] ) || ! is_string( $args['confirm_key'] ) ) {
			return $content;
		}
		$url = LoginLocation::raw_core_url(
			http_build_query(
				array(
					'action'      => 'confirmaction',
					'request_id'  => (int) $args['request_id'],
					'confirm_key' => $args['confirm_key'],
				)
			)
		);

		return str_replace( '###CONFIRM_URL###', esc_url_raw( $url ), $content );
	}

	/**
	 * Recovery mode is handled by core before plugins load (wp-settings.php runs
	 * wp_recovery_mode()->initialize() before the plugin loop), and only when $pagenow is
	 * wp-login.php, so its link must point at the real wp-login.php.
	 *
	 * @param mixed $url Recovery URL.
	 * @return mixed
	 */
	public static function recovery_url( mixed $url ): mixed {
		if ( ! is_string( $url ) || ! LoginLocation::enabled() ) {
			return $url;
		}

		return LoginLocation::raw_core_url( (string) wp_parse_url( $url, PHP_URL_QUERY ) );
	}

	/**
	 * Multisite new-site welcome email (default template names BLOG_URLwp-login.php).
	 *
	 * @param mixed $email   Email body.
	 * @param mixed $blog_id New site ID.
	 * @return mixed
	 */
	public static function welcome_email( mixed $email, mixed $blog_id = 0 ): mixed {
		if ( ! is_string( $email ) || ! is_numeric( $blog_id ) ) {
			return $email;
		}
		$slug = self::slug_for_site( (int) $blog_id );

		return null === $slug ? $email : str_replace( 'wp-login.php', $slug, $email );
	}

	/**
	 * Multisite new-user welcome email.
	 *
	 * @param mixed $email Email body.
	 * @return mixed
	 */
	public static function welcome_user_email( mixed $email ): mixed {
		if ( ! is_string( $email ) || ! LoginLocation::enabled() ) {
			return $email;
		}

		return str_replace( 'wp-login.php', LoginLocation::slug(), $email );
	}

	/**
	 * Replaces a wp-login.php URL with $base, keeping its query, unless the action must
	 * stay on wp-login.php or another filter already moved the URL.
	 *
	 * @param string $url  URL.
	 * @param string $path Requested path.
	 * @param string $base Login URL to use.
	 */
	private static function rewrite( string $url, string $path, string $base ): string {
		$path = ltrim( $path, '/' );
		if ( ! str_starts_with( $path, 'wp-login.php' ) || ! str_contains( $url, 'wp-login.php' ) ) {
			return $url;
		}
		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
		parse_str( $query, $args );
		if ( isset( $args['action'] ) && in_array( $args['action'], self::CORE_ACTIONS, true ) ) {
			return $url;
		}

		return '' !== $query ? $base . '?' . $query : $base;
	}

	/**
	 * Login URL of the main site when it runs this plugin with the login location on.
	 */
	private static function main_site_login_url(): ?string {
		$main = get_main_site_id();
		$slug = self::slug_for_site( $main );
		if ( null === $slug ) {
			return null;
		}

		return set_url_scheme( trailingslashit( get_home_url( $main ) ) . $slug, 'login' );
	}

	/**
	 * Slug of another site on the network, or null when the plugin or the login location
	 * is not active there.
	 *
	 * @param int $blog_id Site ID.
	 */
	private static function slug_for_site( int $blog_id ): ?string {
		if ( ! is_multisite() || get_current_blog_id() === $blog_id ) {
			return LoginLocation::enabled() ? LoginLocation::slug() : null;
		}
		$basename = plugin_basename( MDMFA_FILE );
		$network  = (array) get_site_option( 'active_sitewide_plugins', array() );
		$active   = isset( $network[ $basename ] ) || in_array( $basename, (array) get_blog_option( $blog_id, 'active_plugins', array() ), true );
		if ( ! $active || ( defined( 'MDMFA_DISABLE_LOGIN_LOCATION' ) && (bool) constant( 'MDMFA_DISABLE_LOGIN_LOCATION' ) ) ) {
			return null;
		}
		if ( defined( 'MDMFA_LOGIN_SLUG' ) ) {
			return LoginLocation::slug();
		}
		$option = get_blog_option( $blog_id, Options::LOGIN );
		if ( ! is_array( $option ) || empty( $option['enabled'] ) || ! isset( $option['slug'] ) || ! is_string( $option['slug'] ) ) {
			return null;
		}

		return $option['slug'];
	}
}
