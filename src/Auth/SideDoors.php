<?php
/**
 * Ways in that skip the login form (plan 4.3): application passwords and XML-RPC.
 * Non-interactive password logins (REST token plugins, XML-RPC) are refused by the
 * Interceptor; this class applies the owner's policy to the rest.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Application-password and XML-RPC policy.
 */
final class SideDoors {

	public const APP_OFF      = 'off';
	public const APP_PER_ROLE = 'per_role';
	public const APP_ON       = 'on';

	public const XMLRPC_OFF   = 'off';
	public const XMLRPC_BLOCK = 'block_password';
	public const XMLRPC_ALLOW = 'allow';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'wp_is_application_passwords_available', array( self::class, 'app_passwords_available' ), 20 );
		add_filter( 'wp_is_application_passwords_available_for_user', array( self::class, 'app_passwords_for_user' ), 20, 2 );
		add_action( 'application_password_did_authenticate', array( self::class, 'log_app_password' ), 10, 2 );
		add_filter( 'rest_request_before_callbacks', array( self::class, 'guard_app_password_rest' ), 10, 3 );
		add_action( 'wp_authorize_application_password_request_errors', array( self::class, 'guard_app_password_authorize' ), 10, 3 );
		add_action( 'load-authorize-application.php', array( self::class, 'guard_app_password_authorize_post' ), 0 );
		add_action( 'wp_create_application_password', array( self::class, 'log_app_password_created' ), 10, 1 );
		add_filter( 'xmlrpc_enabled', array( self::class, 'xmlrpc_enabled' ), 20 );
		add_filter( 'xmlrpc_login_error', array( self::class, 'xmlrpc_login_error' ), 20, 2 );
	}

	/**
	 * Application-password mode: off, per_role or on.
	 */
	public static function app_password_mode(): string {
		$mode = Settings::get()['application_passwords'];

		return is_string( $mode ) && in_array( $mode, array( self::APP_OFF, self::APP_PER_ROLE, self::APP_ON ), true ) ? $mode : self::APP_PER_ROLE;
	}

	/**
	 * XML-RPC mode: off, block_password or allow.
	 */
	public static function xmlrpc_mode(): string {
		$mode = Settings::get()['xmlrpc'];

		return is_string( $mode ) && in_array( $mode, array( self::XMLRPC_OFF, self::XMLRPC_BLOCK, self::XMLRPC_ALLOW ), true ) ? $mode : self::XMLRPC_BLOCK;
	}

	/**
	 * Global switch. Never turns the feature on where core or another plugin turned it off.
	 *
	 * @param mixed $available Core's value.
	 * @return mixed
	 */
	public static function app_passwords_available( mixed $available ): mixed {
		// Core asks this on every request while it works out the current user
		// (wp_validate_application_password). Settings are not autoloaded, so they are
		// read only where the answer matters: a request that carries credentials, or an
		// admin, REST, XML-RPC or WP-CLI request. A plain page view costs no query.
		if ( ! $available || ! self::answer_matters() ) {
			return $available;
		}

		return self::APP_OFF === self::app_password_mode() ? false : $available;
	}

	/**
	 * Whether this request can use or manage application passwords.
	 */
	private static function answer_matters(): bool {
		return isset( $_SERVER['PHP_AUTH_USER'] )
			|| is_admin()
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * Per-role switch: roles whose policy is Required have no application passwords unless
	 * the owner allows them for that role. On a network an application password works on
	 * every site, so every site the user belongs to must allow it, whatever this site's
	 * mode is (Policy::effective() folds each site's mode in).
	 *
	 * @param mixed $available Core's value.
	 * @param mixed $user      User.
	 * @return mixed
	 */
	public static function app_passwords_for_user( mixed $available, mixed $user = null ): mixed {
		if ( ! $available || ! $user instanceof \WP_User || ( ! is_multisite() && self::APP_PER_ROLE !== self::app_password_mode() ) ) {
			return $available;
		}

		return ! empty( Policy::effective( $user )['app_passwords'] );
	}

	/**
	 * Logs application-password use, at most once an hour per password.
	 *
	 * @param mixed $user User.
	 * @param mixed $item Application password record.
	 */
	public static function log_app_password( mixed $user, mixed $item = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$uuid = is_array( $item ) && isset( $item['uuid'] ) && is_string( $item['uuid'] ) ? $item['uuid'] : '';
		$key  = 'mdmfa_apppass_' . substr( hash( 'sha256', $user->ID . '|' . $uuid ), 0, 24 );
		if ( false !== get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, HOUR_IN_SECONDS );
		Logger::log( 'app_password_used', $user->ID, '', Context::APPPASS, null, substr( $uuid, 0, 36 ) );
	}

	/**
	 * Creating an application password over REST needs a fresh verification (step-up) for
	 * users who have a second factor.
	 *
	 * @param mixed $response Response so far.
	 * @param mixed $handler  Route handler.
	 * @param mixed $request  Request.
	 * @return mixed
	 */
	public static function guard_app_password_rest( mixed $response, mixed $handler = null, mixed $request = null ): mixed {
		// The handler decides, not the URL: core matches routes case-insensitively, and
		// another route could reuse the controller.
		$callback = is_array( $handler ) && isset( $handler['callback'] ) ? $handler['callback'] : null;
		$creates  = is_array( $callback ) && isset( $callback[0], $callback[1] )
			&& $callback[0] instanceof \WP_REST_Application_Passwords_Controller && 'create_item' === $callback[1];
		if ( is_wp_error( $response ) || ! $request instanceof \WP_REST_Request || ! $creates ) {
			return $response;
		}
		$message = self::app_password_stepup_error();

		return null === $message ? $response : new \WP_Error( 'mdmfa_stepup_required', $message, array( 'status' => 403 ) );
	}

	/**
	 * The same rule for wp-admin/authorize-application.php.
	 *
	 * @param mixed $error   Error object to add to.
	 * @param mixed $request Request details (unused).
	 * @param mixed $user    User authorizing the application.
	 */
	public static function guard_app_password_authorize( mixed $error, mixed $request = null, mixed $user = null ): void {
		unset( $request, $user );
		$message = self::app_password_stepup_error();
		if ( $error instanceof \WP_Error && null !== $message ) {
			$error->add( 'mdmfa_stepup_required', $message );
		}
	}

	/**
	 * The authorize screen creates the password on POST without re-running the check
	 * above, so the POST is refused here when the verification is not recent.
	 */
	public static function guard_app_password_authorize_post(): void {
		$method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		$message = 'POST' === $method ? self::app_password_stepup_error() : null;
		if ( null !== $message ) {
			wp_die( esc_html( $message ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Logs every new application password: it is a credential that skips the second step.
	 *
	 * @param mixed $user_id Owner of the new password.
	 */
	public static function log_app_password_created( mixed $user_id ): void {
		if ( is_numeric( $user_id ) ) {
			Logger::log( 'app_password_created', (int) $user_id, '', Context::APPPASS, get_current_user_id() > 0 ? get_current_user_id() : null );
		}
	}

	/**
	 * XML-RPC "off" disables every authenticated method.
	 *
	 * @param mixed $enabled Core's value.
	 * @return mixed
	 */
	public static function xmlrpc_enabled( mixed $enabled ): mixed {
		return self::XMLRPC_OFF === self::xmlrpc_mode() ? false : $enabled;
	}

	/**
	 * Says why a password was refused over XML-RPC instead of "incorrect password".
	 *
	 * @param mixed $error IXR_Error.
	 * @param mixed $user  The WP_Error from authentication.
	 * @return mixed
	 */
	public static function xmlrpc_login_error( mixed $error, mixed $user = null ): mixed {
		if ( $user instanceof \WP_Error && 'mdmfa_required' === $user->get_error_code() && class_exists( '\IXR_Error' ) ) {
			return new \IXR_Error( 403, __( 'This account uses two-step verification, so its password cannot be used here. Use an application password instead.', 'maxtdesign-mfa' ) );
		}

		return $error;
	}

	/**
	 * The step-up message when the current user must verify first, or null.
	 */
	private static function app_password_stepup_error(): ?string {
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! Policy::is_enrolled( $user->ID ) || StepUp::is_fresh( $user->ID ) ) {
			return null;
		}

		return __( 'Confirm it is you on your security page first, then create the application password within 10 minutes.', 'maxtdesign-mfa' );
	}
}
