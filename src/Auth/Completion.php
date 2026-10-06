<?php
/**
 * The only routine that creates a session for an MFA user (plan 4.4).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Claims the pending record (atomic single use), sets the auth cookie with the session
 * stamped `mdmfa => {verified_at, factor}`, clears user_activation_key and fires wp_login,
 * mirroring wp_signon() (wp-includes/user.php).
 */
final class Completion {

	/**
	 * True only while complete() calls wp_set_auth_cookie().
	 *
	 * @var bool
	 */
	private static bool $blessed = false;

	/**
	 * Factor to stamp on the session being created, or null for a grace skip.
	 *
	 * @var string|null
	 */
	private static ?string $factor = null;

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_filter( 'attach_session_information', array( self::class, 'stamp' ), 10, 1 );
	}

	/**
	 * Adds the verification stamp to a session created by complete(). WP_Session_Tokens
	 * only applies this filter when it creates a session (class-wp-session-tokens.php);
	 * re-issuing a cookie for an existing token does not, so stamps survive re-issue.
	 *
	 * @param mixed $session Session data.
	 * @return mixed
	 */
	public static function stamp( mixed $session ): mixed {
		if ( self::$blessed && null !== self::$factor && is_array( $session ) ) {
			$session['mdmfa'] = array(
				'verified_at' => Clock::now(),
				'factor'      => self::$factor,
			);
		}

		return $session;
	}

	/**
	 * Whether the current wp_set_auth_cookie() call comes from complete().
	 */
	public static function is_blessed(): bool {
		return self::$blessed;
	}

	/**
	 * Finishes a login. False when the record was already used (a concurrent request won).
	 *
	 * @param \WP_User      $user   User.
	 * @param string|null   $factor Factor that passed, or null for a grace skip.
	 * @param PendingRecord $record Pending record.
	 */
	public static function complete( \WP_User $user, ?string $factor, PendingRecord $record ): bool {
		global $wpdb;

		if ( $record->user_id !== $user->ID || ! PendingStore::claim( $record ) ) {
			return false;
		}
		PendingCookie::clear();
		HttpAuth::release();

		self::$blessed = true;
		self::$factor  = $factor;
		try {
			wp_set_auth_cookie( $user->ID, $record->flag( 'remember' ), $record->flag( 'secure' ) );
		} finally {
			self::$blessed = false;
			self::$factor  = null;
		}

		// Parity with wp_signon(): clear user_activation_key after a successful login.
		if ( ! empty( $user->user_activation_key ) ) {
			$wpdb->update( $wpdb->users, array( 'user_activation_key' => '' ), array( 'ID' => $user->ID ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- same write wp_signon() makes.
			$user->user_activation_key = '';
		}

		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired where wp_signon() would have fired it.

		if ( null !== $factor ) {
			if ( TrustedDevice::FACTOR !== $factor ) {
				EmailRecovery::cancel( $user->ID );
			}
			Lockout::reset( $user->ID );
			Logger::log( 'challenge_ok', $user->ID, $factor, $record->context() );
			do_action( 'mdmfa_login_completed', $user, $factor, $record->context() );
		} else {
			// No factor: a skip during the setup period, or a policy relaxed since the password step.
			Logger::log( Policy::GRACE === $record->string( 'decision' ) ? 'grace_skipped' : 'password_only', $user->ID, '', $record->context() );
		}

		return true;
	}

	/**
	 * Sends the browser on after complete(), and exits.
	 *
	 * @param \WP_User      $user   User.
	 * @param PendingRecord $record The claimed record.
	 * @return never
	 */
	public static function redirect( \WP_User $user, PendingRecord $record ): void {
		if ( $record->flag( 'interim' ) && function_exists( 'login_header' ) ) {
			self::interim_success();
		}
		if ( Context::CORE === $record->context() ) {
			self::core_redirect( $user, $record );
		}

		$account  = ChallengeUrl::account();
		$fallback = '' !== $account ? $account : home_url( '/' );
		$target   = $record->string( 'redirect_to' );
		if ( Context::WC === $record->context() ) {
			// Mirrors WC_Form_Handler::process_login(): the woocommerce_login_redirect
			// filter, minus the wc_error and password-reset args, validated to My Account.
			$target = '' !== $target ? $target : $fallback;
			$target = (string) apply_filters( 'woocommerce_login_redirect', $target, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce's filter, applied where its own login would have.
			$target = remove_query_arg( array( 'wc_error', 'password-reset' ), $target );
		}

		wp_safe_redirect( wp_validate_redirect( $target, $fallback ) );
		exit;
	}

	/**
	 * Mirrors wp-login.php's post-login redirect (the `login` case): default admin_url(),
	 * login_redirect filter, admin email confirmation, and the capability fallbacks.
	 *
	 * @param \WP_User      $user   User.
	 * @param PendingRecord $record The claimed record.
	 * @return never
	 */
	private static function core_redirect( \WP_User $user, PendingRecord $record ): void {
		$requested   = $record->string( 'redirect_to' );
		$redirect_to = '' !== $requested ? $requested : admin_url();
		if ( $record->flag( 'secure' ) && str_contains( $redirect_to, 'wp-admin' ) ) {
			$redirect_to = (string) preg_replace( '|^http://|', 'https://', $redirect_to );
		}
		$redirect_to = (string) apply_filters( 'login_redirect', $redirect_to, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, applied as wp-login.php does.

		if ( $user->has_cap( 'manage_options' ) ) {
			$lifespan = (int) get_option( 'admin_email_lifespan' );
			$interval = (int) apply_filters( 'admin_email_check_interval', 6 * MONTH_IN_SECONDS ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter, applied as wp-login.php does.
			if ( $interval > 0 && time() > $lifespan ) {
				$redirect_to = add_query_arg(
					array(
						'action'  => 'confirm_admin_email',
						'wp_lang' => get_user_locale( $user ),
					),
					wp_login_url( $redirect_to )
				);
			}
		}

		if ( '' === $redirect_to || 'wp-admin/' === $redirect_to || admin_url() === $redirect_to ) {
			if ( is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ) {
				$redirect_to = user_admin_url();
			} elseif ( is_multisite() && ! $user->has_cap( 'read' ) ) {
				$redirect_to = get_dashboard_url( $user->ID );
			} elseif ( ! $user->has_cap( 'edit_posts' ) ) {
				$redirect_to = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
			}
			wp_redirect( $redirect_to ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- same call wp-login.php makes; every branch is a local URL.
			exit;
		}

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * The interim-login success page (the wp-auth-check modal), as wp-login.php renders it.
	 *
	 * @return never
	 */
	private static function interim_success(): void {
		$GLOBALS['interim_login'] = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php's own global; login_header() reads it.
		login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'maxtdesign-mfa' ) . '</p>' );
		echo '</div>';
		do_action( 'login_footer' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired exactly as wp-login.php does here.
		echo '</body></html>';
		exit;
	}
}
