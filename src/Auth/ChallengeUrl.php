<?php
/**
 * Where the second step lives (plan 4.3). Customer-side contexts (the WooCommerce login
 * form, front-end login forms, other plugins' forms, and direct cookie issuers heading to
 * a front-end page) finish on WooCommerce My Account when it exists, so customers never
 * see wp-login.php. Everything else uses the core login screen. P4 adds the moved login
 * address.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Auth;

use MaxtDesign\Mfa\Policy\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Challenge and enrollment URLs.
 */
final class ChallengeUrl {

	public const ACTION_VERIFY = 'mdmfa-verify';
	public const ACTION_ENROLL = 'mdmfa-enroll';

	/** Contexts whose challenge belongs on My Account when WooCommerce provides one. */
	private const CUSTOMER_CONTEXTS = array( Context::WC, Context::FRONTEND, Context::UNKNOWN_POST, Context::AJAX, 'guard' );

	/**
	 * URL for a decision.
	 *
	 * @param string $decision Policy decision.
	 * @param string $context  Login context.
	 * @param string $target   Where the login was heading (the guard passes the caller's redirect).
	 */
	public static function for_decision( string $decision, string $context, string $target = '' ): string {
		$action  = Policy::CHALLENGE === $decision ? self::ACTION_VERIFY : self::ACTION_ENROLL;
		$account = self::account();
		$url     = '' !== $account && self::belongs_on_account( $context, $target ) ? $account : self::core( $action );
		$url     = apply_filters( 'mdmfa_challenge_url', $url, $decision, $context );

		return is_string( $url ) && '' !== $url ? $url : self::core( $action );
	}

	/**
	 * A wp-login.php action URL.
	 *
	 * @param string                $action Login action.
	 * @param array<string, string> $args   Extra query args.
	 */
	public static function core( string $action, array $args = array() ): string {
		return add_query_arg( array_merge( array( 'action' => $action ), $args ), site_url( 'wp-login.php', 'login' ) );
	}

	/**
	 * The WooCommerce My Account URL, or '' when WooCommerce or the page is missing.
	 */
	public static function account(): string {
		if ( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'wc_get_page_permalink' ) || wc_get_page_id( 'myaccount' ) <= 0 ) {
			return '';
		}

		return (string) wc_get_page_permalink( 'myaccount' );
	}

	/**
	 * Whether a login in this context finishes on My Account. A direct cookie issuer
	 * heading into wp-admin (for example an SSO for staff) keeps the core screen.
	 *
	 * @param string $context Login context.
	 * @param string $target  Destination, when known.
	 */
	private static function belongs_on_account( string $context, string $target ): bool {
		if ( ! in_array( $context, self::CUSTOMER_CONTEXTS, true ) ) {
			return false;
		}

		return 'guard' !== $context || ! str_starts_with( $target, admin_url() );
	}
}
