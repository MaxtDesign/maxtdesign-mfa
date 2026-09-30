<?php
/**
 * Where the second step lives. P2: the core login screen. P3 adds My Account for WC
 * contexts and P4 the moved login address.
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

	/**
	 * URL for a decision.
	 *
	 * @param string $decision Policy decision.
	 * @param string $context  Login context.
	 */
	public static function for_decision( string $decision, string $context ): string {
		$action = Policy::CHALLENGE === $decision ? self::ACTION_VERIFY : self::ACTION_ENROLL;
		$url    = self::core( $action );
		$url    = apply_filters( 'mdmfa_challenge_url', $url, $decision, $context );

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
}
