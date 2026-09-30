<?php
/**
 * Security notifications through the site's own wp_mail().
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Notify;

defined( 'ABSPATH' ) || exit;

/**
 * Plain-text notices. They never include codes, secrets or the login address.
 */
final class Mailer {

	/**
	 * Tells the user and the site admin that an account's second factor is locked.
	 *
	 * @param \WP_User $user  Locked user.
	 * @param int      $until Unix time the lock ends.
	 */
	public static function locked( \WP_User $user, int $until ): void {
		$site = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$when = wp_date( (string) get_option( 'time_format' ), $until );

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] Sign-in locked after failed verification codes', 'maxtdesign-mfa' ), $site );
		$body    = sprintf(
			/* translators: 1: username, 2: time the lock ends. */
			__( "Too many wrong verification codes were entered for the account %1\$s, so two-step verification for it is locked until %2\$s.\n\nWhoever entered them already knew the password. If this was not you, change your password now.", 'maxtdesign-mfa' ),
			$user->user_login,
			$when
		);

		$recipients = array_unique( array_filter( array( $user->user_email, (string) get_option( 'admin_email' ) ), static fn ( string $email ): bool => false !== is_email( $email ) ) );
		foreach ( $recipients as $to ) {
			wp_mail( $to, $subject, $body );
		}
	}

	/**
	 * Tells a user an administrator reset their two-step verification.
	 *
	 * @param \WP_User $user Affected user.
	 */
	public static function factors_reset( \WP_User $user ): void {
		if ( ! is_email( $user->user_email ) ) {
			return;
		}
		$site = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		wp_mail(
			$user->user_email,
			/* translators: %s: site name. */
			sprintf( __( '[%s] Your two-step verification was reset', 'maxtdesign-mfa' ), $site ),
			sprintf(
				/* translators: %s: username. */
				__( "An administrator reset two-step verification for your account %s. You will be asked to set it up again the next time you sign in.\n\nIf you did not ask for this, contact the site administrator.", 'maxtdesign-mfa' ),
				$user->user_login
			)
		);
	}
}
