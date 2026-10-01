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

	/**
	 * Sends a sign-in code. The only message that carries a code; it never names the
	 * login address.
	 *
	 * @param \WP_User $user User.
	 * @param string   $code Six digits.
	 */
	public static function email_code( \WP_User $user, string $code ): bool {
		$message  = array(
			/* translators: 1: site name, 2: the code. */
			'subject' => sprintf( __( '[%1$s] Your sign-in code: %2$s', 'maxtdesign-mfa' ), self::site(), $code ),
			'body'    => sprintf(
				/* translators: 1: the code, 2: minutes it stays valid. */
				__( "Your sign-in code is %1\$s. It works for %2\$d minutes and only once.\n\nIf you did not try to sign in, someone knows your password. Change it now.", 'maxtdesign-mfa' ),
				$code,
				10
			),
		);
		$filtered = apply_filters( 'mdmfa_email_code_message', $message, $user, $code );
		if ( is_array( $filtered ) && isset( $filtered['subject'], $filtered['body'] ) && is_string( $filtered['subject'] ) && is_string( $filtered['body'] ) ) {
			$message = $filtered;
		}

		return (bool) wp_mail( $user->user_email, $message['subject'], $message['body'] );
	}

	/**
	 * Sends the email-recovery link.
	 *
	 * @param \WP_User $user User.
	 * @param string   $url  Single-use link.
	 */
	public static function recovery_link( \WP_User $user, string $url ): bool {
		return (bool) wp_mail(
			$user->user_email,
			/* translators: %s: site name. */
			sprintf( __( '[%s] Reset your two-step verification', 'maxtdesign-mfa' ), self::site() ),
			sprintf(
				/* translators: 1: username, 2: link. */
				__( "Someone who knows the password of the account %1\$s asked to reset its two-step verification.\n\nIf that was you, open this link within one hour:\n%2\$s\n\nIf it was not you, do not open the link, and change your password now.", 'maxtdesign-mfa' ),
				$user->user_login,
				$url
			)
		);
	}

	/**
	 * Tells the user (and the site admin, for staff accounts) that a recovery was confirmed.
	 *
	 * @param \WP_User $user     User.
	 * @param int      $ready_at Unix time the reset takes effect.
	 * @param bool     $waiting  Whether a waiting period applies.
	 * @param bool     $staff    Whether to copy the site admin.
	 */
	public static function recovery_confirmed( \WP_User $user, int $ready_at, bool $waiting, bool $staff ): void {
		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] Two-step verification reset requested', 'maxtdesign-mfa' ), self::site() );
		$body    = $waiting
			? sprintf(
				/* translators: 1: username, 2: date and time. */
				__( "Two-step verification for the account %1\$s will be reset on %2\$s, after a waiting period.\n\nIf you did not ask for this, sign in with your usual second step before then. That cancels the reset. Then change your password.", 'maxtdesign-mfa' ),
				$user->user_login,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ready_at )
			)
			: sprintf(
				/* translators: %s: username. */
				__( "Two-step verification for the account %s was reset through the email recovery link. It can be set up again after signing in.\n\nIf you did not do this, change your account password and your email password now, and contact the site administrator.", 'maxtdesign-mfa' ),
				$user->user_login
			);

		$to = array( $user->user_email );
		if ( $staff ) {
			$to[] = (string) get_option( 'admin_email' );
		}
		foreach ( array_unique( array_filter( $to, static fn ( string $email ): bool => false !== is_email( $email ) ) ) as $address ) {
			wp_mail( $address, $subject, $body );
		}
	}

	/**
	 * Site name for subjects.
	 */
	private static function site(): string {
		return wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
	}
}
