<?php
/**
 * Email recovery (plan 11.2 step 3): a user who lost every factor can reset them through
 * their mailbox. Only offered on the challenge screen, after the password, so it reveals
 * nothing about accounts. Off for staff roles by default; staff wait 24 hours.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Flow;

use MaxtDesign\Mfa\Auth\FormToken;
use MaxtDesign\Mfa\Auth\PendingRecord;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\Reset;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Notify\Mailer;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;
use MaxtDesign\Mfa\Support\IpThrottle;

defined( 'ABSPATH' ) || exit;

/**
 * Request (from the challenge), confirmation (the emailed link: a GET that changes
 * nothing, then a POST), waiting period, reset.
 */
final class EmailRecovery {

	public const KIND   = 'recovery_link';
	public const ACTION = 'mdmfa_recover';
	public const TTL    = HOUR_IN_SECONDS;

	/** Email recovery stays closed this long after the account's address changes. */
	public const ADDRESS_COOLDOWN = DAY_IN_SECONDS;

	/** User meta: unix time a confirmed reset takes effect. */
	public const META = 'mdmfa_recovery_pending';

	/**
	 * Registers hooks. admin-post.php is a neutral address: not the login slug, not
	 * wp-login.php, and reachable when logged out.
	 */
	public static function register(): void {
		add_action( 'admin_post_nopriv_' . self::ACTION, array( self::class, 'handle' ) );
		add_action( 'admin_post_' . self::ACTION, array( self::class, 'handle' ) );
	}

	/**
	 * Whether the user's role allows email recovery.
	 *
	 * @param \WP_User $user User.
	 */
	public static function allowed( \WP_User $user ): bool {
		// A mailbox that changed in the last day proves nothing about the account's owner.
		$changed = (int) get_user_meta( $user->ID, EmailCode::CHANGED, true );
		if ( $changed > Clock::now() - self::ADDRESS_COOLDOWN ) {
			return false;
		}

		return ! empty( Policy::effective( $user )['email_recovery'] ) && false !== is_email( $user->user_email );
	}

	/**
	 * Mails the recovery link. Called from the challenge, so the password already passed.
	 *
	 * @param \WP_User $user    User.
	 * @param string   $context Login context, for the log.
	 * @return bool False when a limit stopped the send.
	 */
	public static function request( \WP_User $user, string $context ): bool {
		if ( ! self::allowed( $user ) || ! IpThrottle::allow( 'recovery' ) || ! EmailCode::take_send_slot( $user->ID ) ) {
			return false;
		}
		$token = PendingStore::create( $user->ID, self::KIND, array( 'context' => $context ), self::TTL );
		$url   = add_query_arg(
			array(
				'action' => self::ACTION,
				't'      => $token,
			),
			admin_url( 'admin-post.php' )
		);
		Logger::log( 'recovery_requested', $user->ID, 'email', $context );

		return Mailer::recovery_link( $user, $url );
	}

	/**
	 * The emailed link: GET shows a confirmation, POST confirms.
	 */
	public static function handle(): void {
		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );
		header( 'X-Robots-Tag: noindex, nofollow' );

		// phpcs:disable WordPress.Security.NonceVerification -- logged-out flow; the POST is bound to the single-use link token by FormToken.
		$token  = isset( $_REQUEST['t'] ) && is_string( $_REQUEST['t'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['t'] ) ) : '';
		$form   = isset( $_POST['mdmfa_form'] ) && is_string( $_POST['mdmfa_form'] ) ? sanitize_text_field( wp_unslash( $_POST['mdmfa_form'] ) ) : null;
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		// phpcs:enable

		$invalid = __( 'This recovery link is not valid any more. Sign in again and ask for a new one.', 'maxtdesign-mfa' );
		$record  = PendingStore::find( $token, self::KIND );
		$user    = null === $record ? false : get_userdata( $record->user_id );
		if ( null === $record || ! $user instanceof \WP_User || ! self::allowed( $user ) ) {
			self::page( $invalid, 403 );
		}

		if ( 'POST' !== $method ) {
			self::confirm_page( $record, $token );
		}
		if ( ! FormToken::check( $form, $record->token_hash, 'recover-confirm' ) || ! PendingStore::claim( $record ) ) {
			self::page( $invalid, 403 );
		}

		$hours    = Policy::effective( $user )['recovery_wait_hours'] ?? 0;
		$wait     = ( is_int( $hours ) ? max( 0, $hours ) : 0 ) * HOUR_IN_SECONDS;
		$ready_at = Clock::now() + $wait;
		Logger::log( 'recovery_confirmed', $user->ID, 'email', $record->context() );
		Mailer::recovery_confirmed( $user, $ready_at, $wait > 0, $user->has_cap( 'edit_posts' ) );

		if ( 0 === $wait ) {
			self::apply( $user );
			self::page( __( 'Two-step verification was reset for your account. Sign in with your password; you can set it up again afterwards.', 'maxtdesign-mfa' ), 200, true );
		}
		update_user_meta( $user->ID, self::META, $ready_at );
		self::page(
			sprintf(
				/* translators: %s: human-readable waiting time, for example "24 hours". */
				__( 'Confirmed. For your security, two-step verification will be reset in %s. After that, sign in with your password.', 'maxtdesign-mfa' ),
				human_time_diff( Clock::now(), $ready_at )
			),
			200,
			true
		);
	}

	/**
	 * Applies a confirmed reset whose waiting period is over. Called at the password step.
	 *
	 * @param \WP_User $user User.
	 */
	public static function maybe_apply( \WP_User $user ): void {
		$ready_at = (int) get_user_meta( $user->ID, self::META, true );
		if ( $ready_at > 0 && $ready_at <= Clock::now() ) {
			self::apply( $user );
		}
	}

	/**
	 * A sign-in that passed the second step proves the owner still has a factor: any
	 * waiting reset is cancelled.
	 *
	 * @param int $user_id User ID.
	 */
	public static function cancel( int $user_id ): void {
		if ( '' !== (string) get_user_meta( $user_id, self::META, true ) ) {
			delete_user_meta( $user_id, self::META );
			Logger::log( 'recovery_cancelled', $user_id, 'email' );
		}
	}

	/**
	 * Resets the user's factors.
	 *
	 * @param \WP_User $user User.
	 */
	private static function apply( \WP_User $user ): void {
		Reset::all( $user->ID );
		Logger::log( 'recovery_reset', $user->ID, 'email' );
		do_action( 'mdmfa_factor_removed', $user, 'all', $user->ID );
	}

	/**
	 * The confirmation page: nothing changes until the button is pressed, so mail
	 * scanners that open links cannot trigger a reset.
	 *
	 * @param PendingRecord $record Link record.
	 * @param string        $token  Raw link token.
	 * @return never
	 */
	private static function confirm_page( PendingRecord $record, string $token ): void {
		$html = sprintf(
			'<p>%1$s</p><form method="post" action="%2$s"><input type="hidden" name="action" value="%3$s"><input type="hidden" name="t" value="%4$s"><input type="hidden" name="mdmfa_form" value="%5$s"><p><button type="submit" class="button button-large">%6$s</button></p></form>',
			esc_html__( 'Reset two-step verification for your account? Your authenticator app, passkeys and recovery codes will be removed.', 'maxtdesign-mfa' ),
			esc_url( admin_url( 'admin-post.php' ) ),
			esc_attr( self::ACTION ),
			esc_attr( $token ),
			esc_attr( FormToken::make( $record->token_hash, 'recover-confirm' ) ),
			esc_html__( 'Yes, reset it', 'maxtdesign-mfa' )
		);
		wp_die( $html, esc_html__( 'Reset two-step verification', 'maxtdesign-mfa' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
	}

	/**
	 * A plain result page.
	 *
	 * @param string $message Plain text.
	 * @param int    $status  HTTP status.
	 * @param bool   $login   Whether to link to the sign-in page.
	 * @return never
	 */
	private static function page( string $message, int $status, bool $login = false ): void {
		// Never the slug: this page is shown to a logged-out visitor.
		$html = '<p>' . esc_html( $message ) . '</p>';
		if ( $login ) {
			$html .= sprintf( '<p><a href="%1$s">%2$s</a></p>', esc_url( LoginLocation::enabled() ? LoginLocation::public_url() : wp_login_url() ), esc_html__( 'Sign in', 'maxtdesign-mfa' ) );
		}
		wp_die( $html, esc_html__( 'Two-step verification', 'maxtdesign-mfa' ), array( 'response' => $status ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
	}
}
