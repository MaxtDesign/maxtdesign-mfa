<?php
/**
 * Changing the login slug (plan 5.4): validate, save, purge caches for the old and new
 * URLs, tell every administrator, log it (without the slug), fire mdmfa_login_slug_changed.
 * The admin screen (P7) calls this behind step-up; WP-CLI calls it with server access.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Location;

use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Settings\LoginSlug;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Slug lifecycle.
 */
final class SlugChanger {

	/**
	 * Sets a new slug.
	 *
	 * @param string   $raw   Owner input, or '' for a fresh random slug.
	 * @param int|null $actor Acting user ID, or null for WP-CLI.
	 * @return string|\WP_Error The new slug.
	 */
	public static function change( string $raw, ?int $actor ): string|\WP_Error {
		$slug = '' === $raw ? LoginSlug::generate() : LoginSlug::validate( $raw );
		if ( $slug instanceof \WP_Error ) {
			return $slug;
		}

		$option = get_option( Options::LOGIN );
		$option = is_array( $option ) ? $option : Settings::login_defaults();
		$old    = LoginLocation::enabled() ? LoginLocation::url() : '';

		$option['slug'] = $slug;
		update_option( Options::LOGIN, $option, true );

		$new = LoginLocation::url();
		CacheBridge::purge( array_filter( array( $old, $new ) ) );

		$notices                 = get_option( Options::NOTICES, array() );
		$notices                 = is_array( $notices ) ? $notices : array();
		$notices['slug_changed'] = Clock::now();
		update_option( Options::NOTICES, $notices, false );

		self::notify_admins( $new );
		Logger::log( 'slug_changed', null, '', null === $actor ? 'cli' : 'admin', $actor );
		do_action( 'mdmfa_login_slug_changed' );

		return $slug;
	}

	/**
	 * Emails every administrator the new login address.
	 *
	 * @param string $url New login URL.
	 */
	private static function notify_admins( string $url ): void {
		$site    = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] The login address changed', 'maxtdesign-mfa' ),
			$site
		);
		$body = sprintf(
			/* translators: %s: new login URL. */
			__( "The login address for this site changed. Log in here from now on:\n\n%s\n\nThe old address no longer works. Keep this email somewhere safe: if you lose the address, a server administrator can print it with `wp mdmfa slug get`.", 'maxtdesign-mfa' ),
			$url
		);
		$admins = get_users(
			array(
				'capability' => 'manage_options',
				'fields'     => array( 'user_email' ),
			)
		);
		foreach ( $admins as $admin ) {
			if ( isset( $admin->user_email ) && is_email( $admin->user_email ) ) {
				wp_mail( $admin->user_email, $subject, $body );
			}
		}
	}
}
