<?php
/**
 * Daily purge and account-deletion cleanup (plan 6.4, 6.6).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Install;

use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Cron and user-deletion handlers.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own credentials table; deletes by user.
 */
final class Maintenance {

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( Options::CRON_PURGE, array( self::class, 'purge' ) );
		// On a network wp_delete_user() only removes the user from one site and still
		// fires deleted_user; their passkeys go when the account itself is deleted.
		if ( is_multisite() ) {
			add_action( 'wpmu_delete_user', array( self::class, 'user_deleted' ) );
		} else {
			add_action( 'deleted_user', array( self::class, 'user_deleted' ) );
		}
	}

	/**
	 * Schedules the daily purge if it is not scheduled (the cron array is autoloaded).
	 */
	public static function schedule(): void {
		if ( false === wp_next_scheduled( Options::CRON_PURGE ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', Options::CRON_PURGE );
		}
	}

	/**
	 * Unschedules the purge (deactivation). No data is removed.
	 */
	public static function unschedule(): void {
		wp_clear_scheduled_hook( Options::CRON_PURGE );
	}

	/**
	 * Deletes expired pending records and log rows past retention.
	 */
	public static function purge(): void {
		PendingStore::purge_expired();
		Logger::purge();
	}

	/**
	 * Removes a deleted user's pending records and passkeys. User meta is removed by core;
	 * log rows stay until retention or the privacy eraser.
	 *
	 * @param mixed $user_id Deleted user ID.
	 */
	public static function user_deleted( mixed $user_id ): void {
		global $wpdb;

		if ( ! is_numeric( $user_id ) ) {
			return;
		}
		PendingStore::delete_for_user( (int) $user_id );
		$wpdb->delete( Schema::credentials_table( $wpdb ), array( 'user_id' => (int) $user_id ), array( '%d' ) );
	}
}
