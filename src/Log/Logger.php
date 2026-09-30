<?php
/**
 * Activity log (plan 6.1 mdmfa_log). Never stores secrets, codes or the login slug.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Log;

use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Writes and purges log rows.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own log table; writes are the point and nothing is cached.
 */
final class Logger {

	/**
	 * Adds a row. Failures are swallowed: logging must never break a login.
	 *
	 * @param string   $event   Event name (enrolled, challenge_ok, challenge_fail, locked, ...).
	 * @param int|null $user_id Subject user.
	 * @param string   $factor  Factor involved.
	 * @param string   $context Login context (core, wc, guard, admin, cli, ...).
	 * @param int|null $actor   User who acted, when not the subject.
	 * @param string   $detail  Short non-secret detail (for example the bypass source).
	 */
	public static function log( string $event, ?int $user_id, string $factor = '', string $context = '', ?int $actor = null, string $detail = '' ): void {
		global $wpdb;

		$wpdb->insert(
			Schema::site_tables( $wpdb )['log'],
			array(
				'user_id'    => $user_id,
				'event'      => substr( $event, 0, 32 ),
				'factor'     => substr( $factor, 0, 16 ),
				'context'    => substr( $context, 0, 16 ),
				'ip'         => self::ip(),
				'actor_id'   => $actor,
				'detail'     => substr( $detail, 0, 64 ),
				'created_at' => Clock::now(),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);
	}

	/**
	 * Deletes rows older than the retention setting.
	 *
	 * @return int Rows deleted.
	 */
	public static function purge(): int {
		global $wpdb;

		$settings = Settings::get();
		$days     = is_int( $settings['log_retention_days'] ) ? max( 1, $settings['log_retention_days'] ) : 90;
		$deleted  = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE created_at < %d',
				Schema::site_tables( $wpdb )['log'],
				Clock::now() - $days * DAY_IN_SECONDS
			)
		);

		return is_int( $deleted ) ? $deleted : 0;
	}

	/**
	 * Client address as packed binary, truncated unless the owner opted into full IPs
	 * (plan decision 11: /24 for IPv4, /48 for IPv6). Only REMOTE_ADDR is trusted;
	 * forwarded headers are client-controlled.
	 */
	public static function ip(): ?string {
		$raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( false === filter_var( $raw, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$packed = inet_pton( $raw );
		if ( false === $packed ) {
			return null;
		}
		$settings = Settings::get();
		if ( 'full' === $settings['log_ip_mode'] ) {
			return $packed;
		}

		return self::truncate( $packed );
	}

	/**
	 * Zeroes the host part of a packed address.
	 *
	 * @param string $packed 4 or 16 byte packed address.
	 */
	public static function truncate( string $packed ): string {
		$keep = 4 === strlen( $packed ) ? 3 : 6;

		return substr( $packed, 0, $keep ) . str_repeat( "\0", strlen( $packed ) - $keep );
	}
}
