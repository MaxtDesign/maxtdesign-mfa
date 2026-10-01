<?php
/**
 * Privacy tools (plan 6.6): suggested policy text, personal-data exporter and eraser.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Privacy;

use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Install\Schema;

defined( 'ABSPATH' ) || exit;

/**
 * Exports what the plugin holds about a person, never secrets: the export goes to a
 * mailbox. Erases the activity log rows; factor data goes when the account is deleted.
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own log table, by user.
 */
final class Privacy {

	public const PAGE_SIZE = 200;

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'admin_init', array( self::class, 'policy_text' ) );
		add_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'exporters' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'erasers' ) );
	}

	/**
	 * Suggested text for the site's privacy policy.
	 */
	public static function policy_text(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$text  = '<p>' . esc_html__( 'This site uses two-step verification to protect accounts. If you turn it on, we store what is needed to check your second step: an encrypted authenticator key, the public part of your passkeys with the name you gave them and when they were last used, hashed recovery codes, and whether email codes are on. We never store a passkey\'s private part; it stays on your device.', 'maxtdesign-mfa' ) . '</p>';
		$text .= '<p>' . esc_html__( 'We keep a security log of sign-ins with a second step, setup changes and failed attempts, with the date, the account and a shortened network address. Entries are deleted after 90 days unless the site owner chose a different period.', 'maxtdesign-mfa' ) . '</p>';
		$text .= '<p>' . esc_html__( 'Two cookies are set, both strictly necessary for signing in: "mdmfa_pending" holds your place between the password and the second step and is removed when you finish or close the browser; "mdmfa_td" is set only if you choose "do not ask again on this device" and lasts 30 days unless the site owner chose a different period.', 'maxtdesign-mfa' ) . '</p>';
		$text .= '<p>' . esc_html__( 'None of this information is sent to any other service.', 'maxtdesign-mfa' ) . '</p>';

		wp_add_privacy_policy_content( 'MaxtDesign MFA', wp_kses_post( $text ) );
	}

	/**
	 * Registers the exporter.
	 *
	 * @param mixed $exporters Exporters.
	 * @return mixed
	 */
	public static function exporters( mixed $exporters ): mixed {
		if ( is_array( $exporters ) ) {
			$exporters['maxtdesign-mfa'] = array(
				'exporter_friendly_name' => __( 'MaxtDesign MFA', 'maxtdesign-mfa' ),
				'callback'               => array( self::class, 'export' ),
			);
		}

		return $exporters;
	}

	/**
	 * Registers the eraser.
	 *
	 * @param mixed $erasers Erasers.
	 * @return mixed
	 */
	public static function erasers( mixed $erasers ): mixed {
		if ( is_array( $erasers ) ) {
			$erasers['maxtdesign-mfa'] = array(
				'eraser_friendly_name' => __( 'MaxtDesign MFA', 'maxtdesign-mfa' ),
				'callback'             => array( self::class, 'erase' ),
			);
		}

		return $erasers;
	}

	/**
	 * Exports the person's methods, passkey names and dates, and log rows.
	 *
	 * @param mixed $email Email address.
	 * @param mixed $page  Page, from 1.
	 * @return array{data: array<int, array<string, mixed>>, done: bool}
	 */
	public static function export( mixed $email, mixed $page = 1 ): array {
		global $wpdb;

		$user = is_string( $email ) ? get_user_by( 'email', $email ) : false;
		if ( ! $user instanceof \WP_User ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}
		$page = max( 1, (int) $page );
		$data = array();

		if ( 1 === $page ) {
			$data[] = array(
				'group_id'    => 'mdmfa-methods',
				'group_label' => __( 'Two-step verification', 'maxtdesign-mfa' ),
				'item_id'     => 'mdmfa-methods-' . $user->ID,
				'data'        => array(
					self::field( __( 'Authenticator app', 'maxtdesign-mfa' ), TotpStore::has( $user->ID ) ? __( 'Set up', 'maxtdesign-mfa' ) : __( 'Not set up', 'maxtdesign-mfa' ) ),
					self::field( __( 'Email codes', 'maxtdesign-mfa' ), EmailCode::has( $user->ID ) ? __( 'On', 'maxtdesign-mfa' ) : __( 'Off', 'maxtdesign-mfa' ) ),
					self::field( __( 'Recovery codes left', 'maxtdesign-mfa' ), (string) RecoveryCodes::remaining( $user->ID ) ),
					self::field( __( 'Trusted devices', 'maxtdesign-mfa' ), (string) TrustedDevice::count( $user->ID ) ),
				),
			);
			$rows   = $wpdb->get_results( $wpdb->prepare( 'SELECT id, name, rp_id, created_at, last_used_at FROM %i WHERE user_id = %d ORDER BY id', Schema::credentials_table( $wpdb ), $user->ID ), ARRAY_A );
			foreach ( is_array( $rows ) ? $rows : array() as $row ) {
				$data[] = array(
					'group_id'    => 'mdmfa-passkeys',
					'group_label' => __( 'Passkeys', 'maxtdesign-mfa' ),
					'item_id'     => 'mdmfa-passkey-' . (int) $row['id'],
					'data'        => array(
						self::field( __( 'Name', 'maxtdesign-mfa' ), (string) $row['name'] ),
						self::field( __( 'Site', 'maxtdesign-mfa' ), (string) $row['rp_id'] ),
						self::field( __( 'Added (UTC)', 'maxtdesign-mfa' ), (string) $row['created_at'] ),
						self::field( __( 'Last used (UTC)', 'maxtdesign-mfa' ), (string) ( $row['last_used_at'] ?? '' ) ),
					),
				);
			}
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, event, factor, context, ip, created_at FROM %i WHERE user_id = %d ORDER BY id LIMIT %d OFFSET %d',
				Schema::site_tables( $wpdb )['log'],
				$user->ID,
				self::PAGE_SIZE,
				( $page - 1 ) * self::PAGE_SIZE
			),
			ARRAY_A
		);
		$rows = is_array( $rows ) ? $rows : array();
		foreach ( $rows as $row ) {
			$packed = isset( $row['ip'] ) ? (string) $row['ip'] : '';
			$ip     = 4 === strlen( $packed ) || 16 === strlen( $packed ) ? (string) inet_ntop( $packed ) : '';
			$data[] = array(
				'group_id'    => 'mdmfa-log',
				'group_label' => __( 'Sign-in security log', 'maxtdesign-mfa' ),
				'item_id'     => 'mdmfa-log-' . (int) $row['id'],
				'data'        => array(
					self::field( __( 'Date (UTC)', 'maxtdesign-mfa' ), gmdate( 'Y-m-d H:i:s', (int) $row['created_at'] ) ),
					self::field( __( 'Event', 'maxtdesign-mfa' ), (string) $row['event'] ),
					self::field( __( 'Method', 'maxtdesign-mfa' ), (string) $row['factor'] ),
					self::field( __( 'Where', 'maxtdesign-mfa' ), (string) $row['context'] ),
					self::field( __( 'Network address', 'maxtdesign-mfa' ), $ip ),
				),
			);
		}

		return array(
			'data' => $data,
			'done' => count( $rows ) < self::PAGE_SIZE,
		);
	}

	/**
	 * Erases the person's log rows. Their methods are kept: removing them would switch
	 * off the protection of a live account. They go when the account is deleted.
	 *
	 * @param mixed $email Email address.
	 * @param mixed $page  Page (unused: each call deletes one batch).
	 * @return array{items_removed: bool, items_retained: bool, messages: string[], done: bool}
	 */
	public static function erase( mixed $email, mixed $page = 1 ): array {
		global $wpdb;

		unset( $page );
		$user   = is_string( $email ) ? get_user_by( 'email', $email ) : false;
		$result = array(
			'items_removed'  => false,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
		if ( ! $user instanceof \WP_User ) {
			return $result;
		}
		$deleted = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE user_id = %d LIMIT %d', Schema::site_tables( $wpdb )['log'], $user->ID, self::PAGE_SIZE ) );
		$deleted = is_int( $deleted ) ? $deleted : 0;

		$result['items_removed'] = $deleted > 0;
		$result['done']          = $deleted < self::PAGE_SIZE;
		if ( TotpStore::has( $user->ID ) || PasskeyStore::count( $user->ID ) > 0 || EmailCode::has( $user->ID ) ) {
			$result['items_retained'] = true;
			$result['messages'][]     = __( 'Two-step verification methods were kept because the account still exists. They are removed when the account is deleted.', 'maxtdesign-mfa' );
		}

		return $result;
	}

	/**
	 * One exported field.
	 *
	 * @param string $name  Label.
	 * @param string $value Value.
	 * @return array{name: string, value: string}
	 */
	private static function field( string $name, string $value ): array {
		return array(
			'name'  => $name,
			'value' => $value,
		);
	}
}
