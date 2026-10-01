<?php
/**
 * Every admin mutation (plan section 8): admin-post.php, nonce, the mdmfa_manage
 * capability, step-up for administrators who have a second step, then a redirect with a
 * notice code. Nothing is written while a page renders.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Admin;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Auth\StepUp;
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Factors\Reset;
use MaxtDesign\Mfa\Location\CacheBridge;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Location\SlugChanger;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Notify\Mailer;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Status\Snapshot;

defined( 'ABSPATH' ) || exit;

/**
 * Handlers for admin-post.php.
 *
 * phpcs:disable WordPress.Security.NonceVerification.Missing -- every handler calls guard(), which verifies the nonce, before reading input.
 */
final class Actions {

	public const NONCE = 'mdmfa_admin';

	/**
	 * Whether this save switched application passwords off for a role that became Required.
	 *
	 * @var bool
	 */
	private static bool $doors_closed = false;

	public const SAVE    = 'mdmfa_save';
	public const SLUG    = 'mdmfa_slug';
	public const USERS   = 'mdmfa_users';
	public const EXPORT  = 'mdmfa_export';
	public const REFRESH = 'mdmfa_refresh';

	/**
	 * Registers hooks (admin requests only).
	 */
	public static function register(): void {
		add_action( 'admin_post_' . self::SAVE, array( self::class, 'save' ) );
		add_action( 'admin_post_' . self::SLUG, array( self::class, 'slug' ) );
		add_action( 'admin_post_' . self::USERS, array( self::class, 'users' ) );
		add_action( 'admin_post_' . self::EXPORT, array( self::class, 'export' ) );
		add_action( 'admin_post_' . self::REFRESH, array( self::class, 'refresh' ) );
	}

	/**
	 * Notices by code: [type, message].
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function notices(): array {
		return array(
			'saved'       => array( 'success', __( 'Settings saved.', 'maxtdesign-mfa' ) ),
			'saved_fixed' => array( 'warning', __( 'Settings saved. A Required role must keep an authenticator app or a passkey, so the authenticator app was left on for it.', 'maxtdesign-mfa' ) ),
			'saved_doors' => array( 'warning', __( 'Settings saved. Application passwords were turned off for the roles you set to Required, because they skip the second step. You can allow them again on the Side doors tab.', 'maxtdesign-mfa' ) ),
			'stepup'      => array( 'error', __( 'Nothing was changed. Confirm it is you on your My security page first, then make the change within 10 minutes.', 'maxtdesign-mfa' ) ),
			'slug_ok'     => array( 'success', __( 'The login address changed. Every administrator was emailed the new one.', 'maxtdesign-mfa' ) ),
			'slug_bad'    => array( 'error', __( 'That address cannot be used. Use 4 to 64 letters, numbers or dashes, and avoid names WordPress or your pages already use.', 'maxtdesign-mfa' ) ),
			'page_needed' => array( 'error', __( 'Choose a published page to use as the public login page. Nothing was changed.', 'maxtdesign-mfa' ) ),
			'users_none'  => array( 'error', __( 'Select at least one user and an action. Nothing was changed.', 'maxtdesign-mfa' ) ),
			'users_reset' => array( 'success', __( 'Two-step verification was reset for the selected users you are allowed to edit. They were emailed.', 'maxtdesign-mfa' ) ),
			'users_open'  => array( 'success', __( 'The selected users were unlocked.', 'maxtdesign-mfa' ) ),
			'users_out'   => array( 'success', __( 'The selected users were signed out everywhere and their trusted devices were forgotten.', 'maxtdesign-mfa' ) ),
			'users_some'  => array( 'warning', __( 'Done for the users you are allowed to edit. The others were skipped.', 'maxtdesign-mfa' ) ),
			'users_no'    => array( 'error', __( 'You are not allowed to change any of the selected users. Nothing was changed.', 'maxtdesign-mfa' ) ),
			'refreshed'   => array( 'success', __( 'Counts refreshed.', 'maxtdesign-mfa' ) ),
		);
	}

	/**
	 * Saves one settings tab.
	 */
	public static function save(): void {
		self::guard();
		$tab = isset( $_POST['tab'] ) ? sanitize_key( wp_unslash( $_POST['tab'] ) ) : '';
		self::require_stepup( $tab );

		if ( 'location' === $tab ) {
			self::save_location();
		}

		$settings = Settings::get();
		$fixed    = false;
		switch ( $tab ) {
			case 'policy':
				$fixed = self::merge_roles( $settings, array( 'policy', 'factors', 'passwordless', 'grace_days', 'trusted_devices' ) );
				break;
			case 'recovery':
				self::merge_roles( $settings, array( 'email_recovery', 'recovery_wait_hours' ) );
				break;
			case 'sidedoors':
				self::merge_roles( $settings, array( 'app_passwords' ) );
				$settings['application_passwords'] = Settings::choice( self::post( 'application_passwords' ), array( SideDoors::APP_OFF, SideDoors::APP_PER_ROLE, SideDoors::APP_ON ), SideDoors::APP_PER_ROLE );
				$settings['xmlrpc']                = Settings::choice( self::post( 'xmlrpc' ), array( SideDoors::XMLRPC_OFF, SideDoors::XMLRPC_BLOCK, SideDoors::XMLRPC_ALLOW ), SideDoors::XMLRPC_BLOCK );
				$settings['block_wpcom_sso']       = isset( $_POST['block_wpcom_sso'] );
				break;
			case 'factors':
				$settings['trusted_device_days']   = Settings::clamp( self::post( 'trusted_device_days' ), 1, 365, 30 );
				$settings['counter_anomaly_block'] = isset( $_POST['counter_anomaly_block'] );
				break;
			case 'activity':
				$settings['log_retention_days'] = Settings::clamp( self::post( 'log_retention_days' ), 1, 730, 90 );
				$settings['log_ip_mode']        = Settings::choice( self::post( 'log_ip_mode' ), array( 'truncated', 'full' ), 'truncated' );
				break;
			default:
				self::back( 'policy', '' );
		}

		Settings::save( $settings );
		Logger::log( 'policy_changed', null, '', 'admin', get_current_user_id(), $tab );
		self::back( $tab, $fixed ? 'saved_fixed' : ( self::$doors_closed ? 'saved_doors' : 'saved' ) );
	}

	/**
	 * Changes the login address.
	 */
	public static function slug(): void {
		self::guard();
		self::require_stepup( 'location' );
		if ( defined( 'MDMFA_LOGIN_SLUG' ) ) {
			self::back( 'location', 'slug_bad' );
		}
		$result = SlugChanger::change( self::post( 'slug' ), get_current_user_id() );
		Snapshot::flush();
		self::back( 'location', $result instanceof \WP_Error ? 'slug_bad' : 'slug_ok' );
	}

	/**
	 * Reset, unlock or sign out the selected users.
	 */
	public static function users(): void {
		self::guard();
		self::require_stepup( 'coverage' );
		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$ids = isset( $_POST['users'] ) && is_array( $_POST['users'] ) ? array_unique( array_filter( array_map( 'absint', wp_unslash( $_POST['users'] ) ) ) ) : array();
		if ( array() === $ids || ! in_array( $do, array( 'reset', 'unlock', 'signout' ), true ) ) {
			self::back( 'coverage', 'users_none' );
		}

		$actor   = get_current_user_id();
		$done    = 0;
		$skipped = 0;
		foreach ( array_slice( $ids, 0, 200 ) as $id ) {
			$user = get_userdata( $id );
			// Managing a user needs edit_user on them; a super admin only by a super admin.
			if ( ! $user instanceof \WP_User || ! current_user_can( 'edit_user', $id ) || ( is_multisite() && is_super_admin( $id ) && ! is_super_admin( $actor ) ) ) {
				++$skipped;
				continue;
			}
			if ( 'reset' === $do ) {
				Reset::all( $id );
				Logger::log( 'admin_reset', $id, 'all', 'admin', $actor );
				do_action( 'mdmfa_factor_removed', $user, 'all', $actor );
				Mailer::factors_reset( $user );
			} elseif ( 'unlock' === $do ) {
				Lockout::unlock( $id, $actor );
			} else {
				\WP_Session_Tokens::get_instance( $id )->destroy_all();
				TrustedDevice::revoke_all( $id );
				Logger::log( 'signed_out', $id, '', 'admin', $actor );
			}
			++$done;
		}
		Snapshot::flush();

		if ( 0 === $done ) {
			self::back( 'coverage', 'users_no' );
		}
		$codes = array(
			'reset'   => 'users_reset',
			'unlock'  => 'users_open',
			'signout' => 'users_out',
		);
		self::back( 'coverage', $skipped > 0 ? 'users_some' : $codes[ $do ] );
	}

	/**
	 * Downloads the settings as JSON: policy and options only.
	 */
	public static function export(): void {
		self::guard();
		$login = get_option( Options::LOGIN );
		$data  = array(
			'plugin'         => 'maxtdesign-mfa',
			'version'        => MDMFA_VERSION,
			'settings'       => Settings::get(),
			// The address itself is a secret of sorts and stays out of the file.
			'login_location' => array(
				'enabled'      => is_array( $login ) && ! empty( $login['enabled'] ),
				'public_login' => is_array( $login ) && isset( $login['public_login'] ) && is_string( $login['public_login'] ) ? $login['public_login'] : 'auto',
			),
		);
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="maxtdesign-mfa-settings.json"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo wp_json_encode( $data, JSON_PRETTY_PRINT ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- a JSON download, not HTML.
		exit;
	}

	/**
	 * Rebuilds the cached status.
	 */
	public static function refresh(): void {
		self::guard();
		Snapshot::get( true );
		self::back( 'tools', 'refreshed' );
	}

	/**
	 * Saves the login location tab and redirects.
	 *
	 * @return never
	 */
	private static function save_location(): void {
		$option = get_option( Options::LOGIN );
		$option = is_array( $option ) ? $option : Settings::login_defaults();
		$mode   = Settings::choice( self::post( 'public_login' ), array( 'auto', 'slug', 'page' ), 'auto' );
		$page   = absint( self::post( 'public_page' ) );
		if ( 'page' === $mode && ( $page <= 0 || 'publish' !== get_post_status( $page ) || 'page' !== get_post_type( $page ) ) ) {
			self::back( 'location', 'page_needed' );
		}
		$old = LoginLocation::enabled() ? LoginLocation::url() : '';

		$option['enabled']      = isset( $_POST['enabled'] );
		$option['public_login'] = $mode;
		$option['public_page']  = 'page' === $mode ? $page : 0;
		update_option( Options::LOGIN, $option, true );

		// Turning the moved login on or off changes what both addresses must serve.
		CacheBridge::purge( array_filter( array( $old, LoginLocation::enabled() ? LoginLocation::url() : '' ) ) );
		Snapshot::flush();
		Logger::log( 'policy_changed', null, '', 'admin', get_current_user_id(), 'location' );
		self::back( 'location', 'saved' );
	}

	/**
	 * Applies the posted values of some role keys to every role row, validated.
	 *
	 * @param array<string, mixed> $settings Settings, updated in place.
	 * @param string[]             $keys     Role keys this tab owns.
	 * @return bool Whether a Required role had its authenticator app kept on.
	 */
	private static function merge_roles( array &$settings, array $keys ): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each value is validated by Settings::sanitize_role() against closed sets and ranges.
		$posted = isset( $_POST['roles'] ) && is_array( $_POST['roles'] ) ? wp_unslash( $_POST['roles'] ) : array();
		$roles  = is_array( $settings['roles'] ) ? $settings['roles'] : array();
		$fixed  = false;
		foreach ( SettingsViews::role_rows() as $slug => $row ) {
			$given = isset( $posted[ $slug ] ) && is_array( $posted[ $slug ] ) ? $posted[ $slug ] : array();
			$input = $row['config'];
			foreach ( $keys as $key ) {
				// An unticked checkbox is absent from the request: absent means off.
				$input[ $key ] = $given[ $key ] ?? ( 'factors' === $key ? array() : false );
			}
			$clean = Settings::sanitize_role( $input, $row['config'] );
			// A role that becomes Required loses application passwords (they skip the
			// second step); the owner can allow them again on the Side doors tab.
			if ( in_array( 'policy', $keys, true ) && Settings::POLICY_REQUIRED === $clean['policy'] && Settings::POLICY_REQUIRED !== ( $row['config']['policy'] ?? '' ) && $clean['app_passwords'] ) {
				$clean['app_passwords'] = false;
				self::$doors_closed     = true;
			}
			$fixed = $fixed || ( in_array( 'factors', $keys, true ) && Settings::POLICY_REQUIRED === $clean['policy'] && empty( $given['factors']['totp'] ) && empty( $given['factors']['passkey'] ) );
			if ( SettingsViews::UNLISTED === $slug ) {
				$settings['unlisted_role'] = $clean;
			} else {
				$roles[ $slug ] = $clean;
			}
		}
		$settings['roles'] = $roles;

		return $fixed;
	}

	/**
	 * A posted scalar as a trimmed string.
	 *
	 * @param string $key Field name.
	 */
	private static function post( string $key ): string {
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? trim( sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) ) : '';
	}

	/**
	 * Nonce and capability, or stop.
	 */
	private static function guard(): void {
		check_admin_referer( self::NONCE );
		if ( ! current_user_can( Plugin::MANAGE_CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to change these settings.', 'maxtdesign-mfa' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Step-up (plan 4.3): an administrator who has a second step must have verified in
	 * the last 10 minutes. One who has none yet cannot, and is let through.
	 *
	 * @param string $tab Tab to return to.
	 */
	private static function require_stepup( string $tab ): void {
		$actor = get_current_user_id();
		if ( Policy::is_enrolled( $actor ) && ! StepUp::is_fresh( $actor ) ) {
			self::back( $tab, 'stepup' );
		}
	}

	/**
	 * Redirects to a tab with a notice code, and exits.
	 *
	 * @param string $tab    Tab slug.
	 * @param string $notice Notice code.
	 * @return never
	 */
	private static function back( string $tab, string $notice ): void {
		wp_safe_redirect( SettingsPage::url( $tab, '' !== $notice ? array( 'mdmfa_notice' => $notice ) : array() ) );
		exit;
	}
}
