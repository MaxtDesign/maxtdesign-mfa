<?php
/**
 * The settings tabs: Policy, Factors, Login location, Side doors, Recovery. Server-rendered
 * native forms that work without JavaScript; saves go through admin-post (Actions).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Admin;

use MaxtDesign\Mfa\Auth\ChallengeUrl;
use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Integrations\Jetpack;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Status\Snapshot;
use MaxtDesign\Mfa\WebAuthn\RelyingParty;

defined( 'ABSPATH' ) || exit;

/**
 * Settings tab markup. Every dynamic value is escaped here or by Ui.
 *
 * phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Ui returns escaped markup; every other value is escaped inline.
 */
final class SettingsViews {

	/** Row key of the configuration used for roles created later. */
	public const UNLISTED = '__unlisted';

	/**
	 * Role configurations to edit: every role on the site, then the default for new roles.
	 *
	 * @return array<string, array{label: string, config: array<string, mixed>}>
	 */
	public static function role_rows(): array {
		$settings = Settings::get();
		$roles    = is_array( $settings['roles'] ) ? $settings['roles'] : array();
		$unlisted = is_array( $settings['unlisted_role'] ) ? $settings['unlisted_role'] : array();
		$rows     = array();
		foreach ( wp_roles()->roles as $slug => $role ) {
			$rows[ (string) $slug ] = array(
				'label'  => translate_user_role( (string) $role['name'] ),
				'config' => isset( $roles[ $slug ] ) && is_array( $roles[ $slug ] ) ? $roles[ $slug ] : $unlisted,
			);
		}
		$rows[ self::UNLISTED ] = array(
			'label'  => __( 'Roles added later', 'maxtdesign-mfa' ),
			'config' => $unlisted,
		);

		return $rows;
	}

	/**
	 * Policy: role x policy, factors, passkey-only sign-in, grace, trusted devices.
	 */
	public static function policy(): void {
		$status   = Snapshot::get();
		$counts   = isset( $status['roles'] ) && is_array( $status['roles'] ) ? $status['roles'] : array();
		$policies = array(
			Settings::POLICY_OFF      => __( 'Off', 'maxtdesign-mfa' ),
			Settings::POLICY_OPTIONAL => __( 'Optional', 'maxtdesign-mfa' ),
			Settings::POLICY_REQUIRED => __( 'Required', 'maxtdesign-mfa' ),
		);

		echo '<p>' . esc_html__( 'Choose who must use two-step verification and which methods each role may use. A user with several roles follows the strictest one.', 'maxtdesign-mfa' ) . '</p>';
		$passkey_only = Passkeys::passkey_only_enabled();
		echo Ui::notice( 'info', __( 'Passkeys are in beta. The code that checks them was written for this plugin and has not had an independent security review yet, so they are off until you turn them on for a role, and they work as a second step after the password only.', 'maxtdesign-mfa' ) );
		if ( ! RelyingParty::available() ) {
			echo Ui::notice( 'warning', __( 'Passkeys need https. This site is not on https, so passkey options have no effect yet.', 'maxtdesign-mfa' ) );
		}
		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'policy' ) );
		echo Ui::table_open( __( 'Policy by role', 'maxtdesign-mfa' ) );
		echo '<table class="widefat striped mdmfa-matrix"><thead><tr>';
		$headings = array(
			__( 'Role', 'maxtdesign-mfa' ),
			__( 'Users', 'maxtdesign-mfa' ),
			__( 'Set up', 'maxtdesign-mfa' ),
			__( 'Policy', 'maxtdesign-mfa' ),
			__( 'Authenticator app', 'maxtdesign-mfa' ),
			__( 'Passkey (beta)', 'maxtdesign-mfa' ),
			__( 'Email code', 'maxtdesign-mfa' ),
			__( 'Passkey-only sign-in', 'maxtdesign-mfa' ),
			__( 'Days to set up', 'maxtdesign-mfa' ),
			__( 'Trusted devices', 'maxtdesign-mfa' ),
		);
		if ( ! $passkey_only ) {
			unset( $headings[7] );
		}
		foreach ( $headings as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( self::role_rows() as $slug => $row ) {
			$config  = $row['config'];
			$factors = isset( $config['factors'] ) && is_array( $config['factors'] ) ? $config['factors'] : array();
			$name    = 'roles[' . $slug . ']';
			$label   = $row['label'];
			$count   = isset( $counts[ $slug ] ) && is_array( $counts[ $slug ] ) ? $counts[ $slug ] : null;
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th>';
			echo '<td>' . esc_html( null === $count ? '' : (string) (int) $count['users'] ) . '</td>';
			echo '<td>' . esc_html( null === $count ? '' : (string) (int) $count['enrolled'] ) . '</td>';
			/* translators: %s: role name. */
			echo '<td>' . Ui::select( $name . '[policy]', $policies, (string) ( $config['policy'] ?? Settings::POLICY_OPTIONAL ), sprintf( __( 'Policy for %s', 'maxtdesign-mfa' ), $label ) ) . '</td>';
			/* translators: %s: role name. */
			echo '<td>' . Ui::checkbox( $name . '[factors][totp]', ! empty( $factors['totp'] ), sprintf( __( 'Authenticator app for %s', 'maxtdesign-mfa' ), $label ), true ) . '</td>';
			/* translators: %s: role name. */
			echo '<td>' . Ui::checkbox( $name . '[factors][passkey]', ! empty( $factors['passkey'] ), sprintf( __( 'Passkey for %s', 'maxtdesign-mfa' ), $label ), true ) . '</td>';
			/* translators: %s: role name. */
			echo '<td>' . Ui::checkbox( $name . '[factors][email]', ! empty( $factors['email'] ), sprintf( __( 'Email code for %s', 'maxtdesign-mfa' ), $label ), true ) . '</td>';
			if ( $passkey_only ) {
				/* translators: %s: role name. */
				echo '<td>' . Ui::checkbox( $name . '[passwordless]', ! empty( $config['passwordless'] ), sprintf( __( 'Passkey-only sign-in for %s', 'maxtdesign-mfa' ), $label ), true ) . '</td>';
			}
			printf(
				'<td><input type="number" class="small-text" min="0" max="90" name="%1$s" value="%2$d" aria-label="%3$s"></td>',
				esc_attr( $name . '[grace_days]' ),
				(int) ( $config['grace_days'] ?? 7 ),
				/* translators: %s: role name. */
				esc_attr( sprintf( __( 'Days to set up for %s', 'maxtdesign-mfa' ), $label ) )
			);
			/* translators: %s: role name. */
			echo '<td>' . Ui::checkbox( $name . '[trusted_devices]', ! empty( $config['trusted_devices'] ), sprintf( __( 'Trusted devices for %s', 'maxtdesign-mfa' ), $label ), true ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table></div>';
		echo '<ul class="mdmfa-notes">';
		echo '<li>' . esc_html__( 'Required: after the days to set up, the user must set up a method before the sign-in finishes. A Required role always keeps an authenticator app or a passkey.', 'maxtdesign-mfa' ) . '</li>';
		echo '<li>' . esc_html__( 'Email code: weaker than an app or a passkey, because anyone who can read the mailbox can use it. Keep it off for staff.', 'maxtdesign-mfa' ) . '</li>';
		if ( $passkey_only ) {
			echo '<li>' . esc_html__( 'Passkey-only sign-in: lets the role sign in with a passkey and no password. It needs a passkey that checks a fingerprint, face or screen lock. While passkeys are in beta this removes the password as a safety net.', 'maxtdesign-mfa' ) . '</li>';
		}
		echo '<li>' . esc_html__( 'Trusted devices: lets a user skip the second step on a device for a while. Anyone holding that device and the password gets in.', 'maxtdesign-mfa' ) . '</li>';
		echo '</ul>';
		echo '<p>' . Ui::submit( __( 'Save policy', 'maxtdesign-mfa' ) ) . '</p></form>';
	}

	/**
	 * Factors: site-wide options of the methods.
	 */
	public static function factors(): void {
		$settings = Settings::get();
		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'factors' ) );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row"><label for="mdmfa-td-days">%1$s</label></th><td><input type="number" class="small-text" id="mdmfa-td-days" name="trusted_device_days" min="1" max="365" value="%2$d"> <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Trusted device lifetime (days)', 'maxtdesign-mfa' ),
			(int) $settings['trusted_device_days'],
			esc_html__( 'How long a trusted device skips the second step, for roles that allow trusted devices.', 'maxtdesign-mfa' )
		);
		printf(
			'<tr><th scope="row">%1$s</th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Copied passkeys', 'maxtdesign-mfa' ),
			Ui::checkbox( 'counter_anomaly_block', ! empty( $settings['counter_anomaly_block'] ), __( 'Also refuse a synced passkey that reports an unexpected counter', 'maxtdesign-mfa' ) ),
			esc_html__( 'An unexpected counter can mean the passkey was copied. It is always flagged and logged. A passkey that lives on one device only (a security key) is always refused when that happens. Passkeys synced by a phone or password manager usually report no counter and are not affected; tick this to refuse them too if one ever does.', 'maxtdesign-mfa' )
		);
		echo '</tbody></table>';
		echo '<p>' . Ui::submit( __( 'Save factor settings', 'maxtdesign-mfa' ) ) . '</p></form>';
	}

	/**
	 * Login location: address, public login page, slug change.
	 */
	public static function location(): void {
		$option  = get_option( Options::LOGIN );
		$option  = is_array( $option ) ? $option : array();
		$enabled = LoginLocation::enabled();
		$forced  = defined( 'MDMFA_LOGIN_SLUG' );
		$off     = defined( 'MDMFA_DISABLE_LOGIN_LOCATION' ) && (bool) constant( 'MDMFA_DISABLE_LOGIN_LOCATION' );

		$body = $enabled
			? sprintf(
				'<p>%1$s %2$s</p><p><code id="mdmfa-login-url">%3$s</code> <button type="button" class="button" data-mdmfa-copy="mdmfa-login-url" data-mdmfa-copied="%4$s">%5$s</button> <span class="mdmfa-copied" role="status" aria-live="polite"></span></p><p class="description">%6$s</p>',
				Ui::badge( 'good', __( 'Moved', 'maxtdesign-mfa' ) ),
				esc_html__( 'The login page lives at this address. The old wp-login.php address shows a "not found" page.', 'maxtdesign-mfa' ),
				esc_html( LoginLocation::url() ),
				esc_attr__( 'Copied', 'maxtdesign-mfa' ),
				esc_html__( 'Copy', 'maxtdesign-mfa' ),
				esc_html__( 'Bookmark it. Moving the login cuts bot noise; it is not a security boundary on its own.', 'maxtdesign-mfa' )
			)
			: sprintf(
				'<p>%1$s %2$s</p>',
				Ui::badge( 'neutral', __( 'Not moved', 'maxtdesign-mfa' ) ),
				esc_html( $off ? __( 'MDMFA_DISABLE_LOGIN_LOCATION is set in wp-config.php, so the login is at wp-login.php.', 'maxtdesign-mfa' ) : __( 'The login is at wp-login.php.', 'maxtdesign-mfa' ) )
			);
		echo Ui::card( __( 'Login address', 'maxtdesign-mfa' ), $body );
		if ( '' === (string) get_option( 'permalink_structure' ) ) {
			echo Ui::notice( 'warning', __( 'This site uses plain permalinks. On some servers the moved login address does not load with that setting. Before you turn it on or sign out, open the address in a private window and check that the login form appears.', 'maxtdesign-mfa' ) );
		}

		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'location' ) );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row">%1$s</th><td>%2$s</td></tr>',
			esc_html__( 'Moved login', 'maxtdesign-mfa' ),
			Ui::checkbox( 'enabled', ! empty( $option['enabled'] ), __( 'Move the login to a private address and hide wp-login.php', 'maxtdesign-mfa' ) )
		);
		$modes = array(
			'auto' => '' !== ChallengeUrl::account() ? __( 'WooCommerce My Account (recommended)', 'maxtdesign-mfa' ) : __( 'The login address (no WooCommerce account page found)', 'maxtdesign-mfa' ),
			'slug' => __( 'The login address', 'maxtdesign-mfa' ),
			'page' => __( 'A page I choose', 'maxtdesign-mfa' ),
		);
		printf(
			'<tr><th scope="row"><label for="mdmfa-public-login">%1$s</label></th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Where visitors are sent to log in', 'maxtdesign-mfa' ),
			Ui::select( 'public_login', $modes, isset( $option['public_login'] ) && is_string( $option['public_login'] ) ? $option['public_login'] : 'auto', '', 'mdmfa-public-login' ),
			esc_html__( 'Login links shown to logged-out visitors (comment forms, the Login block) point here. Choosing "The login address" publishes that address wherever such a link appears.', 'maxtdesign-mfa' )
		);
		printf(
			'<tr><th scope="row"><label for="mdmfa-public-page">%1$s</label></th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Public login page', 'maxtdesign-mfa' ),
			(string) wp_dropdown_pages(
				array(
					'name'              => 'public_page',
					'id'                => 'mdmfa-public-page',
					'echo'              => 0,
					'show_option_none'  => esc_html__( 'Select a page', 'maxtdesign-mfa' ),
					'option_none_value' => '0',
					'selected'          => isset( $option['public_page'] ) ? (int) $option['public_page'] : 0,
				)
			),
			esc_html__( 'Used with "A page I choose". Put a login form on it, for example the Login/out block set to show the form.', 'maxtdesign-mfa' )
		);
		echo '</tbody></table>';
		echo '<p>' . Ui::submit( __( 'Save login location', 'maxtdesign-mfa' ) ) . '</p></form>';

		$change = '';
		if ( $forced ) {
			$change = '<p>' . esc_html__( 'MDMFA_LOGIN_SLUG is set in wp-config.php, so the address is fixed there and cannot be changed here.', 'maxtdesign-mfa' ) . '</p>';
		} else {
			$change  = Ui::form_open( Actions::SLUG );
			$change .= sprintf(
				'<p><label for="mdmfa-slug">%1$s</label><br><input type="text" class="regular-text code" id="mdmfa-slug" name="slug" value="" autocomplete="off" spellcheck="false" maxlength="64"></p><p class="description">%2$s</p>',
				esc_html__( 'New address (letters, numbers and dashes), or leave empty for a random one', 'maxtdesign-mfa' ),
				esc_html__( 'The old address stops working at once. Every administrator is emailed the new one.', 'maxtdesign-mfa' )
			);
			$change .= '<p>' . Ui::submit( __( 'Change login address', 'maxtdesign-mfa' ), 'button', __( 'The current login address stops working at once and every administrator is emailed the new one.', 'maxtdesign-mfa' ) ) . '</p></form>';
		}
		echo Ui::card( __( 'Change the address', 'maxtdesign-mfa' ), $change );

		echo Ui::card(
			__( 'Page caches', 'maxtdesign-mfa' ),
			'<p>' . esc_html__( 'The login address sends "do not cache" headers and is excluded from MaxtDesign Cache, LiteSpeed Cache and WP Rocket automatically. If another cache or a CDN caches whole pages, exclude the login address there too.', 'maxtdesign-mfa' ) . '</p>'
			. '<p>' . esc_html__( 'Lost the address? Run "wp mdmfa slug get" on the server, or define MDMFA_DISABLE_LOGIN_LOCATION in wp-config.php.', 'maxtdesign-mfa' ) . '</p>'
		);
	}

	/**
	 * Side doors: application passwords, XML-RPC, WordPress.com sign-in.
	 */
	public static function side_doors(): void {
		$settings = Settings::get();
		echo '<p>' . esc_html__( 'These are ways to reach an account without the login form. Apps cannot answer a second step, so each door has its own rule.', 'maxtdesign-mfa' ) . '</p>';
		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'sidedoors' ) );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row"><label for="mdmfa-app">%1$s</label></th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Application passwords', 'maxtdesign-mfa' ),
			Ui::select(
				'application_passwords',
				array(
					SideDoors::APP_PER_ROLE => __( 'Allowed for the roles ticked below', 'maxtdesign-mfa' ),
					SideDoors::APP_ON       => __( 'Allowed for every role', 'maxtdesign-mfa' ),
					SideDoors::APP_OFF      => __( 'Off for the whole site', 'maxtdesign-mfa' ),
				),
				SideDoors::app_password_mode(),
				'',
				'mdmfa-app'
			),
			esc_html__( 'An application password skips the second step by design: it is a separate password for one app that you can revoke. Creating one needs a recent verification.', 'maxtdesign-mfa' )
		);
		echo '<tr><th scope="row">' . esc_html__( 'Roles that may use them', 'maxtdesign-mfa' ) . '</th><td><fieldset><legend class="screen-reader-text">' . esc_html__( 'Roles that may use application passwords', 'maxtdesign-mfa' ) . '</legend>';
		foreach ( self::role_rows() as $slug => $row ) {
			echo Ui::checkbox( 'roles[' . $slug . '][app_passwords]', ! empty( $row['config']['app_passwords'] ), $row['label'] ) . '<br>';
		}
		echo '</fieldset></td></tr>';
		printf(
			'<tr><th scope="row"><label for="mdmfa-xmlrpc">%1$s</label></th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'XML-RPC', 'maxtdesign-mfa' ),
			Ui::select(
				'xmlrpc',
				array(
					SideDoors::XMLRPC_BLOCK => __( 'Refuse account passwords for users with two-step verification (recommended)', 'maxtdesign-mfa' ),
					SideDoors::XMLRPC_OFF   => __( 'Off: no XML-RPC logins at all', 'maxtdesign-mfa' ),
					SideDoors::XMLRPC_ALLOW => __( 'Allow account passwords (skips the second step)', 'maxtdesign-mfa' ),
				),
				SideDoors::xmlrpc_mode(),
				'',
				'mdmfa-xmlrpc'
			),
			esc_html__( 'Used by the WordPress mobile app and some older tools. Application passwords keep working over XML-RPC unless it is off. Jetpack is not affected.', 'maxtdesign-mfa' )
		);
		$jetpack = Jetpack::detected()
			? ( Jetpack::sso_blocked() ? Ui::badge( 'neutral', __( 'Blocked', 'maxtdesign-mfa' ) ) : ( Jetpack::sso_active() ? Ui::badge( 'good', __( 'Asks for the second step', 'maxtdesign-mfa' ) ) : Ui::badge( 'neutral', __( 'Not in use', 'maxtdesign-mfa' ) ) ) )
			: Ui::badge( 'neutral', __( 'Jetpack is not active', 'maxtdesign-mfa' ) );
		printf(
			'<tr><th scope="row">%1$s</th><td><p>%2$s</p>%3$s <p class="description">%4$s</p></td></tr>',
			esc_html__( 'WordPress.com sign-in (Jetpack)', 'maxtdesign-mfa' ),
			$jetpack,
			Ui::checkbox( 'block_wpcom_sso', ! empty( $settings['block_wpcom_sso'] ), __( 'Block WordPress.com sign-in', 'maxtdesign-mfa' ) ),
			esc_html__( 'Without the block, a WordPress.com sign-in still works but is asked for this site\'s second step. WordPress.com\'s own two-step check is not accepted in its place.', 'maxtdesign-mfa' )
		);
		echo '</tbody></table>';
		echo '<p>' . esc_html__( 'Plugins that take a username and password over the REST API are always refused for users with two-step verification.', 'maxtdesign-mfa' ) . '</p>';
		echo '<p>' . Ui::submit( __( 'Save side doors', 'maxtdesign-mfa' ) ) . '</p></form>';
	}

	/**
	 * Recovery: email recovery per role and its waiting period.
	 */
	public static function recovery(): void {
		echo '<p>' . esc_html__( 'When a user loses every method, they can use a recovery code, ask you to reset them on the Coverage tab, or, if you allow it here, reset through a link sent to their email.', 'maxtdesign-mfa' ) . '</p>';
		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'recovery' ) );
		echo Ui::table_open( __( 'Email recovery by role', 'maxtdesign-mfa' ) );
		echo '<table class="widefat striped mdmfa-matrix"><thead><tr><th scope="col">' . esc_html__( 'Role', 'maxtdesign-mfa' ) . '</th><th scope="col">' . esc_html__( 'Email recovery', 'maxtdesign-mfa' ) . '</th><th scope="col">' . esc_html__( 'Waiting period (hours)', 'maxtdesign-mfa' ) . '</th></tr></thead><tbody>';
		foreach ( self::role_rows() as $slug => $row ) {
			$name = 'roles[' . $slug . ']';
			printf(
				'<tr><th scope="row">%1$s</th><td>%2$s</td><td><input type="number" class="small-text" min="0" max="168" name="%3$s" value="%4$d" aria-label="%5$s"></td></tr>',
				esc_html( $row['label'] ),
				/* translators: %s: role name. */
				Ui::checkbox( $name . '[email_recovery]', ! empty( $row['config']['email_recovery'] ), sprintf( __( 'Email recovery for %s', 'maxtdesign-mfa' ), $row['label'] ), true ),
				esc_attr( $name . '[recovery_wait_hours]' ),
				(int) ( $row['config']['recovery_wait_hours'] ?? 0 ),
				/* translators: %s: role name. */
				esc_attr( sprintf( __( 'Waiting period in hours for %s', 'maxtdesign-mfa' ), $row['label'] ) )
			);
		}
		echo '</tbody></table></div>';
		echo '<ul class="mdmfa-notes">';
		echo '<li>' . esc_html__( 'Email recovery means the password plus the mailbox is enough to remove two-step verification. Keep it off for staff, or keep a waiting period.', 'maxtdesign-mfa' ) . '</li>';
		echo '<li>' . esc_html__( 'During the waiting period the user and the site administrator are emailed, and a normal sign-in with the second step cancels the reset.', 'maxtdesign-mfa' ) . '</li>';
		echo '</ul>';
		echo '<p>' . Ui::submit( __( 'Save recovery settings', 'maxtdesign-mfa' ) ) . '</p></form>';
	}
}
