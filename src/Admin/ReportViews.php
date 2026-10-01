<?php
/**
 * The reporting tabs: Coverage (who is set up, with reset, unlock and sign-out), Activity
 * (the log) and Tools (key status, conflicts, export).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Admin;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Factors\EmailCode;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Integrations\Conflicts;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Status\Snapshot;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Report tab markup.
 *
 * phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Ui returns escaped markup; every other value is escaped inline.
 * phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only list filters and paging.
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own log table, read for display.
 */
final class ReportViews {

	public const PER_PAGE = 20;
	public const LOG_PAGE = 50;

	/**
	 * Coverage: per-user state and the bulk actions.
	 */
	public static function coverage(): void {
		$status = Snapshot::get();
		$roles  = isset( $status['roles'] ) && is_array( $status['roles'] ) ? $status['roles'] : array();
		$users  = 0;
		$late   = 0;
		foreach ( $roles as $role ) {
			$late += is_array( $role ) ? (int) $role['overdue'] : 0;
		}
		$users = (int) ( $status['total_users'] ?? 0 );
		printf(
			'<p class="mdmfa-summary">%1$s %2$s %3$s %4$s</p>',
			/* translators: %d: number of users. */
			Ui::badge( 'neutral', sprintf( _n( '%d user', '%d users', $users, 'maxtdesign-mfa' ), $users ) ),
			/* translators: %d: number of users. */
			Ui::badge( 'good', sprintf( __( '%d set up', 'maxtdesign-mfa' ), (int) ( $status['enrolled_users'] ?? 0 ) ) ),
			/* translators: %d: number of users. */
			Ui::badge( $late > 0 ? 'warn' : 'neutral', sprintf( __( '%d overdue', 'maxtdesign-mfa' ), $late ) ),
			/* translators: %d: number of users. */
			Ui::badge( (int) ( $status['active_lockouts'] ?? 0 ) > 0 ? 'bad' : 'neutral', sprintf( __( '%d locked', 'maxtdesign-mfa' ), (int) ( $status['active_lockouts'] ?? 0 ) ) )
		);
		if ( (int) ( $status['unverified_sessions'] ?? 0 ) > 0 ) {
			echo Ui::notice(
				'warning',
				sprintf(
					/* translators: %d: number of users. */
					_n(
						'%d user in a Required role is signed in without having passed the second step (signed in before the policy applied, or still in the setup period). "Sign out everywhere" ends those sessions.',
						'%d users in Required roles are signed in without having passed the second step (signed in before the policy applied, or still in the setup period). "Sign out everywhere" ends those sessions.',
						(int) $status['unverified_sessions'],
						'maxtdesign-mfa'
					),
					(int) $status['unverified_sessions']
				)
			);
		}

		$search = isset( $_GET['s'] ) && is_string( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$state  = isset( $_GET['state'] ) ? sanitize_key( wp_unslash( $_GET['state'] ) ) : '';
		$paged  = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;
		$args   = array(
			'number'  => self::PER_PAGE,
			'offset'  => ( $paged - 1 ) * self::PER_PAGE,
			'orderby' => 'login',
			'order'   => 'ASC',
		);
		if ( '' !== $search ) {
			$args['search']         = '*' . $search . '*';
			$args['search_columns'] = array( 'user_login', 'user_email', 'display_name' );
		}
		if ( 'setup' === $state || 'none' === $state ) {
			$args['meta_query'] = array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- an owner-requested filter on one admin screen.
				array(
					'key'     => 'mdmfa_enrolled',
					'compare' => 'setup' === $state ? 'EXISTS' : 'NOT EXISTS',
				),
			);
		}
		$query = new \WP_User_Query( $args );
		$found = (int) $query->get_total();

		echo '<form method="get" action="' . esc_url( admin_url( SettingsPage::in_suite() ? 'admin.php' : 'users.php' ) ) . '" class="mdmfa-filter">';
		echo '<input type="hidden" name="page" value="' . esc_attr( SettingsPage::SLUG ) . '"><input type="hidden" name="tab" value="coverage">';
		printf( '<label for="mdmfa-user-search" class="screen-reader-text">%1$s</label><input type="search" id="mdmfa-user-search" name="s" value="%2$s" placeholder="%3$s"> ', esc_html__( 'Search users', 'maxtdesign-mfa' ), esc_attr( $search ), esc_attr__( 'Search users', 'maxtdesign-mfa' ) );
		echo Ui::select(
			'state',
			array(
				''      => __( 'All users', 'maxtdesign-mfa' ),
				'setup' => __( 'Set up', 'maxtdesign-mfa' ),
				'none'  => __( 'Not set up', 'maxtdesign-mfa' ),
			),
			$state,
			__( 'Filter by two-step verification', 'maxtdesign-mfa' )
		);
		echo ' ' . Ui::submit( __( 'Filter', 'maxtdesign-mfa' ), 'button' ) . '</form>';

		if ( 0 === $found ) {
			echo Ui::empty_state( __( 'No users match.', 'maxtdesign-mfa' ), __( 'Clear the search or choose "All users" to see everyone.', 'maxtdesign-mfa' ) );
			return;
		}

		echo Ui::form_open( Actions::USERS );
		echo Ui::table_open( __( 'Users and their two-step verification', 'maxtdesign-mfa' ) );
		echo '<table class="widefat striped"><thead><tr><td class="check-column"><span class="screen-reader-text">' . esc_html__( 'Select', 'maxtdesign-mfa' ) . '</span></td>';
		foreach ( array( __( 'User', 'maxtdesign-mfa' ), __( 'Role', 'maxtdesign-mfa' ), __( 'Policy', 'maxtdesign-mfa' ), __( 'Status', 'maxtdesign-mfa' ), __( 'Methods', 'maxtdesign-mfa' ) ) as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $query->get_results() as $user ) {
			if ( ! $user instanceof \WP_User ) {
				continue;
			}
			$names = array_map( static fn ( string $role ): string => isset( wp_roles()->roles[ $role ] ) ? translate_user_role( (string) wp_roles()->roles[ $role ]['name'] ) : $role, array_values( (array) $user->roles ) );
			printf(
				'<tr><th scope="row" class="check-column"><input type="checkbox" name="users[]" value="%1$d" id="mdmfa-user-%1$d"><label for="mdmfa-user-%1$d" class="screen-reader-text">%2$s</label></th><td><strong>%3$s</strong><br>%4$s</td><td>%5$s</td><td>%6$s</td><td>%7$s</td><td>%8$s</td></tr>',
				(int) $user->ID,
				/* translators: %s: username. */
				esc_html( sprintf( __( 'Select %s', 'maxtdesign-mfa' ), $user->user_login ) ),
				esc_html( $user->user_login ),
				esc_html( $user->user_email ),
				esc_html( implode( ', ', $names ) ),
				self::policy_badge( Policy::policy( $user ) ),
				self::status_badges( $user ),
				esc_html( self::methods( $user ) )
			);
		}
		echo '</tbody></table></div>';
		echo '<p class="mdmfa-bulk"><label for="mdmfa-do" class="screen-reader-text">' . esc_html__( 'Action for the selected users', 'maxtdesign-mfa' ) . '</label>';
		echo Ui::select(
			'do',
			array(
				''        => __( 'Choose an action', 'maxtdesign-mfa' ),
				'reset'   => __( 'Reset two-step verification (set up again)', 'maxtdesign-mfa' ),
				'unlock'  => __( 'Unlock', 'maxtdesign-mfa' ),
				'signout' => __( 'Sign out everywhere', 'maxtdesign-mfa' ),
			),
			'',
			'',
			'mdmfa-do'
		);
		echo ' ' . Ui::submit( __( 'Apply to selected', 'maxtdesign-mfa' ), 'button', __( 'This applies to every selected user. A reset removes their methods, recovery codes and trusted devices, and emails them.', 'maxtdesign-mfa' ) ) . '</p></form>';
		self::pagination(
			$found,
			self::PER_PAGE,
			$paged,
			array_filter(
				array(
					's'     => $search,
					'state' => $state,
				)
			),
			'coverage'
		);
	}

	/**
	 * Activity: the log, newest first.
	 */
	public static function activity(): void {
		global $wpdb;

		$settings = Settings::get();
		$table    = Schema::site_tables( $wpdb )['log'];
		$event    = isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		$paged    = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;
		$offset   = ( $paged - 1 ) * self::LOG_PAGE;

		$events = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT event FROM %i ORDER BY event', $table ) );
		$events = is_array( $events ) ? array_map( 'strval', $events ) : array();
		if ( '' !== $event && in_array( $event, $events, true ) ) {
			$found = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE event = %s', $table, $event ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE event = %s ORDER BY id DESC LIMIT %d OFFSET %d', $table, $event, self::LOG_PAGE, $offset ), ARRAY_A );
		} else {
			$event = '';
			$found = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d OFFSET %d', $table, self::LOG_PAGE, $offset ), ARRAY_A );
		}
		$rows = is_array( $rows ) ? $rows : array();

		echo '<form method="get" action="' . esc_url( admin_url( SettingsPage::in_suite() ? 'admin.php' : 'users.php' ) ) . '" class="mdmfa-filter">';
		echo '<input type="hidden" name="page" value="' . esc_attr( SettingsPage::SLUG ) . '"><input type="hidden" name="tab" value="activity">';
		echo Ui::select( 'event', array_merge( array( '' => __( 'All events', 'maxtdesign-mfa' ) ), array_combine( $events, $events ) ), $event, __( 'Filter by event', 'maxtdesign-mfa' ) );
		echo ' ' . Ui::submit( __( 'Filter', 'maxtdesign-mfa' ), 'button' ) . '</form>';

		if ( array() === $rows ) {
			echo Ui::empty_state( __( 'Nothing logged yet.', 'maxtdesign-mfa' ), __( 'Sign-ins with a second step, setup, resets and blocked attempts appear here as they happen.', 'maxtdesign-mfa' ) );
		} else {
			echo Ui::table_open( __( 'Activity log', 'maxtdesign-mfa' ) );
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'When (UTC)', 'maxtdesign-mfa' ), __( 'User', 'maxtdesign-mfa' ), __( 'Event', 'maxtdesign-mfa' ), __( 'Method', 'maxtdesign-mfa' ), __( 'Where', 'maxtdesign-mfa' ), __( 'Network', 'maxtdesign-mfa' ), __( 'Detail', 'maxtdesign-mfa' ), __( 'Done by', 'maxtdesign-mfa' ) ) as $heading ) {
				echo '<th scope="col">' . esc_html( $heading ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				printf(
					'<tr><td>%1$s</td><td>%2$s</td><td><code>%3$s</code></td><td>%4$s</td><td>%5$s</td><td>%6$s</td><td>%7$s</td><td>%8$s</td></tr>',
					esc_html( gmdate( 'Y-m-d H:i:s', (int) $row['created_at'] ) ),
					esc_html( self::user_label( isset( $row['user_id'] ) ? (int) $row['user_id'] : 0 ) ),
					esc_html( (string) $row['event'] ),
					esc_html( (string) $row['factor'] ),
					esc_html( (string) $row['context'] ),
					esc_html( self::ip( isset( $row['ip'] ) ? (string) $row['ip'] : '' ) ),
					esc_html( (string) $row['detail'] ),
					esc_html( self::user_label( isset( $row['actor_id'] ) ? (int) $row['actor_id'] : 0 ) )
				);
			}
			echo '</tbody></table></div>';
			self::pagination( $found, self::LOG_PAGE, $paged, array_filter( array( 'event' => $event ) ), 'activity' );
		}

		echo '<h2>' . esc_html__( 'Log settings', 'maxtdesign-mfa' ) . '</h2>';
		echo Ui::form_open( Actions::SAVE, array( 'tab' => 'activity' ) );
		echo '<table class="form-table" role="presentation"><tbody>';
		printf(
			'<tr><th scope="row"><label for="mdmfa-retention">%1$s</label></th><td><input type="number" class="small-text" id="mdmfa-retention" name="log_retention_days" min="1" max="730" value="%2$d"></td></tr>',
			esc_html__( 'Keep log entries for (days)', 'maxtdesign-mfa' ),
			(int) $settings['log_retention_days']
		);
		printf(
			'<tr><th scope="row"><label for="mdmfa-ip">%1$s</label></th><td>%2$s <p class="description">%3$s</p></td></tr>',
			esc_html__( 'Network addresses', 'maxtdesign-mfa' ),
			Ui::select(
				'log_ip_mode',
				array(
					'truncated' => __( 'Shortened (recommended)', 'maxtdesign-mfa' ),
					'full'      => __( 'Full address', 'maxtdesign-mfa' ),
				),
				(string) $settings['log_ip_mode'],
				'',
				'mdmfa-ip'
			),
			esc_html__( 'Shortened keeps the network and drops the last part, so a log entry does not identify one device. If you store full addresses, say so in your privacy policy.', 'maxtdesign-mfa' )
		);
		echo '</tbody></table><p>' . Ui::submit( __( 'Save log settings', 'maxtdesign-mfa' ) ) . '</p></form>';
	}

	/**
	 * Tools: key status, conflicts, status refresh, settings export.
	 */
	public static function tools(): void {
		$status = Snapshot::get();
		$source = (string) ( $status['key_source'] ?? 'invalid' );
		$labels = array(
			'constant' => array( 'good', __( 'Own key in wp-config.php', 'maxtdesign-mfa' ), __( 'Authenticator secrets are encrypted with MDMFA_ENCRYPTION_KEY. Changing the WordPress salts does not affect them.', 'maxtdesign-mfa' ) ),
			'salts'    => array( 'good', __( 'WordPress salts in wp-config.php', 'maxtdesign-mfa' ), __( 'Authenticator secrets are encrypted with a key derived from AUTH_KEY and SECURE_AUTH_KEY. Before changing those salts, run "wp mdmfa key export-define" on the server and add the line it prints to wp-config.php. That pins the current key, so authenticator apps keep working after the salts change.', 'maxtdesign-mfa' ) ),
			'db'       => array( 'warn', __( 'Salts stored in the database', 'maxtdesign-mfa' ), __( 'The salts are not defined in wp-config.php, so the key sits next to the data it protects. A copy of the database would expose authenticator secrets. Run "wp mdmfa key export-define" on the server and add the line it prints to wp-config.php.', 'maxtdesign-mfa' ) ),
			'invalid'  => array( 'bad', __( 'Invalid key', 'maxtdesign-mfa' ), __( 'MDMFA_ENCRYPTION_KEY is set but is not a valid key. Authenticator apps cannot be set up or checked until it is fixed.', 'maxtdesign-mfa' ) ),
		);
		$key    = $labels[ $source ] ?? $labels['invalid'];
		$body   = '<p>' . Ui::badge( $key[0], $key[1] ) . '</p><p>' . esc_html( $key[2] ) . '</p>';
		if ( 'invalid' !== $source && empty( $status['key_ok'] ) ) {
			$body .= ! empty( $status['key_migrating'] )
				? '<p>' . Ui::badge( 'warn', __( 'Converting', 'maxtdesign-mfa' ) ) . ' ' . esc_html__( 'A new key was defined. Authenticator secrets written under the old key still work and are re-encrypted as users sign in. Run "wp mdmfa key rewrap" on the server to convert them all now.', 'maxtdesign-mfa' ) . '</p>'
				: '<p>' . Ui::badge( 'bad', __( 'Key changed', 'maxtdesign-mfa' ) ) . ' ' . esc_html__( 'The key is not the one this site started with, and the old one is gone (the salts changed). Authenticator apps set up before the change cannot be read; those users need a reset on the Coverage tab. "wp mdmfa key status" on the server lists how many.', 'maxtdesign-mfa' ) . '</p>';
		}
		echo Ui::card( __( 'Encryption key', 'maxtdesign-mfa' ), $body );

		$conflicts = Conflicts::detect();
		echo Ui::card(
			__( 'Other two-step verification plugins', 'maxtdesign-mfa' ),
			array() === $conflicts
				? '<p>' . Ui::badge( 'good', __( 'None found', 'maxtdesign-mfa' ) ) . '</p>'
				: '<p>' . Ui::badge( 'warn', __( 'Conflict', 'maxtdesign-mfa' ) ) . ' ' . esc_html(
					sprintf(
						/* translators: %s: comma-separated plugin names. */
						__( '%s is active too. Users may be asked twice or locked out. Keep one plugin and turn the other off.', 'maxtdesign-mfa' ),
						implode( ', ', $conflicts )
					)
				) . '</p>'
		);

		$body  = '<p>' . ( ! empty( $status['schema_current'] ) ? Ui::badge( 'good', __( 'Up to date', 'maxtdesign-mfa' ) ) : Ui::badge( 'bad', __( 'Needs an update', 'maxtdesign-mfa' ) ) ) . ' ';
		$body .= esc_html(
			sprintf(
				/* translators: 1: plugin version, 2: time. */
				__( 'Version %1$s. Counts on these screens were worked out at %2$s UTC and refresh every 15 minutes.', 'maxtdesign-mfa' ),
				MDMFA_VERSION,
				gmdate( 'H:i', (int) ( $status['generated_at'] ?? Clock::now() ) )
			)
		) . '</p>';
		$body .= Ui::form_open( Actions::REFRESH ) . '<p>' . Ui::submit( __( 'Refresh counts now', 'maxtdesign-mfa' ), 'button' ) . '</p></form>';
		echo Ui::card( __( 'Status', 'maxtdesign-mfa' ), $body );

		echo Ui::card(
			__( 'Passkeys (beta)', 'maxtdesign-mfa' ),
			'<p>' . ( Passkeys::passkey_only_enabled() ? Ui::badge( 'warn', __( 'Passkey-only sign-in is available', 'maxtdesign-mfa' ) ) : Ui::badge( 'good', __( 'Second step only', 'maxtdesign-mfa' ) ) ) . '</p>'
			. '<p>' . esc_html__( 'The code that checks passkeys was written for this plugin and has not had an independent security review yet. A passkey is used after the password, never in place of it, so a mistake in that code alone cannot sign anyone in. Turn passkeys on per role on the Policy tab.', 'maxtdesign-mfa' ) . '</p>'
			. '<p>' . esc_html__( 'To also allow signing in with a passkey and no password, add this line to wp-config.php. Only do this if you accept that risk:', 'maxtdesign-mfa' ) . '</p><p><code>define( \'MDMFA_PASSKEY_ONLY_SIGNIN\', true );</code></p>'
		);

		echo Ui::card(
			__( 'Export settings', 'maxtdesign-mfa' ),
			'<p>' . esc_html__( 'Downloads the policy and options as a JSON file. It contains no secrets, no user data and not the login address.', 'maxtdesign-mfa' ) . '</p>'
			. Ui::form_open( Actions::EXPORT ) . '<p>' . Ui::submit( __( 'Download settings', 'maxtdesign-mfa' ), 'button' ) . '</p></form>'
		);

		echo Ui::card(
			__( 'Locked out?', 'maxtdesign-mfa' ),
			'<p>' . esc_html__( 'Add this line to wp-config.php to switch the plugin off and sign in with a password only:', 'maxtdesign-mfa' ) . '</p><p><code>define( \'MDMFA_DISABLE\', true );</code></p>'
			. '<p>' . esc_html__( 'On the server, "wp mdmfa user reset <user>" removes one user\'s methods and "wp mdmfa unlock <user>" clears a lock.', 'maxtdesign-mfa' ) . '</p>'
		);
	}

	/**
	 * Policy as a badge.
	 *
	 * @param string $policy Policy value.
	 */
	private static function policy_badge( string $policy ): string {
		if ( Settings::POLICY_REQUIRED === $policy ) {
			return Ui::badge( 'neutral', __( 'Required', 'maxtdesign-mfa' ) );
		}

		return Ui::badge( 'neutral', Settings::POLICY_OFF === $policy ? __( 'Off', 'maxtdesign-mfa' ) : __( 'Optional', 'maxtdesign-mfa' ) );
	}

	/**
	 * A user's state as badges.
	 *
	 * @param \WP_User $user User.
	 */
	private static function status_badges( \WP_User $user ): string {
		$out = array();
		if ( Policy::is_enrolled( $user->ID ) ) {
			$out[] = Ui::badge( 'good', __( 'Set up', 'maxtdesign-mfa' ) );
		} elseif ( Settings::POLICY_REQUIRED === Policy::policy( $user ) ) {
			$left  = Policy::grace_remaining( $user );
			$out[] = $left > 0
				/* translators: %d: days left. */
				? Ui::badge( 'warn', sprintf( _n( '%d day left to set up', '%d days left to set up', (int) ceil( $left / DAY_IN_SECONDS ), 'maxtdesign-mfa' ), (int) ceil( $left / DAY_IN_SECONDS ) ) )
				: ( '' === (string) get_user_meta( $user->ID, Policy::GRACE_META, true ) ? Ui::badge( 'warn', __( 'Not set up, not signed in yet', 'maxtdesign-mfa' ) ) : Ui::badge( 'bad', __( 'Overdue', 'maxtdesign-mfa' ) ) );
		} else {
			$out[] = Ui::badge( 'neutral', __( 'Not set up', 'maxtdesign-mfa' ) );
		}
		if ( Lockout::state( $user->ID )['locked_until'] > Clock::now() ) {
			$out[] = Ui::badge( 'bad', __( 'Locked', 'maxtdesign-mfa' ) );
		}

		return implode( ' ', $out );
	}

	/**
	 * A user's methods in words.
	 *
	 * @param \WP_User $user User.
	 */
	private static function methods( \WP_User $user ): string {
		$methods  = array();
		$passkeys = PasskeyStore::count( $user->ID );
		$trusted  = TrustedDevice::count( $user->ID );
		if ( TotpStore::has( $user->ID ) ) {
			$methods[] = __( 'Authenticator app', 'maxtdesign-mfa' );
		}
		if ( $passkeys > 0 ) {
			/* translators: %d: number of passkeys. */
			$methods[] = sprintf( _n( '%d passkey', '%d passkeys', $passkeys, 'maxtdesign-mfa' ), $passkeys );
		}
		if ( EmailCode::has( $user->ID ) ) {
			$methods[] = __( 'Email code', 'maxtdesign-mfa' );
		}
		if ( $trusted > 0 ) {
			/* translators: %d: number of devices. */
			$methods[] = sprintf( _n( '%d trusted device', '%d trusted devices', $trusted, 'maxtdesign-mfa' ), $trusted );
		}

		return array() === $methods ? __( 'None', 'maxtdesign-mfa' ) : implode( ', ', $methods );
	}

	/**
	 * Login name for a log row, or a placeholder for a deleted or absent user.
	 *
	 * @param int $user_id User ID.
	 */
	private static function user_label( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		$user = get_userdata( $user_id );

		/* translators: %d: user ID. */
		return $user instanceof \WP_User ? $user->user_login : sprintf( __( 'Deleted user %d', 'maxtdesign-mfa' ), $user_id );
	}

	/**
	 * Packed address as text.
	 *
	 * @param string $packed 4 or 16 bytes, or ''.
	 */
	private static function ip( string $packed ): string {
		if ( 4 !== strlen( $packed ) && 16 !== strlen( $packed ) ) {
			return '';
		}
		$text = inet_ntop( $packed );

		return false === $text ? '' : $text;
	}

	/**
	 * Previous and next links.
	 *
	 * @param int                   $found    Total rows.
	 * @param int                   $per_page Rows per page.
	 * @param int                   $paged    Current page.
	 * @param array<string, string> $args     Filters to keep.
	 * @param string                $tab      Tab slug.
	 */
	private static function pagination( int $found, int $per_page, int $paged, array $args, string $tab ): void {
		$pages = (int) ceil( $found / $per_page );
		if ( $pages <= 1 ) {
			return;
		}
		echo '<nav class="mdmfa-pages" aria-label="' . esc_attr__( 'Pages', 'maxtdesign-mfa' ) . '">';
		if ( $paged > 1 ) {
			printf( '<a class="button" href="%1$s">%2$s</a> ', esc_url( SettingsPage::url( $tab, array_merge( $args, array( 'paged' => $paged - 1 ) ) ) ), esc_html__( 'Previous', 'maxtdesign-mfa' ) );
		}
		/* translators: 1: current page, 2: total pages. */
		echo '<span>' . esc_html( sprintf( __( 'Page %1$d of %2$d', 'maxtdesign-mfa' ), $paged, $pages ) ) . '</span>';
		if ( $paged < $pages ) {
			printf( ' <a class="button" href="%1$s">%2$s</a>', esc_url( SettingsPage::url( $tab, array_merge( $args, array( 'paged' => $paged + 1 ) ) ) ), esc_html__( 'Next', 'maxtdesign-mfa' ) );
		}
		echo '</nav>';
	}
}
