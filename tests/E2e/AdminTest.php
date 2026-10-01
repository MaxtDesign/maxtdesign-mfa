<?php
/**
 * P7 definition of done: the settings page (menu, tabs, assets, saves with validation,
 * capability and step-up), coverage actions, the status contract and the privacy tools.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class AdminTest extends E2eTestCase {

	private const PAGE = 'wp-admin/users.php?page=md-mfa';
	private const POST = 'wp-admin/admin-post.php';

	protected function tearDown(): void {
		if ( '' !== self::$url ) {
			self::reset_settings();
			self::eval( '$o = get_option( "mdmfa_login" ); $o["enabled"] = true; $o["public_login"] = "auto"; $o["public_page"] = 0; update_option( "mdmfa_login", $o, true ); delete_transient( "mdmfa_status_cache" );' );
		}
		parent::tearDown();
	}

	/**
	 * A signed-in administrator. With $enrolled the session is MFA-verified (and fresh).
	 *
	 * @return array{Browser, int, string, string}
	 */
	private function admin( bool $enrolled = false ): array {
		list( $id, $login, $pass ) = self::user( 'administrator' );
		$browser                   = $this->browser();
		$secret                    = $enrolled ? self::enroll( $id ) : '';
		$first                     = $this->password( $browser, $login, $pass );
		if ( $enrolled ) {
			self::assertTrue( $this->submit_code( $browser, self::code( $secret ) )->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		} else {
			// Required role, still in the setup period: skip once.
			$page = $browser->get( $first->location() );
			$skip = $browser->post( self::lp( 'action=mdmfa-enroll' ), array( 'mdmfa_form' => $page->form_token(), 'mdmfa_skip' => '1' ) );
			self::assertTrue( $skip->sets_cookie_prefix( 'wordpress_logged_in_' ) );
		}
		return array( $browser, $id, $login, $secret );
	}

	/**
	 * Posts an admin form with the nonce of the tab it lives on.
	 *
	 * @param array<string, mixed> $fields
	 */
	private function submit( Browser $browser, string $tab, string $action, array $fields ): Response {
		$page = $browser->get( self::PAGE . '&tab=' . $tab );
		return $browser->post( self::POST, array_merge( array( 'action' => $action, '_wpnonce' => $page->input( '_wpnonce' ) ), $fields ) );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function mfa_status( bool $fresh = true ): array {
		return (array) json_decode( $fresh ? self::wp( 'mdmfa', 'status', '--fresh', '--format=json' ) : self::wp( 'mdmfa', 'status', '--format=json' ), true );
	}

	/**
	 * The role fields a policy save posts for every role, as the form would.
	 *
	 * @param array<string, array<string, mixed>> $overrides
	 * @return array<string, mixed>
	 */
	private static function policy_form( array $overrides ): array {
		$roles = array();
		foreach ( array( 'administrator', 'editor', 'author', 'contributor', 'subscriber', '__unlisted' ) as $role ) {
			$required       = in_array( $role, array( 'administrator', 'editor' ), true );
			$roles[ $role ] = array_merge(
				array(
					'policy'     => $required ? 'required' : 'optional',
					'factors'    => array( 'totp' => '1', 'passkey' => '1' ),
					'grace_days' => '7',
				),
				$overrides[ $role ] ?? array()
			);
		}
		return array( 'tab' => 'policy', 'roles' => $roles );
	}

	public function test_one_menu_entry_under_users_with_tabs_and_scoped_assets(): void {
		list( $browser ) = $this->admin();

		$page = $browser->get( self::PAGE );
		self::assertSame( 200, $page->status );
		self::assertStringContainsString( '<h1 class="md-suite-page-header__title">MFA</h1>', $page->body );
		self::assertSame( 1, preg_match_all( '/<a[^>]+href=[\'"]users\.php\?page=md-mfa[\'"]/', $page->body ), 'exactly one menu entry, under Users' );
		self::assertStringNotContainsString( 'toplevel_page_maxtdesign', $page->body, 'a lone install grows no MaxtDesign top-level menu' );
		self::assertSame( 1, preg_match( '/<a class="nav-tab nav-tab-active" aria-current="page" href="[^"]*tab=policy"/', $page->body ) );
		self::assertSame( 8, preg_match_all( '/<a class="nav-tab[ "]/', $page->body ), 'eight tabs' );

		$unknown = $browser->get( self::PAGE . '&tab=nope' );
		self::assertSame( 1, preg_match( '/nav-tab-active" aria-current="page" href="[^"]*tab=policy"/', $unknown->body ), 'an unknown tab falls back to the first' );

		foreach ( array( 'factors', 'location', 'sidedoors', 'recovery', 'coverage', 'activity', 'tools' ) as $tab ) {
			$screen = $browser->get( self::PAGE . '&tab=' . $tab );
			self::assertSame( 200, $screen->status, $tab );
			self::assertSame( 1, preg_match( '/nav-tab-active" aria-current="page" href="[^"]*tab=' . $tab . '"/', $screen->body ), $tab );
			self::assertStringNotContainsString( 'Warning</b>', $screen->body, $tab );
			self::assertStringNotContainsString( 'Fatal error', $screen->body, $tab );
			self::assertSame( 1, preg_match( '/<div class="wrap md-suite-wrap mdmfa-admin.*?<div class="clear">/s', $screen->body, $own ), $tab );
			self::assertSame( 0, preg_match( '/<(style|script)\b|\sstyle="/i', $own[0] ), "no inline style or script in the plugin's markup on {$tab}" );
		}

		// Assets: on this screen only, and nowhere else in wp-admin.
		self::assertSame( 1, preg_match_all( '#assets/admin/mdmfa-admin\.css#', $page->body ) );
		self::assertSame( 1, preg_match( '#<script[^>]+assets/admin/mdmfa-admin\.js[^>]*>#', $page->body, $tag ) );
		self::assertStringContainsString( ' defer', $tag[0], 'the script is deferred' );
		foreach ( array( 'wp-admin/', 'wp-admin/users.php', 'wp-admin/plugins.php', 'wp-admin/profile.php?page=mdmfa-account' ) as $other ) {
			self::assertStringNotContainsString( 'mdmfa-admin', $browser->get( $other )->body, "no admin assets on {$other}" );
		}

		$plugins = $browser->get( 'wp-admin/plugins.php' );
		self::assertSame( 1, preg_match( '#<a href="[^"]*users\.php\?page=md-mfa">Settings</a>#', $plugins->body ), 'Settings link on the Plugins screen' );
	}

	public function test_only_managers_reach_the_page_and_its_actions(): void {
		list( $id, $login, $pass ) = self::user( 'subscriber' );
		$browser                   = $this->browser();
		$this->password( $browser, $login, $pass );

		self::assertSame( 403, $browser->get( self::PAGE )->status );
		self::assertStringNotContainsString( 'md-mfa', $browser->get( 'wp-admin/profile.php' )->body, 'no menu entry for them' );

		// A nonce from one of their own screens does not help.
		$account = $browser->get( 'wp-admin/profile.php?page=mdmfa-account' );
		$forged  = $browser->post( self::POST, array_merge( array( 'action' => 'mdmfa_save', '_wpnonce' => $account->input( '_wpnonce' ) ), self::policy_form( array( 'subscriber' => array( 'policy' => 'off' ) ) ) ) );
		self::assertSame( 403, $forged->status );
		self::assertSame( 'optional', self::mfa_status()['roles']['subscriber']['policy'] );

		$anonymous = $this->browser()->post( self::POST, array( 'action' => 'mdmfa_save', 'tab' => 'policy' ) );
		self::assertNotSame( 200, $anonymous->status, 'logged-out posts go nowhere' );
		self::assertSame( 'optional', self::mfa_status()['roles']['subscriber']['policy'] );
	}

	public function test_policy_save_validates_and_shows_in_status(): void {
		list( $browser ) = $this->admin();

		$saved = $this->submit(
			$browser,
			'policy',
			'mdmfa_save',
			self::policy_form(
				array(
					'author'      => array( 'policy' => 'required', 'factors' => array( 'totp' => '1', 'email' => '1' ), 'grace_days' => '3', 'trusted_devices' => '1', 'passwordless' => '1' ),
					'contributor' => array( 'policy' => 'bogus', 'grace_days' => '999' ),
					'subscriber'  => array( 'policy' => 'required', 'factors' => array() ),
				)
			)
		);
		self::assertSame( 302, $saved->status );
		self::assertStringContainsString( 'mdmfa_notice=saved_fixed', $saved->location() );
		self::assertStringContainsString( 'A Required role must keep an authenticator app or a passkey', $browser->get( $saved->location() )->body );

		$roles = self::mfa_status()['roles'];
		self::assertSame( 'required', $roles['author']['policy'] );
		self::assertSame( array( 'totp', 'recovery', 'email' ), $roles['author']['factors'] );
		self::assertSame( 3, $roles['author']['grace_days'] );
		self::assertSame( 'optional', $roles['contributor']['policy'], 'an unknown policy keeps the current one' );
		self::assertSame( 90, $roles['contributor']['grace_days'], 'days are clamped' );
		self::assertSame( array( 'totp', 'recovery' ), $roles['subscriber']['factors'], 'a Required role keeps the authenticator app' );

		$stored = (array) json_decode( self::wp( 'option', 'get', 'mdmfa_settings', '--format=json' ), true );
		self::assertTrue( $stored['roles']['author']['trusted_devices'] );
		self::assertFalse( $stored['roles']['author']['passwordless'], 'passkey-only sign-in needs the passkey method' );
		self::assertFalse( $stored['roles']['author']['email_recovery'], 'the Recovery tab\'s fields are untouched by a Policy save' );
		self::assertContains( 'policy_changed', array_column( (array) json_decode( self::eval( 'global $wpdb; echo wp_json_encode( $wpdb->get_results( "SELECT event FROM {$wpdb->prefix}mdmfa_log ORDER BY id DESC LIMIT 5", ARRAY_A ) );' ), true ), 'event' ) );

		// The form shows what was stored.
		$page = $browser->get( self::PAGE . '&tab=policy' );
		self::assertSame( 1, preg_match( '/name="roles\[author\]\[grace_days\]" value="3"/', $page->body ) );
		self::assertSame( 1, preg_match( '/name="roles\[author\]\[factors\]\[email\]" value="1" checked/', $page->body ) );
	}

	public function test_side_doors_recovery_factors_and_log_settings_save(): void {
		list( $browser ) = $this->admin();

		$this->submit( $browser, 'sidedoors', 'mdmfa_save', array( 'tab' => 'sidedoors', 'application_passwords' => 'on', 'xmlrpc' => 'off', 'block_wpcom_sso' => '1', 'roles' => array( 'editor' => array( 'app_passwords' => '1' ) ) ) );
		$status = self::mfa_status();
		self::assertSame( 'on', $status['app_passwords'] );
		self::assertSame( 'off', $status['xmlrpc'] );
		self::assertSame( 'blocked', $status['wpcom_sso'] );

		$this->submit( $browser, 'sidedoors', 'mdmfa_save', array( 'tab' => 'sidedoors', 'application_passwords' => 'nonsense', 'xmlrpc' => 'nonsense' ) );
		$status = self::mfa_status();
		self::assertSame( 'per_role', $status['app_passwords'], 'unknown values fall back to the safe default' );
		self::assertSame( 'block_password', $status['xmlrpc'] );
		self::assertSame( 'inactive', $status['wpcom_sso'] );

		$this->submit( $browser, 'recovery', 'mdmfa_save', array( 'tab' => 'recovery', 'roles' => array( 'editor' => array( 'email_recovery' => '1', 'recovery_wait_hours' => '9999' ) ) ) );
		$this->submit( $browser, 'factors', 'mdmfa_save', array( 'tab' => 'factors', 'trusted_device_days' => '0', 'counter_anomaly_block' => '1' ) );
		$this->submit( $browser, 'activity', 'mdmfa_save', array( 'tab' => 'activity', 'log_retention_days' => '30', 'log_ip_mode' => 'full' ) );
		$stored = (array) json_decode( self::wp( 'option', 'get', 'mdmfa_settings', '--format=json' ), true );
		self::assertTrue( $stored['roles']['editor']['email_recovery'] );
		self::assertSame( 168, $stored['roles']['editor']['recovery_wait_hours'] );
		self::assertSame( 'required', $stored['roles']['editor']['policy'], 'other tabs\' fields survive' );
		self::assertSame( 1, $stored['trusted_device_days'] );
		self::assertTrue( $stored['counter_anomaly_block'] );
		self::assertSame( 30, $stored['log_retention_days'] );
		self::assertSame( 'full', $stored['log_ip_mode'] );
	}

	public function test_a_request_without_the_nonce_changes_nothing(): void {
		list( $browser ) = $this->admin();

		$forged = $browser->post( self::POST, array_merge( array( 'action' => 'mdmfa_save', '_wpnonce' => 'abcdef1234' ), self::policy_form( array( 'editor' => array( 'policy' => 'off' ) ) ) ) );
		self::assertSame( 403, $forged->status );
		self::assertSame( 'required', self::mfa_status()['roles']['editor']['policy'] );

		$get = $browser->get( self::POST . '?action=mdmfa_save&tab=policy' );
		self::assertSame( 403, $get->status, 'no GET mutations' );
	}

	public function test_an_enrolled_administrator_needs_a_recent_verification_to_change_settings(): void {
		list( $browser, $id, , $secret ) = $this->admin( true );
		self::age_sessions( $id );

		$refused = $this->submit( $browser, 'policy', 'mdmfa_save', self::policy_form( array( 'editor' => array( 'policy' => 'off' ) ) ) );
		self::assertStringContainsString( 'mdmfa_notice=stepup', $refused->location() );
		$notice = $browser->get( $refused->location() );
		self::assertStringContainsString( 'Nothing was changed.', $notice->body );
		self::assertStringContainsString( 'page=mdmfa-account', $notice->body, 'with a link to confirm' );
		self::assertSame( 'required', self::mfa_status()['roles']['editor']['policy'] );

		$slug = $this->submit( $browser, 'location', 'mdmfa_slug', array( 'slug' => 'new-door-' . bin2hex( random_bytes( 3 ) ) ) );
		self::assertStringContainsString( 'mdmfa_notice=stepup', $slug->location(), 'the login address is protected the same way' );
		list( $victim ) = self::user( 'subscriber' );
		self::enroll( $victim );
		$reset = $this->submit( $browser, 'coverage', 'mdmfa_users', array( 'do' => 'reset', 'users' => array( (string) $victim ) ) );
		self::assertStringContainsString( 'mdmfa_notice=stepup', $reset->location(), 'and so is resetting users' );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Factors\TotpStore::has( %d ) ? "true" : "false";', $victim ) ) );

		$account = $browser->get( 'wp-admin/users.php?page=mdmfa-account' );
		$browser->post( 'wp-admin/users.php?page=mdmfa-account', array( '_wpnonce' => $account->input( '_wpnonce' ), 'mdmfa_op' => 'stepup', 'mdmfa_method' => 'totp', 'mdmfa_code' => self::code( $secret, 1 ) ) );
		$ok = $this->submit( $browser, 'policy', 'mdmfa_save', self::policy_form( array( 'editor' => array( 'policy' => 'optional' ) ) ) );
		self::assertStringContainsString( 'mdmfa_notice=saved', $ok->location() );
		self::assertSame( 'optional', self::mfa_status()['roles']['editor']['policy'] );
	}

	public function test_login_address_change_and_public_login_page(): void {
		list( $browser ) = $this->admin();
		$old             = self::$login;
		self::eval( 'delete_option( "e2e_mail" );' );

		$bad = $this->submit( $browser, 'location', 'mdmfa_slug', array( 'slug' => 'wp-admin' ) );
		self::assertStringContainsString( 'mdmfa_notice=slug_bad', $bad->location() );
		self::assertSame( rtrim( self::$url, '/' ) . '/' . $old, self::wp( 'mdmfa', 'slug', 'get' ) );

		$new     = 'staff-door-' . bin2hex( random_bytes( 3 ) );
		$changed = $this->submit( $browser, 'location', 'mdmfa_slug', array( 'slug' => $new ) );
		try {
			self::assertStringContainsString( 'mdmfa_notice=slug_ok', $changed->location() );
			self::assertSame( 404, $this->browser()->get( $old )->status, 'the old address stops working' );
			self::assertSame( 200, $this->browser()->get( $new )->status );
			self::assertStringContainsString( $new, $browser->get( self::PAGE . '&tab=location' )->body, 'the screen shows the new address to a manager' );
			$subjects = self::eval( 'echo implode( "|", array_column( (array) get_option( "e2e_mail", array() ), "subject" ) );' );
			self::assertStringContainsString( 'The login address changed', $subjects, 'administrators are emailed' );
		} finally {
			self::wp( 'mdmfa', 'slug', 'set', $old );
		}

		// "A page I choose" needs a published page.
		$missing = $this->submit( $browser, 'location', 'mdmfa_save', array( 'tab' => 'location', 'enabled' => '1', 'public_login' => 'page', 'public_page' => '0' ) );
		self::assertStringContainsString( 'mdmfa_notice=page_needed', $missing->location() );
		$page_id = (int) self::wp( 'post', 'create', '--post_type=page', '--post_status=publish', '--post_title=Sign in here', '--porcelain' );
		$this->submit( $browser, 'location', 'mdmfa_save', array( 'tab' => 'location', 'enabled' => '1', 'public_login' => 'page', 'public_page' => (string) $page_id ) );
		$public = self::eval( 'echo MaxtDesign\Mfa\Location\LoginLocation::public_url();' );
		self::assertSame( self::eval( sprintf( 'echo get_permalink( %d );', $page_id ) ), $public );
		self::assertStringNotContainsString( $old, $public, 'logged-out login links no longer publish the login address' );

		// Unticking the box puts the login back at wp-login.php.
		$this->submit( $browser, 'location', 'mdmfa_save', array( 'tab' => 'location', 'public_login' => 'auto', 'public_page' => '0' ) );
		self::assertSame( 200, $this->browser()->get( 'wp-login.php' )->status );
		self::assertFalse( self::mfa_status()['login_location'] );
	}

	public function test_coverage_resets_unlocks_and_signs_users_out(): void {
		list( $browser, $admin_id ) = $this->admin();
		self::eval( 'delete_option( "e2e_mail" );' );
		list( $reset, $reset_login, $reset_pass ) = self::user( 'subscriber' );
		self::enroll( $reset );
		list( $locked ) = self::user( 'subscriber' );
		self::enroll( $locked );
		self::wp( 'user', 'meta', 'update', (string) $locked, 'mdmfa_failures', '{"count":20,"last_fail":' . time() . ',"locked_until":' . ( time() + 3000 ) . ',"lock_level":1}', '--format=json' );
		list( $out, $out_login, $out_pass ) = self::user( 'subscriber' );
		$session                            = $this->browser();
		$this->password( $session, $out_login, $out_pass );
		self::assertSame( 1, self::sessions( $out ) );

		$list = $browser->get( self::PAGE . '&tab=coverage&s=' . $reset_login );
		self::assertStringContainsString( $reset_login . '@example.com', $list->body );
		self::assertStringContainsString( 'md-suite-badge--good">Set up', $list->body, 'state words are badges' );
		self::assertStringContainsString( 'Authenticator app', $list->body );
		self::assertStringContainsString( 'md-suite-empty', $browser->get( self::PAGE . '&tab=coverage&s=no-such-user-zzz' )->body, 'a designed empty state' );

		$none = $this->submit( $browser, 'coverage', 'mdmfa_users', array( 'do' => 'reset' ) );
		self::assertStringContainsString( 'mdmfa_notice=users_none', $none->location() );

		$done = $this->submit( $browser, 'coverage', 'mdmfa_users', array( 'do' => 'reset', 'users' => array( (string) $reset ) ) );
		self::assertStringContainsString( 'mdmfa_notice=users_reset', $done->location() );
		self::assertSame( 'false', self::eval( sprintf( 'echo MaxtDesign\Mfa\Policy\Policy::is_enrolled( %d ) ? "true" : "false";', $reset ) ) );
		self::assertCount( 1, self::mail_to( $reset_login . '@example.com' ), 'the user is told' );
		$log = (array) json_decode( self::eval( sprintf( 'global $wpdb; echo wp_json_encode( $wpdb->get_row( "SELECT event, actor_id FROM {$wpdb->prefix}mdmfa_log WHERE user_id = %d ORDER BY id DESC LIMIT 1", ARRAY_A ) );', $reset ) ), true );
		self::assertSame( 'admin_reset', $log['event'] );
		self::assertSame( $admin_id, (int) $log['actor_id'], 'the log names who did it' );
		self::assertTrue( $this->password( $this->browser(), $reset_login, $reset_pass )->sets_cookie_prefix( 'wordpress_logged_in_' ), 'an Optional user is password-only again' );

		$this->submit( $browser, 'coverage', 'mdmfa_users', array( 'do' => 'unlock', 'users' => array( (string) $locked ) ) );
		self::assertSame( '0', self::eval( sprintf( '$f = get_user_meta( %d, "mdmfa_failures", true ); echo is_array( $f ) ? (int) $f["locked_until"] : 0;', $locked ) ) );

		$this->submit( $browser, 'coverage', 'mdmfa_users', array( 'do' => 'signout', 'users' => array( (string) $out ) ) );
		self::assertSame( 0, self::sessions( $out ) );
		self::assertSame( 404, $session->get( 'wp-admin/profile.php' )->status, 'their browser is signed out (logged-out wp-admin is a 404 with the moved login)' );
	}

	public function test_status_matches_the_admin_counts_and_holds_no_secret(): void {
		list( $browser, , $admin_login ) = $this->admin();
		list( $id, $login )              = self::user( 'contributor' );
		self::enroll( $id );
		list( $second ) = self::user( 'contributor' );

		$status = self::mfa_status();
		self::assertGreaterThanOrEqual( 2, $status['roles']['contributor']['users'] );
		self::assertGreaterThanOrEqual( 1, $status['roles']['contributor']['enrolled'] );
		self::assertSame( $status['roles']['contributor']['enrolled'], $status['roles']['contributor']['by_factor']['totp'] );

		// The Policy tab prints the same numbers (both read the cached snapshot).
		$page = $browser->get( self::PAGE . '&tab=policy' );
		foreach ( array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' ) as $role ) {
			self::assertSame(
				1,
				preg_match( '/<tr><th scope="row">[^<]+<\/th><td>(\d+)<\/td><td>(\d+)<\/td><td><select name="roles\[' . $role . '\]\[policy\]"/', $page->body, $m ),
				$role
			);
			self::assertSame( $status['roles'][ $role ]['users'], (int) $m[1], "users in {$role}" );
			self::assertSame( $status['roles'][ $role ]['enrolled'], (int) $m[2], "set up in {$role}" );
		}
		$coverage = $browser->get( self::PAGE . '&tab=coverage' );
		self::assertStringContainsString( '>' . $status['enrolled_users'] . ' set up<', $coverage->body );

		// Never a secret, a user name or the login address: in the CLI, the filter and the export.
		$salt   = self::eval( 'echo AUTH_KEY;' );
		$cipher = self::eval( sprintf( '$t = get_user_meta( %d, "mdmfa_totp", true ); echo $t["ct"];', $id ) );
		$export = $browser->post( self::POST, array( 'action' => 'mdmfa_export', '_wpnonce' => $browser->get( self::PAGE . '&tab=tools' )->input( '_wpnonce' ) ) );
		self::assertSame( 200, $export->status );
		self::assertStringContainsString( 'attachment; filename="maxtdesign-mfa-settings.json"', $export->headers['content-disposition'] ?? '' );
		self::assertIsArray( json_decode( $export->body, true )['settings']['roles'] ?? null );
		foreach ( array( 'wp mdmfa status' => (string) json_encode( $status ), 'mdmfa_status build' => self::eval( 'echo wp_json_encode( MaxtDesign\Mfa\Status\Snapshot::build() );' ), 'settings export' => $export->body ) as $name => $text ) {
			self::assertStringNotContainsString( self::$login, $text, "{$name}: no login address" );
			self::assertStringNotContainsString( $salt, $text, "{$name}: no key material" );
			self::assertStringNotContainsString( $cipher, $text, "{$name}: no factor data" );
			self::assertStringNotContainsString( $login, $text, "{$name}: no user names" );
			self::assertStringNotContainsString( $admin_login, $text, "{$name}: no user names" );
		}

		// Cached for 15 minutes; --fresh rebuilds.
		self::enroll( $second );
		self::assertSame( $status['roles']['contributor']['enrolled'], self::mfa_status( false )['roles']['contributor']['enrolled'], 'cached' );
		self::assertSame( $status['roles']['contributor']['enrolled'] + 1, self::mfa_status()['roles']['contributor']['enrolled'], 'fresh' );
	}

	public function test_privacy_export_and_erase(): void {
		list( $id, $login, $pass ) = self::user( 'author' );
		$secret                    = self::enroll( $id );
		$authenticator             = new \MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator();
		self::seed_passkey( $id, $authenticator );
		$browser = $this->browser();
		$this->password( $browser, $login, $pass );
		$this->submit_code( $browser, self::code( $secret ) );

		$export = (array) json_decode( self::eval( sprintf( 'echo wp_json_encode( MaxtDesign\Mfa\Privacy\Privacy::export( %s, 1 ) );', var_export( $login . '@example.com', true ) ) ), true );
		self::assertTrue( $export['done'] );
		$groups = array_column( $export['data'], 'group_id' );
		self::assertContains( 'mdmfa-methods', $groups );
		self::assertContains( 'mdmfa-passkeys', $groups );
		self::assertContains( 'mdmfa-log', $groups );
		$text = (string) json_encode( $export );
		self::assertStringContainsString( 'E2E key', $text, 'passkey names are exported' );
		self::assertStringContainsString( 'challenge_ok', $text );
		self::assertStringNotContainsString( self::eval( sprintf( '$t = get_user_meta( %d, "mdmfa_totp", true ); echo $t["ct"];', $id ) ), $text, 'no secrets in an export that goes to a mailbox' );
		self::assertStringNotContainsString( rtrim( strtr( base64_encode( $authenticator->cose() ), '+/', '-_' ), '=' ), $text );

		$erase = (array) json_decode( self::eval( sprintf( 'echo wp_json_encode( MaxtDesign\Mfa\Privacy\Privacy::erase( %s, 1 ) );', var_export( $login . '@example.com', true ) ) ), true );
		self::assertTrue( $erase['items_removed'] );
		self::assertTrue( $erase['items_retained'], 'methods are kept while the account exists' );
		self::assertSame( array(), self::log_events( $id ) );
		self::assertSame( 'true', self::eval( sprintf( 'echo MaxtDesign\Mfa\Policy\Policy::is_enrolled( %d ) ? "true" : "false";', $id ) ) );

		self::assertSame( array( 'data' => array(), 'done' => true ), json_decode( self::eval( 'echo wp_json_encode( MaxtDesign\Mfa\Privacy\Privacy::export( "nobody@example.com", 1 ) );' ), true ) );
		self::assertSame( 'yes', self::eval( '$e = apply_filters( "wp_privacy_personal_data_exporters", array() ); $r = apply_filters( "wp_privacy_personal_data_erasers", array() ); echo isset( $e["maxtdesign-mfa"], $r["maxtdesign-mfa"] ) ? "yes" : "no";' ) );
	}
}
