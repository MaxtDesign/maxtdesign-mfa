<?php
/**
 * P4 definition of done, core site without WooCommerce (plan 5.1-5.6, section 14).
 * Pretty permalinks (the CI job sets /%postname%/).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class LoginLocationTest extends E2eTestCase {

	private static function mails(): array {
		return (array) json_decode( self::eval( 'echo wp_json_encode( get_option( "e2e_mail", array() ) );' ), true );
	}

	public function test_request_matrix_of_plan_section_5_2(): void {
		$b = $this->browser();

		$rows = array(
			array( 'GET', 'wp-login.php', 404 ),
			array( 'GET', 'wp-login.php?action=lostpassword', 404 ),
			array( 'GET', 'wp-login.php?action=register', 404 ),
			array( 'GET', 'wp-login.php?action=logout', 404 ),
			array( 'GET', 'wp-login.php?action=postpass', 404 ),
			array( 'POST', 'wp-login.php', 404 ),
			array( 'GET', 'wp-admin/', 404 ),
			array( 'GET', 'wp-admin/options-general.php', 404 ),
			array( 'GET', 'wp-admin/profile.php', 404 ),
			array( 'GET', 'wp-admin/network/', 404 ),
			array( 'GET', 'login', 404 ),
			array( 'GET', 'login.php', 404 ),
			array( 'GET', 'admin', 404 ),
			array( 'GET', 'dashboard', 404 ),
			array( 'GET', self::lp(), 200 ),
		);
		foreach ( $rows as list( $method, $path, $status ) ) {
			$r = 'POST' === $method ? $b->post( $path, array( 'log' => 'admin', 'pwd' => 'x' ) ) : $b->get( $path );
			self::assertSame( $status, $r->status, "{$method} /{$path}" );
			self::assertStringNotContainsString( self::$login, $r->location(), "{$method} /{$path} must not redirect to the slug" );
			if ( 404 === $status ) {
				self::assertStringNotContainsString( self::$login, $r->body, "{$method} /{$path} body must not contain the slug" );
				self::assertStringNotContainsString( 'name="pwd"', $r->body, "{$method} /{$path} must not show a login form" );
			}
		}

		$theme404 = $b->get( 'wp-login.php' );
		self::assertStringContainsString( '<body', $theme404->body, 'wp-login.php 404 is the theme\'s page' );
		self::assertStringContainsString( 'no-store', $theme404->headers['cache-control'] ?? '' );

		// Exempt wp-admin entry points still work logged out.
		self::assertNotSame( 404, $b->post( 'wp-admin/admin-ajax.php', array( 'action' => 'nopriv-nothing' ) )->status, 'admin-ajax.php' );
		self::assertNotSame( 404, $b->post( 'wp-admin/admin-post.php', array( 'action' => 'nothing' ) )->status, 'admin-post.php' );
		self::assertNotSame( 404, $b->get( 'wp-admin/upgrade.php' )->status, 'upgrade.php' );
	}

	public function test_slug_serves_core_login_with_no_store_headers_and_is_login(): void {
		$r = $this->browser()->get( self::lp() );

		self::assertSame( 200, $r->status );
		self::assertStringContainsString( 'name="pwd"', $r->body );
		self::assertStringContainsString( 'no-store', $r->headers['cache-control'] ?? '' );
		self::assertSame( 'noindex, nofollow', $r->headers['x-robots-tag'] ?? '' );
		// Core's wp_admin_headers() (login_init) sets strict-origin-when-cross-origin after ours;
		// either way no other origin receives the slug path in a Referer.
		self::assertContains( $r->headers['referrer-policy'] ?? '', array( 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer' ) );
		self::assertSame( 'wp-login.php', $r->headers['x-e2e-pagenow'] ?? '', '$pagenow is wp-login.php on the slug' );
		self::assertSame( '1', $r->headers['x-e2e-is-login'] ?? '', 'is_login() is true on the slug' );
		self::assertStringNotContainsString( 'wp-login.php', $r->body, 'the login page\'s own links use the slug' );
	}

	public function test_admins_log_in_at_the_slug_and_links_follow(): void {
		list( $id, $login, $pass ) = self::user( 'editor' );
		$secret                    = self::enroll( $id );
		$b                         = $this->browser();

		$step1 = $this->password( $b, $login, $pass );
		self::assertStringContainsString( self::$login . '?action=mdmfa-verify', $step1->location() );
		$done = $this->submit_code( $b, self::code( $secret ) );
		self::assertTrue( $done->sets_cookie_prefix( 'wordpress_logged_in_' ) );

		$admin = $b->get( 'wp-admin/' );
		self::assertSame( 200, $admin->status, 'logged-in wp-admin works' );
		self::assertSame( 1, preg_match( '/href=["\']([^"\']*action=logout[^"\']*)["\']/', $admin->body, $m ), 'logout link present' );
		self::assertStringContainsString( self::$login . '?action=logout', html_entity_decode( $m[1] ) );
	}

	public function test_public_login_links_point_at_the_slug_on_a_site_without_woocommerce(): void {
		// Plan decision 8: with no My Account page, the public login page is the slug.
		$url = self::eval( 'echo wp_login_url();' );
		self::assertStringEndsWith( '/' . self::$login, $url, 'wp-cli context uses the slug' );
		self::assertStringNotContainsString( 'wp-login.php', self::eval( 'echo wp_lostpassword_url(); echo " "; echo wp_registration_url(); echo " "; echo wp_logout_url();' ) );
	}

	public function test_password_protected_post_still_unlocks_through_wp_login_php(): void {
		$id   = (int) self::wp( 'post', 'create', '--post_title=Locked', '--post_status=publish', '--post_password=opensesame', '--post_content=Hidden treasure', '--porcelain' );
		$link = self::eval( sprintf( 'echo get_permalink( %d );', $id ) );
		$b    = $this->browser();

		$page = $b->get( $link );
		self::assertSame( 1, preg_match( '/<form action="([^"]+)" class="post-password-form/', $page->body, $m ) );
		$action = html_entity_decode( $m[1] );
		self::assertStringContainsString( 'wp-login.php?action=postpass', $action, 'postpass stays on wp-login.php: the form is public' );
		self::assertStringNotContainsString( self::$login, $page->body );

		$form = array( 'post_password' => 'opensesame' );
		if ( str_contains( $page->body, 'name="redirect_to"' ) ) {
			$form['redirect_to'] = $page->input( 'redirect_to' );
		}
		$unlock = $b->post( $action, $form );
		self::assertSame( 302, $unlock->status );
		self::assertTrue( $b->has_cookie_prefix( 'wp-postpass_' ) );
		self::assertStringContainsString( 'Hidden treasure', $b->get( $link )->body );
	}

	public function test_privacy_confirmation_email_links_to_the_allow_listed_action(): void {
		$email = 'privacy' . bin2hex( random_bytes( 3 ) ) . '@example.com';
		$id    = (int) self::eval( sprintf( '$id = wp_create_user_request( %s, "export_personal_data" ); wp_send_user_request( $id ); echo $id;', var_export( $email, true ) ) );
		$mail  = array_values( array_filter( self::mails(), static fn ( array $m ): bool => $m['to'] === $email ) );

		self::assertNotEmpty( $mail );
		self::assertStringNotContainsString( self::$login, $mail[0]['message'], 'non-users never receive the slug' );
		self::assertSame( 1, preg_match( '#(https?://\S*wp-login\.php\?action=confirmaction\S+)#', $mail[0]['message'], $m ) );

		$confirm = $this->browser()->get( $m[1] );
		self::assertSame( 200, $confirm->status );
		self::assertSame( 'request-confirmed', self::eval( sprintf( 'echo get_post_status( %d );', $id ) ) );
	}

	public function test_recovery_mode_link_points_at_wp_login_php_and_works(): void {
		$url = self::eval( '$ls = new WP_Recovery_Mode_Link_Service( new WP_Recovery_Mode_Cookie_Service(), new WP_Recovery_Mode_Key_Service() ); echo $ls->generate_url();' );

		self::assertStringContainsString( 'wp-login.php?action=enter_recovery_mode', $url, 'core handles this link before plugins load, so it must stay on wp-login.php' );
		$b = $this->browser();
		$r = $b->get( $url );
		self::assertSame( 302, $r->status );
		self::assertTrue( $b->has_cookie_prefix( 'wordpress_rec_' ), 'recovery mode cookie set' );
	}

	public function test_slug_change_purges_caches_emails_admins_and_moves_the_login(): void {
		$old = self::$login;
		self::eval( 'update_option( "e2e_purged", array() ); update_option( "e2e_mail", array() );' );
		$out = self::wp( 'mdmfa', 'slug', 'set', 'team-access-e2e' );
		self::assertStringContainsString( '/team-access-e2e', $out );
		try {
			$purged = (array) json_decode( self::eval( 'echo wp_json_encode( get_option( "e2e_purged" ) );' ), true );
			self::assertContains( rtrim( self::$url, '/' ) . '/' . $old, $purged, 'old URL purged' );
			self::assertContains( rtrim( self::$url, '/' ) . '/team-access-e2e', $purged, 'new URL purged' );

			$mail = self::mails();
			self::assertNotEmpty( array_filter( $mail, static fn ( array $m ): bool => str_contains( $m['message'], '/team-access-e2e' ) ), 'admins emailed the new URL' );

			$events = (array) json_decode( self::eval( 'global $wpdb; echo wp_json_encode( $wpdb->get_results( "SELECT event, detail FROM {$wpdb->prefix}mdmfa_log WHERE event = \'slug_changed\'", ARRAY_A ) );' ), true );
			self::assertNotEmpty( $events );
			self::assertStringNotContainsString( 'team-access-e2e', wp_json_encode_safe( $events ), 'the log never stores the slug' );

			$b = $this->browser();
			self::assertSame( 404, $b->get( $old )->status, 'old slug is gone' );
			self::assertSame( 200, $b->get( 'team-access-e2e' )->status, 'new slug serves the login' );

			$bad = self::run_wp_expect_warning( 'mdmfa', 'slug', 'set', 'wp-admin' );
			self::assertStringContainsString( 'reserved', $bad );
		} finally {
			self::wp( 'mdmfa', 'slug', 'set', $old );
		}
		self::assertSame( 200, $this->browser()->get( $old )->status );
	}

	public function test_recovery_constants(): void {
		self::wp( 'config', 'set', 'MDMFA_LOGIN_SLUG', 'forced-e2e-slug', '--type=constant' );
		try {
			$b = $this->browser();
			self::assertSame( 200, $b->get( 'forced-e2e-slug' )->status, 'MDMFA_LOGIN_SLUG serves the forced address' );
			self::assertSame( 404, $b->get( self::$login )->status, 'the saved address yields to the constant' );
		} finally {
			self::wp( 'config', 'delete', 'MDMFA_LOGIN_SLUG', '--type=constant' );
		}

		self::wp( 'config', 'set', 'MDMFA_DISABLE_LOGIN_LOCATION', 'true', '--raw', '--type=constant' );
		try {
			$b = $this->browser();
			self::assertSame( 200, $b->get( 'wp-login.php' )->status, 'wp-login.php is back' );
			self::assertStringContainsString( 'name="pwd"', $b->get( 'wp-login.php' )->body );
		} finally {
			self::wp( 'config', 'delete', 'MDMFA_DISABLE_LOGIN_LOCATION', '--type=constant' );
		}
		self::assertSame( 404, $this->browser()->get( 'wp-login.php' )->status );
	}

	/**
	 * Runs WP-CLI where a warning (exit 0) is expected; returns stderr and stdout.
	 */
	private static function run_wp_expect_warning( string ...$args ): string {
		$process = proc_open(
			array_merge( array( 'wp', '--path=' . self::$path ), $args ),
			array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ),
			$pipes
		);
		$out = (string) stream_get_contents( $pipes[1] ) . (string) stream_get_contents( $pipes[2] );
		proc_close( $process );
		return $out;
	}
}

function wp_json_encode_safe( mixed $data ): string {
	return (string) json_encode( $data );
}
