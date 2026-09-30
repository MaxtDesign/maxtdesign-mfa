<?php
/**
 * Base for end-to-end tests against a live WordPress (CI job "e2e"). Skipped when
 * MDMFA_E2E_URL and WP_PATH are not set.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

use MaxtDesign\Mfa\Factors\Totp;
use PHPUnit\Framework\TestCase;

// phpcs:ignoreFile

abstract class E2eTestCase extends TestCase {

	protected static string $url  = '';
	protected static string $path = '';

	/** Login page path relative to the site root ('abc123def456'), from `wp mdmfa slug get`. */
	protected static string $login = '';

	public static function setUpBeforeClass(): void {
		self::$url  = (string) getenv( 'MDMFA_E2E_URL' );
		self::$path = (string) getenv( 'WP_PATH' );
	}

	protected function setUp(): void {
		if ( '' === self::$url || '' === self::$path ) {
			self::markTestSkipped( 'MDMFA_E2E_URL and WP_PATH are not set (CI job "e2e" runs this suite).' );
		}
		if ( '' === self::$login ) {
			self::$login = ltrim( substr( self::wp( 'mdmfa', 'slug', 'get' ), strlen( rtrim( self::$url, '/' ) ) ), '/' );
		}
	}

	/**
	 * Login page path with an optional query string.
	 */
	protected static function lp( string $query = '' ): string {
		return self::$login . ( '' !== $query ? '?' . $query : '' );
	}

	protected function browser(): Browser {
		return new Browser( self::$url );
	}

	/**
	 * Runs WP-CLI and returns trimmed stdout. Fails the test on a non-zero exit.
	 */
	protected static function wp( string ...$args ): string {
		$process = proc_open(
			array_merge( array( 'wp', '--path=' . self::$path, '--skip-themes' ), $args ),
			array(
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes
		);
		if ( ! is_resource( $process ) ) {
			throw new \RuntimeException( 'Cannot start wp-cli' );
		}
		$out  = (string) stream_get_contents( $pipes[1] );
		$err  = (string) stream_get_contents( $pipes[2] );
		$code = proc_close( $process );
		if ( 0 !== $code ) {
			throw new \RuntimeException( "wp " . implode( ' ', $args ) . " exited {$code}:\n{$err}\n{$out}" );
		}
		return trim( $out );
	}

	protected static function eval( string $php ): string {
		return self::wp( 'eval', $php );
	}

	/**
	 * Creates a user and returns [id, login, password].
	 *
	 * @return array{int, string, string}
	 */
	protected static function user( string $role ): array {
		$login = 'e2e' . bin2hex( random_bytes( 4 ) );
		$pass  = bin2hex( random_bytes( 12 ) );
		$id    = (int) self::wp( 'user', 'create', $login, $login . '@example.com', '--role=' . $role, '--user_pass=' . $pass, '--porcelain' );
		return array( $id, $login, $pass );
	}

	/**
	 * Enrolls TOTP with a secret the test knows.
	 */
	protected static function enroll( int $user_id ): string {
		$secret = Totp::generate_secret();
		self::eval( sprintf( 'MaxtDesign\\Mfa\\Factors\\TotpStore::save( %d, base64_decode( %s ) ); update_user_meta( %d, "mdmfa_enrolled", "1" );', $user_id, var_export( base64_encode( $secret ), true ), $user_id ) );
		return $secret;
	}

	protected static function code( string $secret, int $offset = 0 ): string {
		return Totp::code( $secret, Totp::step( time() ) + $offset );
	}

	/**
	 * A 6-digit code that is not valid in the current window.
	 */
	protected static function wrong_code( string $secret ): string {
		$valid = array( self::code( $secret, -1 ), self::code( $secret ), self::code( $secret, 1 ) );
		for ( $n = 0; ; $n++ ) {
			$candidate = str_pad( (string) ( ( 123456 + $n * 7919 ) % 1000000 ), 6, '0', STR_PAD_LEFT );
			if ( ! in_array( $candidate, $valid, true ) ) {
				return $candidate;
			}
		}
	}

	protected static function sessions( int $user_id ): int {
		return (int) self::eval( sprintf( 'echo count( WP_Session_Tokens::get_instance( %d )->get_all() );', $user_id ) );
	}

	/**
	 * mdmfa stamps of the user's sessions.
	 *
	 * @return array<int, array<string, mixed>|null>
	 */
	protected static function stamps( int $user_id ): array {
		$json = self::eval( sprintf( 'echo wp_json_encode( array_map( static fn ( $s ) => $s["mdmfa"] ?? null, array_values( WP_Session_Tokens::get_instance( %d )->get_all() ) ) );', $user_id ) );
		return (array) json_decode( $json, true );
	}

	protected static function counter( string $name ): int {
		return (int) self::eval( sprintf( 'echo (int) get_option( %s, 0 );', var_export( $name, true ) ) );
	}

	protected static function log_events( int $user_id ): array {
		$json = self::eval( sprintf( 'global $wpdb; echo wp_json_encode( $wpdb->get_results( $wpdb->prepare( "SELECT event, factor, context, detail FROM %%i WHERE user_id = %%d ORDER BY id", $wpdb->prefix . "mdmfa_log", %d ), ARRAY_A ) );', $user_id ) );
		return (array) json_decode( $json, true );
	}

	/**
	 * Password step. Returns the response.
	 *
	 * @param array<string, string> $extra
	 */
	protected function password( Browser $browser, string $login, string $pass, array $extra = array() ): Response {
		return $browser->post( self::lp(), array_merge( array( 'log' => $login, 'pwd' => $pass, 'wp-submit' => 'Log In' ), $extra ) );
	}

	/**
	 * Fetches the verify screen and submits a code.
	 */
	protected function submit_code( Browser $browser, string $code, string $method = 'totp' ): Response {
		$page = $browser->get( self::lp( 'action=mdmfa-verify&method=' . $method ) );
		return $browser->post(
			self::lp( 'action=mdmfa-verify&method=' . $method ),
			array(
				'mdmfa_form' => $page->form_token(),
				'mdmfa_code' => $code,
			)
		);
	}

	protected static function assertNoAuthCookie( Response $response, string $message = '' ): void {
		foreach ( $response->set_cookies as $cookie ) {
			list( $name ) = Browser::cookie_pair( $cookie );
			if ( str_starts_with( $name, 'wordpress_' ) && 'wordpress_test_cookie' !== $name && Browser::cookie_is_live( $cookie ) ) {
				self::fail( "Auth cookie {$name} was set. {$message}" );
			}
		}
		self::assertTrue( true );
	}
}
