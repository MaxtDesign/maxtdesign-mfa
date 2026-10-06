<?php
/**
 * User, meta, password, action and mail stand-ins for unit tests, backed by
 * $GLOBALS['mdmfa_test'] (see bootstrap.php).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:ignoreFile

/**
 * Minimal user object. Constructing one registers it for get_userdata().
 */
class WP_User {
	public int $ID;
	/** @var string[] */
	public array $roles;
	public string $user_login;
	public string $user_email;
	public string $user_activation_key = '';

	/**
	 * @param string[] $roles
	 */
	public function __construct( int $id = 1, array $roles = array( 'administrator' ) ) {
		$this->ID         = $id;
		$this->roles      = $roles;
		$this->user_login = 'user' . $id;
		$this->user_email = 'user' . $id . '@example.com';
		$GLOBALS['mdmfa_test']['users'][ $id ] = $this;
	}

	public function exists(): bool {
		return $this->ID > 0;
	}

	public function has_cap( string $cap ): bool {
		return true;
	}
}

function maybe_serialize( mixed $data ): mixed {
	return is_array( $data ) || is_object( $data ) ? serialize( $data ) : $data;
}

function get_user_meta( int $user_id, string $key = '', bool $single = false ): mixed {
	if ( '' === $key ) {
		return array_map( static fn ( mixed $v ): array => array( $v ), $GLOBALS['mdmfa_test']['usermeta'][ $user_id ] ?? array() );
	}
	$value = $GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ $key ] ?? null;
	if ( $single ) {
		return $value ?? '';
	}
	return null === $value ? array() : array( $value );
}

function update_user_meta( int $user_id, string $key, mixed $value ): bool {
	$GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ $key ] = $value;
	return true;
}

function delete_user_meta( int $user_id, string $key ): bool {
	unset( $GLOBALS['mdmfa_test']['usermeta'][ $user_id ][ $key ] );
	return true;
}

function get_userdata( int $user_id ): mixed {
	return $GLOBALS['mdmfa_test']['users'][ $user_id ] ?? false;
}

function is_super_admin( mixed $user_id = false ): bool {
	return in_array( $user_id, $GLOBALS['mdmfa_test']['super_admins'], true );
}

function wp_hash_password( string $password ): string {
	return password_hash( $password, PASSWORD_BCRYPT, array( 'cost' => 4 ) );
}

function wp_check_password( string $password, string $hash, mixed $user_id = '' ): bool {
	return password_verify( $password, $hash );
}

function do_action( string $hook, mixed ...$args ): void {
	$GLOBALS['mdmfa_test']['actions'][] = array_merge( array( $hook ), $args );
}

function wp_mail( string $to, string $subject, string $message ): bool {
	$GLOBALS['mdmfa_test']['mail'][] = array( $to, $subject, $message );
	return true;
}

function wp_specialchars_decode( string $text, mixed $quote_style = 0 ): string {
	return $text;
}

function wp_date( string $format, ?int $timestamp = null ): string {
	return gmdate( $format, $timestamp ?? time() );
}

function is_email( string $email ): string|false {
	return false !== filter_var( $email, FILTER_VALIDATE_EMAIL ) ? $email : false;
}

function __( string $text, string $domain = 'default' ): string {
	return $text;
}

function esc_attr( string $text ): string {
	return htmlspecialchars( $text, ENT_QUOTES );
}

function wp_next_scheduled( string $hook ): int|false {
	return $GLOBALS['mdmfa_test']['scheduled'][ $hook ] ?? false;
}

function wp_schedule_event( int $timestamp, string $recurrence, string $hook ): bool {
	$GLOBALS['mdmfa_test']['scheduled'][ $hook ] = $timestamp;
	return true;
}

function sanitize_text_field( string $text ): string {
	return trim( strip_tags( $text ) );
}

function wp_unslash( mixed $value ): mixed {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}

class WP_Error {
	/** @var array<string, string[]> */
	public array $errors = array();

	public function __construct( string $code = '', string $message = '' ) {
		if ( '' !== $code ) {
			$this->errors[ $code ][] = $message;
		}
	}

	public function add( string $code, string $message ): void {
		$this->errors[ $code ][] = $message;
	}

	public function get_error_code(): string {
		return (string) ( array_key_first( $this->errors ) ?? '' );
	}

	/**
	 * @return string[]
	 */
	public function get_error_messages(): array {
		return array_merge( array(), ...array_values( $this->errors ) );
	}
}

function get_current_blog_id(): int {
	return (int) ( $GLOBALS['mdmfa_test']['blog_id'] ?? 1 );
}

/**
 * @return array<int, object>
 */
function get_blogs_of_user( int $user_id ): array {
	$out = array();
	foreach ( $GLOBALS['mdmfa_test']['user_blogs'][ $user_id ] ?? array() as $blog_id ) {
		$out[ $blog_id ] = (object) array( 'userblog_id' => $blog_id );
	}
	return $out;
}

function get_blog_option( int $blog_id, string $option, mixed $default_value = false ): mixed {
	return $GLOBALS['mdmfa_test']['blog_options'][ $blog_id ][ $option ] ?? $default_value;
}

function did_action( string $hook ): int {
	return count( array_filter( $GLOBALS['mdmfa_test']['actions'], static fn ( array $a ): bool => $a[0] === $hook ) );
}

function wp_doing_ajax(): bool {
	return ! empty( $GLOBALS['mdmfa_test']['ajax'] );
}

function get_current_user_id(): int {
	return (int) ( $GLOBALS['mdmfa_test']['current_user'] ?? 0 );
}

function maybe_unserialize( mixed $data ): mixed {
	return is_string( $data ) && 1 === preg_match( '/^[aOs]:\d+:/', $data ) ? unserialize( $data ) : $data;
}

function get_site( int $site_id ): ?object {
	return in_array( $site_id, $GLOBALS['mdmfa_test']['deleted_sites'] ?? array(), true ) ? null : (object) array( 'blog_id' => $site_id );
}

function is_admin(): bool {
	return ! empty( $GLOBALS['mdmfa_test']['is_admin'] );
}

function wp_fast_hash( string $message ): string {
	return '$generic$' . hash_hmac( 'sha256', $message, 'fast-hash-test-key' );
}

function wp_verify_fast_hash( string $message, string $hash ): bool {
	return hash_equals( $hash, wp_fast_hash( $message ) );
}

function get_transient( string $key ): mixed {
	return $GLOBALS['mdmfa_test']['transients'][ $key ] ?? false;
}

function delete_transient( string $key ): bool {
	unset( $GLOBALS['mdmfa_test']['transients'][ $key ] );
	return true;
}

function set_transient( string $key, mixed $value, int $expiration = 0 ): bool {
	$GLOBALS['mdmfa_test']['transients'][ $key ] = $value;
	return true;
}

function home_url( string $path = '' ): string {
	return 'https://example.test' . $path;
}

function site_url( string $path = '' ): string {
	return 'https://example.test' . $path;
}

function wp_parse_url( string $url, int $component = -1 ): mixed {
	return parse_url( $url, $component );
}

function sanitize_title( string $title ): string {
	return trim( (string) preg_replace( '/[^a-z0-9-]+/', '-', strtolower( $title ) ), '-' );
}

function sanitize_key( mixed $key ): string {
	return strtolower( (string) preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $key ) );
}

function sanitize_user( string $username, bool $strict = false ): string {
	return trim( (string) preg_replace( '/[^a-zA-Z0-9 _.\-@]/', '', strip_tags( $username ) ) );
}

function wp_sanitize_redirect( string $location ): string {
	return (string) preg_replace( '/[^a-zA-Z0-9\-~+_.?#=&;,\/:%!*\[\]()@]/', '', $location );
}

function trailingslashit( string $value ): string {
	return rtrim( $value, '/' ) . '/';
}

function add_action( string $hook, callable $callback, int $priority = 10, int $args = 1 ): bool {
	return add_filter( $hook, $callback, $priority, $args );
}
