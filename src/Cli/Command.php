<?php
/**
 * `wp mdmfa` command group (skeleton; plan 11.4 lists the full set).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Integrations\Conflicts;
use MaxtDesign\Mfa\Integrations\Jetpack;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Server-side escape hatch and read surface. Never prints secrets, keys or the login slug
 * (the slug is available only through `wp mdmfa slug get`, added in P4).
 */
final class Command {

	/**
	 * Shows plugin, schema and key status.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa status --format=json
	 *
	 * @param string[]              $args       Positional arguments.
	 * @param array<string, string> $assoc_args Named arguments.
	 */
	public function status( array $args, array $assoc_args ): void {
		unset( $args );
		$rows   = array();
		$status = self::snapshot();
		foreach ( $status as $key => $value ) {
			$rows[] = array(
				'key'   => $key,
				'value' => is_bool( $value ) ? ( $value ? 'true' : 'false' ) : (string) $value,
			);
		}

		if ( 'json' === ( $assoc_args['format'] ?? 'table' ) ) {
			\WP_CLI::line( (string) wp_json_encode( $status ) );
			return;
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'key', 'value' ) );
	}

	/**
	 * Reports whether the MDMFA_DISABLE escape hatch is active.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa disable-check
	 *
	 * @subcommand disable-check
	 */
	public function disable_check(): void {
		if ( Plugin::is_disabled() ) {
			\WP_CLI::warning( 'MDMFA_DISABLE is set: multi-factor authentication is OFF and logins use a password only.' );
			return;
		}
		\WP_CLI::success( 'MDMFA_DISABLE is not set: multi-factor authentication is active.' );
	}

	/**
	 * Clears a user's second-factor lockout and failure count.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa unlock admin
	 *
	 * @param string[] $args Positional arguments.
	 */
	public function unlock( array $args ): void {
		$identifier = $args[0] ?? '';
		$user       = is_numeric( $identifier ) ? get_user_by( 'id', (int) $identifier ) : get_user_by( 'login', $identifier );
		if ( ! $user instanceof \WP_User && is_email( $identifier ) ) {
			$user = get_user_by( 'email', $identifier );
		}
		if ( ! $user instanceof \WP_User ) {
			\WP_CLI::warning( 'User not found.' );
			return;
		}
		Lockout::unlock( $user->ID, null );
		\WP_CLI::success( sprintf( 'Unlocked %s.', $user->user_login ) );
	}

	/**
	 * Read-only status values. No secrets, no key material, no slug.
	 *
	 * @return array<string, string|bool|int>
	 */
	public static function snapshot(): array {
		global $wpdb;

		$login   = get_option( Options::LOGIN, array() );
		$stored  = get_option( Options::KEY_CHECK, array() );
		$kid     = '';
		$source  = 'invalid';
		$key_ok  = false;
		$db_ver  = get_option( Options::DB_VERSION, '' );
		$enabled = is_array( $login ) && ! empty( $login['enabled'] );

		try {
			$keys   = KeyProvider::from_environment();
			$kid    = $keys->kid();
			$source = $keys->source();
			$key_ok = is_array( $stored ) && isset( $stored['kid'] ) && is_string( $stored['kid'] ) && hash_equals( $stored['kid'], $kid );
		} catch ( InvalidKeyException $e ) {
			$key_ok = false;
		}

		return array(
			'version'        => MDMFA_VERSION,
			'schema'         => is_string( $db_ver ) ? $db_ver : '',
			'schema_current' => Schema::VERSION === $db_ver,
			'disabled'       => Plugin::is_disabled(),
			'login_location' => $enabled,
			'key_source'     => $source,
			'key_ok'         => $key_ok,
			// Network-wide user meta; P7's status contract adds the per-role breakdown.
			'app_passwords'  => SideDoors::app_password_mode(),
			'xmlrpc'         => SideDoors::xmlrpc_mode(),
			'jetpack'        => Jetpack::detected(),
			'wpcom_sso'      => Jetpack::sso_blocked() ? 'blocked' : ( Jetpack::sso_active() ? 'challenged' : 'inactive' ),
			'conflicts'      => implode( ', ', Conflicts::detect() ),
			'enrolled_users' => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(DISTINCT user_id) FROM %i WHERE meta_key = %s', $wpdb->usermeta, 'mdmfa_enrolled' ) ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- CLI-only count.
		);
	}
}
