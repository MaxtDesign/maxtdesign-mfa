<?php
/**
 * `wp mdmfa` command group (skeleton; plan 11.4 lists the full set).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Install\Schema;
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
	 * Read-only status values. No secrets, no key material, no slug.
	 *
	 * @return array<string, string|bool>
	 */
	public static function snapshot(): array {
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
		);
	}
}
