<?php
/**
 * `wp mdmfa` command group (skeleton; plan 11.4 lists the full set).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Plugin;
use MaxtDesign\Mfa\Status\Snapshot;

defined( 'ABSPATH' ) || exit;

/**
 * Server-side escape hatch and read surface. Never prints secrets, keys or the login slug
 * (the slug is available only through `wp mdmfa slug get`, added in P4).
 */
final class Command {

	/**
	 * Shows the read-only status: plugin, schema and key state, policy and counts per role,
	 * side doors, lockouts. No secrets, no user names, no login address. Cached 15 minutes.
	 *
	 * ## OPTIONS
	 *
	 * [--fresh]
	 * : Rebuild the status instead of reading the cached one.
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
		$status = Snapshot::get( isset( $assoc_args['fresh'] ) );
		foreach ( $status as $key => $value ) {
			if ( is_bool( $value ) ) {
				$value = $value ? 'true' : 'false';
			}
			$rows[] = array(
				'key'   => $key,
				'value' => is_scalar( $value ) ? (string) $value : (string) wp_json_encode( $value ),
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
}
