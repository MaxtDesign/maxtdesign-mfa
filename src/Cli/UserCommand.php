<?php
/**
 * `wp mdmfa user` (plan 11.4): per-user status and factor reset from the server.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Notify\Mailer;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Support\Clock;

defined( 'ABSPATH' ) || exit;

/**
 * Manages one user's two-step verification. Never prints secrets or codes.
 */
final class UserCommand {

	/**
	 * Shows a user's two-step verification state.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
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
	 *     wp mdmfa user status admin
	 *
	 * @param string[]              $args       Positional arguments.
	 * @param array<string, string> $assoc_args Named arguments.
	 */
	public function status( array $args, array $assoc_args ): void {
		$user = self::user( $args[0] ?? '' );
		if ( null === $user ) {
			return;
		}
		$lock  = Lockout::state( $user->ID );
		$state = array(
			'user'           => $user->user_login,
			'policy'         => Policy::policy( $user ),
			'decision'       => Policy::decide( $user ),
			'enrolled'       => Policy::is_enrolled( $user->ID ),
			'totp'           => TotpStore::has( $user->ID ) ? ( null === TotpStore::secret( $user->ID ) ? 'unreadable' : 'on' ) : 'off',
			'passkeys'       => PasskeyStore::count( $user->ID ),
			'recovery_codes' => RecoveryCodes::remaining( $user->ID ),
			'grace_seconds'  => Policy::grace_remaining( $user ),
			'failures'       => $lock['count'],
			'locked'         => $lock['locked_until'] > Clock::now(),
		);

		if ( 'json' === ( $assoc_args['format'] ?? 'table' ) ) {
			\WP_CLI::line( (string) wp_json_encode( $state ) );
			return;
		}
		$rows = array();
		foreach ( $state as $key => $value ) {
			$rows[] = array(
				'key'   => $key,
				'value' => is_bool( $value ) ? ( $value ? 'true' : 'false' ) : (string) $value,
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'key', 'value' ) );
	}

	/**
	 * Removes a user's factors. They enroll again at their next login, and the grace
	 * period restarts.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * [--factor=<factor>]
	 * : Which factor to remove.
	 * ---
	 * default: all
	 * options:
	 *   - all
	 *   - totp
	 *   - passkey
	 *   - recovery
	 * ---
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa user reset admin --yes
	 *
	 * @param string[]              $args       Positional arguments.
	 * @param array<string, string> $assoc_args Named arguments.
	 */
	public function reset( array $args, array $assoc_args ): void {
		$user = self::user( $args[0] ?? '' );
		if ( null === $user ) {
			return;
		}
		$factor = $assoc_args['factor'] ?? 'all';
		if ( ! in_array( $factor, array( 'all', 'totp', 'passkey', 'recovery' ), true ) ) {
			\WP_CLI::warning( 'Unknown factor.' );
			return;
		}
		if ( ! isset( $assoc_args['yes'] ) ) {
			\WP_CLI::confirm( sprintf( 'Remove %s for %s?', 'all' === $factor ? 'every factor' : $factor, $user->user_login ) );
		}

		if ( 'all' === $factor || 'totp' === $factor ) {
			TotpStore::remove( $user->ID );
		}
		if ( 'all' === $factor || 'passkey' === $factor ) {
			PasskeyStore::delete_all( $user->ID );
		}
		if ( 'all' === $factor || 'recovery' === $factor ) {
			RecoveryCodes::remove( $user->ID );
		}
		if ( ! Policy::is_enrolled( $user->ID ) ) {
			delete_user_meta( $user->ID, 'mdmfa_enrolled' );
			delete_user_meta( $user->ID, Policy::GRACE_META );
		}
		Lockout::reset( $user->ID );
		PendingStore::delete_for_user( $user->ID );

		Logger::log( 'admin_reset', $user->ID, $factor, 'cli' );
		do_action( 'mdmfa_factor_removed', $user, $factor, 0 );
		Mailer::factors_reset( $user );

		\WP_CLI::success( sprintf( 'Removed %s for %s.', 'all' === $factor ? 'every factor' : $factor, $user->user_login ) );
	}

	/**
	 * Resolves a user argument.
	 *
	 * @param string $identifier ID, login or email.
	 */
	private static function user( string $identifier ): ?\WP_User {
		$user = is_numeric( $identifier ) ? get_user_by( 'id', (int) $identifier ) : false;
		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'login', $identifier );
		}
		if ( ! $user instanceof \WP_User && is_email( $identifier ) ) {
			$user = get_user_by( 'email', $identifier );
		}
		if ( ! $user instanceof \WP_User ) {
			\WP_CLI::warning( 'User not found.' );
			return null;
		}

		return $user;
	}
}
