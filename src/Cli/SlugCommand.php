<?php
/**
 * `wp mdmfa slug` (plan 5.5): lost-slug recovery with server access.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Location\SlugChanger;

defined( 'ABSPATH' ) || exit;

/**
 * Prints or changes the login address. The only command that prints the slug: whoever
 * runs WP-CLI already has the server.
 */
final class SlugCommand {

	/**
	 * Prints the login URL.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa slug get
	 */
	public function get(): void {
		if ( ! LoginLocation::enabled() ) {
			\WP_CLI::line( LoginLocation::raw_core_url() );
			\WP_CLI::warning( 'The login location is off; the login is at wp-login.php.' );
			return;
		}
		\WP_CLI::line( LoginLocation::url() );
		if ( defined( 'MDMFA_LOGIN_SLUG' ) ) {
			\WP_CLI::warning( 'MDMFA_LOGIN_SLUG in wp-config.php sets this address.' );
		}
	}

	/**
	 * Sets a new login address. Admins are emailed the new URL.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : 4 to 64 lowercase letters, numbers and single hyphens.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa slug set team-access
	 *
	 * @param string[] $args Positional arguments.
	 */
	public function set( array $args ): void {
		self::apply( $args[0] ?? '' );
	}

	/**
	 * Replaces the login address with a new random one.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa slug reset
	 */
	public function reset(): void {
		self::apply( '' );
	}

	/**
	 * Runs the change and reports.
	 *
	 * @param string $raw Requested slug, or '' for random.
	 */
	private static function apply( string $raw ): void {
		$result = SlugChanger::change( $raw, null );
		if ( $result instanceof \WP_Error ) {
			\WP_CLI::warning( $result->get_error_message() );
			return;
		}
		\WP_CLI::success( 'Login address: ' . LoginLocation::url() );
		if ( defined( 'MDMFA_LOGIN_SLUG' ) ) {
			\WP_CLI::warning( 'MDMFA_LOGIN_SLUG in wp-config.php still overrides the saved address.' );
		}
	}
}
