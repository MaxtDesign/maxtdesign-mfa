<?php
/**
 * Opportunistic MaxtDesign suite integration (plan decision 1): nothing is vendored. When
 * another MaxtDesign plugin has loaded suite-core, this plugin appears in its registry and
 * contributes its status; otherwise none of this runs.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Integrations;

use MaxtDesign\Mfa\Status\Snapshot;

defined( 'ABSPATH' ) || exit;

/**
 * Registry row and status contribution.
 */
final class Suite {

	public const SLUG = 'maxtdesign-mfa';

	/**
	 * Registers hooks.
	 */
	public static function register(): void {
		add_action( 'md_suite_loaded', array( self::class, 'register_plugin' ) );
		add_action( 'plugins_loaded', array( self::class, 'register_plugin' ), 20 );
		// Before suite-core's own callback (priority 10), which rebuilds the snapshot
		// from what was contributed.
		add_filter( 'md_suite_status', array( self::class, 'contribute' ), 5 );
	}

	/**
	 * Adds the registry row (idempotent).
	 */
	public static function register_plugin(): void {
		// A stale suite-core copy may win the load race, so the method is checked too.
		if ( ! empty( $GLOBALS['md_suite_loaded'] ) && class_exists( '\MdSuite_Registry', false ) && method_exists( '\MdSuite_Registry', 'register' ) ) { // @phpstan-ignore function.alreadyNarrowedType
			\MdSuite_Registry::register(
				self::SLUG,
				array(
					'version'      => MDMFA_VERSION,
					'capabilities' => array( 'mfa', 'login-location' ),
				)
			);
		}
	}

	/**
	 * Contributes the read-only status. The snapshot holds no secret and no login address.
	 *
	 * @param mixed $value Passed through.
	 * @return mixed
	 */
	public static function contribute( mixed $value ): mixed {
		// A stale suite-core copy may win the load race, so the method is checked too.
		if ( ! empty( $GLOBALS['md_suite_loaded'] ) && class_exists( '\MdSuite_Status', false ) && method_exists( '\MdSuite_Status', 'contribute' ) ) { // @phpstan-ignore function.alreadyNarrowedType
			\MdSuite_Status::contribute( self::SLUG, Snapshot::get() );
		}

		return $value;
	}
}
