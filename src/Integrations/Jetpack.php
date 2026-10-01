<?php
/**
 * Jetpack (plan decision 10). The bypass guard already challenges a WordPress.com
 * sign-in; this adds the owner's option to switch that sign-in off entirely.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Integrations;

use MaxtDesign\Mfa\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Detection and the optional SSO block.
 */
final class Jetpack {

	/**
	 * Registers hooks. The filter is inert unless Jetpack applies it.
	 */
	public static function register(): void {
		add_filter( 'jetpack_get_available_modules', array( self::class, 'filter_modules' ), PHP_INT_MAX );
	}

	/**
	 * Whether Jetpack is loaded.
	 */
	public static function detected(): bool {
		return defined( 'JETPACK__VERSION' ) || class_exists( '\Jetpack', false );
	}

	/**
	 * Whether Jetpack's WordPress.com sign-in module is active.
	 */
	public static function sso_active(): bool {
		return class_exists( '\Jetpack', false ) && is_callable( array( '\Jetpack', 'is_module_active' ) ) && true === \Jetpack::is_module_active( 'sso' );
	}

	/**
	 * Whether the owner chose to block WordPress.com sign-in.
	 */
	public static function sso_blocked(): bool {
		// Jetpack asks for its module list on every request, front end included. The
		// flag is mirrored into the autoloaded login option (Settings::save()), so the
		// answer costs no query; the settings themselves are not autoloaded.
		$login = get_option( Options::LOGIN );

		return is_array( $login ) && ! empty( $login['block_sso'] );
	}

	/**
	 * Removes the sso module from Jetpack's module list when the block is on.
	 *
	 * @param mixed $modules Module slug => version introduced.
	 * @return mixed
	 */
	public static function filter_modules( mixed $modules ): mixed {
		if ( is_array( $modules ) && self::sso_blocked() ) {
			unset( $modules['sso'] );
		}

		return $modules;
	}
}
