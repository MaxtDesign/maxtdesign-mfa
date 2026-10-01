<?php
/**
 * Detects other two-factor plugins (plan section 8, Tools). Two plugins challenging the
 * same login confuse users and can lock them out, so the owner is told to keep one.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Integrations;

use MaxtDesign\Mfa\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Conflict detector. It only warns: this plugin keeps enforcing its own policy.
 */
final class Conflicts {

	/**
	 * Registers the admin notice.
	 */
	public static function register(): void {
		add_action( 'admin_notices', array( self::class, 'render_notice' ) );
	}

	/**
	 * Names of other active two-factor plugins.
	 *
	 * @return string[]
	 */
	public static function detect(): array {
		$found = array();
		if ( class_exists( '\Two_Factor_Core', false ) ) {
			$found[] = 'Two Factor';
		}
		if ( defined( 'WP_2FA_VERSION' ) || class_exists( '\WP2FA\WP2FA', false ) ) {
			$found[] = 'WP 2FA';
		}
		if ( defined( 'FLUENT_AUTH_VERSION' ) ) {
			$found[] = 'FluentAuth';
		}
		if ( class_exists( '\ITSEC_Modules', false ) && is_callable( array( '\ITSEC_Modules', 'is_active' ) ) && true === \ITSEC_Modules::is_active( 'two-factor' ) ) {
			$found[] = 'Solid Security (two-factor)';
		}
		if ( defined( 'MO2F_VERSION' ) || class_exists( '\Miniorange_Authentication', false ) ) {
			$found[] = 'miniOrange 2FA';
		}
		$found = apply_filters( 'mdmfa_conflicts', $found );

		return is_array( $found ) ? array_values( array_filter( $found, 'is_string' ) ) : array();
	}

	/**
	 * Warns managers on the Dashboard, Plugins and Users screens.
	 */
	public static function render_notice(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( null === $screen || ! in_array( $screen->base, array( 'dashboard', 'plugins', 'users' ), true ) || ! current_user_can( Plugin::MANAGE_CAP ) ) {
			return;
		}
		$found = self::detect();
		if ( array() === $found ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s</p></div>',
			esc_html__( 'Two two-step verification plugins are active.', 'maxtdesign-mfa' ),
			esc_html(
				sprintf(
					/* translators: %s: comma-separated plugin names. */
					__( 'MaxtDesign MFA is running alongside %s. Users may be asked twice or locked out. Keep one and turn the other off.', 'maxtdesign-mfa' ),
					implode( ', ', $found )
				)
			)
		);
	}
}
