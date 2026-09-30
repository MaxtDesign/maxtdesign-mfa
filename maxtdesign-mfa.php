<?php
/**
 * Plugin Name:       MaxtDesign MFA
 * Plugin URI:        https://github.com/MaxtDesign/maxtdesign-mfa
 * Description:       Multi-factor authentication for staff and customers: TOTP, passkeys, recovery codes, per-role policy, and a moved login address. No outbound HTTP.
 * Version:           0.1.0
 * Requires at least: 7.0
 * Requires PHP:      8.3
 * Author:            MaxtDesign
 * Author URI:        https://maxtdesign.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       maxtdesign-mfa
 * Domain Path:       /languages
 * WC requires at least: 11.0
 * WC tested up to:   11.1
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

define( 'MDMFA_VERSION', '0.1.0' );
define( 'MDMFA_FILE', __FILE__ );
define( 'MDMFA_DIR', __DIR__ );

// PSR-4 for MaxtDesign\Mfa\ -> src/. The plugin has no Composer runtime
// dependencies, so the shipped zip carries no vendor/ directory at all.
spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'MaxtDesign\\Mfa\\';
		if ( 0 !== strncmp( $class_name, $prefix, strlen( $prefix ) ) ) {
			return;
		}
		$file = __DIR__ . '/src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
		if ( is_file( $file ) ) {
			require $file;
		}
	}
);

register_activation_hook( __FILE__, array( \MaxtDesign\Mfa\Install\Installer::class, 'activate' ) );

\MaxtDesign\Mfa\Plugin::boot();
