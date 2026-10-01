<?php
/**
 * Bootstrap: registers hooks and nothing else. No work happens at file load.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa;

use MaxtDesign\Mfa\Account\AccountPage;
use MaxtDesign\Mfa\Auth\BypassGuard;
use MaxtDesign\Mfa\Auth\Completion;
use MaxtDesign\Mfa\Auth\Interceptor;
use MaxtDesign\Mfa\Auth\SideDoors;
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Integrations\Conflicts;
use MaxtDesign\Mfa\Integrations\Jetpack;
use MaxtDesign\Mfa\Cli\Command;
use MaxtDesign\Mfa\Cli\UserCommand;
use MaxtDesign\Mfa\Install\Installer;
use MaxtDesign\Mfa\Install\Maintenance;
use MaxtDesign\Mfa\Frontend\LoginForm;
use MaxtDesign\Mfa\Frontend\PasskeyLogin;
use MaxtDesign\Mfa\Location\CacheBridge;
use MaxtDesign\Mfa\Location\LoginLocation;
use MaxtDesign\Mfa\Location\Router;
use MaxtDesign\Mfa\Location\UrlRewriter;
use MaxtDesign\Mfa\Cli\SlugCommand;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Support\Clock;
use MaxtDesign\Mfa\Screens\LoginScreens;
use MaxtDesign\Mfa\WooCommerce\AccountChallenge;
use MaxtDesign\Mfa\WooCommerce\SecurityEndpoint;

defined( 'ABSPATH' ) || exit;

/**
 * Plugin entry point.
 */
final class Plugin {

	/**
	 * Meta capability for every MFA administration action (plan section 8).
	 */
	public const MANAGE_CAP = 'mdmfa_manage';

	/**
	 * Guards against a second boot() if the main file is included twice.
	 *
	 * @var bool
	 */
	private static bool $booted = false;

	/**
	 * Registers the plugin's hooks.
	 */
	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		add_filter( 'map_meta_cap', array( self::class, 'map_meta_cap' ), 10, 2 );
		add_action( 'cli_init', array( self::class, 'register_cli' ) );

		if ( self::is_disabled() ) {
			// Escape hatch (plan 11.4): behave exactly like core, and say so loudly to admins.
			add_action( 'admin_notices', array( self::class, 'render_disabled_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'render_disabled_notice' ) );
			return;
		}

		add_action( 'plugins_loaded', array( Installer::class, 'maybe_upgrade' ) );
		add_action( 'wp_initialize_site', array( Installer::class, 'initialize_site' ), 20 );
		add_action( 'before_woocommerce_init', array( self::class, 'declare_wc_compatibility' ) );

		// Registration only: every callback below works on demand, in login, admin or
		// cron requests. Nothing prints on a normal front-end page.
		Interceptor::register();
		Completion::register();
		BypassGuard::register();
		LoginScreens::register();
		Maintenance::register();
		LoginForm::register();
		PasskeyLogin::register();
		TrustedDevice::register();
		SideDoors::register();
		EmailRecovery::register();
		Jetpack::register();
		// Login location (plan 5): routing, 404s, URL rewrites, cache signals.
		Router::register();
		UrlRewriter::register();
		CacheBridge::register();
		add_action( 'admin_notices', array( self::class, 'render_slug_notice' ) );
		// WooCommerce hooks are inert until WooCommerce loads.
		AccountChallenge::register();
		SecurityEndpoint::register();
		if ( is_admin() ) {
			AccountPage::register();
			Conflicts::register();
		}
	}

	/**
	 * True when MDMFA_DISABLE is defined truthy in wp-config.php.
	 */
	public static function is_disabled(): bool {
		return defined( 'MDMFA_DISABLE' ) && (bool) constant( 'MDMFA_DISABLE' );
	}

	/**
	 * Maps the mdmfa_manage meta capability to a primitive capability.
	 *
	 * @param string[] $caps Primitive capabilities required so far.
	 * @param string   $cap  Capability being checked.
	 * @return string[]
	 */
	public static function map_meta_cap( array $caps, string $cap ): array {
		if ( self::MANAGE_CAP !== $cap ) {
			return $caps;
		}
		$default  = is_network_admin() ? 'manage_network_options' : 'manage_options';
		$required = apply_filters( 'mdmfa_manage_capability', $default );

		return array( is_string( $required ) && '' !== $required ? $required : $default );
	}

	/**
	 * Registers the `wp mdmfa` command group.
	 */
	public static function register_cli(): void {
		if ( class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'mdmfa', Command::class );
			\WP_CLI::add_command( 'mdmfa user', UserCommand::class );
			\WP_CLI::add_command( 'mdmfa slug', SlugCommand::class );
		}
	}

	/**
	 * Declares WooCommerce feature compatibility. The plugin never reads or writes orders.
	 */
	public static function declare_wc_compatibility(): void {
		if ( ! class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
			return;
		}
		\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', MDMFA_FILE, true );
		\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', MDMFA_FILE, true );
	}

	/**
	 * For a day after a slug change, reminds administrators of the new login address.
	 */
	public static function render_slug_notice(): void {
		if ( ! current_user_can( self::MANAGE_CAP ) || ! LoginLocation::enabled() ) {
			return;
		}
		$notices = get_option( Options::NOTICES, array() );
		$changed = is_array( $notices ) && isset( $notices['slug_changed'] ) ? (int) $notices['slug_changed'] : 0;
		if ( $changed < Clock::now() - DAY_IN_SECONDS ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
			esc_html__( 'The login address changed. Bookmark the new one:', 'maxtdesign-mfa' ),
			esc_url( LoginLocation::url() ),
			esc_html( LoginLocation::url() )
		);
	}

	/**
	 * Red notice on every admin screen while the escape hatch is active.
	 */
	public static function render_disabled_notice(): void {
		if ( ! current_user_can( self::MANAGE_CAP ) ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s</p></div>',
			esc_html__( 'MaxtDesign MFA is disabled.', 'maxtdesign-mfa' ),
			esc_html__( 'MDMFA_DISABLE is set in wp-config.php, so logins use a password only. Remove the constant to turn multi-factor authentication back on.', 'maxtdesign-mfa' )
		);
	}
}
