<?php
/**
 * The plugin's one admin entry (plan section 8, nav handoff section 4): page `md-mfa`,
 * every screen a tab. Under the MaxtDesign menu when suite-core is loaded, otherwise
 * under Users, so a lone install never grows a top-level menu.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Admin;

use MaxtDesign\Mfa\Account\AccountPage;
use MaxtDesign\Mfa\Plugin;

defined( 'ABSPATH' ) || exit;

/**
 * Menu, tabs, assets and dispatch.
 */
final class SettingsPage {

	public const SLUG = 'md-mfa';

	public const STYLE  = 'mdmfa-admin';
	public const SCRIPT = 'mdmfa-admin';

	/**
	 * Hook suffix returned by add_*_page(); assets load on this screen only.
	 *
	 * @var string
	 */
	private static string $hook = '';

	/**
	 * Registers hooks (admin requests only).
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'assets' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( MDMFA_FILE ), array( self::class, 'action_links' ) );
	}

	/**
	 * Whether the page is mounted under the suite menu: another MaxtDesign plugin started
	 * suite-core in this request. The classes alone are not enough; a vendored copy can
	 * be declared without the suite menu ever being registered.
	 */
	public static function in_suite(): bool {
		return ! empty( $GLOBALS['md_suite_loaded'] ) && class_exists( '\MdSuite_Admin', false ) && defined( '\MdSuite_Admin::MENU_SLUG' );
	}

	/**
	 * Adds the single menu entry.
	 */
	public static function menu(): void {
		if ( self::in_suite() ) {
			$hook = add_submenu_page(
				(string) constant( '\MdSuite_Admin::MENU_SLUG' ),
				__( 'MaxtDesign MFA', 'maxtdesign-mfa' ),
				__( 'MFA', 'maxtdesign-mfa' ),
				Plugin::MANAGE_CAP,
				self::SLUG,
				array( self::class, 'render' )
			);
			if ( Ui::suite_has( 'register_screen' ) ) {
				\MdSuite_Admin::register_screen( self::SLUG );
			}
		} else {
			$hook = add_users_page(
				__( 'Login security (MFA)', 'maxtdesign-mfa' ),
				__( 'Login security (MFA)', 'maxtdesign-mfa' ),
				Plugin::MANAGE_CAP,
				self::SLUG,
				array( self::class, 'render' )
			);
		}
		self::$hook = is_string( $hook ) ? $hook : '';
	}

	/**
	 * Loads the stylesheet and script on this screen only (exact hook suffix).
	 *
	 * @param mixed $hook_suffix Current screen's hook suffix.
	 */
	public static function assets( mixed $hook_suffix ): void {
		if ( '' === self::$hook || $hook_suffix !== self::$hook ) {
			return;
		}
		wp_enqueue_style( self::STYLE, plugins_url( 'assets/admin/mdmfa-admin.css', MDMFA_FILE ), array(), MDMFA_VERSION );
		wp_enqueue_script(
			self::SCRIPT,
			plugins_url( 'assets/admin/mdmfa-admin.js', MDMFA_FILE ),
			array(),
			MDMFA_VERSION,
			array(
				'strategy'  => 'defer',
				'in_footer' => true,
			)
		);
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param mixed $links Existing links.
	 * @return mixed
	 */
	public static function action_links( mixed $links ): mixed {
		if ( is_array( $links ) && current_user_can( Plugin::MANAGE_CAP ) ) {
			array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Settings', 'maxtdesign-mfa' ) . '</a>' );
		}

		return $links;
	}

	/**
	 * Tabs: slug => label. Filter: mdmfa_admin_tabs.
	 *
	 * @return array<string, string>
	 */
	public static function tabs(): array {
		$tabs     = array(
			'policy'    => __( 'Policy', 'maxtdesign-mfa' ),
			'factors'   => __( 'Factors', 'maxtdesign-mfa' ),
			'location'  => __( 'Login location', 'maxtdesign-mfa' ),
			'sidedoors' => __( 'Side doors', 'maxtdesign-mfa' ),
			'recovery'  => __( 'Recovery', 'maxtdesign-mfa' ),
			'coverage'  => __( 'Coverage', 'maxtdesign-mfa' ),
			'activity'  => __( 'Activity', 'maxtdesign-mfa' ),
			'tools'     => __( 'Tools', 'maxtdesign-mfa' ),
		);
		$filtered = apply_filters( 'mdmfa_admin_tabs', $tabs );
		$clean    = array();
		foreach ( is_array( $filtered ) ? $filtered : $tabs as $slug => $label ) {
			if ( is_string( $slug ) && is_string( $label ) && '' !== sanitize_key( $slug ) ) {
				$clean[ sanitize_key( $slug ) ] = $label;
			}
		}

		return array() !== $clean ? $clean : $tabs;
	}

	/**
	 * The active tab: unknown or absent falls back to the first.
	 */
	public static function active_tab(): string {
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		$tabs = self::tabs();

		return isset( $tabs[ $tab ] ) ? $tab : (string) array_key_first( $tabs );
	}

	/**
	 * Raw URL of a tab.
	 *
	 * @param string                    $tab  Tab slug ('' for the default).
	 * @param array<string, string|int> $args Extra query arguments.
	 */
	public static function url( string $tab = '', array $args = array() ): string {
		$query = array_merge( array( 'page' => self::SLUG ), '' !== $tab ? array( 'tab' => $tab ) : array(), $args );

		return add_query_arg( $query, admin_url( self::in_suite() ? 'admin.php' : 'users.php' ) );
	}

	/**
	 * URL of the acting admin's own security page (step-up happens there).
	 */
	public static function my_security_url(): string {
		return add_query_arg( 'page', AccountPage::SLUG, admin_url( current_user_can( 'edit_users' ) ? 'users.php' : 'profile.php' ) );
	}

	/**
	 * Renders the page.
	 */
	public static function render(): void {
		if ( ! current_user_can( Plugin::MANAGE_CAP ) ) {
			return;
		}
		$tab     = self::active_tab();
		$notice  = isset( $_GET['mdmfa_notice'] ) ? sanitize_key( wp_unslash( $_GET['mdmfa_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only; the text comes from a fixed map.
		$notices = Actions::notices();

		echo '<div class="wrap md-suite-wrap mdmfa-admin' . ( self::in_suite() ? '' : ' mdmfa-standalone' ) . '" data-mdmfa-cancel="' . esc_attr__( 'Cancel', 'maxtdesign-mfa' ) . '">';
		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Ui returns escaped markup.
		echo Ui::page_header();
		// WordPress moves admin notices to this marker instead of into the header row.
		echo '<hr class="wp-header-end">';
		echo Ui::tabs( self::tabs(), $tab );
		if ( isset( $notices[ $notice ] ) ) {
			echo Ui::notice( $notices[ $notice ][0], $notices[ $notice ][1] );
			if ( 'stepup' === $notice ) {
				printf( '<p><a class="button" href="%1$s">%2$s</a></p>', esc_url( self::my_security_url() ), esc_html__( 'Go to My security', 'maxtdesign-mfa' ) );
			}
		}
		// phpcs:enable

		switch ( $tab ) {
			case 'policy':
				SettingsViews::policy();
				break;
			case 'factors':
				SettingsViews::factors();
				break;
			case 'location':
				SettingsViews::location();
				break;
			case 'sidedoors':
				SettingsViews::side_doors();
				break;
			case 'recovery':
				SettingsViews::recovery();
				break;
			case 'coverage':
				ReportViews::coverage();
				break;
			case 'activity':
				ReportViews::activity();
				break;
			case 'tools':
				ReportViews::tools();
				break;
			default:
				// A tab added through mdmfa_admin_tabs renders itself.
				do_action( 'mdmfa_admin_tab_' . $tab );
		}
		echo '</div>';
	}
}
