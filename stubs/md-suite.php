<?php
/**
 * Minimal MaxtDesign suite-core declarations for PHPStan. The plugin does not vendor
 * suite-core; it calls these only when another plugin has loaded it, behind
 * class_exists() and method_exists(). Not shipped.
 *
 * @package MaxtDesign\Mfa
 */

// phpcs:ignoreFile

class MdSuite_Admin {
	public const MENU_SLUG = 'maxtdesign';

	public static function register_screen( string $page_slug ): void {}

	/**
	 * @param array<string, mixed> $args
	 */
	public static function render_page_header( string $product_name, array $args = array() ): string {
		return '';
	}

	public static function render_status_badge( string $status, string $label ): string {
		return '';
	}

	public static function render_empty_state( string $title, string $message, string $action_html = '' ): string {
		return '';
	}
}

class MdSuite_Registry {
	/**
	 * @param array<string, mixed> $meta
	 */
	public static function register( string $slug, array $meta = array() ): void {}
}

class MdSuite_Status {
	/**
	 * @param array<string, mixed> $data
	 */
	public static function contribute( string $plugin, array $data ): void {}
}
