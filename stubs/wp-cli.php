<?php
/**
 * Minimal WP-CLI declarations for PHPStan. php-stubs/wp-cli-stubs 2.12 caps
 * php-stubs/wordpress-stubs below 7.0, and this plugin analyses against the 7.1 stubs,
 * so only the WP-CLI surface the plugin calls is declared here. Not shipped.
 *
 * @package MaxtDesign\Mfa
 */

// phpcs:ignoreFile

namespace {
	class WP_CLI {
		/**
		 * @param string          $name     Command name.
		 * @param callable|string $callable Class name or callable.
		 * @param array<string, mixed> $args Registration arguments.
		 */
		public static function add_command( string $name, $callable, array $args = array() ): bool {
			return true;
		}

		public static function line( string $message = '' ): void {}

		public static function success( string $message ): void {}

		public static function warning( string $message ): void {}
	}
}

namespace WP_CLI\Utils {
	/**
	 * @param string                       $format Output format.
	 * @param array<int, array<string, mixed>> $items  Rows.
	 * @param string[]|string              $fields Columns.
	 */
	function format_items( string $format, array $items, $fields ): void {}
}
