<?php
/**
 * PHPUnit bootstrap: the few WordPress functions the P1 classes call, backed by an
 * in-memory store, plus a recording \wpdb. No WordPress, no database. Activation and
 * uninstall against a real WordPress + MySQL run in CI (.github/workflows/ci.yml, job
 * "smoke").
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:ignoreFile

define( 'ABSPATH', sys_get_temp_dir() . '/mdmfa-tests/' );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
define( 'MDMFA_VERSION', '0.1.0' );
define( 'MDMFA_FILE', dirname( __DIR__ ) . '/maxtdesign-mfa.php' );
define( 'MDMFA_DIR', dirname( __DIR__ ) );

require dirname( __DIR__ ) . '/vendor/autoload.php';
require __DIR__ . '/wp-shims.php';

// Installer::install() requires ABSPATH/wp-admin/includes/upgrade.php for dbDelta();
// give it a recording stand-in.
if ( ! is_dir( ABSPATH . 'wp-admin/includes' ) ) {
	mkdir( ABSPATH . 'wp-admin/includes', 0777, true );
}
file_put_contents(
	ABSPATH . 'wp-admin/includes/upgrade.php',
	'<?php if ( ! function_exists( "dbDelta" ) ) { function dbDelta( $queries = "", $execute = true ) { foreach ( (array) $queries as $q ) { $GLOBALS["mdmfa_test"]["dbdelta"][] = $q; } return array(); } }'
);

/**
 * Resets the fake WordPress state between tests.
 */
function mdmfa_test_reset(): void {
	$GLOBALS['mdmfa_test'] = array(
		'options'      => array(),
		'autoload'     => array(),
		'deleted_meta' => array(),
		'cleared_cron' => array(),
		'filters'      => array(),
		'multisite'    => false,
		'sites'        => array( 1 ),
		'network'      => false,
		'dbdelta'      => array(),
		'usermeta'     => array(),
		'users'        => array(),
		'super_admins' => array(),
		'actions'      => array(),
		'mail'         => array(),
		'inserts'      => array(),
		'scheduled'    => array(),
	);
	MaxtDesign\Mfa\Support\Clock::freeze( null );
	$GLOBALS['wpdb'] = new wpdb();
}

/**
 * Recording stand-in for WordPress's database class.
 */
class wpdb {
	public string $prefix      = 'wp_';
	public string $base_prefix = 'wp_';
	public string $options     = 'wp_options';
	public string $usermeta    = 'wp_usermeta';
	public string $sitemeta    = 'wp_sitemeta';
	/** @var string[] */
	public array $queries = array();

	/**
	 * @param array<string, mixed> $data
	 */
	public function insert( string $table, array $data, mixed $format = null ): int {
		$GLOBALS['mdmfa_test']['inserts'][] = array( $table, $data );
		return 1;
	}

	/**
	 * Applies user meta compare-and-swap updates to the in-memory store, like MySQL would.
	 *
	 * @param array<string, mixed> $data
	 * @param array<string, mixed> $where
	 */
	public function update( string $table, array $data, array $where, mixed $format = null, mixed $where_format = null ): int {
		if ( $this->usermeta !== $table ) {
			return 1;
		}
		$uid = (int) $where['user_id'];
		$key = (string) $where['meta_key'];
		if ( ! isset( $GLOBALS['mdmfa_test']['usermeta'][ $uid ][ $key ] ) ) {
			return 0;
		}
		if ( isset( $where['meta_value'] ) && maybe_serialize( $GLOBALS['mdmfa_test']['usermeta'][ $uid ][ $key ] ) !== $where['meta_value'] ) {
			return 0;
		}
		$GLOBALS['mdmfa_test']['usermeta'][ $uid ][ $key ] = unserialize( (string) $data['meta_value'] );
		return 1;
	}

	public function get_charset_collate(): string {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci';
	}

	public function query( string $query ): int {
		$this->queries[] = $query;
		return 0;
	}

	public function prepare( string $query, ...$args ): string {
		foreach ( $args as $arg ) {
			$query = preg_replace_callback(
				'/%[si]/',
				static fn ( array $m ): string => '%i' === $m[0] ? '`' . $arg . '`' : "'" . addslashes( (string) $arg ) . "'",
				$query,
				1
			) ?? $query;
		}
		return $query;
	}

	public function esc_like( string $text ): string {
		return addcslashes( $text, '_%\\' );
	}
}

function get_option( string $option, mixed $default_value = false ): mixed {
	return $GLOBALS['mdmfa_test']['options'][ $option ] ?? $default_value;
}

function add_option( string $option, mixed $value = '', string $deprecated = '', ?bool $autoload = null ): bool {
	if ( array_key_exists( $option, $GLOBALS['mdmfa_test']['options'] ) ) {
		return false;
	}
	$GLOBALS['mdmfa_test']['options'][ $option ]  = $value;
	$GLOBALS['mdmfa_test']['autoload'][ $option ] = $autoload;
	return true;
}

function update_option( string $option, mixed $value, ?bool $autoload = null ): bool {
	$GLOBALS['mdmfa_test']['options'][ $option ]  = $value;
	$GLOBALS['mdmfa_test']['autoload'][ $option ] = $autoload;
	return true;
}

function delete_option( string $option ): bool {
	unset( $GLOBALS['mdmfa_test']['options'][ $option ] );
	return true;
}

function delete_metadata( string $type, int $object_id, string $key, mixed $value = '', bool $all = false ): bool {
	$GLOBALS['mdmfa_test']['deleted_meta'][] = array( $type, $object_id, $key, $all );
	return true;
}

function wp_clear_scheduled_hook( string $hook ): int {
	$GLOBALS['mdmfa_test']['cleared_cron'][] = $hook . '@' . $GLOBALS['wpdb']->prefix;
	return 0;
}

function wp_cache_delete( int|string $key, string $group = '' ): bool {
	return true;
}

function wp_salt( string $scheme = 'auth' ): string {
	return 'db-salt-' . $scheme . str_repeat( 'x', 48 );
}

function add_filter( string $hook, callable $callback, int $priority = 10, int $args = 1 ): bool {
	$GLOBALS['mdmfa_test']['filters'][ $hook ][] = $callback;
	return true;
}

function apply_filters( string $hook, mixed $value, mixed ...$args ): mixed {
	foreach ( $GLOBALS['mdmfa_test']['filters'][ $hook ] ?? array() as $callback ) {
		$value = $callback( $value, ...$args );
	}
	return $value;
}

function is_network_admin(): bool {
	return $GLOBALS['mdmfa_test']['network'];
}

function is_multisite(): bool {
	return $GLOBALS['mdmfa_test']['multisite'];
}

/**
 * @param array<string, mixed> $args
 * @return int[]
 */
function get_sites( array $args = array() ): array {
	return $GLOBALS['mdmfa_test']['sites'];
}

function switch_to_blog( int $site_id ): bool {
	$GLOBALS['wpdb']->prefix  = 1 === $site_id ? 'wp_' : 'wp_' . $site_id . '_';
	$GLOBALS['wpdb']->options = $GLOBALS['wpdb']->prefix . 'options';
	return true;
}

function restore_current_blog(): bool {
	$GLOBALS['wpdb']->prefix  = 'wp_';
	$GLOBALS['wpdb']->options = 'wp_options';
	return true;
}

mdmfa_test_reset();
