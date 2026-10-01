<?php
/**
 * Router for PHP's built-in server in CI, matching a typical nginx `try_files $uri
 * $uri/ /index.php?$args` setup: existing files and directories are served as they are,
 * everything else (pretty permalinks, robots.txt, sitemaps, the login slug) goes to
 * WordPress's index.php. Never shipped: /tests is in .distignore.
 *
 * @package MaxtDesign\Mfa
 */

// phpcs:ignoreFile

$root = rtrim( (string) $_SERVER['DOCUMENT_ROOT'], '/' );
$path = (string) parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH );
$file = $root . $path;

if ( '/' !== $path && is_file( $file ) ) {
	return false;
}

// Subdirectory multisite, as the network's rewrite rules do: /{site}/wp-admin/... and
// /{site}/wp-*.php are the main install's files, run for that site.
if ( 1 === preg_match( '#^/[_0-9a-zA-Z-]+(/(?:wp-(?:content|admin|includes)/.*|[^/]+\.php))$#', $path, $m ) ) {
	$target = $root . $m[1];
	if ( is_dir( $target ) ) {
		$target = rtrim( $target, '/' ) . '/index.php';
	}
	if ( is_file( $target ) ) {
		if ( '.php' !== substr( $target, -4 ) ) {
			$types = array( 'css' => 'text/css', 'js' => 'application/javascript', 'png' => 'image/png', 'svg' => 'image/svg+xml', 'gif' => 'image/gif', 'jpg' => 'image/jpeg', 'woff2' => 'font/woff2' );
			header( 'Content-Type: ' . ( $types[ pathinfo( $target, PATHINFO_EXTENSION ) ] ?? 'application/octet-stream' ) );
			readfile( $target );
			return true;
		}
		$_SERVER['SCRIPT_NAME']     = $path;
		$_SERVER['PHP_SELF']        = $path;
		$_SERVER['SCRIPT_FILENAME'] = $target;
		chdir( dirname( $target ) );
		require $target;
		return true;
	}
}
if ( is_dir( $file ) && is_file( rtrim( $file, '/' ) . '/index.php' ) ) {
	return false;
}

$_SERVER['SCRIPT_NAME']     = '/index.php';
$_SERVER['PHP_SELF']        = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = $root . '/index.php';
chdir( $root );
require $root . '/index.php';
