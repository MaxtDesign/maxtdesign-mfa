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
if ( is_dir( $file ) && is_file( rtrim( $file, '/' ) . '/index.php' ) ) {
	return false;
}

$_SERVER['SCRIPT_NAME']     = '/index.php';
$_SERVER['PHP_SELF']        = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = $root . '/index.php';
chdir( $root );
require $root . '/index.php';
