<?php
/**
 * Byte budgets for every shipped CSS/JS file (plan sections 8 and 9). CI fails when a
 * budget is exceeded. Not shipped (/tools is in .distignore).
 *
 * Usage:
 *   php tools/size-check.php [plugin-dir]
 *   php tools/size-check.php --self-test   proves the check fails on over-budget files
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI tool, runs outside WordPress.

/**
 * Budgets. A glob that matches nothing passes: P1 ships no assets yet, and the budget
 * must already exist when the first file lands.
 *
 * - front-css:   front-end CSS is always zero bytes.
 * - passkey-js:  the deferred passkey module, per file, raw minified and gzip.
 * - admin-css / admin-js: totals across our own admin screens.
 *
 * @return array<string, array{glob: string, per_file_raw?: int, per_file_gzip?: int, total_raw?: int}>
 */
function mdmfa_size_budgets(): array {
	return array(
		'front-css'  => array(
			'glob'      => 'assets/front/*.css',
			'total_raw' => 0,
		),
		'passkey-js' => array(
			'glob'          => 'assets/front/*.js',
			'per_file_raw'  => 3072,
			'per_file_gzip' => 1536,
		),
		'admin-css'  => array(
			'glob'      => 'assets/admin/*.css',
			'total_raw' => 4096,
		),
		'admin-js'   => array(
			'glob'      => 'assets/admin/*.js',
			'total_raw' => 8192,
		),
	);
}

/**
 * Runs every budget against a plugin directory.
 *
 * @param string $root Plugin directory.
 * @return array{fails: int, lines: string[]}
 */
function mdmfa_size_check( string $root ): array {
	$fails = 0;
	$lines = array();
	foreach ( mdmfa_size_budgets() as $name => $budget ) {
		$files = glob( rtrim( $root, '/\\' ) . '/' . $budget['glob'] );
		$files = false === $files ? array() : $files;
		$total = 0;
		foreach ( $files as $file ) {
			$bytes  = (string) file_get_contents( $file );
			$raw    = strlen( $bytes );
			$gzip   = strlen( (string) gzencode( $bytes, 9 ) );
			$total += $raw;
			$label  = basename( $file ) . " raw {$raw} B, gzip {$gzip} B";
			if ( isset( $budget['per_file_raw'] ) && $raw > $budget['per_file_raw'] ) {
				++$fails;
				$lines[] = "FAIL  {$name}: {$label} exceeds {$budget['per_file_raw']} B raw";
			} elseif ( isset( $budget['per_file_gzip'] ) && $gzip > $budget['per_file_gzip'] ) {
				++$fails;
				$lines[] = "FAIL  {$name}: {$label} exceeds {$budget['per_file_gzip']} B gzip";
			} else {
				$lines[] = "ok    {$name}: {$label}";
			}
		}
		if ( isset( $budget['total_raw'] ) ) {
			if ( $total > $budget['total_raw'] ) {
				++$fails;
				$lines[] = "FAIL  {$name}: total {$total} B exceeds {$budget['total_raw']} B";
			} else {
				$lines[] = "ok    {$name}: total {$total} B of {$budget['total_raw']} B (" . count( $files ) . ' files)';
			}
		} elseif ( array() === $files ) {
			$lines[] = "ok    {$name}: no files yet";
		}
	}

	return array(
		'fails' => $fails,
		'lines' => $lines,
	);
}

/**
 * Builds synthetic plugin trees and asserts the check passes and fails where it should.
 */
function mdmfa_size_self_test(): int {
	$cases = array(
		'empty tree passes'                 => array( true, array() ),
		'front CSS of 1 byte fails'         => array( false, array( 'assets/front/a.css' => 'a' ) ),
		'passkey JS at budget passes'       => array( true, array( 'assets/front/p.js' => str_repeat( 'a', 3072 ) ) ),
		'passkey JS 1 byte over fails'      => array( false, array( 'assets/front/p.js' => str_repeat( 'a', 3073 ) ) ),
		'passkey JS over gzip budget fails' => array( false, array( 'assets/front/p.js' => random_bytes( 2000 ) ) ),
		'admin JS total over budget fails'  => array(
			false,
			array(
				'assets/admin/a.js' => str_repeat( 'a', 5000 ),
				'assets/admin/b.js' => str_repeat( 'b', 3193 ),
			),
		),
		'admin CSS at budget passes'        => array( true, array( 'assets/admin/a.css' => str_repeat( 'a', 4096 ) ) ),
	);
	$bad   = 0;
	foreach ( $cases as $label => $case ) {
		list( $should_pass, $files ) = $case;
		$dir                         = sys_get_temp_dir() . '/mdmfa-size-' . bin2hex( random_bytes( 6 ) );
		foreach ( $files as $path => $content ) {
			$full = $dir . '/' . $path;
			if ( ! is_dir( dirname( $full ) ) ) {
				mkdir( dirname( $full ), 0777, true );
			}
			file_put_contents( $full, $content );
		}
		$result = mdmfa_size_check( $dir );
		$passed = 0 === $result['fails'];
		if ( $passed === $should_pass ) {
			echo "ok    {$label}\n";
		} else {
			++$bad;
			echo "BAD   {$label}\n    " . implode( "\n    ", $result['lines'] ) . "\n";
		}
	}
	echo 0 === $bad ? "SELF-TEST PASSED\n" : "SELF-TEST FAILED ({$bad})\n";

	return 0 === $bad ? 0 : 1;
}

if ( 'cli' === PHP_SAPI && isset( $argv ) && realpath( $argv[0] ) === __FILE__ ) {
	if ( in_array( '--self-test', $argv, true ) ) {
		exit( mdmfa_size_self_test() );
	}
	$mdmfa_root   = $argv[1] ?? dirname( __DIR__ );
	$mdmfa_result = mdmfa_size_check( $mdmfa_root );
	echo implode( "\n", $mdmfa_result['lines'] ) . "\n";
	echo 0 === $mdmfa_result['fails'] ? "SIZE CHECK PASSED\n" : "SIZE CHECK FAILED ({$mdmfa_result['fails']})\n";
	exit( 0 === $mdmfa_result['fails'] ? 0 : 1 );
}
