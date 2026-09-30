<?php
/**
 * Proves the in-house QR encoder produces symbols a real decoder reads: renders the SVG
 * for payloads that land on versions 1 to 15, rasterises with rsvg-convert, decodes with
 * zbarimg and compares byte for byte. Needs zbar-tools and librsvg2-bin (CI installs
 * them). Not shipped (/tools is in .distignore).
 *
 * Usage: php tools/qr-decode-check.php
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.PHP.DiscouragedPHPFunctions, WordPress.PHP.DevelopmentFunctions, WordPress.NamingConventions.PrefixAllGlobals -- CI tool, runs outside WordPress and defines the two WordPress symbols the renderer needs.

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! function_exists( 'esc_attr' ) ) {
	/**
	 * Stand-in for WordPress's esc_attr() outside WordPress.
	 *
	 * @param string $text Text.
	 */
	function esc_attr( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES );
	}
}
require dirname( __DIR__ ) . '/vendor/autoload.php';

use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Qr\QrCode;
use MaxtDesign\Mfa\Qr\QrSvg;

$mdmfa_payloads = array(
	'tiny'                 => 'abc',
	'totp, short site'     => Totp::uri( random_bytes( 20 ), 'Shop', 'jane' ),
	'totp, typical'        => Totp::uri( random_bytes( 20 ), 'Maxt Offroad Parts & Accessories', 'jane.doe@example.com' ),
	'totp, unicode issuer' => Totp::uri( random_bytes( 20 ), 'Café Zürich – Boutique', 'müller@example.de' ),
	'totp, long labels'    => Totp::uri( random_bytes( 20 ), str_repeat( 'Long Site Name ', 6 ), str_repeat( 'account', 12 ) . '@example.com' ),
);
foreach ( array( 30, 60, 100, 150, 200, 260, 320, 400 ) as $mdmfa_len ) {
	$mdmfa_payloads[ "{$mdmfa_len} bytes" ] = substr( str_repeat( 'otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&', 20 ), 0, $mdmfa_len );
}

$mdmfa_dir  = sys_get_temp_dir() . '/mdmfa-qr-' . bin2hex( random_bytes( 4 ) );
$mdmfa_bad  = 0;
$mdmfa_seen = array();
mkdir( $mdmfa_dir );

foreach ( $mdmfa_payloads as $mdmfa_label => $mdmfa_data ) {
	$mdmfa_qr                         = QrCode::encode( $mdmfa_data );
	$mdmfa_seen[ $mdmfa_qr->version ] = true;
	$mdmfa_svg                        = $mdmfa_dir . '/qr.svg';
	$mdmfa_png                        = $mdmfa_dir . '/qr.png';
	file_put_contents( $mdmfa_svg, QrSvg::from_code( $mdmfa_qr, 'check', 8 * ( $mdmfa_qr->size + 8 ) ) );
	exec( 'rsvg-convert -o ' . escapeshellarg( $mdmfa_png ) . ' ' . escapeshellarg( $mdmfa_svg ) . ' 2>&1', $mdmfa_out, $mdmfa_rc );
	if ( 0 !== $mdmfa_rc ) {
		echo "FAIL  {$mdmfa_label}: rsvg-convert failed: " . implode( ' ', $mdmfa_out ) . "\n";
		++$mdmfa_bad;
		continue;
	}
	$mdmfa_decoded = shell_exec( 'zbarimg --quiet --raw -Sbinary ' . escapeshellarg( $mdmfa_png ) . ' 2>/dev/null' );
	$mdmfa_decoded = is_string( $mdmfa_decoded ) ? $mdmfa_decoded : '';
	// zbarimg ends the raw output with a newline.
	if ( str_ends_with( $mdmfa_decoded, "\n" ) ) {
		$mdmfa_decoded = substr( $mdmfa_decoded, 0, -1 );
	}
	if ( $mdmfa_decoded === $mdmfa_data ) {
		echo "ok    {$mdmfa_label}: version {$mdmfa_qr->version}, mask {$mdmfa_qr->mask}, " . strlen( $mdmfa_data ) . " bytes decoded exactly\n";
	} else {
		echo "FAIL  {$mdmfa_label}: version {$mdmfa_qr->version} decoded as " . var_export( substr( $mdmfa_decoded, 0, 80 ), true ) . "\n";
		++$mdmfa_bad;
	}
}

ksort( $mdmfa_seen );
echo 'versions covered: ' . implode( ', ', array_keys( $mdmfa_seen ) ) . "\n";
echo 0 === $mdmfa_bad ? "QR DECODE CHECK PASSED\n" : "QR DECODE CHECK FAILED ({$mdmfa_bad})\n";
exit( 0 === $mdmfa_bad ? 0 : 1 );
