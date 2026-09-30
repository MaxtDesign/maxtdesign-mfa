<?php
/**
 * Renders a QrCode as inline SVG markup (content, not an asset: zero requests).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Qr;

defined( 'ABSPATH' ) || exit;

/**
 * SVG output.
 */
final class QrSvg {

	/** Light border in modules; the standard asks for four. */
	public const QUIET_ZONE = 4;

	/**
	 * SVG for data, or '' when it does not fit (callers show the text secret instead).
	 *
	 * @param string $data  Bytes to encode.
	 * @param string $label Accessible name.
	 * @param int    $pixels Rendered width and height in CSS pixels.
	 */
	public static function render( string $data, string $label, int $pixels = 200 ): string {
		try {
			$qr = QrCode::encode( $data, QrCode::ECC_M );
		} catch ( \LengthException $e ) {
			return '';
		}

		return self::from_code( $qr, $label, $pixels );
	}

	/**
	 * SVG for an encoded symbol.
	 *
	 * @param QrCode $qr     Symbol.
	 * @param string $label  Accessible name.
	 * @param int    $pixels Rendered size.
	 */
	public static function from_code( QrCode $qr, string $label, int $pixels = 200 ): string {
		$path = '';
		for ( $y = 0; $y < $qr->size; $y++ ) {
			for ( $x = 0; $x < $qr->size; $x++ ) {
				if ( $qr->get( $x, $y ) ) {
					$path .= 'M' . ( $x + self::QUIET_ZONE ) . ',' . ( $y + self::QUIET_ZONE ) . 'h1v1h-1z';
				}
			}
		}
		$box = $qr->size + 2 * self::QUIET_ZONE;

		return sprintf(
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %1$d %1$d" width="%2$d" height="%2$d" role="img" aria-label="%3$s" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path d="%4$s" fill="#000"/></svg>',
			$box,
			$pixels,
			esc_attr( $label ),
			$path
		);
	}
}
