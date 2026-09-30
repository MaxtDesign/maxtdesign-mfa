<?php
/**
 * Structural and known-answer tests. Readability by a real decoder is proven in CI
 * (tools/qr-decode-check.php with zbar).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Qr;

use MaxtDesign\Mfa\Qr\QrCode;
use MaxtDesign\Mfa\Qr\QrSvg;
use PHPUnit\Framework\TestCase;

final class QrCodeTest extends TestCase {

	public function test_reed_solomon_known_answer_hello_world_1m(): void {
		// ISO/IEC 18004 worked example ("HELLO WORLD", version 1-M, alphanumeric).
		$data = array( 32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17 );

		self::assertSame( array( 196, 35, 39, 119, 235, 215, 231, 226, 93, 23 ), QrCode::reed_solomon( $data, 10 ) );
	}

	public function test_capacity_tables(): void {
		self::assertSame( 208, QrCode::raw_data_modules( 1 ) );
		self::assertSame( 16, QrCode::data_codewords( 1, QrCode::ECC_M ) );
		self::assertSame( 19, QrCode::data_codewords( 1, QrCode::ECC_L ) );
		self::assertSame( 62, QrCode::data_codewords( 5, QrCode::ECC_Q ) );
		self::assertSame( 216, QrCode::data_codewords( 10, QrCode::ECC_M ) );
		self::assertSame( 415, QrCode::data_codewords( 15, QrCode::ECC_M ) );
		self::assertSame( 669, QrCode::data_codewords( 20, QrCode::ECC_M ) );
		// Version 40 at every level: the published maxima.
		self::assertSame( 2956, QrCode::data_codewords( 40, QrCode::ECC_L ) );
		self::assertSame( 2334, QrCode::data_codewords( 40, QrCode::ECC_M ) );
		self::assertSame( 1666, QrCode::data_codewords( 40, QrCode::ECC_Q ) );
		self::assertSame( 1276, QrCode::data_codewords( 40, QrCode::ECC_H ) );
	}

	public function test_smallest_version_is_chosen_and_size_follows(): void {
		$qr = QrCode::encode( str_repeat( 'a', 14 ) );
		self::assertSame( 1, $qr->version, '14 bytes fit 1-M' );
		self::assertSame( 21, $qr->size );

		$qr = QrCode::encode( str_repeat( 'a', 15 ) );
		self::assertSame( 2, $qr->version );
		self::assertSame( 25, $qr->size );
	}

	public function test_finder_patterns_are_in_the_three_corners(): void {
		$qr   = QrCode::encode( 'otpauth://totp/Shop:jane?secret=JBSWY3DPEHPK3PXP&issuer=Shop' );
		$last = $qr->size - 1;
		foreach ( array( array( 0, 0 ), array( $last - 6, 0 ), array( 0, $last - 6 ) ) as list( $ox, $oy ) ) {
			for ( $i = 0; $i < 7; $i++ ) {
				self::assertTrue( $qr->get( $ox + $i, $oy ), 'top edge' );
				self::assertTrue( $qr->get( $ox + $i, $oy + 6 ), 'bottom edge' );
				self::assertTrue( $qr->get( $ox, $oy + $i ), 'left edge' );
			}
			self::assertFalse( $qr->get( $ox + 1, $oy + 1 ), 'light ring' );
			self::assertTrue( $qr->get( $ox + 3, $oy + 3 ), 'dark centre' );
		}
		self::assertTrue( $qr->get( 8, $qr->size - 8 ), 'the always-dark module' );
	}

	public function test_both_format_copies_decode_to_level_m_and_the_chosen_mask(): void {
		$qr = QrCode::encode( 'otpauth://totp/Shop:jane?secret=JBSWY3DPEHPK3PXP&issuer=Shop' );

		$first = 0;
		for ( $i = 0; $i <= 5; $i++ ) {
			$first |= ( $qr->get( 8, $i ) ? 1 : 0 ) << $i;
		}
		$first |= ( $qr->get( 8, 7 ) ? 1 : 0 ) << 6;
		$first |= ( $qr->get( 8, 8 ) ? 1 : 0 ) << 7;
		$first |= ( $qr->get( 7, 8 ) ? 1 : 0 ) << 8;
		for ( $i = 9; $i < 15; $i++ ) {
			$first |= ( $qr->get( 14 - $i, 8 ) ? 1 : 0 ) << $i;
		}
		$second = 0;
		for ( $i = 0; $i < 8; $i++ ) {
			$second |= ( $qr->get( $qr->size - 1 - $i, 8 ) ? 1 : 0 ) << $i;
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$second |= ( $qr->get( 8, $qr->size - 15 + $i ) ? 1 : 0 ) << $i;
		}

		self::assertSame( $first, $second );
		$data = ( $first ^ 0x5412 ) >> 10;
		self::assertSame( 0, $data >> 3, 'level M is format bits 00' );
		self::assertSame( $qr->mask, $data & 7 );
	}

	public function test_version_seven_carries_version_information(): void {
		$qr = QrCode::encode( str_repeat( 'x', 120 ) );
		self::assertSame( 7, $qr->version, '120 bytes need 7-M' );

		$bits = 0;
		for ( $i = 0; $i < 18; $i++ ) {
			$bits |= ( $qr->get( $qr->size - 11 + $i % 3, intdiv( $i, 3 ) ) ? 1 : 0 ) << $i;
		}
		self::assertSame( $qr->version, $bits >> 12 );
	}

	public function test_output_is_deterministic(): void {
		$a = QrSvg::render( 'abc', 'label' );

		self::assertSame( $a, QrSvg::render( 'abc', 'label' ) );
		self::assertStringStartsWith( '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 29 29"', $a );
		self::assertStringContainsString( 'aria-label="label"', $a );
	}

	public function test_largest_symbol_holds_2331_bytes(): void {
		$qr = QrCode::encode( str_repeat( 'x', 2331 ) );

		self::assertSame( 40, $qr->version );
		self::assertSame( 177, $qr->size );
	}

	public function test_too_long_data_throws_and_svg_falls_back_to_empty(): void {
		self::assertSame( '', QrSvg::render( str_repeat( 'x', 2332 ), 'label' ) );

		$this->expectException( \LengthException::class );
		QrCode::encode( str_repeat( 'x', 2332 ) );
	}
}
