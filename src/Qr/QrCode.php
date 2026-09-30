<?php
/**
 * QR Code Model 2 encoder, byte mode (ISO/IEC 18004). Used only to render the TOTP key URI
 * as an inline SVG at enrollment: no JavaScript, no remote QR service (plan section 3).
 *
 * Structure follows the widely used reference design by Project Nayuki (MIT), rewritten
 * for this plugin. CI decodes generated symbols with zbar to prove them readable.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Qr;

defined( 'ABSPATH' ) || exit;

/**
 * An encoded QR symbol.
 */
final class QrCode {

	public const ECC_L = 0;
	public const ECC_M = 1;
	public const ECC_Q = 2;
	public const ECC_H = 3;

	/** Largest version (177x177 modules; 2,331 bytes at level M). */
	public const MAX_VERSION = 40;

	/** Format-information bits per level (L=01, M=00, Q=11, H=10). */
	private const FORMAT_BITS = array( 1, 0, 3, 2 );

	/** Error-correction codewords per block, by level then version (index 0 unused). */
	private const ECC_PER_BLOCK = array(
		array( -1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 ),
		array( -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28 ),
		array( -1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 ),
		array( -1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30 ),
	);

	/** Error-correction blocks, by level then version (index 0 unused). */
	private const BLOCKS = array(
		array( -1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25 ),
		array( -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49 ),
		array( -1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68 ),
		array( -1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81 ),
	);

	/**
	 * Module grid, [row][column], true = dark.
	 *
	 * @var array<int, array<int, bool>>
	 */
	private array $modules = array();

	/**
	 * Function-pattern mask, [row][column].
	 *
	 * @var array<int, array<int, bool>>
	 */
	private array $is_function = array();

	/**
	 * Side length in modules.
	 *
	 * @var int
	 */
	public readonly int $size;

	/**
	 * Constructor; use encode().
	 *
	 * @param int $version Version 1..MAX_VERSION.
	 * @param int $ecc     ECC_* level.
	 * @param int $mask    Chosen mask 0..7.
	 */
	private function __construct(
		public readonly int $version,
		public readonly int $ecc,
		public int $mask = 0
	) {
		$this->size = $version * 4 + 17;
		$row        = array_fill( 0, $this->size, false );
		for ( $y = 0; $y < $this->size; $y++ ) {
			$this->modules[ $y ]     = $row;
			$this->is_function[ $y ] = $row;
		}
	}

	/**
	 * Encodes bytes at the smallest version that fits.
	 *
	 * @param string $data Bytes to encode.
	 * @param int    $ecc  ECC_* level.
	 * @throws \LengthException When the data does not fit MAX_VERSION.
	 */
	public static function encode( string $data, int $ecc = self::ECC_M ): self {
		$length  = strlen( $data );
		$version = 0;
		for ( $v = 1; $v <= self::MAX_VERSION; $v++ ) {
			$count_bits = $v <= 9 ? 8 : 16;
			if ( $length < ( 1 << $count_bits ) && 4 + $count_bits + 8 * $length <= self::data_codewords( $v, $ecc ) * 8 ) {
				$version = $v;
				break;
			}
		}
		if ( 0 === $version ) {
			throw new \LengthException( 'Data too long for a QR code.' );
		}

		// Byte-mode segment, terminator, bit padding, pad codewords.
		$count_bits = $version <= 9 ? 8 : 16;
		$bits       = array();
		self::append_bits( $bits, 0x4, 4 );
		self::append_bits( $bits, $length, $count_bits );
		for ( $i = 0; $i < $length; $i++ ) {
			self::append_bits( $bits, ord( $data[ $i ] ), 8 );
		}
		$capacity = self::data_codewords( $version, $ecc ) * 8;
		self::append_bits( $bits, 0, min( 4, $capacity - count( $bits ) ) );
		self::append_bits( $bits, 0, ( 8 - count( $bits ) % 8 ) % 8 );
		$pad    = 0xEC;
		$filled = count( $bits );
		while ( $filled < $capacity ) {
			self::append_bits( $bits, $pad, 8 );
			$pad    ^= 0xEC ^ 0x11;
			$filled += 8;
		}
		$codewords = array();
		foreach ( array_chunk( $bits, 8 ) as $byte_bits ) {
			$byte = 0;
			foreach ( $byte_bits as $bit ) {
				$byte = ( $byte << 1 ) | $bit;
			}
			$codewords[] = $byte;
		}

		$qr = new self( $version, $ecc );
		$qr->draw_function_patterns();
		$qr->draw_codewords( self::add_ecc_and_interleave( $codewords, $version, $ecc ) );

		// Pick the mask with the lowest penalty, as the standard requires.
		$best_mask    = 0;
		$best_penalty = PHP_INT_MAX;
		for ( $mask = 0; $mask < 8; $mask++ ) {
			$qr->apply_mask( $mask );
			$qr->draw_format_bits( $mask );
			$penalty = $qr->penalty();
			if ( $penalty < $best_penalty ) {
				$best_mask    = $mask;
				$best_penalty = $penalty;
			}
			$qr->apply_mask( $mask );
		}
		$qr->mask = $best_mask;
		$qr->apply_mask( $best_mask );
		$qr->draw_format_bits( $best_mask );

		return $qr;
	}

	/**
	 * Whether the module at (x, y) is dark. Outside the symbol is light.
	 *
	 * @param int $x Column.
	 * @param int $y Row.
	 */
	public function get( int $x, int $y ): bool {
		return $x >= 0 && $y >= 0 && $x < $this->size && $y < $this->size && $this->modules[ $y ][ $x ];
	}

	/**
	 * Data codewords available at a version and level.
	 *
	 * @param int $version Version.
	 * @param int $ecc     Level.
	 */
	public static function data_codewords( int $version, int $ecc ): int {
		return intdiv( self::raw_data_modules( $version ), 8 ) - self::ECC_PER_BLOCK[ $ecc ][ $version ] * self::BLOCKS[ $ecc ][ $version ];
	}

	/**
	 * Modules available for data and ECC bits (everything but function patterns).
	 *
	 * @param int $version Version.
	 */
	public static function raw_data_modules( int $version ): int {
		$result = ( 16 * $version + 128 ) * $version + 64;
		if ( $version >= 2 ) {
			$align   = intdiv( $version, 7 ) + 2;
			$result -= ( 25 * $align - 10 ) * $align - 55;
			if ( $version >= 7 ) {
				$result -= 36;
			}
		}

		return $result;
	}

	/**
	 * Reed-Solomon remainder of $data by the generator of the given degree (public for
	 * known-answer tests).
	 *
	 * @param int[] $data   Data codewords.
	 * @param int   $degree ECC codeword count.
	 * @return int[]
	 */
	public static function reed_solomon( array $data, int $degree ): array {
		$divisor                = array_fill( 0, $degree, 0 );
		$divisor[ $degree - 1 ] = 1;
		$root                   = 1;
		for ( $i = 0; $i < $degree; $i++ ) {
			for ( $j = 0; $j < $degree; $j++ ) {
				$divisor[ $j ] = self::gf_multiply( $divisor[ $j ], $root );
				if ( $j + 1 < $degree ) {
					$divisor[ $j ] ^= $divisor[ $j + 1 ];
				}
			}
			$root = self::gf_multiply( $root, 0x02 );
		}

		$result = array_fill( 0, $degree, 0 );
		foreach ( $data as $byte ) {
			$factor   = $byte ^ array_shift( $result );
			$result[] = 0;
			foreach ( $divisor as $i => $coefficient ) {
				$result[ $i ] ^= self::gf_multiply( $coefficient, $factor );
			}
		}

		return $result;
	}

	/**
	 * Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
	 *
	 * @param int $x Factor.
	 * @param int $y Factor.
	 */
	private static function gf_multiply( int $x, int $y ): int {
		$z = 0;
		for ( $i = 7; $i >= 0; $i-- ) {
			$z  = ( $z << 1 ) ^ ( ( $z >> 7 ) * 0x11D );
			$z ^= ( ( $y >> $i ) & 1 ) * $x;
		}

		return $z;
	}

	/**
	 * Splits data into blocks, adds ECC to each, and interleaves them.
	 *
	 * @param int[] $data    Data codewords.
	 * @param int   $version Version.
	 * @param int   $ecc     Level.
	 * @return int[]
	 */
	private static function add_ecc_and_interleave( array $data, int $version, int $ecc ): array {
		$blocks_count = self::BLOCKS[ $ecc ][ $version ];
		$ecc_len      = self::ECC_PER_BLOCK[ $ecc ][ $version ];
		$raw          = intdiv( self::raw_data_modules( $version ), 8 );
		$short_blocks = $blocks_count - $raw % $blocks_count;
		$short_len    = intdiv( $raw, $blocks_count );
		$blocks       = array();
		$offset       = 0;
		for ( $i = 0; $i < $blocks_count; $i++ ) {
			$take    = $short_len - $ecc_len + ( $i < $short_blocks ? 0 : 1 );
			$chunk   = array_slice( $data, $offset, $take );
			$offset += $take;
			$check   = self::reed_solomon( $chunk, $ecc_len );
			if ( $i < $short_blocks ) {
				$chunk[] = 0;
			}
			$blocks[] = array_merge( $chunk, $check );
		}

		$result = array();
		$width  = count( $blocks[0] );
		for ( $i = 0; $i < $width; $i++ ) {
			foreach ( $blocks as $j => $block ) {
				if ( $i !== $short_len - $ecc_len || $j >= $short_blocks ) {
					$result[] = $block[ $i ];
				}
			}
		}

		return $result;
	}

	/**
	 * Finder, separator, timing and alignment patterns; reserves format and version areas.
	 */
	private function draw_function_patterns(): void {
		for ( $i = 0; $i < $this->size; $i++ ) {
			$this->set_function( 6, $i, 0 === $i % 2 );
			$this->set_function( $i, 6, 0 === $i % 2 );
		}

		$this->draw_finder( 3, 3 );
		$this->draw_finder( $this->size - 4, 3 );
		$this->draw_finder( 3, $this->size - 4 );

		$positions = $this->alignment_positions();
		$count     = count( $positions );
		foreach ( $positions as $i => $px ) {
			foreach ( $positions as $j => $py ) {
				$corner = ( 0 === $i && 0 === $j ) || ( 0 === $i && $count - 1 === $j ) || ( $count - 1 === $i && 0 === $j );
				if ( ! $corner ) {
					$this->draw_alignment( $px, $py );
				}
			}
		}

		$this->draw_format_bits( 0 );
		$this->draw_version();
	}

	/**
	 * Centre coordinates of alignment patterns.
	 *
	 * @return int[]
	 */
	private function alignment_positions(): array {
		if ( 1 === $this->version ) {
			return array();
		}
		$count  = intdiv( $this->version, 7 ) + 2;
		$step   = intdiv( $this->version * 8 + $count * 3 + 5, $count * 4 - 4 ) * 2;
		$result = array( 6 );
		for ( $i = 1, $pos = $this->size - 7; $i < $count; $i++, $pos -= $step ) {
			array_splice( $result, 1, 0, array( $pos ) );
		}

		return $result;
	}

	/**
	 * Draws a finder pattern and its separator centred at (x, y).
	 *
	 * @param int $x Centre column.
	 * @param int $y Centre row.
	 */
	private function draw_finder( int $x, int $y ): void {
		for ( $dy = -4; $dy <= 4; $dy++ ) {
			for ( $dx = -4; $dx <= 4; $dx++ ) {
				$xx = $x + $dx;
				$yy = $y + $dy;
				if ( $xx >= 0 && $xx < $this->size && $yy >= 0 && $yy < $this->size ) {
					$distance = max( abs( $dx ), abs( $dy ) );
					$this->set_function( $xx, $yy, 2 !== $distance && 4 !== $distance );
				}
			}
		}
	}

	/**
	 * Draws a 5x5 alignment pattern centred at (x, y).
	 *
	 * @param int $x Centre column.
	 * @param int $y Centre row.
	 */
	private function draw_alignment( int $x, int $y ): void {
		for ( $dy = -2; $dy <= 2; $dy++ ) {
			for ( $dx = -2; $dx <= 2; $dx++ ) {
				$ring = max( abs( $dx ), abs( $dy ) );
				$this->set_function( $x + $dx, $y + $dy, 1 !== $ring );
			}
		}
	}

	/**
	 * Draws both copies of the 15-bit format information for a mask.
	 *
	 * @param int $mask Mask 0..7.
	 */
	private function draw_format_bits( int $mask ): void {
		$data = ( self::FORMAT_BITS[ $this->ecc ] << 3 ) | $mask;
		$rem  = $data;
		for ( $i = 0; $i < 10; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 9 ) * 0x537 );
		}
		$bits = ( ( $data << 10 ) | $rem ) ^ 0x5412;

		for ( $i = 0; $i <= 5; $i++ ) {
			$this->set_function( 8, $i, self::bit( $bits, $i ) );
		}
		$this->set_function( 8, 7, self::bit( $bits, 6 ) );
		$this->set_function( 8, 8, self::bit( $bits, 7 ) );
		$this->set_function( 7, 8, self::bit( $bits, 8 ) );
		for ( $i = 9; $i < 15; $i++ ) {
			$this->set_function( 14 - $i, 8, self::bit( $bits, $i ) );
		}

		for ( $i = 0; $i < 8; $i++ ) {
			$this->set_function( $this->size - 1 - $i, 8, self::bit( $bits, $i ) );
		}
		for ( $i = 8; $i < 15; $i++ ) {
			$this->set_function( 8, $this->size - 15 + $i, self::bit( $bits, $i ) );
		}
		$this->set_function( 8, $this->size - 8, true );
	}

	/**
	 * Draws the two 18-bit version blocks (version 7 and up).
	 */
	private function draw_version(): void {
		if ( $this->version < 7 ) {
			return;
		}
		$rem = $this->version;
		for ( $i = 0; $i < 12; $i++ ) {
			$rem = ( $rem << 1 ) ^ ( ( $rem >> 11 ) * 0x1F25 );
		}
		$bits = ( $this->version << 12 ) | $rem;
		for ( $i = 0; $i < 18; $i++ ) {
			$dark = self::bit( $bits, $i );
			$a    = $this->size - 11 + $i % 3;
			$b    = intdiv( $i, 3 );
			$this->set_function( $a, $b, $dark );
			$this->set_function( $b, $a, $dark );
		}
	}

	/**
	 * Places data and ECC bits in the zigzag order, skipping function modules.
	 *
	 * @param int[] $codewords Interleaved codewords.
	 */
	private function draw_codewords( array $codewords ): void {
		$total = count( $codewords ) * 8;
		$index = 0;
		for ( $right = $this->size - 1; $right >= 1; $right -= 2 ) {
			if ( 6 === $right ) {
				$right = 5;
			}
			for ( $vert = 0; $vert < $this->size; $vert++ ) {
				for ( $j = 0; $j < 2; $j++ ) {
					$x      = $right - $j;
					$upward = 0 === ( ( $right + 1 ) & 2 );
					$y      = $upward ? $this->size - 1 - $vert : $vert;
					if ( ! $this->is_function[ $y ][ $x ] && $index < $total ) {
						$this->modules[ $y ][ $x ] = self::bit( $codewords[ $index >> 3 ], 7 - ( $index & 7 ) );
						++$index;
					}
				}
			}
		}
	}

	/**
	 * XORs a mask pattern over the data modules (applying twice undoes it).
	 *
	 * @param int $mask Mask 0..7.
	 */
	private function apply_mask( int $mask ): void {
		for ( $y = 0; $y < $this->size; $y++ ) {
			for ( $x = 0; $x < $this->size; $x++ ) {
				if ( $this->is_function[ $y ][ $x ] ) {
					continue;
				}
				switch ( $mask ) {
					case 0:
						$invert = 0 === ( $x + $y ) % 2;
						break;
					case 1:
						$invert = 0 === $y % 2;
						break;
					case 2:
						$invert = 0 === $x % 3;
						break;
					case 3:
						$invert = 0 === ( $x + $y ) % 3;
						break;
					case 4:
						$invert = 0 === ( intdiv( $x, 3 ) + intdiv( $y, 2 ) ) % 2;
						break;
					case 5:
						$product = $x * $y;
						$invert  = 0 === $product % 2 + $product % 3;
						break;
					case 6:
						$invert = 0 === ( ( $x * $y ) % 2 + ( $x * $y ) % 3 ) % 2;
						break;
					default:
						$invert = 0 === ( ( $x + $y ) % 2 + ( $x * $y ) % 3 ) % 2;
				}
				if ( $invert ) {
					$this->modules[ $y ][ $x ] = ! $this->modules[ $y ][ $x ];
				}
			}
		}
	}

	/**
	 * Penalty score (ISO/IEC 18004 section 7.8.3): runs, 2x2 blocks, finder-like
	 * patterns and dark/light balance.
	 */
	private function penalty(): int {
		$score = 0;
		$size  = $this->size;
		$lines = array();
		for ( $i = 0; $i < $size; $i++ ) {
			$row = '';
			$col = '';
			for ( $j = 0; $j < $size; $j++ ) {
				$row .= $this->modules[ $i ][ $j ] ? '1' : '0';
				$col .= $this->modules[ $j ][ $i ] ? '1' : '0';
			}
			$lines[] = $row;
			$lines[] = $col;
		}
		foreach ( $lines as $line ) {
			// Rule 1: runs of five or more.
			preg_match_all( '/0{5,}|1{5,}/', $line, $runs );
			foreach ( $runs[0] as $run ) {
				$score += 3 + strlen( $run ) - 5;
			}
			// Rule 3: finder-like 1011101 with four light modules on either side.
			$padded = '0000' . $line . '0000';
			$score += 40 * ( substr_count( $padded, '00001011101' ) + substr_count( $padded, '10111010000' ) );
		}
		$dark = 0;
		for ( $y = 0; $y < $size; $y++ ) {
			for ( $x = 0; $x < $size; $x++ ) {
				$color = $this->modules[ $y ][ $x ];
				$dark += $color ? 1 : 0;
				// Rule 2: 2x2 blocks of one colour.
				if ( $x < $size - 1 && $y < $size - 1
					&& $color === $this->modules[ $y ][ $x + 1 ]
					&& $color === $this->modules[ $y + 1 ][ $x ]
					&& $color === $this->modules[ $y + 1 ][ $x + 1 ] ) {
					$score += 3;
				}
			}
		}
		// Rule 4: distance of the dark ratio from 50 %, in 5 % steps.
		$score += 10 * intdiv( abs( $dark * 100 - $size * $size * 50 ), $size * $size * 5 );

		return $score;
	}

	/**
	 * Sets a function module.
	 *
	 * @param int  $x    Column.
	 * @param int  $y    Row.
	 * @param bool $dark Colour.
	 */
	private function set_function( int $x, int $y, bool $dark ): void {
		$this->modules[ $y ][ $x ]     = $dark;
		$this->is_function[ $y ][ $x ] = true;
	}

	/**
	 * Appends $length bits of $value, most significant first.
	 *
	 * @param int[] $bits   Bit buffer.
	 * @param int   $value  Value.
	 * @param int   $length Bit count.
	 */
	private static function append_bits( array &$bits, int $value, int $length ): void {
		for ( $i = $length - 1; $i >= 0; $i-- ) {
			$bits[] = ( $value >> $i ) & 1;
		}
	}

	/**
	 * Bit $i of $value.
	 *
	 * @param int $value Value.
	 * @param int $i     Bit index.
	 */
	private static function bit( int $value, int $i ): bool {
		return 0 !== ( ( $value >> $i ) & 1 );
	}
}
