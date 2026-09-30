<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Factors;

use MaxtDesign\Mfa\Factors\RecoveryCodes;
use PHPUnit\Framework\TestCase;

final class RecoveryCodesTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_generates_ten_unique_80_bit_codes_stored_only_as_hashes(): void {
		$codes = RecoveryCodes::generate( 7 );

		self::assertCount( 10, $codes );
		self::assertCount( 10, array_unique( $codes ) );
		foreach ( $codes as $code ) {
			self::assertMatchesRegularExpression( '/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/', $code );
		}
		$stored = serialize( $GLOBALS['mdmfa_test']['usermeta'][7][ RecoveryCodes::META ] );
		foreach ( $codes as $code ) {
			self::assertStringNotContainsString( str_replace( '-', '', $code ), $stored, 'plaintext must never be stored' );
		}
		self::assertSame( 10, RecoveryCodes::remaining( 7 ) );
	}

	public function test_a_code_works_once_and_input_is_normalised(): void {
		$codes = RecoveryCodes::generate( 7 );
		$typed = strtolower( str_replace( '-', ' ', $codes[3] ) );

		self::assertSame( 9, RecoveryCodes::consume( 7, $typed ) );
		self::assertNull( RecoveryCodes::consume( 7, $codes[3] ), 'a used code must fail' );
		self::assertSame( 8, RecoveryCodes::consume( 7, $codes[0] ) );
		self::assertSame( 8, RecoveryCodes::remaining( 7 ) );
	}

	public function test_wrong_or_malformed_codes_fail(): void {
		RecoveryCodes::generate( 7 );

		self::assertNull( RecoveryCodes::consume( 7, 'AAAA-AAAA-AAAA-AAAA' ) );
		self::assertNull( RecoveryCodes::consume( 7, 'short' ) );
		self::assertNull( RecoveryCodes::consume( 7, '' ) );
		self::assertSame( 10, RecoveryCodes::remaining( 7 ) );
	}

	public function test_concurrent_spend_loses_the_compare_and_swap(): void {
		$codes = RecoveryCodes::generate( 7 );
		// Another request already changed the row between our read and our write.
		$GLOBALS['wpdb'] = new class() extends \wpdb {
			public function update( string $table, array $data, array $where, mixed $format = null, mixed $where_format = null ): int {
				return 0;
			}
		};

		self::assertNull( RecoveryCodes::consume( 7, $codes[0] ) );
	}

	public function test_regenerating_invalidates_the_old_set(): void {
		$old = RecoveryCodes::generate( 7 );
		RecoveryCodes::generate( 7 );

		self::assertNull( RecoveryCodes::consume( 7, $old[0] ) );
	}

	public function test_user_without_codes(): void {
		self::assertSame( 0, RecoveryCodes::remaining( 9 ) );
		self::assertNull( RecoveryCodes::consume( 9, 'AAAA-AAAA-AAAA-AAAA' ) );
	}
}
