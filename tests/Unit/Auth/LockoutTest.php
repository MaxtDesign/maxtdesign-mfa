<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Support\Clock;
use PHPUnit\Framework\TestCase;

final class LockoutTest extends TestCase {

	private const T0 = 1800000000;

	protected function setUp(): void {
		mdmfa_test_reset();
		new \WP_User( 5, array( 'administrator' ) );
		Clock::freeze( self::T0 );
	}

	private function fail_times( int $n ): void {
		for ( $i = 0; $i < $n; $i++ ) {
			Lockout::record_failure( 5 );
		}
	}

	public function test_first_four_failures_do_not_block(): void {
		$this->fail_times( 4 );

		self::assertSame( 0, Lockout::blocked_until( 5 ) );
	}

	public function test_backoff_starts_at_the_fifth_failure_and_doubles(): void {
		$this->fail_times( 5 );
		self::assertSame( self::T0 + 30, Lockout::blocked_until( 5 ) );

		Clock::freeze( self::T0 + 31 );
		self::assertSame( 0, Lockout::blocked_until( 5 ) );
		Lockout::record_failure( 5 );
		self::assertSame( self::T0 + 31 + 60, Lockout::blocked_until( 5 ) );
	}

	public function test_backoff_is_capped_at_fifteen_minutes(): void {
		$this->fail_times( 19 );

		self::assertSame( self::T0 + 900, Lockout::blocked_until( 5 ) );
		self::assertFalse( Lockout::is_locked( 5 ) );
	}

	public function test_twentieth_failure_locks_for_an_hour_and_notifies(): void {
		$this->fail_times( 20 );

		self::assertTrue( Lockout::is_locked( 5 ) );
		self::assertSame( self::T0 + 3600, Lockout::blocked_until( 5 ) );
		self::assertSame( 0, Lockout::state( 5 )['count'] );
		self::assertSame( 1, Lockout::state( 5 )['lock_level'] );
		self::assertContains( 'mdmfa_user_locked', array_column( $GLOBALS['mdmfa_test']['actions'], 0 ) );
		self::assertSame( array( 'user5@example.com' ), array_column( $GLOBALS['mdmfa_test']['mail'], 0 ), 'admin_email is unset in tests' );
		self::assertSame( 'locked', $GLOBALS['mdmfa_test']['inserts'][0][1]['event'] );
	}

	public function test_a_repeat_lock_lasts_a_day(): void {
		$this->fail_times( 20 );
		Clock::freeze( self::T0 + 3601 );
		$this->fail_times( 20 );

		self::assertSame( 2, Lockout::state( 5 )['lock_level'] );
		self::assertSame( self::T0 + 3601 + 86400, Lockout::blocked_until( 5 ) );
	}

	public function test_success_resets_and_unlock_clears(): void {
		$this->fail_times( 20 );
		Lockout::unlock( 5, null );
		self::assertSame( 0, Lockout::blocked_until( 5 ) );
		self::assertSame( 0, Lockout::state( 5 )['lock_level'] );

		$this->fail_times( 7 );
		Lockout::reset( 5 );
		self::assertSame( 0, Lockout::state( 5 )['count'] );
	}

	public function test_thresholds_are_filterable_and_bad_values_fall_back(): void {
		add_filter(
			'mdmfa_lockout_thresholds',
			static fn ( array $t ): array => array_merge( $t, array( 'lock_after' => 3, 'backoff_after' => 'x' ) )
		);

		$limits = Lockout::thresholds();
		self::assertSame( 3, $limits['lock_after'] );
		self::assertSame( 5, $limits['backoff_after'] );

		$this->fail_times( 3 );
		self::assertTrue( Lockout::is_locked( 5 ) );
	}
}
