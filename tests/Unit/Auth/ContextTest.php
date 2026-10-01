<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Auth;

use MaxtDesign\Mfa\Auth\Context;
use PHPUnit\Framework\TestCase;

final class ContextTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
		Context::reset();
	}

	protected function tearDown(): void {
		Context::reset();
	}

	public function test_the_application_password_exemption_belongs_to_the_user_it_authenticated(): void {
		$attacker = new \WP_User( 11, array( 'subscriber' ) );
		$victim   = new \WP_User( 12, array( 'administrator' ) );

		self::assertNotSame( Context::APPPASS, Context::detect( $victim->ID ) );

		// The attacker's own application password authenticates them in this request...
		Context::mark_apppass( $attacker );

		self::assertSame( Context::APPPASS, Context::detect( $attacker->ID ) );
		// ...and that says nothing about the victim, whose account password comes next
		// (XML-RPC body, system.multicall, a REST token endpoint).
		self::assertNotSame( Context::APPPASS, Context::detect( $victim->ID ), 'another user\'s password in the same request is a password login' );
		self::assertNotSame( Context::APPPASS, Context::detect(), 'no user, no exemption' );
	}

	public function test_a_malformed_hook_argument_grants_nothing(): void {
		Context::mark_apppass( null );
		Context::mark_apppass( 12 );

		self::assertNotSame( Context::APPPASS, Context::detect( 12 ) );
	}
}
