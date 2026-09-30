<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit;

use MaxtDesign\Mfa\Plugin;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

final class PluginTest extends TestCase {

	protected function setUp(): void {
		mdmfa_test_reset();
	}

	public function test_manage_cap_maps_to_manage_options(): void {
		self::assertSame( array( 'manage_options' ), Plugin::map_meta_cap( array( 'do_not_allow' ), Plugin::MANAGE_CAP ) );
	}

	public function test_manage_cap_maps_to_network_cap_in_network_admin(): void {
		$GLOBALS['mdmfa_test']['network'] = true;

		self::assertSame( array( 'manage_network_options' ), Plugin::map_meta_cap( array(), Plugin::MANAGE_CAP ) );
	}

	public function test_manage_cap_is_filterable_but_never_empty(): void {
		add_filter( 'mdmfa_manage_capability', static fn (): string => 'edit_users' );
		self::assertSame( array( 'edit_users' ), Plugin::map_meta_cap( array(), Plugin::MANAGE_CAP ) );

		mdmfa_test_reset();
		add_filter( 'mdmfa_manage_capability', static fn (): string => '' );
		self::assertSame( array( 'manage_options' ), Plugin::map_meta_cap( array(), Plugin::MANAGE_CAP ) );
	}

	public function test_other_caps_pass_through(): void {
		self::assertSame( array( 'edit_posts' ), Plugin::map_meta_cap( array( 'edit_posts' ), 'edit_post' ) );
	}

	public function test_not_disabled_by_default(): void {
		self::assertFalse( Plugin::is_disabled() );
	}

	#[RunInSeparateProcess]
	public function test_disable_constant_turns_the_plugin_off(): void {
		define( 'MDMFA_DISABLE', true );

		self::assertTrue( Plugin::is_disabled() );
	}
}
