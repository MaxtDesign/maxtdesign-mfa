<?php
/**
 * Time source. Tests freeze it; production reads time().
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Unix time.
 */
final class Clock {

	/**
	 * Frozen time for tests, or null for the real clock.
	 *
	 * @var int|null
	 */
	private static ?int $frozen = null;

	/**
	 * Current Unix time.
	 */
	public static function now(): int {
		return self::$frozen ?? time();
	}

	/**
	 * Freezes the clock (tests only). Null unfreezes.
	 *
	 * @param int|null $timestamp Unix time.
	 */
	public static function freeze( ?int $timestamp ): void {
		self::$frozen = $timestamp;
	}
}
