<?php
/**
 * Ordered CBOR map for tests.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Support;

// phpcs:ignoreFile

/**
 * A map with explicit key order and possibly duplicate or mixed keys (for negative tests).
 */
final class CborMap {
	/** @param array<int, array{mixed, mixed}> $pairs */
	public function __construct( public array $pairs ) {
	}
}
