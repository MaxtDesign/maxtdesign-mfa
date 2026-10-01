<?php
/**
 * An assertion that passed verification.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Assertion result.
 */
final class AssertionResult {

	/**
	 * Constructor.
	 *
	 * @param int  $sign_count New counter to store.
	 * @param bool $anomaly    Counter did not grow (possible cloned authenticator).
	 * @param bool $uv         User verified.
	 * @param bool $bs         Backed up (BS can change after registration).
	 */
	public function __construct(
		public readonly int $sign_count,
		public readonly bool $anomaly,
		public readonly bool $uv,
		public readonly bool $bs
	) {
	}
}
