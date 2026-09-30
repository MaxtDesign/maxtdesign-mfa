<?php
/**
 * A credential that passed registration.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Registration result.
 */
final class RegisteredCredential {

	/**
	 * Constructor.
	 *
	 * @param string $id         Credential ID (raw).
	 * @param string $public_key COSE key bytes.
	 * @param int    $alg        COSE algorithm.
	 * @param int    $sign_count Initial counter.
	 * @param string $aaguid     AAGUID (16 bytes).
	 * @param bool   $be         Backup eligible.
	 * @param bool   $bs         Backed up.
	 * @param bool   $uv         User verified during registration.
	 */
	public function __construct(
		public readonly string $id,
		public readonly string $public_key,
		public readonly int $alg,
		public readonly int $sign_count,
		public readonly string $aaguid,
		public readonly bool $be,
		public readonly bool $bs,
		public readonly bool $uv
	) {
	}
}
