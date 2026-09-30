<?php
/**
 * Options sent to navigator.credentials.create() / get(), as JSON with base64url binary
 * fields (the browser module converts them). The UV requirement comes from policy.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

use MaxtDesign\Mfa\Support\Base64Url;

defined( 'ABSPATH' ) || exit;

/**
 * Options builders.
 */
final class Options {

	public const TIMEOUT = 120000;

	/**
	 * Creation options.
	 *
	 * @param string                                              $challenge    Raw challenge.
	 * @param string                                              $user_handle  Raw user handle (never the user ID).
	 * @param string                                              $user_name    Account name shown by the authenticator.
	 * @param string                                              $display_name Display name.
	 * @param array<int, array{id: string, transports: string[]}> $exclude Existing credentials (raw IDs).
	 * @param bool                                                $discoverable Ask for a discoverable credential (passwordless).
	 * @return array<string, mixed>
	 */
	public static function creation( string $challenge, string $user_handle, string $user_name, string $display_name, array $exclude, bool $discoverable ): array {
		return array(
			'rp'                     => array(
				'id'   => RelyingParty::id(),
				'name' => RelyingParty::name(),
			),
			'user'                   => array(
				'id'          => Base64Url::encode( $user_handle ),
				'name'        => $user_name,
				'displayName' => '' !== $display_name ? $display_name : $user_name,
			),
			'challenge'              => Base64Url::encode( $challenge ),
			'pubKeyCredParams'       => array_map(
				static fn ( int $alg ): array => array(
					'type' => 'public-key',
					'alg'  => $alg,
				),
				CoseKey::SUPPORTED
			),
			'timeout'                => self::TIMEOUT,
			'attestation'            => 'none',
			'excludeCredentials'     => self::descriptors( $exclude ),
			'authenticatorSelection' => array(
				'residentKey'        => $discoverable ? 'required' : 'preferred',
				'requireResidentKey' => $discoverable,
				'userVerification'   => $discoverable ? 'required' : 'preferred',
			),
		);
	}

	/**
	 * Request options. An empty allow list means a discoverable (usernameless) request.
	 *
	 * @param string                                              $challenge  Raw challenge.
	 * @param array<int, array{id: string, transports: string[]}> $allow      Allowed credentials (raw IDs).
	 * @param bool                                                $require_uv Require user verification.
	 * @return array<string, mixed>
	 */
	public static function request( string $challenge, array $allow, bool $require_uv ): array {
		return array(
			'challenge'        => Base64Url::encode( $challenge ),
			'rpId'             => RelyingParty::id(),
			'timeout'          => self::TIMEOUT,
			'allowCredentials' => self::descriptors( $allow ),
			'userVerification' => $require_uv ? 'required' : 'preferred',
		);
	}

	/**
	 * Credential descriptors.
	 *
	 * @param array<int, array{id: string, transports: string[]}> $credentials Raw IDs and transports.
	 * @return array<int, array<string, mixed>>
	 */
	private static function descriptors( array $credentials ): array {
		$out = array();
		foreach ( $credentials as $credential ) {
			$descriptor = array(
				'type' => 'public-key',
				'id'   => Base64Url::encode( $credential['id'] ),
			);
			if ( array() !== $credential['transports'] ) {
				$descriptor['transports'] = $credential['transports'];
			}
			$out[] = $descriptor;
		}

		return $out;
	}
}
