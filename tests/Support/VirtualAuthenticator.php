<?php
/**
 * A software authenticator for tests: real ES256 / RS256 / Ed25519 keys, and the exact
 * bytes a browser would post for create() and get(). Knobs allow every negative case.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Support;

use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\WebAuthn\ByteString;

// phpcs:ignoreFile

final class VirtualAuthenticator {

	public string $credential_id;
	public string $user_handle = '';
	public int $counter        = 0;
	public bool $counts        = false;
	public bool $backup_eligible = true;
	public bool $backed_up       = true;

	private mixed $private;
	private string $cose;

	public function __construct( public readonly int $alg = -7 ) {
		$this->credential_id = random_bytes( 32 );
		if ( -7 === $alg ) {
			$key           = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
			$details       = openssl_pkey_get_details( $key );
			$this->private = $key;
			$this->cose    = CborEncoder::encode(
				new CborMap(
					array(
						array( 1, 2 ),
						array( 3, -7 ),
						array( -1, 1 ),
						array( -2, new ByteString( str_pad( $details['ec']['x'], 32, "\0", STR_PAD_LEFT ) ) ),
						array( -3, new ByteString( str_pad( $details['ec']['y'], 32, "\0", STR_PAD_LEFT ) ) ),
					)
				)
			);
		} elseif ( -257 === $alg ) {
			$key           = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048 ) );
			$details       = openssl_pkey_get_details( $key );
			$this->private = $key;
			$this->cose    = CborEncoder::encode(
				new CborMap(
					array(
						array( 1, 3 ),
						array( 3, -257 ),
						array( -1, new ByteString( $details['rsa']['n'] ) ),
						array( -2, new ByteString( $details['rsa']['e'] ) ),
					)
				)
			);
		} else {
			$pair          = sodium_crypto_sign_keypair();
			$this->private = sodium_crypto_sign_secretkey( $pair );
			$this->cose    = CborEncoder::encode(
				new CborMap(
					array(
						array( 1, 1 ),
						array( 3, -8 ),
						array( -1, 6 ),
						array( -2, new ByteString( sodium_crypto_sign_publickey( $pair ) ) ),
					)
				)
			);
		}
	}

	public function cose(): string {
		return $this->cose;
	}

	/**
	 * Registration response JSON.
	 *
	 * @param array<string, mixed> $options Creation options as the server sent them.
	 * @param array<string, mixed> $knobs   Negative-test overrides.
	 */
	public function create( array $options, string $origin, array $knobs = array() ): string {
		$rp_id = $knobs['rp_id'] ?? $options['rp']['id'];
		$this->user_handle = (string) Base64Url::decode( $options['user']['id'] );
		$client = $this->client_data( 'webauthn.create', $options['challenge'], $origin, $knobs );
		$flags  = $this->flags( $knobs, true );
		$auth   = hash( 'sha256', $rp_id, true ) . chr( $flags ) . pack( 'N', $this->counter )
			. str_repeat( "\0", 16 ) . pack( 'n', strlen( $this->credential_id ) ) . $this->credential_id
			. ( $knobs['cose'] ?? $this->cose ) . ( $knobs['auth_trailing'] ?? '' );
		$att    = CborEncoder::encode(
			array(
				'fmt'      => $knobs['fmt'] ?? 'none',
				'attStmt'  => array(),
				'authData' => new ByteString( $auth ),
			)
		) . ( $knobs['att_trailing'] ?? '' );

		return json_encode(
			array(
				'id'       => Base64Url::encode( $this->credential_id ),
				'rawId'    => Base64Url::encode( $this->credential_id ),
				'type'     => 'public-key',
				'response' => array(
					'clientDataJSON'    => Base64Url::encode( $client ),
					'attestationObject' => Base64Url::encode( $att ),
					'transports'        => array( 'internal', 'hybrid' ),
				),
			)
		);
	}

	/**
	 * Assertion response JSON.
	 *
	 * @param array<string, mixed> $options Request options as the server sent them.
	 * @param array<string, mixed> $knobs   Negative-test overrides.
	 */
	public function get( array $options, string $origin, array $knobs = array() ): string {
		$rp_id  = $knobs['rp_id'] ?? $options['rpId'];
		$client = $this->client_data( 'webauthn.get', $options['challenge'], $origin, $knobs );
		if ( $this->counts ) {
			++$this->counter;
		}
		$count  = $knobs['counter'] ?? $this->counter;
		$auth   = hash( 'sha256', $rp_id, true ) . chr( $this->flags( $knobs, false ) ) . pack( 'N', $count ) . ( $knobs['auth_trailing'] ?? '' );
		$signed = $auth . hash( 'sha256', $client, true );
		$sig    = $this->sign( $signed );
		if ( ! empty( $knobs['tamper_signature'] ) ) {
			$sig[ strlen( $sig ) - 1 ] = chr( ord( $sig[ strlen( $sig ) - 1 ] ) ^ 1 );
		}

		return json_encode(
			array(
				'id'       => Base64Url::encode( $this->credential_id ),
				'rawId'    => Base64Url::encode( $this->credential_id ),
				'type'     => 'public-key',
				'response' => array(
					'clientDataJSON'    => Base64Url::encode( $client ),
					'authenticatorData' => Base64Url::encode( $auth ),
					'signature'         => Base64Url::encode( $sig ),
					'userHandle'        => array_key_exists( 'user_handle', $knobs ) ? ( null === $knobs['user_handle'] ? null : Base64Url::encode( $knobs['user_handle'] ) ) : Base64Url::encode( $this->user_handle ),
				),
			)
		);
	}

	public function sign( string $data ): string {
		if ( -8 === $this->alg ) {
			return sodium_crypto_sign_detached( $data, $this->private );
		}
		openssl_sign( $data, $signature, $this->private, OPENSSL_ALGO_SHA256 );
		return $signature;
	}

	private function client_data( string $type, string $challenge, string $origin, array $knobs ): string {
		$data = array(
			'type'        => $knobs['type'] ?? $type,
			'challenge'   => $knobs['challenge'] ?? $challenge,
			'origin'      => $knobs['origin'] ?? $origin,
			'crossOrigin' => $knobs['cross_origin'] ?? false,
		);
		return $knobs['client_json'] ?? json_encode( $data, JSON_UNESCAPED_SLASHES );
	}

	private function flags( array $knobs, bool $attested ): int {
		if ( isset( $knobs['flags'] ) ) {
			return $knobs['flags'];
		}
		$flags = 0x01; // UP.
		if ( $knobs['uv'] ?? true ) {
			$flags |= 0x04;
		}
		if ( $this->backup_eligible ) {
			$flags |= 0x08;
		}
		if ( $this->backed_up ) {
			$flags |= 0x10;
		}
		if ( $attested ) {
			$flags |= 0x40;
		}
		return $flags;
	}
}
