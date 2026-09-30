<?php
/**
 * Authenticated encryption for secrets at rest (plan 6.5).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * XChaCha20-Poly1305 (IETF) with caller-supplied associated data. Uses ext-sodium, or
 * the sodium_compat copy WordPress core loads when the extension is missing. Base64 goes
 * through libsodium's constant-time codecs, never base64_decode().
 *
 * @phpstan-type Box array{ct: string, nonce: string, kid: string}
 */
final class SecretBox {

	/**
	 * Key in use.
	 *
	 * @var KeyProvider
	 */
	private KeyProvider $keys;

	/**
	 * Constructor.
	 *
	 * @param KeyProvider $keys Key in use.
	 */
	public function __construct( KeyProvider $keys ) {
		$this->keys = $keys;
	}

	/**
	 * Associated data for a user's TOTP secret, so a ciphertext cannot be moved to another user.
	 *
	 * @param int $user_id User ID.
	 */
	public static function totp_aad( int $user_id ): string {
		return 'mdmfa:totp:v1:' . $user_id;
	}

	/**
	 * Encrypts a secret.
	 *
	 * @param string $plaintext Secret.
	 * @param string $aad       Associated data bound to the ciphertext.
	 * @return Box Base64 ciphertext and nonce, plus the key id.
	 */
	public function encrypt( string $plaintext, string $aad ): array {
		$nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$ct    = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $plaintext, $aad, $nonce, $this->keys->key() );

		return array(
			'ct'    => sodium_bin2base64( $ct, SODIUM_BASE64_VARIANT_ORIGINAL ),
			'nonce' => sodium_bin2base64( $nonce, SODIUM_BASE64_VARIANT_ORIGINAL ),
			'kid'   => $this->keys->kid(),
		);
	}

	/**
	 * Decrypts a secret. Returns null for a different key, different associated data, a
	 * malformed box or any tampering: callers treat all of these as "unreadable".
	 *
	 * @param array<array-key, mixed> $box Output of encrypt(), as stored.
	 * @param string                  $aad Associated data used at encryption.
	 */
	public function decrypt( array $box, string $aad ): ?string {
		if ( ! isset( $box['ct'], $box['nonce'], $box['kid'] )
			|| ! is_string( $box['ct'] ) || ! is_string( $box['nonce'] ) || ! is_string( $box['kid'] ) ) {
			return null;
		}
		if ( ! hash_equals( $this->keys->kid(), $box['kid'] ) ) {
			return null;
		}

		try {
			$ct    = sodium_base642bin( $box['ct'], SODIUM_BASE64_VARIANT_ORIGINAL );
			$nonce = sodium_base642bin( $box['nonce'], SODIUM_BASE64_VARIANT_ORIGINAL );
			if ( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES !== strlen( $nonce )
				|| strlen( $ct ) < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES ) {
				return null;
			}
			$plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $ct, $aad, $nonce, $this->keys->key() );
		} catch ( \SodiumException $e ) {
			return null;
		}

		return is_string( $plain ) ? $plain : null;
	}
}
