<?php
/**
 * Encryption key resolution (plan 6.5).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the 32-byte key used to encrypt TOTP secrets.
 *
 * Precedence: MDMFA_ENCRYPTION_KEY (base64, 32 bytes) -> HKDF-SHA256 over the AUTH_KEY
 * and SECURE_AUTH_KEY constants -> HKDF over the salts core keeps in the database when
 * those constants are missing. The last source gives no protection against a database
 * dump; the key source is reported so the admin screen can warn about it.
 */
final class KeyProvider {

	public const SOURCE_CONSTANT = 'constant';
	public const SOURCE_SALTS    = 'salts';
	public const SOURCE_DB       = 'db';

	public const HKDF_INFO = 'mdmfa-totp-v1';

	/**
	 * Core's placeholder for unset salts (wp-config-sample.php; wp_salt() rejects it too).
	 */
	private const PLACEHOLDER = 'put your unique phrase here';

	/**
	 * Raw key bytes.
	 *
	 * @var string
	 */
	private string $key;

	/**
	 * One of the SOURCE_* constants.
	 *
	 * @var string
	 */
	private string $source;

	/**
	 * Constructor.
	 *
	 * @param string $key    Raw 32-byte key.
	 * @param string $source One of the SOURCE_* constants.
	 * @throws InvalidKeyException When the key is not 32 bytes.
	 */
	private function __construct( string $key, string $source ) {
		if ( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES !== strlen( $key ) ) {
			throw new InvalidKeyException( 'Encryption key must be 32 bytes.' );
		}
		$this->key    = $key;
		$this->source = $source;
	}

	/**
	 * Key from the running site's configuration.
	 *
	 * @throws InvalidKeyException When MDMFA_ENCRYPTION_KEY is defined but malformed. There
	 *                             is deliberately no silent fallback to the salts.
	 */
	public static function from_environment(): self {
		if ( defined( 'MDMFA_ENCRYPTION_KEY' ) ) {
			return self::from_base64( (string) constant( 'MDMFA_ENCRYPTION_KEY' ) );
		}

		$auth   = defined( 'AUTH_KEY' ) ? (string) constant( 'AUTH_KEY' ) : '';
		$secure = defined( 'SECURE_AUTH_KEY' ) ? (string) constant( 'SECURE_AUTH_KEY' ) : '';
		if ( self::usable_salt( $auth ) && self::usable_salt( $secure ) ) {
			return self::derive( $auth . $secure, self::SOURCE_SALTS );
		}

		return self::derive( wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), self::SOURCE_DB );
	}

	/**
	 * Key from a base64 string, the MDMFA_ENCRYPTION_KEY format.
	 *
	 * @param string $encoded Base64 of 32 random bytes.
	 * @throws InvalidKeyException When the value is not base64 of exactly 32 bytes.
	 */
	public static function from_base64( string $encoded ): self {
		try {
			$raw = sodium_base642bin( trim( $encoded ), SODIUM_BASE64_VARIANT_ORIGINAL );
		} catch ( \SodiumException $e ) {
			throw new InvalidKeyException( 'MDMFA_ENCRYPTION_KEY is not valid base64.' );
		}

		return new self( $raw, self::SOURCE_CONSTANT );
	}

	/**
	 * Key derived from secret input keying material with HKDF-SHA256.
	 *
	 * @param string $ikm    Input keying material.
	 * @param string $source One of the SOURCE_* constants, recorded for reporting.
	 * @throws InvalidKeyException When the material is empty.
	 */
	public static function derive( string $ikm, string $source ): self {
		if ( '' === $ikm ) {
			throw new InvalidKeyException( 'No key material available.' );
		}

		return new self( hash_hkdf( 'sha256', $ikm, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, self::HKDF_INFO ), $source );
	}

	/**
	 * Raw key bytes. Never log, render or store this value.
	 */
	public function key(): string {
		return $this->key;
	}

	/**
	 * Where the key came from.
	 */
	public function source(): string {
		return $this->source;
	}

	/**
	 * Key id: hex of the first 8 bytes of sha256(key). Stored beside each ciphertext.
	 */
	public function kid(): string {
		return bin2hex( substr( hash( 'sha256', $this->key, true ), 0, 8 ) );
	}

	/**
	 * Whether a salt constant holds a real value.
	 *
	 * @param string $salt Constant value.
	 */
	private static function usable_salt( string $salt ): bool {
		return '' !== $salt && self::PLACEHOLDER !== $salt;
	}
}
