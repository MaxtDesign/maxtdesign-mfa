<?php
/**
 * A CBOR byte string (major type 2), kept distinct from text strings (major type 3).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Binary value.
 */
final class ByteString {

	/**
	 * Constructor.
	 *
	 * @param string $bytes Raw bytes.
	 */
	public function __construct( public readonly string $bytes ) {
	}
}
