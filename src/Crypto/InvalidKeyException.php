<?php
/**
 * Thrown when encryption key material is missing or malformed.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * Invalid or missing key.
 */
final class InvalidKeyException extends \RuntimeException {
}
