<?php
/**
 * Every rejection by the WebAuthn verifier. The message is for logs and tests; users see
 * a generic failure.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Verification failure.
 */
final class VerificationException extends \RuntimeException {
}
