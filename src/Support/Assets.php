<?php
/**
 * The plugin's only front-end asset (plan section 9): mdmfa-passkey.js, deferred, in the
 * footer, enqueued only while rendering a screen that offers a passkey.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Asset loading.
 */
final class Assets {

	public const PASSKEY_HANDLE = 'mdmfa-passkey';

	/**
	 * Enqueues the passkey module. Call while rendering a passkey control; footer scripts
	 * print later on the login screen, the front end and admin alike.
	 */
	public static function passkey(): void {
		wp_enqueue_script(
			self::PASSKEY_HANDLE,
			plugins_url( 'assets/front/mdmfa-passkey.js', MDMFA_FILE ),
			array(),
			MDMFA_VERSION,
			array(
				'strategy'  => 'defer',
				'in_footer' => true,
			)
		);
	}
}
