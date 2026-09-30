<?php
/**
 * Markup shared by the login screens and My security. Server-rendered, core classes only.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Screens;

use MaxtDesign\Mfa\Factors\Totp;
use MaxtDesign\Mfa\Qr\QrSvg;
use MaxtDesign\Mfa\Support\Base32;

defined( 'ABSPATH' ) || exit;

/**
 * HTML fragments. Every dynamic value is escaped here.
 */
final class Fragments {

	/**
	 * QR code plus the secret as grouped text, for authenticator setup.
	 *
	 * @param string   $secret Raw TOTP secret.
	 * @param \WP_User $user   Account being enrolled.
	 */
	public static function totp_setup( string $secret, \WP_User $user ): string {
		$issuer  = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
		$issuer  = '' !== trim( $issuer ) ? $issuer : (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$uri     = Totp::uri( $secret, $issuer, $user->user_login );
		$svg     = QrSvg::render( $uri, __( 'QR code for your authenticator app', 'maxtdesign-mfa' ) );
		$grouped = implode( ' ', str_split( Base32::encode( $secret ), 4 ) );

		$html = '<p>' . esc_html__( 'Scan this code with an authenticator app (for example Google Authenticator, Microsoft Authenticator, 1Password or Bitwarden).', 'maxtdesign-mfa' ) . '</p>';
		if ( '' !== $svg ) {
			// The SVG is generated locally from numbers and an esc_attr() label (QrSvg).
			$html .= '<p class="mdmfa-qr">' . $svg . '</p>';
		}
		$html .= '<p>' . esc_html__( 'Or enter this key by hand:', 'maxtdesign-mfa' ) . '<br><code class="mdmfa-secret">' . esc_html( $grouped ) . '</code></p>';

		return $html;
	}

	/**
	 * Recovery codes, shown once.
	 *
	 * @param string[] $codes Plaintext codes.
	 */
	public static function recovery_codes( array $codes ): string {
		$items = '';
		foreach ( $codes as $code ) {
			$items .= '<li><code>' . esc_html( $code ) . '</code></li>';
		}

		return '<p><strong>' . esc_html__( 'Save your recovery codes now.', 'maxtdesign-mfa' ) . '</strong> '
			. esc_html__( 'Each code works once, if you lose access to your authenticator app. They will not be shown again.', 'maxtdesign-mfa' ) . '</p>'
			. '<ol class="mdmfa-recovery-codes">' . $items . '</ol>';
	}

	/**
	 * A one-time-code input.
	 *
	 * @param string $id        Field id and name.
	 * @param string $label     Visible label.
	 * @param bool   $recovery  Recovery-code field (longer, not numeric).
	 * @param string $css_class Input class.
	 * @param string $row_class Wrapper paragraph class.
	 */
	public static function code_field( string $id, string $label, bool $recovery = false, string $css_class = 'input', string $row_class = '' ): string {
		$attributes = $recovery
			? 'autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="24"'
			: 'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 ]*" maxlength="8"';

		return sprintf(
			'<p%5$s><label for="%1$s">%2$s</label><input type="text" name="%1$s" id="%1$s" class="%3$s" value="" size="20" required autofocus %4$s></p>',
			esc_attr( $id ),
			esc_html( $label ),
			esc_attr( $css_class ),
			$attributes,
			'' !== $row_class ? ' class="' . esc_attr( $row_class ) . '"' : ''
		);
	}

	/**
	 * Grace-period prompt text.
	 *
	 * @param int $days Days left.
	 */
	public static function grace_message( int $days ): string {
		return sprintf(
			/* translators: %d: days left to set up two-step verification. */
			_n( 'Your account needs two-step verification. You have %d day left to set it up.', 'Your account needs two-step verification. You have %d days left to set it up.', $days, 'maxtdesign-mfa' ),
			$days
		);
	}

	/**
	 * Recovery codes on first render (or a note after), plus the "saved" checkbox.
	 *
	 * @param string[] $codes Codes to show once, or none.
	 */
	public static function recovery_block( array $codes ): string {
		$html = array() !== $codes
			? self::recovery_codes( $codes )
			: '<p>' . esc_html__( 'Your recovery codes were shown once. If you did not save them, create new ones in your account security settings after you sign in.', 'maxtdesign-mfa' ) . '</p>';

		return $html . sprintf(
			'<p><label><input type="checkbox" name="mdmfa_saved" value="1" required> %s</label></p>',
			esc_html__( 'I have saved my recovery codes', 'maxtdesign-mfa' )
		);
	}
}
