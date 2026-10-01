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
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Flow\FlowState;
use MaxtDesign\Mfa\Support\Assets;
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
			: 'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 \-]*" maxlength="12"';

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
	 * A passkey control: a button the module reveals and drives, the hidden field it fills,
	 * an error line it shows on failure, and a no-JavaScript note. Enqueues the module.
	 *
	 * @param array<string, mixed> $config    Module config: mode (create|get), options, field, optional conditional (input id).
	 * @param string               $label     Button label.
	 * @param string               $css_class Button class.
	 */
	public static function passkey_button( array $config, string $label, string $css_class ): string {
		Assets::passkey();
		$field = isset( $config['field'] ) && is_string( $config['field'] ) ? $config['field'] : 'mdmfa_credential';

		return sprintf(
			'<p class="mdmfa-passkey"><button type="button" class="%1$s" data-mdmfa-passkey="%2$s" hidden>%3$s</button></p><input type="hidden" name="%4$s" value=""><p data-mdmfa-error hidden>%5$s</p><noscript><p>%6$s</p></noscript>',
			esc_attr( $css_class ),
			esc_attr( (string) wp_json_encode( $config ) ),
			esc_html( $label ),
			esc_attr( $field ),
			esc_html__( 'That did not work. Try again, or choose another way to sign in.', 'maxtdesign-mfa' ),
			esc_html__( 'Passkeys need JavaScript. Choose another way to sign in.', 'maxtdesign-mfa' )
		);
	}

	/**
	 * Label field for a new passkey.
	 *
	 * @param string $css_class Input class.
	 * @param string $row_class Wrapper paragraph class.
	 */
	public static function passkey_name_field( string $css_class = 'input', string $row_class = '' ): string {
		return sprintf(
			'<p%1$s><label for="mdmfa_passkey_name">%2$s</label><input type="text" name="mdmfa_passkey_name" id="mdmfa_passkey_name" class="%3$s" maxlength="64" placeholder="%4$s"></p>',
			'' !== $row_class ? ' class="' . esc_attr( $row_class ) . '"' : '',
			esc_html__( 'Name for this passkey (optional)', 'maxtdesign-mfa' ),
			esc_attr( $css_class ),
			esc_attr__( 'For example: My phone', 'maxtdesign-mfa' )
		);
	}

	/**
	 * The "trust this device" checkbox, or nothing when the role does not allow it.
	 *
	 * @param FlowState $state     Flow state.
	 * @param string    $row_class Wrapper paragraph class.
	 */
	public static function trust_field( FlowState $state, string $row_class = 'forgetmenot' ): string {
		if ( ! $state->can_trust || null === $state->user ) {
			return '';
		}
		$days = max( 1, (int) round( TrustedDevice::lifetime( $state->user ) / DAY_IN_SECONDS ) );

		return sprintf(
			'<p class="%1$s"><label><input type="checkbox" name="mdmfa_trust" value="1"> %2$s</label></p>',
			esc_attr( $row_class ),
			esc_html(
				sprintf(
					/* translators: %d: number of days. */
					_n( 'Do not ask again on this device for %d day', 'Do not ask again on this device for %d days', $days, 'maxtdesign-mfa' ),
					$days
				)
			)
		);
	}

	/**
	 * A one-button form for a mail action on the verify screen (send a new code, email
	 * recovery). It carries the verify form token.
	 *
	 * @param string    $action    Form action URL.
	 * @param FlowState $state     Flow state.
	 * @param string    $field     Field that names the action (mdmfa_send or mdmfa_recover).
	 * @param string    $label     Button label.
	 * @param string    $css_class Button class.
	 * @param bool      $wc        Whether the form posts to the My Account handler.
	 */
	public static function mail_form( string $action, FlowState $state, string $field, string $label, string $css_class, bool $wc = false ): string {
		return sprintf(
			'<form method="post" action="%1$s" class="mdmfa-mail"><input type="hidden" name="mdmfa_form" value="%2$s"><input type="hidden" name="%3$s" value="1">%6$s<p><button type="submit" class="%4$s">%5$s</button></p></form>',
			esc_url( $action ),
			esc_attr( $state->token() ),
			esc_attr( $field ),
			esc_attr( $css_class ),
			esc_html( $label ),
			$wc ? '<input type="hidden" name="mdmfa_wc" value="1">' : ''
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
