<?php
/**
 * The self-service security panel, rendered for wp-admin or WooCommerce My Account.
 * Server-rendered with the host's own classes; no plugin CSS or JavaScript.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Account;

use MaxtDesign\Mfa\Auth\StepUp;
use MaxtDesign\Mfa\Factors\PasskeyStore;
use MaxtDesign\Mfa\Factors\Passkeys;
use MaxtDesign\Mfa\Factors\RecoveryCodes;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Screens\Fragments;
use MaxtDesign\Mfa\Settings\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Panel markup. Every dynamic value is escaped here.
 *
 * @phpstan-type Ui array{button: string, primary: string, danger: string, input: string, row: string}
 */
final class SecurityView {

	/**
	 * Renders the panel.
	 *
	 * @param \WP_User              $user     Current user.
	 * @param string                $form_url URL forms post to.
	 * @param string                $view     'totp' while setting up the authenticator.
	 * @param string[]              $codes    Recovery codes to show once.
	 * @param array<string, string> $ui Class names for the host.
	 * @phpstan-param Ui $ui
	 */
	public static function render( \WP_User $user, string $form_url, string $view, array $codes, array $ui ): void {
		$enrolled  = Policy::is_enrolled( $user->ID );
		$policy    = Policy::policy( $user );
		$remaining = RecoveryCodes::remaining( $user->ID );
		$labels    = array(
			Settings::POLICY_REQUIRED => __( 'Required for your account', 'maxtdesign-mfa' ),
			Settings::POLICY_OPTIONAL => __( 'Optional for your account', 'maxtdesign-mfa' ),
			Settings::POLICY_OFF      => __( 'Not used for your account', 'maxtdesign-mfa' ),
		);

		if ( array() !== $codes ) {
			echo '<div class="mdmfa-codes">' . Fragments::recovery_codes( $codes ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		}

		echo '<table class="form-table shop_table" role="presentation"><tbody>';
		printf( '<tr><th scope="row">%1$s</th><td>%2$s</td></tr>', esc_html__( 'Two-step verification', 'maxtdesign-mfa' ), esc_html( $enrolled ? __( 'On', 'maxtdesign-mfa' ) : __( 'Off', 'maxtdesign-mfa' ) ) );
		printf( '<tr><th scope="row">%1$s</th><td>%2$s</td></tr>', esc_html__( 'Site policy', 'maxtdesign-mfa' ), esc_html( $labels[ $policy ] ?? $policy ) );
		if ( $enrolled ) {
			printf(
				'<tr><th scope="row">%1$s</th><td>%2$s</td></tr>',
				esc_html__( 'Recovery codes left', 'maxtdesign-mfa' ),
				esc_html( (string) $remaining ) . ( $remaining <= RecoveryCodes::LOW ? ' <strong>' . esc_html__( 'Running low: create a new set.', 'maxtdesign-mfa' ) . '</strong>' : '' )
			);
		}
		echo '</tbody></table>';

		echo '<h3>' . esc_html__( 'Authenticator app', 'maxtdesign-mfa' ) . '</h3>';
		if ( TotpStore::has( $user->ID ) ) {
			echo '<p>' . esc_html(
				null === TotpStore::secret( $user->ID )
					? __( 'Your authenticator key cannot be read, most likely because the site\'s encryption key changed. Remove it and set it up again.', 'maxtdesign-mfa' )
					: __( 'Your authenticator app is set up.', 'maxtdesign-mfa' )
			) . '</p>';
			self::button_form( $form_url, 'totp_remove', __( 'Remove authenticator app', 'maxtdesign-mfa' ), $ui['danger'] );
		} elseif ( 'totp' === $view && null !== TotpStore::pending( $user->ID ) ) {
			echo Fragments::totp_setup( (string) TotpStore::pending( $user->ID ), $user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally.
			self::form_start( $form_url, 'totp_confirm' );
			echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ), false, $ui['input'], $ui['row'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			printf( '<p><button type="submit" class="%1$s">%2$s</button></p></form>', esc_attr( $ui['primary'] ), esc_html__( 'Confirm and turn on', 'maxtdesign-mfa' ) );
		} elseif ( Policy::allows( $user, 'totp' ) ) {
			echo '<p>' . esc_html__( 'Use an app on your phone to generate sign-in codes.', 'maxtdesign-mfa' ) . '</p>';
			self::button_form( $form_url, 'totp_begin', __( 'Set up authenticator app', 'maxtdesign-mfa' ), $ui['primary'] );
		} else {
			echo '<p>' . esc_html__( 'Authenticator apps are not available for your account.', 'maxtdesign-mfa' ) . '</p>';
		}

		self::passkeys( $user, $form_url, $ui );

		if ( ! $enrolled ) {
			return;
		}
		echo '<h3>' . esc_html__( 'Recovery codes', 'maxtdesign-mfa' ) . '</h3>';
		echo '<p>' . esc_html__( 'Creating a new set replaces every unused code.', 'maxtdesign-mfa' ) . '</p>';
		self::button_form( $form_url, 'recovery_generate', __( 'Create new recovery codes', 'maxtdesign-mfa' ), $ui['button'] );

		if ( StepUp::is_fresh( $user->ID ) ) {
			return;
		}
		echo '<h3>' . esc_html__( 'Confirm it is you', 'maxtdesign-mfa' ) . '</h3>';
		echo '<p>' . esc_html__( 'Adding or removing a method, or creating new recovery codes, needs a verification in the last 10 minutes.', 'maxtdesign-mfa' ) . '</p>';
		self::form_start( $form_url, 'stepup' );
		echo '<fieldset><label><input type="radio" name="mdmfa_method" value="totp" checked> ' . esc_html__( 'Authenticator code', 'maxtdesign-mfa' ) . '</label> ';
		echo '<label><input type="radio" name="mdmfa_method" value="recovery"> ' . esc_html__( 'Recovery code', 'maxtdesign-mfa' ) . '</label></fieldset>';
		printf(
			'<p class="%1$s"><label for="mdmfa_stepup_code">%2$s</label> <input type="text" name="mdmfa_code" id="mdmfa_stepup_code" class="%3$s" autocomplete="one-time-code" required></p>',
			esc_attr( $ui['row'] ),
			esc_html__( 'Code', 'maxtdesign-mfa' ),
			esc_attr( $ui['input'] )
		);
		printf( '<p><button type="submit" class="%1$s">%2$s</button></p></form>', esc_attr( $ui['button'] ), esc_html__( 'Confirm', 'maxtdesign-mfa' ) );

		if ( Passkeys::has( $user->ID ) ) {
			self::form_start( $form_url, 'stepup' );
			echo '<input type="hidden" name="mdmfa_method" value="passkey">';
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'get',
					'options' => Passkeys::request_options( $user, Passkeys::session_challenge( $user->ID, 'stepup' ) ),
					'field'   => 'mdmfa_credential',
				),
				__( 'Confirm with a passkey', 'maxtdesign-mfa' ),
				$ui['button']
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo '</form>';
		}
	}

	/**
	 * Passkeys: list, add, remove.
	 *
	 * @param \WP_User              $user     Current user.
	 * @param string                $form_url Form action.
	 * @param array<string, string> $ui       Class names.
	 */
	private static function passkeys( \WP_User $user, string $form_url, array $ui ): void {
		$allowed     = Passkeys::allowed( $user );
		$credentials = Passkeys::credentials( $user->ID );
		if ( ! $allowed && array() === $credentials ) {
			return;
		}
		echo '<h3>' . esc_html__( 'Passkeys', 'maxtdesign-mfa' ) . '</h3>';
		if ( array() === $credentials ) {
			echo '<p>' . esc_html__( 'Sign in with your fingerprint, face or screen lock instead of typing a code. Passkeys cannot be phished.', 'maxtdesign-mfa' ) . '</p>';
		} else {
			echo '<table class="widefat striped shop_table" role="presentation"><tbody>';
			foreach ( $credentials as $credential ) {
				$used = '' !== $credential['last_used_at'] ? $credential['last_used_at'] : __( 'never', 'maxtdesign-mfa' );
				printf(
					'<tr><td><strong>%1$s</strong><br>%2$s%3$s</td><td>',
					esc_html( (string) $credential['name'] ),
					esc_html(
						sprintf(
							/* translators: 1: date added, 2: date last used. */
							__( 'Added %1$s, last used %2$s (UTC)', 'maxtdesign-mfa' ),
							(string) $credential['created_at'],
							(string) $used
						)
					),
					$credential['flagged'] ? '<br><strong>' . esc_html__( 'Warning: this passkey reported an unexpected counter. If you did not copy it to another device, remove it.', 'maxtdesign-mfa' ) . '</strong>' : ''
				);
				self::form_start( $form_url, 'passkey_remove' );
				printf( '<input type="hidden" name="mdmfa_passkey_id" value="%d">', (int) $credential['id'] );
				printf( '<button type="submit" class="%1$s">%2$s</button></form></td></tr>', esc_attr( $ui['danger'] ), esc_html__( 'Remove', 'maxtdesign-mfa' ) );
			}
			echo '</tbody></table>';
		}
		if ( $allowed && count( $credentials ) < PasskeyStore::MAX_PER_USER ) {
			self::form_start( $form_url, 'passkey_add' );
			echo Fragments::passkey_name_field( $ui['input'], $ui['row'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'create',
					'options' => Passkeys::creation_options( $user, Passkeys::session_challenge( $user->ID, 'add' ) ),
					'field'   => 'mdmfa_credential',
				),
				__( 'Add a passkey', 'maxtdesign-mfa' ),
				$ui['primary']
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo '</form>';
		}
	}

	/**
	 * One-button form.
	 *
	 * @param string $form_url  Form action.
	 * @param string $op        Operation.
	 * @param string $label     Button label.
	 * @param string $css_class Button class.
	 */
	private static function button_form( string $form_url, string $op, string $label, string $css_class ): void {
		self::form_start( $form_url, $op );
		printf( '<p><button type="submit" class="%1$s">%2$s</button></p></form>', esc_attr( $css_class ), esc_html( $label ) );
	}

	/**
	 * Opens a form with the nonce and operation.
	 *
	 * @param string $form_url Form action.
	 * @param string $op       Operation.
	 */
	private static function form_start( string $form_url, string $op ): void {
		printf( '<form method="post" action="%s">', esc_url( $form_url ) );
		wp_nonce_field( SecurityActions::NONCE );
		printf( '<input type="hidden" name="mdmfa_op" value="%s">', esc_attr( $op ) );
	}
}
