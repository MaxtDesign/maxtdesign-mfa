<?php
/**
 * Two-step verification on My Account. Replaces myaccount/form-login.php while a login is
 * pending. Copy to {your-theme}/maxtdesign-mfa/challenge.php to override; keep the field
 * names and the hidden inputs.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

use MaxtDesign\Mfa\Flow\FlowState;
use MaxtDesign\Mfa\Screens\Fragments;
use MaxtDesign\Mfa\WooCommerce\AccountChallenge;

defined( 'ABSPATH' ) || exit;

$mdmfa_state = AccountChallenge::state();
if ( null === $mdmfa_state || null === $mdmfa_state->user ) {
	return;
}
$mdmfa_button = 'woocommerce-button button' . ( function_exists( 'wc_wp_theme_get_element_class_name' ) && wc_wp_theme_get_element_class_name( 'button' ) ? ' ' . wc_wp_theme_get_element_class_name( 'button' ) : '' );
$mdmfa_row    = 'woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide';
$mdmfa_input  = 'woocommerce-Input woocommerce-Input--text input-text';

do_action( 'woocommerce_before_customer_login_form' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce hook kept for theme compatibility (notices print here).
?>
<div class="mdmfa-challenge">
	<h2><?php echo esc_html( FlowState::RECOVERY === $mdmfa_state->screen ? __( 'Recovery codes', 'maxtdesign-mfa' ) : __( 'Two-step verification', 'maxtdesign-mfa' ) ); ?></h2>

	<?php foreach ( $mdmfa_state->errors->get_error_codes() as $mdmfa_code ) : ?>
		<?php foreach ( $mdmfa_state->errors->get_error_messages( $mdmfa_code ) as $mdmfa_error ) : ?>
			<?php if ( 'message' === $mdmfa_state->errors->get_error_data( $mdmfa_code ) ) : ?>
				<div class="woocommerce-message" role="status"><?php echo esc_html( wp_strip_all_tags( $mdmfa_error ) ); ?></div>
			<?php else : ?>
				<ul class="woocommerce-error" role="alert"><li><?php echo esc_html( wp_strip_all_tags( $mdmfa_error ) ); ?></li></ul>
			<?php endif; ?>
		<?php endforeach; ?>
	<?php endforeach; ?>

	<?php if ( FlowState::ENROLL === $mdmfa_state->screen && array() !== $mdmfa_state->passkey ) : ?>
		<form class="woocommerce-form woocommerce-form-login login" method="post" action="<?php echo esc_url( AccountChallenge::form_action( $mdmfa_state ) ); ?>">
			<input type="hidden" name="mdmfa_wc" value="1">
			<input type="hidden" name="mdmfa_form" value="<?php echo esc_attr( $mdmfa_state->token_for( 'enroll-passkey' ) ); ?>">
			<p><strong><?php esc_html_e( 'Use a passkey', 'maxtdesign-mfa' ); ?></strong><br><?php esc_html_e( 'Sign in with your fingerprint, face or screen lock. Nothing to type.', 'maxtdesign-mfa' ); ?></p>
			<?php echo Fragments::passkey_name_field( $mdmfa_input, $mdmfa_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<?php
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'create',
					'options' => $mdmfa_state->passkey,
					'field'   => 'mdmfa_credential',
				),
				__( 'Create a passkey', 'maxtdesign-mfa' ),
				$mdmfa_button
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			?>
		</form>
	<?php endif; ?>

	<?php if ( FlowState::ENROLL !== $mdmfa_state->screen || null !== $mdmfa_state->secret ) : ?>
	<form class="woocommerce-form woocommerce-form-login login" method="post" action="<?php echo esc_url( AccountChallenge::form_action( $mdmfa_state ) ); ?>">
		<input type="hidden" name="mdmfa_wc" value="1">
		<input type="hidden" name="mdmfa_form" value="<?php echo esc_attr( $mdmfa_state->token() ); ?>">

		<?php if ( FlowState::VERIFY === $mdmfa_state->screen && 'passkey' === $mdmfa_state->method ) : ?>
			<p><?php esc_html_e( 'Use your passkey to finish signing in.', 'maxtdesign-mfa' ); ?></p>
			<?php
			$mdmfa_passkey_html = Fragments::passkey_button(
				array(
					'mode'    => 'get',
					'options' => $mdmfa_state->passkey,
					'field'   => 'mdmfa_credential',
				),
				__( 'Use your passkey', 'maxtdesign-mfa' ),
				$mdmfa_button
			);
			echo $mdmfa_passkey_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			echo Fragments::trust_field( $mdmfa_state, 'form-row' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
			?>

		<?php elseif ( FlowState::VERIFY === $mdmfa_state->screen && 'email' === $mdmfa_state->method && ! $mdmfa_state->email_sent ) : ?>
			<p><?php esc_html_e( 'Use a code we send to your email address.', 'maxtdesign-mfa' ); ?></p>
			<input type="hidden" name="mdmfa_send" value="1">
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Email me a code', 'maxtdesign-mfa' ); ?></button></p>

		<?php elseif ( FlowState::VERIFY === $mdmfa_state->screen ) : ?>
			<?php
			$mdmfa_recovery = 'recovery' === $mdmfa_state->method;
			$mdmfa_intro    = __( 'Enter the 6-digit code from your authenticator app.', 'maxtdesign-mfa' );
			$mdmfa_label    = __( 'Authentication code', 'maxtdesign-mfa' );
			if ( $mdmfa_recovery ) {
				$mdmfa_intro = __( 'Enter one of your recovery codes.', 'maxtdesign-mfa' );
				$mdmfa_label = __( 'Recovery code', 'maxtdesign-mfa' );
			} elseif ( 'email' === $mdmfa_state->method ) {
				$mdmfa_intro = __( 'Enter the 8-digit code from the email.', 'maxtdesign-mfa' );
				$mdmfa_label = __( 'Code from the email', 'maxtdesign-mfa' );
			}
			?>
			<p><?php echo esc_html( $mdmfa_intro ); ?></p>
			<?php echo Fragments::code_field( 'mdmfa_code', $mdmfa_label, $mdmfa_recovery, $mdmfa_input, $mdmfa_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<?php echo Fragments::trust_field( $mdmfa_state, 'form-row' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Verify', 'maxtdesign-mfa' ); ?></button></p>

		<?php elseif ( FlowState::GRACE === $mdmfa_state->screen ) : ?>
			<p><?php echo esc_html( Fragments::grace_message( $mdmfa_state->grace_days ) ); ?></p>
			<p class="form-row">
				<button type="submit" name="mdmfa_enroll" value="1" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Set up now', 'maxtdesign-mfa' ); ?></button>
				<button type="submit" name="mdmfa_skip" value="1" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Skip for now', 'maxtdesign-mfa' ); ?></button>
			</p>

		<?php elseif ( FlowState::ENROLL === $mdmfa_state->screen ) : ?>
			<?php if ( array() !== $mdmfa_state->passkey ) : ?>
				<p><strong><?php esc_html_e( 'Or use an authenticator app', 'maxtdesign-mfa' ); ?></strong></p>
			<?php endif; ?>
			<?php echo Fragments::totp_setup( (string) $mdmfa_state->secret, $mdmfa_state->user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally. ?>
			<?php echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ), false, $mdmfa_input, $mdmfa_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Confirm', 'maxtdesign-mfa' ); ?></button></p>

		<?php else : ?>
			<p><?php esc_html_e( 'Two-step verification is on.', 'maxtdesign-mfa' ); ?></p>
			<?php echo Fragments::recovery_block( $mdmfa_state->codes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Continue', 'maxtdesign-mfa' ); ?></button></p>
		<?php endif; ?>
	</form>
	<?php endif; ?>

	<?php
	if ( FlowState::VERIFY === $mdmfa_state->screen ) {
		if ( 'email' === $mdmfa_state->method && $mdmfa_state->email_sent ) {
			echo Fragments::mail_form( AccountChallenge::form_action( $mdmfa_state ), $mdmfa_state, 'mdmfa_send', __( 'Send a new code', 'maxtdesign-mfa' ), $mdmfa_button, true ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		}
		if ( $mdmfa_state->can_recover ) {
			echo Fragments::mail_form( AccountChallenge::form_action( $mdmfa_state ), $mdmfa_state, 'mdmfa_recover', __( 'Lost access? Reset by email', 'maxtdesign-mfa' ), $mdmfa_button, true ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value.
		}
	}
	?>

	<?php if ( FlowState::VERIFY === $mdmfa_state->screen && count( $mdmfa_state->methods ) > 1 ) : ?>
		<p>
			<?php foreach ( $mdmfa_state->methods as $mdmfa_method ) : ?>
				<?php if ( $mdmfa_method !== $mdmfa_state->method ) : ?>
					<a href="<?php echo esc_url( AccountChallenge::method_url( $mdmfa_method ) ); ?>"><?php echo esc_html( \MaxtDesign\Mfa\Screens\LoginScreens::method_label( $mdmfa_method ) ); ?></a><br>
				<?php endif; ?>
			<?php endforeach; ?>
		</p>
	<?php endif; ?>

	<?php if ( FlowState::RECOVERY !== $mdmfa_state->screen ) : ?>
		<p><a href="<?php echo esc_url( AccountChallenge::cancel_url( $mdmfa_state ) ); ?>"><?php esc_html_e( 'Start over', 'maxtdesign-mfa' ); ?></a></p>
	<?php endif; ?>
</div>
<?php
do_action( 'woocommerce_after_customer_login_form' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce hook kept for theme compatibility.
