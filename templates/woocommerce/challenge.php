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

	<?php foreach ( $mdmfa_state->errors->get_error_messages() as $mdmfa_error ) : ?>
		<ul class="woocommerce-error" role="alert"><li><?php echo esc_html( wp_strip_all_tags( $mdmfa_error ) ); ?></li></ul>
	<?php endforeach; ?>

	<form class="woocommerce-form woocommerce-form-login login" method="post" action="<?php echo esc_url( AccountChallenge::form_action( $mdmfa_state ) ); ?>">
		<input type="hidden" name="mdmfa_wc" value="1">
		<input type="hidden" name="mdmfa_form" value="<?php echo esc_attr( $mdmfa_state->token() ); ?>">

		<?php if ( FlowState::VERIFY === $mdmfa_state->screen ) : ?>
			<?php $mdmfa_recovery = 'recovery' === $mdmfa_state->method; ?>
			<p><?php echo esc_html( $mdmfa_recovery ? __( 'Enter one of your recovery codes.', 'maxtdesign-mfa' ) : __( 'Enter the 6-digit code from your authenticator app.', 'maxtdesign-mfa' ) ); ?></p>
			<?php echo Fragments::code_field( 'mdmfa_code', $mdmfa_recovery ? __( 'Recovery code', 'maxtdesign-mfa' ) : __( 'Authentication code', 'maxtdesign-mfa' ), $mdmfa_recovery, $mdmfa_input, $mdmfa_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Verify', 'maxtdesign-mfa' ); ?></button></p>
			<p>
				<a href="<?php echo esc_url( AccountChallenge::method_url( $mdmfa_recovery ? 'totp' : 'recovery' ) ); ?>"><?php echo esc_html( $mdmfa_recovery ? __( 'Use your authenticator app', 'maxtdesign-mfa' ) : __( 'Use a recovery code', 'maxtdesign-mfa' ) ); ?></a>
			</p>

		<?php elseif ( FlowState::GRACE === $mdmfa_state->screen ) : ?>
			<p><?php echo esc_html( Fragments::grace_message( $mdmfa_state->grace_days ) ); ?></p>
			<p class="form-row">
				<button type="submit" name="mdmfa_enroll" value="1" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Set up now', 'maxtdesign-mfa' ); ?></button>
				<button type="submit" name="mdmfa_skip" value="1" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Skip for now', 'maxtdesign-mfa' ); ?></button>
			</p>

		<?php elseif ( FlowState::ENROLL === $mdmfa_state->screen && null !== $mdmfa_state->secret ) : ?>
			<?php echo Fragments::totp_setup( $mdmfa_state->secret, $mdmfa_state->user ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value; the SVG is generated locally. ?>
			<?php echo Fragments::code_field( 'mdmfa_code', __( 'Code from the app', 'maxtdesign-mfa' ), false, $mdmfa_input, $mdmfa_row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Confirm', 'maxtdesign-mfa' ); ?></button></p>

		<?php else : ?>
			<p><?php esc_html_e( 'Two-step verification is on.', 'maxtdesign-mfa' ); ?></p>
			<?php echo Fragments::recovery_block( $mdmfa_state->codes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Fragments escapes every value. ?>
			<p class="form-row"><button type="submit" class="<?php echo esc_attr( $mdmfa_button ); ?>"><?php esc_html_e( 'Continue', 'maxtdesign-mfa' ); ?></button></p>
		<?php endif; ?>
	</form>

	<?php if ( FlowState::RECOVERY !== $mdmfa_state->screen ) : ?>
		<p><a href="<?php echo esc_url( AccountChallenge::cancel_url( $mdmfa_state ) ); ?>"><?php esc_html_e( 'Start over', 'maxtdesign-mfa' ); ?></a></p>
	<?php endif; ?>
</div>
<?php
do_action( 'woocommerce_after_customer_login_form' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce hook kept for theme compatibility.
