<?php
/**
 * Admin UI pieces in the suite's class shapes (admin UI handoff sections 5 and 7.1,
 * tier 2). When suite-core is loaded its helpers render them; otherwise the same markup
 * is produced here, styled as native WordPress by the plugin's own small stylesheet.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Markup helpers. Every method returns escaped HTML.
 */
final class Ui {

	/**
	 * Whether a suite-core helper can be called (a stale vendored copy may lack it).
	 *
	 * @param string $method Method name.
	 */
	public static function suite_has( string $method ): bool {
		return SettingsPage::in_suite() && method_exists( '\MdSuite_Admin', $method );
	}

	/**
	 * Page header: product name as the H1, with the version.
	 */
	public static function page_header(): string {
		if ( self::suite_has( 'render_page_header' ) ) {
			return (string) \MdSuite_Admin::render_page_header( 'MFA', array( 'version' => MDMFA_VERSION ) );
		}

		return '<header class="md-suite-page-header">'
			. '<span class="md-suite-page-header__brand">MaxtDesign</span>'
			. '<span class="md-suite-page-header__sep" aria-hidden="true">/</span>'
			. '<h1 class="md-suite-page-header__title">' . esc_html( 'MFA' ) . '</h1>'
			. '<div class="md-suite-page-header__meta">' . self::badge( 'neutral', 'v' . MDMFA_VERSION ) . '</div>'
			. '</header>';
	}

	/**
	 * Status badge. Every state word an operator sees goes through this.
	 *
	 * @param string $status good, warn, bad or neutral.
	 * @param string $label  Text.
	 */
	public static function badge( string $status, string $label ): string {
		if ( self::suite_has( 'render_status_badge' ) ) {
			return (string) \MdSuite_Admin::render_status_badge( $status, $label );
		}
		if ( ! in_array( $status, array( 'good', 'warn', 'bad', 'neutral' ), true ) ) {
			$status = 'neutral';
		}

		return '<span class="md-suite-badge md-suite-badge--' . $status . '">' . esc_html( $label ) . '</span>';
	}

	/**
	 * Tab bar.
	 *
	 * @param array<string, string> $tabs   Slug => label.
	 * @param string                $active Active slug.
	 */
	public static function tabs( array $tabs, string $active ): string {
		$out = '<nav class="md-suite-tabs nav-tab-wrapper" aria-label="' . esc_attr__( 'MFA sections', 'maxtdesign-mfa' ) . '">';
		foreach ( $tabs as $slug => $label ) {
			$is_active = $slug === $active;
			$out      .= sprintf(
				'<a class="nav-tab%1$s"%2$s href="%3$s">%4$s</a>',
				$is_active ? ' nav-tab-active' : '',
				$is_active ? ' aria-current="page"' : '',
				esc_url( SettingsPage::url( $slug ) ),
				esc_html( $label )
			);
		}

		return $out . '</nav>';
	}

	/**
	 * Empty state: why the list is empty and what to do.
	 *
	 * @param string $title   Bold title.
	 * @param string $message Explanation.
	 */
	public static function empty_state( string $title, string $message ): string {
		if ( self::suite_has( 'render_empty_state' ) ) {
			return (string) \MdSuite_Admin::render_empty_state( $title, $message );
		}

		return '<div class="md-suite-empty"><p class="md-suite-empty__title">' . esc_html( $title ) . '</p><p class="md-suite-empty__message">' . esc_html( $message ) . '</p></div>';
	}

	/**
	 * Admin notice.
	 *
	 * @param string $type    info, success, warning or error.
	 * @param string $message Text.
	 */
	public static function notice( string $type, string $message ): string {
		if ( ! in_array( $type, array( 'info', 'success', 'warning', 'error' ), true ) ) {
			$type = 'info';
		}

		return '<div class="notice notice-' . $type . ' md-suite-notice"><p>' . esc_html( $message ) . '</p></div>';
	}

	/**
	 * Card: the only panel shape.
	 *
	 * @param string $title Title.
	 * @param string $body  Body markup, already escaped by the caller.
	 */
	public static function card( string $title, string $body ): string {
		return '<section class="md-suite-card"><h2 class="md-suite-card__title">' . esc_html( $title ) . '</h2><div class="md-suite-card__body">' . $body . '</div></section>';
	}

	/**
	 * Opens a scrollable, keyboard-focusable table region.
	 *
	 * @param string $label Accessible name.
	 */
	public static function table_open( string $label ): string {
		return '<div class="md-suite-table-region" role="region" tabindex="0" aria-label="' . esc_attr( $label ) . '">';
	}

	/**
	 * Opens a form that posts to admin-post.php with the admin nonce.
	 *
	 * @param string                $action admin-post action.
	 * @param array<string, string> $hidden Extra hidden fields.
	 */
	public static function form_open( string $action, array $hidden = array() ): string {
		$out  = '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		$out .= '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
		$out .= wp_nonce_field( Actions::NONCE, '_wpnonce', true, false );
		foreach ( $hidden as $name => $value ) {
			$out .= '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
		}

		return $out;
	}

	/**
	 * A checkbox with its label.
	 *
	 * @param string $name    Field name.
	 * @param bool   $checked State.
	 * @param string $label   Visible or screen-reader label.
	 * @param bool   $hidden  Hide the label visually (table cells with a column header).
	 */
	public static function checkbox( string $name, bool $checked, string $label, bool $hidden = false ): string {
		return sprintf(
			'<label><input type="checkbox" name="%1$s" value="1"%2$s> <span%3$s>%4$s</span></label>',
			esc_attr( $name ),
			checked( $checked, true, false ),
			$hidden ? ' class="screen-reader-text"' : '',
			esc_html( $label )
		);
	}

	/**
	 * A select.
	 *
	 * @param string                $name    Field name.
	 * @param array<string, string> $options Value => label.
	 * @param string                $current Selected value.
	 * @param string                $label   Accessible label ('' when a visible label targets $id).
	 * @param string                $id      Element id.
	 */
	public static function select( string $name, array $options, string $current, string $label = '', string $id = '' ): string {
		$out = sprintf( '<select name="%1$s"%2$s%3$s>', esc_attr( $name ), '' !== $id ? ' id="' . esc_attr( $id ) . '"' : '', '' !== $label ? ' aria-label="' . esc_attr( $label ) . '"' : '' );
		foreach ( $options as $value => $text ) {
			$out .= sprintf( '<option value="%1$s"%2$s>%3$s</option>', esc_attr( (string) $value ), selected( $current, (string) $value, false ), esc_html( $text ) );
		}

		return $out . '</select>';
	}

	/**
	 * A submit button, with the suite's confirm contract when a message is given. Without
	 * JavaScript nothing intercepts; the server still checks the nonce and capability.
	 *
	 * @param string $label   Button text.
	 * @param string $css     Classes.
	 * @param string $confirm Consequence shown in the confirm dialog, or ''.
	 * @param string $name    Optional name, for forms with several buttons.
	 * @param string $value   Value sent with $name.
	 */
	public static function submit( string $label, string $css = 'button button-primary', string $confirm = '', string $name = '', string $value = '1' ): string {
		return sprintf(
			'<button type="submit" class="%1$s"%2$s%3$s>%4$s</button>',
			esc_attr( $css ),
			'' !== $name ? ' name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '"' : '',
			'' !== $confirm ? ' data-md-suite-confirm="' . esc_attr( $confirm ) . '" data-md-suite-confirm-verb="' . esc_attr( $label ) . '"' : '',
			esc_html( $label )
		);
	}
}
