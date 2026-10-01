<?php
/**
 * What the second-step flow wants shown next. Presenters (core login screen, WooCommerce
 * My Account) render it; they hold no security logic of their own.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Flow;

use MaxtDesign\Mfa\Auth\FormToken;
use MaxtDesign\Mfa\Auth\PendingRecord;

defined( 'ABSPATH' ) || exit;

/**
 * Immutable flow result.
 */
final class FlowState {

	/** Enrolled user: enter a code. */
	public const VERIFY = 'verify';

	/** Required role in grace: set up now or skip. */
	public const GRACE = 'grace';

	/** Authenticator setup. */
	public const ENROLL = 'enroll';

	/** Recovery codes shown once; confirm to finish. */
	public const RECOVERY = 'recovery';

	/** Login completed: the presenter redirects. */
	public const DONE = 'done';

	/** Nothing to continue: the presenter shows $message and a way back to the login form. */
	public const EXPIRED = 'expired';

	/** Form purpose (FormToken) per screen. */
	private const PURPOSES = array(
		self::VERIFY   => 'verify',
		self::GRACE    => 'grace',
		self::ENROLL   => 'enroll-totp',
		self::RECOVERY => 'enroll-ack',
	);

	/**
	 * Constructor.
	 *
	 * @param string               $screen     One of the screen constants.
	 * @param PendingRecord|null   $record     Pending record (null when expired).
	 * @param \WP_User|null        $user       User (null when expired).
	 * @param \WP_Error            $errors     Messages, already escaped.
	 * @param string               $method     totp or recovery (verify screen).
	 * @param string|null          $secret     Raw TOTP secret (enroll screen).
	 * @param string[]             $codes      Recovery codes to show once (recovery screen).
	 * @param string               $message    Plain-text reason (expired screen).
	 * @param int                  $grace_days Days of grace left (grace screen).
	 * @param array<string, mixed> $passkey  WebAuthn options for this screen (verify: request, enroll: creation), or empty.
	 * @param string[]             $methods    Verification methods the user can switch between.
	 */
	public function __construct(
		public readonly string $screen,
		public readonly ?PendingRecord $record,
		public readonly ?\WP_User $user,
		public readonly \WP_Error $errors,
		public readonly string $method = 'totp',
		public readonly ?string $secret = null,
		public readonly array $codes = array(),
		public readonly string $message = '',
		public readonly int $grace_days = 0,
		public readonly array $passkey = array(),
		public readonly array $methods = array()
	) {
	}

	/**
	 * A terminal "start again" state.
	 *
	 * @param string $message Plain-text reason.
	 */
	public static function expired( string $message ): self {
		return new self( self::EXPIRED, null, null, new \WP_Error(), 'totp', null, array(), $message );
	}

	/**
	 * FormToken purpose of the form this screen renders.
	 */
	public function purpose(): string {
		return self::PURPOSES[ $this->screen ] ?? '';
	}

	/**
	 * Form token for this screen's form ('' without a record).
	 */
	public function token(): string {
		return null === $this->record ? '' : FormToken::make( $this->record->token_hash, $this->purpose() );
	}

	/**
	 * Form token for another form on this screen (the passkey setup form: enroll-passkey).
	 *
	 * @param string $purpose Form purpose.
	 */
	public function token_for( string $purpose ): string {
		return null === $this->record ? '' : FormToken::make( $this->record->token_hash, $purpose );
	}

	/**
	 * Token for the "start over" link.
	 */
	public function cancel_token(): string {
		return null === $this->record ? '' : FormToken::make( $this->record->token_hash, 'cancel' );
	}
}
