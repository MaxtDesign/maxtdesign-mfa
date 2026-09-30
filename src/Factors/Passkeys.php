<?php
/**
 * Passkeys as a factor (plan 4.3, 12): challenges, the relying-party checks the verifier
 * leaves to its caller (credential ownership, RP binding, userHandle, counter policy), and
 * passwordless sign-in.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Auth\PendingRecord;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Install\Schema;
use MaxtDesign\Mfa\Log\Logger;
use MaxtDesign\Mfa\Policy\Policy;
use MaxtDesign\Mfa\Settings\Settings;
use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Support\Clock;
use MaxtDesign\Mfa\WebAuthn\Cbor;
use MaxtDesign\Mfa\WebAuthn\CredentialJson;
use MaxtDesign\Mfa\WebAuthn\Options;
use MaxtDesign\Mfa\WebAuthn\RegisteredCredential;
use MaxtDesign\Mfa\WebAuthn\RelyingParty;
use MaxtDesign\Mfa\WebAuthn\VerificationException;
use MaxtDesign\Mfa\WebAuthn\Verifier;

defined( 'ABSPATH' ) || exit;

/**
 * Passkey operations.
 *
 * @phpstan-import-type Row from PasskeyStore
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery -- single-use challenge markers in the plugin's own pending table.
 */
final class Passkeys {

	/** Lifetime of every challenge, in seconds (plan 4.3: age <= 5 minutes). */
	public const CHALLENGE_TTL = 300;

	private const SESSION_KEY = 'mdmfa_wa';

	/**
	 * Whether this user can use passkeys here: a secure context, openssl, and a role that
	 * allows them.
	 *
	 * @param \WP_User $user User.
	 */
	public static function allowed( \WP_User $user ): bool {
		return RelyingParty::available() && Policy::allows( $user, 'passkey' );
	}

	/**
	 * The user's credentials for this site's RP ID.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, array<string, mixed>>
	 * @phpstan-return Row[]
	 */
	public static function credentials( int $user_id ): array {
		return PasskeyStore::for_user( $user_id, RelyingParty::id() );
	}

	/**
	 * Whether the user holds a passkey usable on this site.
	 *
	 * @param int $user_id User ID.
	 */
	public static function has( int $user_id ): bool {
		return RelyingParty::available() && array() !== self::credentials( $user_id );
	}

	/**
	 * Whether any role allows passwordless sign-in (the login pages then offer it).
	 */
	public static function passwordless_offered(): bool {
		if ( ! RelyingParty::available() ) {
			return false;
		}
		$settings = Settings::get();
		$configs  = array_merge( is_array( $settings['roles'] ) ? $settings['roles'] : array(), array( $settings['unlisted_role'] ) );
		foreach ( $configs as $config ) {
			if ( is_array( $config ) && ! empty( $config['passwordless'] ) && ! empty( $config['factors']['passkey'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Creation options for the user.
	 *
	 * @param \WP_User $user      User.
	 * @param string   $challenge Raw challenge.
	 * @return array<string, mixed>
	 */
	public static function creation_options( \WP_User $user, string $challenge ): array {
		$discoverable = ! empty( Policy::effective( $user )['passwordless'] );

		return Options::creation(
			$challenge,
			PasskeyStore::user_handle( $user->ID ),
			$user->user_login,
			$user->display_name ?? $user->user_login,
			PasskeyStore::descriptors( self::credentials( $user->ID ) ),
			$discoverable
		);
	}

	/**
	 * Request options for a known user (second factor or step-up).
	 *
	 * @param \WP_User $user      User.
	 * @param string   $challenge Raw challenge.
	 * @return array<string, mixed>
	 */
	public static function request_options( \WP_User $user, string $challenge ): array {
		return Options::request( $challenge, PasskeyStore::descriptors( self::credentials( $user->ID ) ), false );
	}

	/**
	 * Verifies a registration and stores the credential.
	 *
	 * @param \WP_User $user      User.
	 * @param string   $json      Posted credential JSON.
	 * @param string   $challenge The challenge that was issued.
	 * @param string   $name      Owner-facing label.
	 * @return RegisteredCredential|\WP_Error
	 */
	public static function register( \WP_User $user, string $json, string $challenge, string $name ): RegisteredCredential|\WP_Error {
		if ( ! self::allowed( $user ) ) {
			return new \WP_Error( 'mdmfa_passkey_unavailable', __( 'Passkeys are not available for your account.', 'maxtdesign-mfa' ) );
		}
		try {
			$posted     = CredentialJson::registration( $json );
			$credential = Verifier::register(
				$posted->client_data_json,
				$posted->attestation_object,
				$challenge,
				RelyingParty::id(),
				RelyingParty::origins(),
				! empty( Policy::effective( $user )['passwordless'] )
			);
		} catch ( VerificationException $e ) {
			Logger::log( 'enroll_fail', $user->ID, 'passkey', '', null, substr( $e->getMessage(), 0, 64 ) );
			return new \WP_Error( 'mdmfa_passkey_invalid', __( 'That passkey could not be verified. Please try again.', 'maxtdesign-mfa' ) );
		}
		$label = '' !== trim( $name ) ? sanitize_text_field( $name ) : __( 'Passkey', 'maxtdesign-mfa' );
		if ( ! PasskeyStore::add( $user->ID, $credential, RelyingParty::id(), $posted->transports, $label ) ) {
			return new \WP_Error( 'mdmfa_passkey_exists', __( 'That passkey is already registered, or you have reached the limit of 20.', 'maxtdesign-mfa' ) );
		}
		update_user_meta( $user->ID, 'mdmfa_enrolled', '1' );
		Logger::log( 'enrolled', $user->ID, 'passkey' );
		do_action( 'mdmfa_enrolled', $user, 'passkey' );

		return $credential;
	}

	/**
	 * Verifies an assertion from one of this user's passkeys (second factor, step-up).
	 *
	 * @param \WP_User $user       User.
	 * @param string   $json       Posted credential JSON.
	 * @param string   $challenge  The challenge that was issued.
	 * @param bool     $require_uv Require user verification.
	 */
	public static function verify_for_user( \WP_User $user, string $json, string $challenge, bool $require_uv ): bool {
		try {
			$posted = CredentialJson::assertion( $json );
		} catch ( VerificationException $e ) {
			return false;
		}
		$row = PasskeyStore::find( $posted->raw_id );
		if ( null === $row || $row['user_id'] !== $user->ID || RelyingParty::id() !== $row['rp_id'] ) {
			return false;
		}

		return self::check( $user, $row, $posted, $challenge, $require_uv );
	}

	/**
	 * Passwordless sign-in (plan 4.3): stateless challenge redeemed once, credential
	 * resolved by ID, userHandle bound to its owner, UV required, then the owner's policy
	 * must allow passwordless and account-state checks must pass. Returns the user or a
	 * generic error (never revealing which account or step failed).
	 *
	 * @param string $json Posted credential JSON.
	 * @return \WP_User|\WP_Error
	 */
	public static function passwordless( string $json ): \WP_User|\WP_Error {
		$generic = new \WP_Error( 'mdmfa_passkey_failed', __( 'That passkey did not work. Try again, or sign in with your password.', 'maxtdesign-mfa' ) );
		if ( ! self::passwordless_offered() ) {
			return $generic;
		}
		try {
			$posted = CredentialJson::assertion( $json );
		} catch ( VerificationException $e ) {
			return $generic;
		}
		$challenge = self::challenge_from( $posted->client_data_json );
		if ( null === $challenge || ! self::redeem_login_challenge( $challenge ) ) {
			return $generic;
		}
		$row  = PasskeyStore::find( $posted->raw_id );
		$user = null === $row ? false : get_userdata( $row['user_id'] );
		if ( null === $row || ! $user instanceof \WP_User || RelyingParty::id() !== $row['rp_id'] ) {
			return $generic;
		}
		// Usernameless: the authenticator must return the owner's handle (CVE-2024-39912 lesson).
		if ( '' === $posted->user_handle || ! hash_equals( PasskeyStore::user_handle( $user->ID ), $posted->user_handle ) ) {
			Logger::log( 'passwordless_fail', $user->ID, 'passkey', '', null, 'user handle' );
			return $generic;
		}
		if ( ! self::check( $user, $row, $posted, $challenge, true ) ) {
			return $generic;
		}
		if ( empty( Policy::effective( $user )['passwordless'] ) || ! Policy::allows( $user, 'passkey' ) ) {
			return new \WP_Error( 'mdmfa_passwordless_off', __( 'Please sign in with your password first. Passkey-only sign-in is not enabled for your account.', 'maxtdesign-mfa' ) );
		}
		$vetted = apply_filters( 'wp_authenticate_user', $user, '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's account-state veto (user.php), applied as a password login would.
		if ( ! $vetted instanceof \WP_User || ( is_multisite() && is_user_spammy( $user ) ) ) {
			return $generic;
		}

		return $user;
	}

	/**
	 * Stateless login challenge: nonce(16) | issued-at(8) | HMAC(16). Anonymous page views
	 * write nothing; single use is enforced when it is redeemed.
	 */
	public static function login_challenge(): string {
		$body = random_bytes( 16 ) . pack( 'N2', 0, Clock::now() );

		return $body . substr( hash_hmac( 'sha256', $body, self::key(), true ), 0, 16 );
	}

	/**
	 * Checks a login challenge's MAC and age, and burns it (a second use fails).
	 *
	 * @param string $challenge Raw challenge from clientDataJSON.
	 */
	public static function redeem_login_challenge( string $challenge ): bool {
		global $wpdb;

		if ( 40 !== strlen( $challenge ) ) {
			return false;
		}
		$body = substr( $challenge, 0, 24 );
		if ( ! hash_equals( substr( hash_hmac( 'sha256', $body, self::key(), true ), 0, 16 ), substr( $challenge, 24 ) ) ) {
			return false;
		}
		$issued = Cbor::uint( 'N', substr( $body, 20, 4 ) );
		$age    = Clock::now() - $issued;
		if ( $age < 0 || $age > self::CHALLENGE_TTL ) {
			return false;
		}
		$inserted = $wpdb->query(
			$wpdb->prepare(
				'INSERT IGNORE INTO %i (token_hash, kind, user_id, payload, attempts, created_at, expires_at) VALUES (%s, %s, NULL, %s, 0, %d, %d)',
				Schema::site_tables( $wpdb )['pending'],
				hash( 'sha256', $challenge ),
				'wa_used',
				'{}',
				Clock::now(),
				$issued + self::CHALLENGE_TTL
			)
		);

		return 1 === $inserted;
	}

	/**
	 * Issues a challenge bound to the current login session (enrollment, step-up).
	 *
	 * @param int    $user_id User ID (the current user).
	 * @param string $purpose What it is for.
	 */
	public static function session_challenge( int $user_id, string $purpose ): string {
		$challenge = random_bytes( 32 );
		$token     = wp_get_session_token();
		$manager   = \WP_Session_Tokens::get_instance( $user_id );
		$session   = '' === $token ? null : $manager->get( $token );
		if ( is_array( $session ) ) {
			$pending                      = isset( $session[ self::SESSION_KEY ] ) && is_array( $session[ self::SESSION_KEY ] ) ? $session[ self::SESSION_KEY ] : array();
			$pending[ $purpose ]          = array(
				'c'   => Base64Url::encode( $challenge ),
				'exp' => Clock::now() + self::CHALLENGE_TTL,
			);
			$session[ self::SESSION_KEY ] = $pending;
			$manager->update( $token, $session );
		}

		return $challenge;
	}

	/**
	 * Takes (and removes) the session challenge for a purpose, or null when absent/expired.
	 *
	 * @param int    $user_id User ID (the current user).
	 * @param string $purpose What it is for.
	 */
	public static function take_session_challenge( int $user_id, string $purpose ): ?string {
		$token   = wp_get_session_token();
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = '' === $token ? null : $manager->get( $token );
		if ( ! is_array( $session ) || ! isset( $session[ self::SESSION_KEY ][ $purpose ] ) ) {
			return null;
		}
		$entry = $session[ self::SESSION_KEY ][ $purpose ];
		unset( $session[ self::SESSION_KEY ][ $purpose ] );
		$manager->update( $token, $session );

		return self::unpack_challenge( $entry );
	}

	/**
	 * Issues a challenge stored in a pending login record.
	 *
	 * @param PendingRecord $record  Pending record.
	 * @param string        $purpose What it is for.
	 * @return array{0: PendingRecord, 1: string} Updated record and the raw challenge.
	 */
	public static function pending_challenge( PendingRecord $record, string $purpose ): array {
		$challenge     = random_bytes( 32 );
		$payload       = $record->payload;
		$payload['wa'] = array(
			'p'   => $purpose,
			'c'   => Base64Url::encode( $challenge ),
			'exp' => Clock::now() + self::CHALLENGE_TTL,
		);

		return array( PendingStore::update_payload( $record, $payload ), $challenge );
	}

	/**
	 * Takes (and removes) a pending-record challenge.
	 *
	 * @param PendingRecord $record  Pending record.
	 * @param string        $purpose What it is for.
	 */
	public static function take_pending_challenge( PendingRecord $record, string $purpose ): ?string {
		$entry = $record->payload['wa'] ?? null;
		if ( ! is_array( $entry ) || ( $entry['p'] ?? '' ) !== $purpose ) {
			return null;
		}
		$payload = $record->payload;
		unset( $payload['wa'] );
		PendingStore::update_payload( $record, $payload );

		return self::unpack_challenge( $entry );
	}

	/**
	 * Verifies an assertion against a stored row and applies the counter policy.
	 *
	 * @param \WP_User             $user       Owner.
	 * @param array<string, mixed> $row        Credential row.
	 * @param CredentialJson       $posted     Posted assertion.
	 * @param string               $challenge  Expected challenge.
	 * @param bool                 $require_uv Require UV.
	 */
	private static function check( \WP_User $user, array $row, CredentialJson $posted, string $challenge, bool $require_uv ): bool {
		try {
			$result = Verifier::assert(
				(string) $row['public_key'],
				(int) $row['sign_count'],
				$posted->client_data_json,
				$posted->authenticator_data,
				$posted->signature,
				$challenge,
				RelyingParty::id(),
				RelyingParty::origins(),
				$require_uv
			);
		} catch ( VerificationException $e ) {
			Logger::log( 'passkey_fail', $user->ID, 'passkey', '', null, substr( $e->getMessage(), 0, 64 ) );
			return false;
		}

		if ( $result->anomaly ) {
			Logger::log( 'counter_anomaly', $user->ID, 'passkey' );
			do_action( 'mdmfa_passkey_counter_anomaly', $user, (int) $row['id'] );
			$settings = Settings::get();
			PasskeyStore::used( (int) $row['id'], max( $result->sign_count, (int) $row['sign_count'] ), $result->bs, true );
			return empty( $settings['counter_anomaly_block'] );
		}
		PasskeyStore::used( (int) $row['id'], $result->sign_count, $result->bs, false );

		return true;
	}

	/**
	 * The raw challenge inside clientDataJSON (for the stateless login challenge).
	 *
	 * @param string $client_data_json clientDataJSON bytes.
	 */
	private static function challenge_from( string $client_data_json ): ?string {
		$data = json_decode( $client_data_json, true );

		return is_array( $data ) && isset( $data['challenge'] ) && is_string( $data['challenge'] ) ? Base64Url::decode( $data['challenge'] ) : null;
	}

	/**
	 * Raw challenge from a stored entry, or null when malformed or expired.
	 *
	 * @param mixed $entry Stored entry.
	 */
	private static function unpack_challenge( mixed $entry ): ?string {
		if ( ! is_array( $entry ) || ! isset( $entry['c'], $entry['exp'] ) || ! is_string( $entry['c'] ) || (int) $entry['exp'] < Clock::now() ) {
			return null;
		}

		return Base64Url::decode( $entry['c'] );
	}

	/**
	 * HMAC key for login challenges.
	 */
	private static function key(): string {
		return hash_hkdf( 'sha256', wp_salt( 'auth' ), 32, 'mdmfa-wa-login-v1' );
	}
}
