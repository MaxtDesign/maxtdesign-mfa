<?php
/**
 * Settings model with defaults (plan 6.3 and section 16 decisions).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Reads mdmfa_settings merged over defaults. Validation of owner input lands with the
 * admin screens (P7); this class only guarantees every key exists with a safe value.
 *
 * @phpstan-type RoleConfig array{
 *     policy: string,
 *     factors: array{totp: bool, passkey: bool, recovery: bool, email: bool},
 *     passwordless: bool,
 *     grace_days: int,
 *     trusted_devices: bool,
 *     email_recovery: bool,
 *     recovery_wait_hours: int,
 *     app_passwords: bool
 * }
 */
final class Settings {

	public const POLICY_OFF      = 'off';
	public const POLICY_OPTIONAL = 'optional';
	public const POLICY_REQUIRED = 'required';

	public const FACTORS = array( 'totp', 'passkey', 'recovery', 'email' );

	/**
	 * Default configuration.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return array(
			'roles'                 => array(
				'administrator' => self::role_defaults( self::POLICY_REQUIRED, true ),
				'editor'        => self::role_defaults( self::POLICY_REQUIRED, true ),
				'shop_manager'  => self::role_defaults( self::POLICY_REQUIRED, true ),
				'customer'      => self::role_defaults( self::POLICY_OPTIONAL, false ),
			),
			// Roles not listed above (author, contributor, subscriber, custom roles).
			'unlisted_role'         => self::role_defaults( self::POLICY_OPTIONAL, true ),
			'trusted_device_days'   => 30,
			'lockout'               => array(
				'attempts_per_record' => 5,
				'backoff_after'       => 5,
				'backoff_seconds'     => 30,
				'lock_after'          => 20,
				'lock_seconds'        => HOUR_IN_SECONDS,
				'repeat_lock_seconds' => DAY_IN_SECONDS,
			),
			'email_code_limits'     => array(
				'per_15_minutes' => 3,
				'per_day'        => 10,
			),
			'log_retention_days'    => 90,
			'log_ip_mode'           => 'truncated',
			'xmlrpc'                => 'block_password',
			'application_passwords' => 'per_role',
			'counter_anomaly_block' => false,
			'block_wpcom_sso'       => false,
		);
	}

	/**
	 * Per-role defaults. Staff roles never get email as a factor or email recovery by
	 * default (NIST SP 800-63B-4; plan decision 12). Trusted devices start off everywhere
	 * (decision 15). Application passwords follow the policy (plan 4.3).
	 *
	 * @param string $policy One of the POLICY_* constants.
	 * @param bool   $staff  Whether the role is a staff role.
	 * @return RoleConfig
	 */
	public static function role_defaults( string $policy, bool $staff ): array {
		return array(
			'policy'              => $policy,
			'factors'             => array(
				'totp'     => true,
				'passkey'  => true,
				'recovery' => true,
				'email'    => ! $staff,
			),
			'passwordless'        => false,
			'grace_days'          => 7,
			'trusted_devices'     => false,
			'email_recovery'      => ! $staff,
			'recovery_wait_hours' => $staff ? 24 : 0,
			'app_passwords'       => self::POLICY_REQUIRED !== $policy,
		);
	}

	/**
	 * Stored settings merged over defaults.
	 *
	 * @return array<string, mixed>
	 */
	public static function get(): array {
		$stored = get_option( Options::SETTINGS, array() );

		return self::resolve( is_array( $stored ) ? $stored : array() );
	}

	/**
	 * Resolves stored values against the defaults. Role keys are open-ended (custom
	 * roles), so each stored role is merged over its own default, or over the
	 * unlisted-role default when the role has none.
	 *
	 * @param array<array-key, mixed> $stored Stored values.
	 * @return array<string, mixed>
	 */
	public static function resolve( array $stored ): array {
		$stored_roles = isset( $stored['roles'] ) && is_array( $stored['roles'] ) ? $stored['roles'] : array();
		unset( $stored['roles'] );

		$settings = self::merge( self::defaults(), $stored );
		$roles    = is_array( $settings['roles'] ) ? $settings['roles'] : array();
		$unlisted = is_array( $settings['unlisted_role'] ) ? $settings['unlisted_role'] : array();

		foreach ( $stored_roles as $role => $config ) {
			if ( ! is_string( $role ) || '' === $role || ! is_array( $config ) ) {
				continue;
			}
			$base           = isset( $roles[ $role ] ) && is_array( $roles[ $role ] ) ? $roles[ $role ] : $unlisted;
			$roles[ $role ] = self::merge( $base, $config );
		}
		$settings['roles'] = $roles;

		return $settings;
	}

	/**
	 * Validates one role's configuration from owner input (the Policy and Recovery tabs).
	 * Unknown values fall back to the role's current value. A Required role always keeps
	 * an authenticator app or a passkey: without one, nobody in the role could enroll.
	 *
	 * @param array<array-key, mixed> $input   Owner input for the role.
	 * @param array<array-key, mixed> $current The role's current configuration.
	 * @return RoleConfig
	 */
	public static function sanitize_role( array $input, array $current ): array {
		$base    = self::merge( self::role_defaults( self::POLICY_OPTIONAL, true ), $current );
		$policy  = isset( $input['policy'] ) && is_string( $input['policy'] ) && in_array( $input['policy'], array( self::POLICY_OFF, self::POLICY_OPTIONAL, self::POLICY_REQUIRED ), true ) ? $input['policy'] : $base['policy'];
		$factors = isset( $input['factors'] ) && is_array( $input['factors'] ) ? $input['factors'] : array();
		$totp    = ! empty( $factors['totp'] );
		$passkey = ! empty( $factors['passkey'] );
		if ( self::POLICY_REQUIRED === $policy && ! $totp && ! $passkey ) {
			$totp = true;
		}

		return array(
			'policy'              => $policy,
			'factors'             => array(
				'totp'     => $totp,
				'passkey'  => $passkey,
				'recovery' => true,
				'email'    => ! empty( $factors['email'] ),
			),
			'passwordless'        => $passkey && ! empty( $input['passwordless'] ),
			'grace_days'          => self::clamp( $input['grace_days'] ?? $base['grace_days'], 0, 90, 7 ),
			'trusted_devices'     => ! empty( $input['trusted_devices'] ),
			'email_recovery'      => ! empty( $input['email_recovery'] ),
			'recovery_wait_hours' => self::clamp( $input['recovery_wait_hours'] ?? $base['recovery_wait_hours'], 0, 168, 24 ),
			'app_passwords'       => ! empty( $input['app_passwords'] ),
		);
	}

	/**
	 * An integer inside a range, or the fallback when the input is not a whole number.
	 *
	 * @param mixed $value    Input.
	 * @param int   $min      Lowest allowed.
	 * @param int   $max      Highest allowed.
	 * @param int   $fallback Value for non-numeric input.
	 */
	public static function clamp( mixed $value, int $min, int $max, int $fallback ): int {
		if ( is_string( $value ) && 1 === preg_match( '/^\d{1,6}$/', trim( $value ) ) ) {
			$value = (int) trim( $value );
		}

		return is_int( $value ) ? max( $min, min( $max, $value ) ) : $fallback;
	}

	/**
	 * One of a closed set of strings, or the fallback.
	 *
	 * @param mixed    $value    Input.
	 * @param string[] $allowed  Allowed values.
	 * @param string   $fallback Fallback.
	 */
	public static function choice( mixed $value, array $allowed, string $fallback ): string {
		return is_string( $value ) && in_array( $value, $allowed, true ) ? $value : $fallback;
	}

	/**
	 * Stores settings (not autoloaded) and drops the cached status.
	 *
	 * @param array<string, mixed> $settings Complete, validated settings.
	 */
	public static function save( array $settings ): void {
		update_option( Options::SETTINGS, self::resolve( $settings ), false );
		delete_transient( 'mdmfa_status_cache' );
	}

	/**
	 * Recursive merge over a closed key set. Unknown keys are dropped and a stored
	 * value whose type differs from the default is ignored.
	 *
	 * @param array<array-key, mixed> $defaults Default values.
	 * @param array<array-key, mixed> $stored   Stored values.
	 * @return array<array-key, mixed>
	 */
	public static function merge( array $defaults, array $stored ): array {
		foreach ( $stored as $key => $value ) {
			if ( ! array_key_exists( $key, $defaults ) ) {
				continue;
			}
			$default = $defaults[ $key ];
			if ( is_array( $default ) && is_array( $value ) ) {
				$defaults[ $key ] = self::merge( $default, $value );
			} elseif ( gettype( $default ) === gettype( $value ) ) {
				$defaults[ $key ] = $value;
			}
		}

		return $defaults;
	}

	/**
	 * Default login location option (plan 6.3, 5.4).
	 *
	 * @return array{enabled: bool, slug: string, public_login: string, public_page: int, allow_core_register: bool}
	 */
	public static function login_defaults(): array {
		return array(
			'enabled'             => true,
			'slug'                => LoginSlug::generate(),
			'public_login'        => 'auto',
			'public_page'         => 0,
			'allow_core_register' => false,
		);
	}
}
