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
	 * @return array{enabled: bool, slug: string, public_login: string, allow_core_register: bool}
	 */
	public static function login_defaults(): array {
		return array(
			'enabled'             => true,
			'slug'                => LoginSlug::generate(),
			'public_login'        => 'auto',
			'allow_core_register' => false,
		);
	}
}
