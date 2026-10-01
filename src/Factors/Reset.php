<?php
/**
 * Removes every second factor of a user (admin reset, email recovery). The user enrolls
 * again at the next sign-in and the grace period restarts.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Factors;

use MaxtDesign\Mfa\Auth\Lockout;
use MaxtDesign\Mfa\Auth\PendingStore;
use MaxtDesign\Mfa\Auth\TrustedDevice;
use MaxtDesign\Mfa\Flow\EmailRecovery;
use MaxtDesign\Mfa\Policy\Policy;

defined( 'ABSPATH' ) || exit;

/**
 * Factor reset.
 */
final class Reset {

	/**
	 * Clears all factor data, trusted devices, lockout state and pending sign-ins.
	 *
	 * @param int $user_id User ID.
	 */
	public static function all( int $user_id ): void {
		TotpStore::remove( $user_id );
		PasskeyStore::delete_all( $user_id );
		RecoveryCodes::remove( $user_id );
		EmailCode::remove( $user_id );
		self::after_change( $user_id );
		// Only a reset restarts grace; a user who removes their own factor gets no new grace.
		delete_user_meta( $user_id, Policy::GRACE_META );
		Lockout::reset( $user_id );
		PendingStore::delete_for_user( $user_id );
		delete_user_meta( $user_id, EmailRecovery::META );
	}

	/**
	 * Housekeeping after any factor was removed: trusted devices are revoked, and a user
	 * left with no factor loses the enrolled flag and the recovery codes.
	 *
	 * @param int $user_id User ID.
	 */
	public static function after_change( int $user_id ): void {
		TrustedDevice::revoke_all( $user_id );
		if ( ! Policy::is_enrolled( $user_id ) ) {
			delete_user_meta( $user_id, 'mdmfa_enrolled' );
			RecoveryCodes::remove( $user_id );
		}
	}
}
