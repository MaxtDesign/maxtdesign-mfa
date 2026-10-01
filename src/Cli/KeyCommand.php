<?php
/**
 * `wp mdmfa key`: the encryption key of authenticator secrets (plan 6.5). CLI only,
 * because the key must never render in a browser.
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Cli;

use MaxtDesign\Mfa\Crypto\InvalidKeyException;
use MaxtDesign\Mfa\Crypto\KeyProvider;
use MaxtDesign\Mfa\Factors\TotpStore;
use MaxtDesign\Mfa\Settings\Options;
use MaxtDesign\Mfa\Status\Snapshot;

defined( 'ABSPATH' ) || exit;

/**
 * Key status, export and re-encryption.
 */
final class KeyCommand {

	/**
	 * Shows where the key comes from and how many authenticator secrets it can read.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa key status
	 */
	public function status(): void {
		try {
			$keys = KeyProvider::from_environment();
		} catch ( InvalidKeyException $e ) {
			\WP_CLI::warning( 'MDMFA_ENCRYPTION_KEY is defined but is not base64 of 32 bytes. Authenticator apps cannot be set up or checked.' );
			return;
		}
		$counts = array(
			'current'    => 0,
			'older key'  => 0,
			'unreadable' => 0,
		);
		foreach ( self::user_ids() as $user_id ) {
			++$counts[ TotpStore::key_state( $user_id ) ];
		}
		\WP_CLI::line( 'Key source: ' . $keys->source() . ' (key id ' . $keys->kid() . ')' );
		foreach ( $counts as $label => $count ) {
			\WP_CLI::line( sprintf( 'Authenticator secrets, %s: %d', $label, $count ) );
		}
		if ( $counts['older key'] > 0 ) {
			\WP_CLI::line( 'Run `wp mdmfa key rewrap` to re-encrypt the "older key" secrets now. They also convert one by one as users sign in.' );
		}
		if ( $counts['unreadable'] > 0 ) {
			\WP_CLI::warning( 'Unreadable secrets were encrypted with a key this site no longer has (the salts changed). Those users need `wp mdmfa user reset <user> --factor=totp`.' );
		}
	}

	/**
	 * Prints a wp-config.php line that pins the key the site uses now.
	 *
	 * Add the line before changing the WordPress salts, and authenticator apps keep
	 * working: the key no longer depends on the salts. The output is a secret.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa key export-define
	 *
	 * @subcommand export-define
	 */
	public function export_define(): void {
		try {
			$keys = KeyProvider::from_environment();
		} catch ( InvalidKeyException $e ) {
			\WP_CLI::warning( 'MDMFA_ENCRYPTION_KEY is defined but invalid; there is no key to export.' );
			return;
		}
		if ( KeyProvider::SOURCE_CONSTANT === $keys->source() ) {
			\WP_CLI::success( 'MDMFA_ENCRYPTION_KEY is already defined. Nothing to do.' );
			return;
		}
		\WP_CLI::line( "define( 'MDMFA_ENCRYPTION_KEY', '" . sodium_bin2base64( $keys->key(), SODIUM_BASE64_VARIANT_ORIGINAL ) . "' );" );
	}

	/**
	 * Re-encrypts authenticator secrets that an older key of this site can still read.
	 *
	 * Use it after defining a new MDMFA_ENCRYPTION_KEY while the salts are unchanged.
	 * Safe to run again; it skips secrets that are already current.
	 *
	 * ## EXAMPLES
	 *
	 *     wp mdmfa key rewrap
	 */
	public function rewrap(): void {
		$done   = 0;
		$failed = 0;
		foreach ( self::user_ids() as $user_id ) {
			$state = TotpStore::key_state( $user_id );
			if ( 'older key' === $state ) {
				// Reading a secret under an older key re-encrypts it.
				$done += null !== TotpStore::secret( $user_id ) ? 1 : 0;
			} elseif ( 'unreadable' === $state ) {
				++$failed;
			}
		}
		try {
			$keys = KeyProvider::from_environment();
			update_option(
				Options::KEY_CHECK,
				array(
					'kid'    => $keys->kid(),
					'source' => $keys->source(),
				),
				false
			);
		} catch ( InvalidKeyException $e ) {
			\WP_CLI::warning( 'MDMFA_ENCRYPTION_KEY is invalid; nothing was re-encrypted.' );
			return;
		}
		Snapshot::flush();
		\WP_CLI::success( sprintf( 'Re-encrypted %d secrets. %d are unreadable and need a reset.', $done, $failed ) );
	}

	/**
	 * Users with a stored authenticator secret.
	 *
	 * @return int[]
	 */
	private static function user_ids(): array {
		$ids = get_users(
			array(
				'meta_key' => TotpStore::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- a maintenance command.
				'fields'   => 'ID',
				'blog_id'  => 0,
			)
		);

		return array_map( 'intval', $ids );
	}
}
