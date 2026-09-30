<?php
/**
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\Unit\Install;

use MaxtDesign\Mfa\Install\Schema;
use PHPUnit\Framework\TestCase;

final class SchemaTest extends TestCase {

	private function db(): \wpdb {
		$db              = new \wpdb();
		$db->prefix      = 'wp_3_';
		$db->base_prefix = 'wp_';
		return $db;
	}

	public function test_credentials_are_network_global_and_site_tables_per_site(): void {
		$db = $this->db();

		self::assertSame( 'wp_mdmfa_credentials', Schema::credentials_table( $db ) );
		self::assertSame(
			array(
				'pending' => 'wp_3_mdmfa_pending',
				'log'     => 'wp_3_mdmfa_log',
			),
			Schema::site_tables( $db )
		);
	}

	public function test_credentials_sql_has_every_planned_column(): void {
		$sql = Schema::credentials_sql( $this->db() );

		self::assertStringStartsWith( 'CREATE TABLE wp_mdmfa_credentials (', $sql );
		foreach ( array( 'id', 'user_id', 'cred_hash', 'cred_id', 'public_key', 'alg', 'sign_count', 'transports', 'aaguid', 'be', 'bs', 'rp_id', 'name', 'created_at', 'last_used_at', 'flagged' ) as $column ) {
			self::assertMatchesRegularExpression( '/^  ' . $column . ' /m', $sql, $column );
		}
		self::assertStringContainsString( 'PRIMARY KEY  (id)', $sql, 'dbDelta needs two spaces after PRIMARY KEY' );
		self::assertStringContainsString( 'UNIQUE KEY cred_hash (cred_hash)', $sql );
		self::assertStringContainsString( 'cred_id varchar(1400)', $sql, 'spec caps credential IDs at 1023 bytes; base64url needs 1364 chars' );
	}

	public function test_site_sql_has_pending_and_log(): void {
		list( $pending, $log ) = Schema::site_sql( $this->db() );

		self::assertStringStartsWith( 'CREATE TABLE wp_3_mdmfa_pending (', $pending );
		self::assertStringContainsString( 'PRIMARY KEY  (token_hash)', $pending );
		self::assertStringContainsString( 'KEY expires_at (expires_at)', $pending );
		self::assertStringStartsWith( 'CREATE TABLE wp_3_mdmfa_log (', $log );
		self::assertStringContainsString( 'ip varbinary(16)', $log );
		self::assertStringContainsString( 'KEY created_at (created_at)', $log );
	}

	public function test_every_statement_uses_the_site_collation(): void {
		$db = $this->db();
		foreach ( array_merge( array( Schema::credentials_sql( $db ) ), Schema::site_sql( $db ) ) as $sql ) {
			self::assertStringEndsWith( ') ' . $db->get_charset_collate() . ';', $sql );
		}
	}
}
