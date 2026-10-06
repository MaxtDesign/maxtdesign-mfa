<?php
/** Isolated rewrite lifecycle stand-ins; never loaded outside this test process. */
declare(strict_types=1);
// phpcs:ignoreFile

function WC(): object {
	return (object) array( 'query' => new class() {
		public function get_query_vars(): array {
			return array( 'mdmfa-security' => 'login-security' );
		}
	} );
}
function wp_installing(): bool {
	return ! empty( $GLOBALS['mdmfa_test']['installing'] );
}
function current_user_can( string $cap ): bool {
	return ! empty( $GLOBALS['mdmfa_test']['authorized'] );
}
function flush_rewrite_rules( bool $hard = true ): void {
	++$GLOBALS['mdmfa_test']['flushes'];
	// Like WP, a rebuild knows only currently registered components. Tests seed
	// stored foreign routes, then omit their registrar from this generated set.
	update_option( 'rewrite_rules', $GLOBALS['mdmfa_test']['generated_rules'] );
}
