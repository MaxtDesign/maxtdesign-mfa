#!/usr/bin/env bash
# Activation / uninstall smoke test against a real WordPress + MySQL (plan section 14,
# P1 definition of done). Run by CI after WordPress is installed at $WP_PATH and the
# plugin is staged into wp-content/plugins exactly as it ships (.distignore applied).
#
# Usage: tests/smoke/run.sh single|multisite
set -euo pipefail

MODE="${1:?usage: run.sh single|multisite}"
: "${WP_PATH:?WP_PATH must point at the WordPress install}"
SLUG=maxtdesign-mfa
FAILS=0

wpc() { wp --path="$WP_PATH" "$@"; }
pass() { echo "ok    $1"; }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
expect() { # expect <label> <expected> <actual>
	if [ "$2" = "$3" ]; then pass "$1 ($3)"; else fail "$1: expected '$2', got '$3'"; fi
}

# Counts across every site's tables, independent of the plugin's own code.
count_tables() {
	wpc eval 'global $wpdb; echo count( $wpdb->get_col( $wpdb->prepare( "SHOW TABLES LIKE %s", "%" . $wpdb->esc_like( "mdmfa_" ) . "%" ) ) );'
}
count_rows() {
	wpc eval '
		global $wpdb;
		$like  = "%" . $wpdb->esc_like( "mdmfa_" ) . "%";
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE meta_key LIKE %s", $wpdb->usermeta, $like ) );
		$sites = is_multisite() ? get_sites( array( "fields" => "ids", "number" => 0 ) ) : array( 1 );
		foreach ( $sites as $id ) {
			is_multisite() && switch_to_blog( (int) $id );
			$total += (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE option_name LIKE %s", $wpdb->options, $like ) );
			$cron   = _get_cron_array();
			$total += false !== strpos( (string) wp_json_encode( $cron ), "mdmfa_" ) ? 1 : 0;
			is_multisite() && restore_current_blog();
		}
		if ( is_multisite() ) {
			$total += (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE meta_key LIKE %s", $wpdb->sitemeta, $like ) );
		}
		echo $total;'
}

echo "== activate ($MODE)"
if [ "$MODE" = multisite ]; then
	wpc site create --slug=two --quiet
	wpc plugin activate "$SLUG" --network
	# Network activation installs the main site; other sites install on their first request.
	wpc --url="$(wpc option get home)/two/" eval 'echo "";'
	expect "tables after network activation + second site request" 5 "$(count_tables)"
else
	wpc plugin activate "$SLUG"
	expect "tables after activation" 3 "$(count_tables)"
fi

for t in mdmfa_credentials mdmfa_pending mdmfa_log; do
	got=$(wpc eval "global \$wpdb; \$n = 'mdmfa_credentials' === '$t' ? \$wpdb->base_prefix . '$t' : \$wpdb->prefix . '$t'; echo (int) ( \$n === \$wpdb->get_var( \$wpdb->prepare( 'SHOW TABLES LIKE %s', \$wpdb->esc_like( \$n ) ) ) );")
	expect "table $t exists" 1 "$got"
done

expect "db version" 2 "$(wpc option get mdmfa_db_version)"
slug=$(wpc eval '$o = get_option( "mdmfa_login" ); echo is_array( $o ) ? $o["slug"] : "";')
if [[ "$slug" =~ ^[a-z0-9]{12}$ ]]; then pass "login slug generated"; else fail "login slug: '$slug'"; fi
expect "settings seeded" required "$(wpc eval '$s = get_option( "mdmfa_settings" ); echo $s["roles"]["administrator"]["policy"] ?? "";')"
expect "mdmfa_login autoloads" 1 "$(wpc eval 'global $wpdb; echo (int) in_array( $wpdb->get_var( "SELECT autoload FROM $wpdb->options WHERE option_name = \"mdmfa_login\"" ), array( "yes", "on", "auto-on" ), true );')"
expect "mdmfa_settings does not autoload" 0 "$(wpc eval 'global $wpdb; echo (int) in_array( $wpdb->get_var( "SELECT autoload FROM $wpdb->options WHERE option_name = \"mdmfa_settings\"" ), array( "yes", "on", "auto-on" ), true );')"

echo "== wp mdmfa"
status=$(wpc mdmfa status --format=json)
echo "$status"
expect "status: schema current" true "$(php -r 'echo json_decode($argv[1], true)["schema_current"] ? "true" : "false";' "$status")"
expect "status: key ok" true "$(php -r 'echo json_decode($argv[1], true)["key_ok"] ? "true" : "false";' "$status")"
case "$status $(wpc mdmfa status)" in
	*"$slug"*) fail "status output leaks the login slug" ;;
	*) pass "status output does not contain the login slug" ;;
esac
wpc mdmfa disable-check

echo "== escape hatch"
wpc config set MDMFA_DISABLE true --raw --type=constant --quiet
out=$(wpc mdmfa disable-check 2>&1 || true)
case "$out" in *"OFF"*) pass "MDMFA_DISABLE reported" ;; *) fail "disable-check: $out" ;; esac
expect "no upgrade hook while disabled" 0 "$(wpc eval 'echo (int) has_action( "plugins_loaded", array( MaxtDesign\Mfa\Install\Installer::class, "maybe_upgrade" ) );')"
wpc config delete MDMFA_DISABLE --type=constant --quiet

echo "== seed everything uninstall must remove"
for key in mdmfa_totp mdmfa_totp_step mdmfa_totp_pending mdmfa_recovery mdmfa_email mdmfa_user_handle mdmfa_enrolled mdmfa_grace_started mdmfa_failures mdmfa_trusted mdmfa_prefs mdmfa_future_key; do
	wpc user meta add 1 "$key" x --quiet
done
wpc transient set mdmfa_status_cache x 900 --quiet
wpc transient set mdmfa_ipthrottle_abc123 x 600 --quiet
wpc option update mdmfa_notices '[]' --quiet
wpc cron event schedule mdmfa_purge now daily --quiet
if [ "$MODE" = multisite ]; then
	wpc transient set mdmfa_status_cache x 900 --network --quiet
	wpc --url="$(wpc option get home)/two/" transient set mdmfa_ipthrottle_def x 600 --quiet
fi
wpc option add unrelated_keep_me yes --quiet
before=$(count_rows)
if [ "$before" -gt 10 ]; then pass "seeded $before mdmfa_ rows"; else fail "seeding produced only $before rows"; fi

echo "== uninstall"
if [ "$MODE" = multisite ]; then
	wpc plugin deactivate "$SLUG" --network --quiet
else
	wpc plugin deactivate "$SLUG" --quiet
fi
expect "deactivation removes nothing" 1 "$([ "$(count_tables)" -gt 0 ] && echo 1 || echo 0)"
wpc plugin uninstall "$SLUG" --quiet
expect "tables after uninstall" 0 "$(count_tables)"
expect "mdmfa_ rows after uninstall (options, transients, user meta, sitemeta, cron)" 0 "$(count_rows)"
expect "unrelated option untouched" yes "$(wpc option get unrelated_keep_me)"

echo
if [ "$FAILS" -eq 0 ]; then echo "SMOKE PASSED ($MODE)"; else echo "SMOKE FAILED ($MODE): $FAILS"; exit 1; fi
