# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P1, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased development build).

## Status
Build phase. P1 (scaffold) is on `main`: header + bootstrap, PSR-4 `src/`, schema v1 (3 tables),
settings model with defaults, encryption service (plan 6.5), `MDMFA_DISABLE`, `wp mdmfa status` /
`disable-check`, uninstall, deliverable set, CI. No login behaviour exists yet: no interception,
no screens, no front-end output. Nothing is released; wp.org does not serve this plugin.

## Locked decisions
- 2026-09-30: brief approved; plan ACCEPTED with every section 16 decision as recommended
  ([plan](plan-maxtdesign-mfa.md) section 16). PHP floor 8.3, WP 7.0 / tested 7.1, WC 11.0 / 11.1.
- 2026-09-30: suite-core not vendored (decision 1); in-house WebAuthn verifier (decision 3,
  [eval](webauthn-library-eval.md)); 1.0 waits for the external WebAuthn review (decision 4).
- 2026-09-30 (P1): the plugin loads its own classes (`spl_autoload_register` in the main file), so
  the zip carries no `vendor/`; `.distignore` excludes `/vendor` (no path repos exist). Composer
  holds dev tools only.
- 2026-09-30 (P1): base64 for secrets and keys goes through `sodium_bin2base64`/`sodium_base642bin`
  (constant time; WP's sodium_compat provides both, checked in a WP 7.0 tree).

## Next actions
1. [operator] Review P1 and say go for P2 (plan section 14). Answer the P1 flags below that
   need a decision (unlisted-role defaults, passwordless default).
2. [session] P2 on `feat/core-auth`: policy engine, interception (4.2), pending records,
   completion (4.4), session stamp, TOTP + QR SVG (pick the encoder; licenses UNVERIFIED), recovery
   codes, challenge/enroll/grace screens on `wp-login.php`, throttles + lockout, bypass guard, My
   security (TOTP, recovery), CLI reset/unlock/status. Integration tests per the P2 DoD.
3. [session] P2 also adds: `deleted_user` / `wpmu_delete_user` cleanup, `mdmfa_purge` cron
   scheduling, and the privacy exporter/eraser skeleton (plan 6.6; not in P1).
4. [operator] Optional: install PHP 8.3 locally (WSL Ubuntu 24.04 has `php8.3-cli` in apt; needs
   sudo). Until then local runs use XAMPP PHP 8.2.12 and CI is the authority for 8.3+.

## External relationships
- Vendored libs: none. Runtime Composer deps: none. Path repositories: none.
- Sibling plugins: integrates opportunistically with suite-core (P7) and maxtdesign-cache hooks
  (P4); never `commerce-core`. REST blocking stays with REST API Control.
- SSOT touchpoints: none (no lic rows; free only).
- External services: wp.org SVN (account `slaacr`) at P9. The plugin makes no outbound HTTP.

## Verification state
- 2026-09-30, local (Windows, XAMPP PHP 8.2.12 host; composer `config.platform.php` 8.3.0,
  `platform-check` off so the 8.2 host can run the dev tools): PHPUnit 11.5.56 **60 tests, 693
  assertions, green**; PHPStan 2.2.16 **level 8, 0 errors** (phpVersion 80300, WordPress stubs
  7.1.0, WooCommerce stubs 11.1.2); PHPCS (WPCS 3.4.1) **0 errors, 0 warnings**; size-check
  self-test 7/7 and budgets PASS (0 assets). Outbound-HTTP grep over shipped code: 0 hits.
- 2026-09-30: `plugin-deliverables.php .` **PASSED 14/14, 0 warnings**; `plugin-versions.php .`
  **PASSED, 0 FAIL, 0 WARN** (Tested up to 7.1 = current 7.1.2; WC tested 11.1). Commit gate passed
  on every P1 commit, no bypass.
- 2026-09-30: `build-dist.php` zip = **15 files** (main file, uninstall, readme, `languages/`, 11
  `src/` classes; no `vendor/`, `tests/`, `docs/`); `preflight-vendor.php --zip` PASSED (2 expected
  WARNs: no vendor by design). Outbound-HTTP grep (`wp_remote_|curl_|file_get_contents(http`,
  plus `fsockopen|wp_safe_remote_` in CI) over shipped code: **0 hits**.
- 2026-09-30, CI run 36761775372 on commit `9a59494`, 12/12 jobs green: `php -l` 26 files on
  8.3 / 8.4 / 8.5; PHPUnit 11.5.56 **60 tests, 693 assertions** on 8.3, 8.4 and 8.5 (8.5.11);
  PHPStan level 8 0 errors; PHPCS 0; size-check self-test + budgets PASS; **WordPress 7.1.2 + MySQL
  8.0 smoke** on 8.3 and 8.5, single site and multisite: activation creates the 3 tables (5 with a
  second site), options and slug; `mdmfa_login` autoloads, `mdmfa_settings` does not;
  `wp mdmfa status` shows schema current + key ok and never the slug; `MDMFA_DISABLE` reported and
  removes the upgrade hook; uninstall after seeding 21 (single) / 30 (multisite) `mdmfa_` rows
  leaves **0 tables and 0 rows** (options, transients, user meta, sitemeta, cron); an unrelated
  option survives. First run (36761515039) failed only in the single-site smoke script itself
  (`switch_to_blog()` without multisite), fixed in `9a59494`.
- Not yet applicable: footprint audit (no output exists), security audit (P8), compat matrix (P8).

## History
- [brief-maxtdesign-mfa.md](brief-maxtdesign-mfa.md): approved brief, FluentAuth teardown, v1 scope.
- [plan-maxtdesign-mfa.md](plan-maxtdesign-mfa.md): accepted build plan, phases P1-P9, decisions.
- [webauthn-library-eval.md](webauthn-library-eval.md): WebAuthn library comparison; in-house verifier.
  All three moved here from `projects/plugin/_handoffs/` on 2026-09-30; pointers remain there.

## Flags
- 2026-09-30: **P1 is the initial commit on `main`, not a PR.** The repo was empty (no `main` to
  branch from or merge into). From P2 on: `feat/{slug}` branches, squash PRs, `--delete-branch`.
- 2026-09-30: roles the brief and plan do not name (author, contributor, subscriber, custom roles)
  default to **Optional with staff-safe factors** (no email code, no email recovery). Passwordless
  defaults to **off** for every role (the plan leaves both open). Operator to confirm before P2.
- 2026-09-30: `php-stubs/wp-cli-stubs` 2.12 caps `wordpress-stubs` below 7.0, so PHPStan uses the
  7.1 stubs plus a minimal local `stubs/wp-cli.php`. Mirrored to the improvement log.
- 2026-09-30: no PHP 8.3 on this machine (XAMPP 8.2.12; LocalWP ships 8.2 only; WSL has no PHP and
  needs sudo). Mirrored to the improvement log.
- 2026-09-30: the registry row still cites `_handoffs/` paths for the brief and plan; they now
  point here. Mirrored to the improvement log (shared asset, not edited).
