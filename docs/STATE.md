# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P2, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2 folded into it, nothing on wp.org).

## Status
Build phase. `main` = P1 scaffold. P2 (core auth) is on `feat/core-auth`, CI green, PR open for
operator review: interception at `authenticate`@PHP_INT_MAX, pending records (atomic single use,
DB-enforced 5-attempt cap), the blessed completion routine with session stamp, TOTP + recovery
codes, grace prompt and in-flow enrollment on `wp-login.php` (in-house QR SVG), backoff/lockout,
bypass guard, My security with step-up, `wp mdmfa unlock` / `user status|reset`, daily purge cron,
user-deletion cleanup. Schema v2. Not yet built: WC customer path (P3), login location (P4),
passkeys (P5), email code / side-door settings (P6), admin settings screens (P7).

## Locked decisions
- 2026-09-30: brief approved; plan ACCEPTED with every section 16 decision as recommended
  ([plan](plan-maxtdesign-mfa.md) section 16). PHP floor 8.3, WP 7.0 / tested 7.1, WC 11.0 / 11.1.
- 2026-09-30: suite-core not vendored (decision 1); in-house WebAuthn verifier (decision 3,
  [eval](webauthn-library-eval.md)); 1.0 waits for the external WebAuthn review (decision 4).
- 2026-09-30 (P1): own autoloader, no `vendor/` in the zip; `.distignore` excludes `/vendor`.
  Base64 for secrets and keys via libsodium's constant-time codecs.
- 2026-09-30 (operator): unlisted roles default to Optional with staff-safe factors; passwordless
  defaults to off for every role.
- 2026-09-30 (P2, Build choices within the plan): QR encoder written in-house (server-side SVG,
  byte mode, versions 1-40, zbar-verified in CI) instead of vendoring a candidate; TOTP last step
  in its own meta row `mdmfa_totp_step` (atomic conditional UPDATE; plan 6.2 had it inside
  `mdmfa_totp`); `mdmfa_pending.attempts` column for an atomic attempt cap; `mdmfa_log.detail`
  for the bypass source; recovery codes spent by compare-and-swap.

## Next actions
1. [operator] Review the P2 PR and approve the squash merge (`--delete-branch`).
2. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (GitHub made
   it default because it was pushed first; see Flags).
3. [session] P3 on `feat/customer-path` after operator go: My Account + checkout challenge/enroll
   (`wc_get_template` swap), WC reset auto-login conversion (the guard already blocks it; P3 routes
   it to My Account), My Account Security endpoint, neutral `admin-post` handler, `unknown-post` /
   `ajax` handling. E2E on WC 11.1.2 per the P3 DoD.
4. [session] P7 (not P2, per plan 6.6 / section 14): privacy exporter/eraser + policy text.
5. [operator] Optional: install PHP 8.3 locally (WSL Ubuntu 24.04 `php8.3-cli`, needs sudo).
   Until then local runs use XAMPP PHP 8.2.12 and CI is the authority for 8.3+.

## External relationships
- Vendored libs: none. Runtime Composer deps: none. Path repositories: none.
- Sibling plugins: integrates opportunistically with suite-core (P7) and maxtdesign-cache hooks
  (P4); never `commerce-core`. REST blocking stays with REST API Control.
- SSOT touchpoints: none (no lic rows; free only).
- External services: wp.org SVN (account `slaacr`) at P9. The plugin makes no outbound HTTP.

## Verification state
- 2026-09-30, P2, CI run 36766603241 on `feat/core-auth` (`59e16d8`), **16/16 jobs green**:
  - PHPUnit 11.5.56 unit suite **112 tests, 1,007 assertions** on PHP 8.3, 8.4, 8.5 (RFC 6238 and
    RFC 4226 vectors, RFC 4648 base32, Reed-Solomon known answer, lockout maths, policy).
  - **End-to-end suite over HTTP, WordPress 7.1.2 + MySQL 8.0, `php -S` with 4 workers, PHP 8.3
    and 8.5: 15 tests, 82 assertions.** Covers every P2 DoD item: correct password gives no
    session, no auth cookie, no `wp_login`, no `wp_login_failed`; `wp_login` fires exactly once at
    completion; two concurrent submissions of one record finish exactly one login; the 5th wrong
    code burns the record and a 6th attempt finds nothing; the 20th consecutive failure locks for
    1 h; TOTP replay rejected; recovery code works once; guard blocks a direct
    `wp_set_auth_cookie()` (session destroyed, cookie withheld, redirect rewritten, source logged)
    and passes core's re-issue on password change; interim login shows core's success page; grace
    skip (no stamp); forced enrollment after grace; XML-RPC password auth refused (403) for
    enrolled users only; `MDMFA_DISABLE` restores password-only login; home page carries no
    `mdmfa` output or cookie.
  - QR decode check: 18 payloads, versions 1-40 sampled (1, 3, 4, 6, 7, 8, 10-15, 19, 24, 30,
    35, 40) all decoded byte for byte by zbar.
  - PHPStan 2.2.16 level 8: 0 errors. PHPCS (WPCS 3.4.1): 0. `php -l` on 8.3/8.4/8.5. Smoke
    (activation/uninstall, single + multisite, schema v2): green. Outbound-HTTP grep: 0 hits.
- 2026-09-30: `plugin-deliverables.php .` PASSED 14/14; `plugin-versions.php .` 0 FAIL, 0 WARN.
  `build-dist.php` zip: 42 files, 0 from `vendor/`, `tests/`, `docs/`, `tools/`, `stubs/`.
  Commit gate passed on every commit, no bypass.
- 2026-09-30, P1 (CI run 36761775372): 60 unit tests; smoke proved activation creates 3 tables
  and uninstall leaves 0 tables and 0 `mdmfa_` rows.
- Local runs: Windows, XAMPP PHP 8.2.12 (`config.platform.php` 8.3.0, `platform-check` off).
- Not yet done: footprint audit with numbers (P5/P8: no plugin CSS/JS exists yet; home-page
  output checked in E2E only), security audit (P8), compat matrix (P8), manual browser pass.

## History
- [brief-maxtdesign-mfa.md](brief-maxtdesign-mfa.md): approved brief, FluentAuth teardown, v1 scope.
- [plan-maxtdesign-mfa.md](plan-maxtdesign-mfa.md): accepted build plan, phases P1-P9, decisions.
- [webauthn-library-eval.md](webauthn-library-eval.md): WebAuthn library comparison; in-house verifier.
  All three moved here from `projects/plugin/_handoffs/` on 2026-09-30; pointers remain there.

## Flags
- 2026-09-30: **P1 is the initial commit on `main`, not a PR** (the repo was empty). From P2 on:
  `feat/{slug}` branches, squash PRs, `--delete-branch`.
- 2026-09-30: GitHub set the default branch to `chore/p1-ci-check` (first branch pushed to the
  empty repo) and refuses to delete it. Needs an operator repo-setting change.
- 2026-09-30 (P2): deviations for operator awareness: the record burns on the 5th wrong code (the
  plan's "6th attempt" then finds no record); enrollment-confirmation typos count toward the
  per-record cap but not the per-user lockout; the guard also resets the current user to 0 for the
  rest of a blocked request; the challenge accepts any enrolled factor (role allow-lists apply at
  enrollment); P2 routes WC and front-end logins to the `wp-login.php` challenge until P3.
- 2026-09-30: `wp-login.php` sets `$interim_login` after `login_form_{action}` fires (line 574 vs
  571 in the WP 7.0 tree), so the challenge handler sets that global itself.
- 2026-09-30: `php-stubs/wp-cli-stubs` 2.12 caps `wordpress-stubs` below 7.0; PHPStan uses the 7.1
  stubs plus a minimal local `stubs/wp-cli.php`. Mirrored to the improvement log.
- 2026-09-30: no PHP 8.3 on this machine. Mirrored to the improvement log.
- 2026-09-30: the registry row still cites `_handoffs/` paths for the brief and plan. Mirrored.
