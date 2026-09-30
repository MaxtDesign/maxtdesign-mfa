# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P3, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2 and P3 folded into it, nothing on wp.org).

## Status
Build phase. `main` = P1 + P2 (core auth, merged 2026-09-30 as `5d454ce`, PR #1). P3 (customer
path) is on `feat/customer-path`, CI green, PR open for operator review: the challenge state
machine is one shared `ChallengeFlow` rendered by two presenters (core login screen, WooCommerce
My Account via a `wc_get_template` swap); customer-side contexts (WC login, checkout login,
front-end forms, other plugins' posts and AJAX, guard-caught cookies heading to the front end)
finish on My Account; WC's reset auto-login becomes a challenge; My Account Security tab; neutral
`admin-post` handler for `wp_login_form()`. Not yet built: login location (P4), passkeys (P5),
email code / side-door settings (P6), admin settings screens and privacy tools (P7).

## Locked decisions
- 2026-09-30: brief approved; plan ACCEPTED with every section 16 decision as recommended
  ([plan](plan-maxtdesign-mfa.md) section 16). PHP floor 8.3, WP 7.0 / tested 7.1, WC 11.0 / 11.1.
- 2026-09-30: suite-core not vendored (decision 1); in-house WebAuthn verifier (decision 3,
  [eval](webauthn-library-eval.md)); 1.0 waits for the external WebAuthn review (decision 4).
- 2026-09-30 (P1): own autoloader, no `vendor/` in the zip; base64 via libsodium codecs.
- 2026-09-30 (operator): unlisted roles default to Optional with staff-safe factors; passwordless
  defaults to off for every role.
- 2026-09-30 (P2): in-house QR encoder (versions 1-40, zbar-verified); `mdmfa_totp_step` meta for
  atomic replay protection; `mdmfa_pending.attempts`; `mdmfa_log.detail`; recovery-code CAS.
- 2026-09-30 (P3): My Account Security endpoint key `mdmfa-security` (prefixed), URL slug
  `security` (filter `mdmfa_account_endpoint_slug`); rewrite rules flushed once per
  `SecurityEndpoint::REWRITE_VERSION` via autoloaded `mdmfa_rewrite_version`. Challenge template
  overridable at `{theme}/maxtdesign-mfa/challenge.php`.

## Next actions
1. [operator] Review the P3 PR and approve the squash merge (`--delete-branch`).
2. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (see Flags).
3. [session] P4 on `feat/login-location` after operator go: early routing (5.1), 404 rules and
   allow-list (5.2), URL rewrites (5.3), slug lifecycle + collision checks + admin email (5.4),
   recovery constants/CLI (5.5), cache integration (5.6), `SCRIPT_NAME`/`is_login()` test. P4 also
   decides the public login page (decision 8) that LoginForm's failure redirect and the core
   `login_url` should use; P3 falls back to My Account or `wp_login_url()`.
4. [session] P7: privacy exporter/eraser + policy text (plan 6.6).
5. [operator] Optional: install PHP 8.3 locally (WSL Ubuntu 24.04 `php8.3-cli`, needs sudo).

## External relationships
- Vendored libs: none. Runtime Composer deps: none. Path repositories: none.
- WooCommerce (optional): hooks `wc_get_template`, `woocommerce_login_credentials`,
  `woocommerce_login_redirect` (applied), `woocommerce_get_query_vars`,
  `woocommerce_account_menu_items`, `woocommerce_account_mdmfa-security_endpoint`; tested 11.1.2.
- Sibling plugins: suite-core (P7) and maxtdesign-cache (P4), opportunistic; never `commerce-core`.
- External services: wp.org SVN (account `slaacr`) at P9. The plugin makes no outbound HTTP.

## Verification state
- 2026-09-30, P3, CI run 36769316769 on `feat/customer-path`, **17/17 jobs green**:
  - Unit: PHPUnit 11.5.56, **112 tests, 1,009 assertions** on PHP 8.3, 8.4, 8.5.
  - **E2E core (WordPress 7.1.2, no WooCommerce), PHP 8.3 + 8.5: 15 tests, 82 assertions**: every
    P2 DoD item still passes after the ChallengeFlow refactor.
  - **E2E WooCommerce 11.1.2 (classic checkout, COD, virtual product), PHP 8.3 + 8.5: 9 tests,
    120 assertions.** Every P3 DoD item: customer second step on My Account with no request or
    redirect to `wp-login.php` (asserted over each flow's full URL history, not a server log);
    reset auto-login gives no session (guard detail `wc_set_customer_auth_cookie`), then the
    challenge, then `password-reset=true`; checkout login returns to checkout with the cart;
    new-account checkout (`wc-ajax=checkout`) still logs in; no plugin `<script>`/`<link>`/
    `<style>` on My Account, the challenge, checkout or the Security tab. Also: recovery code +
    start over on My Account, front-end `wp_login_form()` via the neutral handler (enrolled,
    not enrolled, wrong password), another plugin's form post, AJAX login error with link,
    Security tab enroll / recovery codes / removal.
  - QR decode (versions 1-40), smoke (single + multisite), lint 8.3/8.4/8.5, outbound grep 0.
  - PHPStan level 8: 0 errors (CI memory limit raised to 2 GB after a worker OOM; not a finding).
    PHPCS: 0.
- 2026-09-30, P2 (CI run 36766603241, merged): 16/16 green; the numbers above include it.
- 2026-09-30: `plugin-deliverables.php .` PASSED 14/14; `plugin-versions.php .` 0 FAIL, 0 WARN.
  Commit gate passed on every commit, no bypass.
- Local runs: Windows, XAMPP PHP 8.2.12 (`config.platform.php` 8.3.0, `platform-check` off).
- Not yet done: footprint audit with numbers (P5/P8), security audit (P8), compat matrix incl.
  block checkout, Store API new-account and coming-soon mode (P8), manual browser pass.

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
- 2026-09-30 (P3): the plan's P3 DoD says "E2E on Studio"; it ran in CI instead (real WordPress
  7.1.2 + WooCommerce 11.1.2 + MySQL 8.0), because no local PHP 8.3 exists for Studio. "Customer
  never loads wp-login.php" is asserted over each flow's URL history rather than a server log.
  Store API (block checkout) new-account login and coming-soon mode are not covered yet (P8).
- 2026-09-30 (P3): WooCommerce's lost-password code was read in the local 11.0.0 tree (no 11.1.2
  source on disk); CI proved the behaviour on 11.1.2.
- 2026-09-30 (P2): deviations for operator awareness: the record burns on the 5th wrong code; setup
  typos count toward the per-record cap only; the guard resets the current user to 0 for the rest
  of a blocked request; the challenge accepts any enrolled factor (role allow-lists apply at
  enrollment).
- 2026-09-30: `wp-login.php` sets `$interim_login` after `login_form_{action}` fires (WP 7.0 tree,
  lines 574 vs 571), so the challenge handler sets that global itself.
- 2026-09-30: `php-stubs/wp-cli-stubs` 2.12 caps `wordpress-stubs` below 7.0 (improvement log).
- 2026-09-30: no PHP 8.3 on this machine (improvement log).
- 2026-09-30: the registry row still cites `_handoffs/` paths for the brief and plan (improvement log).
