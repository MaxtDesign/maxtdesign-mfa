# Handoff for the next session: maxtdesign-mfa

Written 2026-10-01 at the end of the session that built P1 to P8 and the passkeys-beta change.
Paste everything below the line into a fresh session opened in
`C:/maxt/projects/plugin/maxtdesign-mfa`.

---

You are picking up the MaxtDesign MFA plugin (`maxtdesign-mfa`) from a previous session that
ran out of room. Start by reading `docs/STATE.md`; it is authoritative. The wp-plugin skill
applies as usual.

## Where things stand

- `main` is at `f179387` (PR #8, squash). The plugin is feature complete: authenticator apps,
  recovery codes, emailed codes, trusted devices, email recovery, side-door policy, a moved
  login address, settings screens, status contract, privacy tools, multisite support.
- Passkeys are an **opt-in beta**: off for every role by default, a second step only, and
  passkey-only sign-in exists only with `define( 'MDMFA_PASSKEY_ONLY_SIGNIN', true )`. No
  "audited" or "reviewed" claim anywhere. Do not loosen any of this.
- Operator decisions that stand: the conflict detector warns and keeps enforcing; multisite is
  network-activated only; no paid external review (plan decision 4 was amended in place).
- **Distribution is undecided.** The plugin is not approved for WordPress.org and may never be
  listed there. Do no SVN work, no wp.org submission, no 1.0 version bump and no release gate
  until the operator names the channel. If the channel changes, the plugin's shape in the
  wp-plugin skill changes with it.
- The runtime code the independent review examined (`242d761`) is the same code that is on
  `main`: `242d761` became PR #8's squash commit `f179387`, and the only later commit on that
  branch (`a5c7586`) was documentation. Nothing has fixed either finding below yet. Check
  `git log` for anything newer before you start.
- Branch `docs/session-handoff` (PR open, not merged) only adds this file and the distribution
  note in `docs/STATE.md`. Merge it or build on it, as the operator prefers.

## Your task (operator's instructions, verbatim)

Address the two findings from Codex's independent MFA plugin review.

Repository:
C:/maxt/projects/plugin/maxtdesign-mfa

Read thoroughly before editing:
- Applicable AGENTS.md/CLAUDE.md instructions
- C:/maxt/ops/sops/agent-sops/maxtdesign-quality-standard.md
- Current plugin STATE, build plan, and beta decisions
- C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-review-20261001/REVIEW.md
- C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-review-20261001/STAGING-E2E-PLAN.md

The review examined runtime code at 242d761. Final observed HEAD was a5c75867dc75389e662b1a9138cc80e543da009d, a documentation-only update. Inspect subsequent changes and existing work before proceeding; don't overwrite or redo completed fixes.

Fix and add meaningful regression coverage for:

1. HIGH: Multisite policy downgrade
   src/Policy/Policy.php:70-78 promotes only the policy mode while retaining weaker current-site recovery, grace, and application-password settings. The reproduction uses a strict administrator membership on one site and a customer membership on another. Effective policy becomes Required but still permits immediate email recovery, seven days' grace, and application passwords.
   Establish coherent network-wide enforcement, including conflicting/equal-rank configurations. Verify recovery/reset consequences and both site entry points, not just the returned policy enum.

2. MEDIUM, staging blocker: WooCommerce intercepts admin security forms
   src/WooCommerce/SecurityEndpoint.php:108-120 accepts the shared form on wp_loaded before AccountPage handles it. Initial admin TOTP enrollment saves successfully, but recovery codes remain in the WooCommerce presenter; the admin handler then reports setup_expired without displaying them.
   Make dispatch exclusive to the intended presenter while preserving nonce, capability, and ownership checks. Verify exactly-once execution and correct redirects/code presentation for both wp-admin and My Account, including TOTP, passkeys, recovery-code regeneration, and step-up.

Private reproduction and results:
C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-review-20261001/reproduce.php
C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-review-20261001/reproduction-results.json

These probes use actual plugin classes with in-memory WordPress shims; they are not full browser or multisite HTTP tests. The existing suite passed 305 tests / 1,607 assertions and asset budgets passed, so those results alone do not close the findings.

Implement the fixes, run relevant regressions and required project checks, and validate actual WordPress/WooCommerce request ordering in a disposable local environment. Use a separate multisite fixture for the network issue. Preserve the original independent-review evidence; save new fix/verification evidence separately.

Keep current passkey beta restrictions and operator decisions intact. Update project documentation with the changes, evidence, and any remaining unverified checks.

Do not install on shared staging or production as part of this task. For junction-mounted plugin copies, deactivate, never delete. Preserve unrelated work and shared-record ownership.

Finish with the exact commit/diff, tests and reproduction results, remaining limitations, and whether the two findings are ready for independent re-review. Do not claim staging acceptance or a formal security audit.

## Pointers from the session that wrote the code (not instructions; verify against source)

Finding 1, multisite policy:
- `Policy::effective()` calls `Policy::network_floor()`, which returns only a policy string and
  raises `$best['policy']`. Everything else in `$best` (factors, `grace_days`, `email_recovery`,
  `recovery_wait_hours`, `app_passwords`, `trusted_devices`, `passwordless`) still comes from
  the current site's role. That was a deliberate shortcut in P8 and is the bug.
- Readers of those keys: `Policy::allows()`, `Policy::grace_remaining()`,
  `EmailRecovery::allowed()` and its wait in `EmailRecovery::handle()`,
  `SideDoors::app_passwords_for_user()`, `TrustedDevice::allowed()`, `EmailCode::allowed()`,
  `Passkeys` (passwordless). Each needs the network-wide answer.
- `network_floor()` must not call `switch_to_blog()`, `get_blog_option()` or
  `get_blogs_of_user()`: all three switch blogs, which re-enters `determine_current_user` during
  application-password authentication and recurses until memory runs out. It reads the user's
  sites from their `{prefix}{N_}capabilities` meta keys and each site's settings row with a
  direct query. Keep that property.
- Existing coverage: `tests/Unit/Policy/PolicyTest.php` (two network tests) and
  `tests/E2e/MultisiteTest.php` assert the policy and the login decision only, which is why
  this was missed.

Finding 2, WooCommerce intercepting admin forms:
- `SecurityEndpoint::handle_post()` is hooked on `wp_loaded`, and `AccountPage::handle()` on
  `load-{hook}`. Both accept a POST with `mdmfa_op` and a nonce for `SecurityActions::NONCE`
  (`mdmfa_account`), so with WooCommerce active the first one runs for wp-admin posts too.
- The P8 admin audit listed "the WooCommerce handler double-running on wp-admin posts" under
  remaining uncertainty as reasoned, not tested. The CI suites never caught it because
  `e2e-wc` does not exercise the wp-admin security page and `e2e` has no WooCommerce.
- An explicit presenter marker in the form, or a check that the request is the My Account
  endpoint (not `is_admin()`), are the obvious shapes; `SecurityView::form_start()` builds the
  form for both presenters.

## Local tooling (see the project memory files; scratch paths from the old session are gone)

- PHP 8.3: `%APPDATA%/Local/lightning-services/php-8.3.29+1/bin/win64/php.exe`, with `PHPRC`
  pointing at an ini that sets `extension_dir` and loads sodium, openssl, zip, mbstring, curl,
  mysqli; `OPENSSL_CONF` at that build's `extras/ssl/openssl.cnf`. XAMPP's PHP is 8.2 and is
  too old (that is what Codex's sandbox found).
- Checks: `vendor/bin/phpcs`, `vendor/bin/phpstan analyse --memory-limit=2G`,
  `vendor/bin/phpunit` (unit), `php tools/size-check.php`.
- End-to-end locally: a throwaway WordPress with XAMPP's MariaDB on a scratch data dir and
  `php -S` with `tests/e2e-fixtures/router.php` (the router understands subdirectory
  multisite). Env: `MDMFA_E2E_URL`, `WP_PATH`, `MDMFA_E2E_WP_CMD`. Copy WordPress core and
  WooCommerce from the `plugin-test` Local site; never junction the plugin into a scratch
  site. Windows `php -S` has one worker, so race tests only mean something in CI.
- CI runs `e2e`, `e2e-wc` and `multisite` suites on PHP 8.3 and 8.5. The `compat` jobs are
  informational; Wordfence, Ultimate Member and Limit Login Attempts Reloaded fail there for
  known reasons (`docs/compat-matrix-p8.md`).
- When generating PHP from a Python script, use raw strings: `\b` in a normal string becomes
  a backspace byte. Shell heredocs containing PHP sometimes fail to parse; write a script file.

## Working rules that applied all session

- One branch per change off `main`, Conventional Commits, PR, squash merge with
  `--delete-branch`, and only when the operator says to merge.
- Update `docs/STATE.md` before finishing. Shared-asset observations go to
  `C:/maxt/ops/sops/agent-sops/improvement-log.md`.
- Report with numbers, say what is unverified, and stop for the operator after opening the PR.
