# STATE: maxtdesign-mfa
Updated: 2026-10-01 by session (Build P7, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2-P7 folded into it, nothing on wp.org).

## Status
Build phase complete through P7. `main` = P1-P6 (P6 `79ec66d` PR #5, 2026-10-01). P7 is on
`feat/admin-ux`, CI green (run 36870781642, 19/19 jobs), PR open for operator review:
- One admin entry, page `md-mfa`: Users > "Login security (MFA)" on its own, or "MFA" under the
  MaxtDesign menu when another plugin has started suite-core (`$GLOBALS['md_suite_loaded']`).
  Tabs: Policy, Factors, Login location, Side doors, Recovery, Coverage, Activity, Tools
  (filter `mdmfa_admin_tabs`, action `mdmfa_admin_tab_{slug}`). Plugins-screen Settings link.
- Saves: `admin-post.php`, nonce `mdmfa_admin`, `mdmfa_manage`, step-up for enrolled
  administrators, validation (`Settings::sanitize_role`, `clamp`, `choice`), notice codes, log
  row `policy_changed`. A Required role always keeps an authenticator app or a passkey.
- Coverage: per-user state with search and filter; bulk reset, unlock, sign out everywhere
  (needs `edit_user` on each target; a super admin only by a super admin).
- Activity: the log with an event filter; retention and IP mode settings.
- Tools: key status, conflicts, status refresh, settings export (no secrets, no slug).
- Status contract `Status\Snapshot` (15 min cache `mdmfa_status_cache`, filter `mdmfa_status`):
  feeds `wp mdmfa status [--fresh]`, the admin counts and the suite status (`md_suite_status`@5).
- Owner-set public login page (`mdmfa_login.public_login = page`, `public_page`).
- Privacy: policy text, exporter (methods, passkey names and dates, log), eraser (log rows).
- Assets, on the plugin's screen only: `assets/admin/mdmfa-admin.css` 3,506 B (budget 4,096),
  `assets/admin/mdmfa-admin.js` 1,754 B (budget 8,192): copy button and the confirm dialog
  when the suite script is absent.
Next: P8 (review, security audit, footprint audit, compatibility matrix, external WebAuthn
review), then P9 (gate and release).

## Locked decisions
- 2026-09-30: brief approved; plan ACCEPTED with every section 16 decision as recommended
  ([plan](plan-maxtdesign-mfa.md) section 16). PHP floor 8.3, WP 7.0 / tested 7.1, WC 11.0 / 11.1.
- 2026-09-30: suite-core not vendored (decision 1); in-house WebAuthn verifier (decision 3,
  [eval](webauthn-library-eval.md)); 1.0 waits for the external WebAuthn review (decision 4).
- 2026-09-30 (P1): own autoloader, no `vendor/` in the zip; base64 via libsodium codecs.
- 2026-09-30 (operator): unlisted roles default to Optional with staff-safe factors; passwordless
  defaults to off for every role.
- 2026-09-30 (P2): in-house QR encoder; `mdmfa_totp_step`; `mdmfa_pending.attempts`;
  `mdmfa_log.detail`; recovery-code CAS.
- 2026-09-30 (P3): Security endpoint key `mdmfa-security`, slug `security`; challenge template
  overridable at `{theme}/maxtdesign-mfa/challenge.php`.
- 2026-09-30 (P4): recovery-mode links stay on `wp-login.php` (see Flags: the plan's `$pagenow`
  route cannot work); the 404s render at `wp_loaded` (after blocks register), not `init`@1; core's
  `strict-origin-when-cross-origin` referrer policy is kept on the slug page.
- 2026-09-30 (P5): adding a factor (passkey or TOTP) to an already-enrolled account needs a fresh
  step-up (10 min), same as removing one; right after a 2FA login the session is fresh. Passwordless
  login challenge is stateless (nonce | ts | HMAC, 300 s) with single use via an `INSERT IGNORE`
  pending row; session/pending challenges are bound to the WP session or the pending record.
  Passwordless is offered on a login page only when some role enables it; the IP soft throttle
  (30 / 10 min, transients) covers the pre-user endpoint. Oracles `web-auth/webauthn-lib` 5.3 and
  `lbuchs/webauthn` 2.2 are require-dev only (differential tests), never shipped.
- 2026-09-30 (P6): an emailed code is sent only when the user asks (a POST), never on page load.
  A trusted-device sign-in is stamped `trusted` and never counts as a fresh verification.
  Self-removing a factor does not restart grace; only a reset (admin, CLI, email recovery) does.
  The conflict detector warns and keeps enforcing (see Flags: confirm this reading of the plan).
  Email recovery pages are plain `wp_die()` pages on `admin-post.php`, shared by staff and
  customers, so neither wp-login.php nor the slug is ever mailed or shown.
- 2026-10-01 (P7): suite mode is keyed on `$GLOBALS['md_suite_loaded']`, not on the suite classes
  existing (a vendored copy can declare them without starting the suite). Role settings are
  stored for every role on save; "Roles added later" edits `unlisted_role`. Each tab owns a
  fixed set of role keys, so saving one tab never changes another's. Administrators with no
  second step yet (in the setup period) can save without step-up, because they cannot do one.
  Sign out everywhere (Coverage) also forgets trusted devices, which closes the P6 gap.
  Screens are server-rendered with native forms; no React, no build step.

## Next actions
1. [operator] Review the P7 PR and approve the squash merge (`--delete-branch`).
2. [operator] Look at the screens on `plugin-test`: activate, then Users > Login security (MFA).
   Activation moves that site's login (`wp mdmfa slug get` prints it). Junction-mounted:
   deactivate, never delete. The manual passkey pass on real devices (P5) is still open.
3. [operator] Commission the external WebAuthn review (decision 4: 1.0 waits for it).
   Also still open: confirm the conflict-detector reading (Flags; P6 was merged without a
   decision either way, so it stays as built: warn and keep enforcing).
4. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (see Flags).
5. [session] P8 after operator go: lanes review (`wp-reviewer`), source-to-sink security audit
   (`wp-security-auditor`), footprint audit with numbers (`wp-perf-qa`), compatibility matrix
   (plan 13: multisite, Jetpack 16.2, caches, membership and security plugins, block checkout),
   escape-hatch test. Reports into `docs/`.
6. [session] P9: wp.org screenshots (need a visible browser; see Flags), version triple,
   `release-gate.php`, SVN.

## External relationships
- Vendored libs: none. Runtime Composer deps: none. Path repositories: none.
- WooCommerce (optional): `wc_get_template`, `woocommerce_login_credentials`,
  `woocommerce_login_redirect` (applied), account endpoint hooks; tested 11.1.2.
- maxtdesign-cache: `md_cache_config` (slug in `exclude_paths`), fires `md_suite_content_changed`
  per URL on slug change, calls `md_cache_regenerate_config` if it ever exists (requested hook).
- Local test site: `plugin-test` (https://plugin-test.local, WP 7.1.2, PHP 8.3.29 since
  2026-09-30, WC 10.9.4). Plugin junction-mounted there on 2026-09-30, inactive.
- External services: wp.org SVN (account `slaacr`) at P9. The plugin makes no outbound HTTP.

## Verification state
- 2026-10-01, P7, CI run 36870781642 on `feat/admin-ux` (`45951f4`), **19/19 green, first push**:
  - Unit: **294 tests, 1,549 assertions** on PHP 8.3, 8.4, 8.5. P7 adds 16 (role validation,
    Required keeps a method, clamp table, choice, save structure and autoload).
  - **E2E core, PHP 8.3 + 8.5: 55 tests, 623 assertions.** P7 adds 10: one menu entry under Users,
    8 tabs with `aria-current`, unknown tab falls back, no inline style or script in the plugin's
    markup, assets on the plugin's screen only (not on Dashboard, Users, Plugins or My security),
    script deferred, Settings link; non-managers get 403 on the page and its actions; policy save
    validates (unknown policy kept, days clamped, Required keeps the authenticator app,
    passkey-only needs the passkey method) and other tabs' fields survive; side doors, recovery,
    factors and log settings save with safe fallbacks; a missing or wrong nonce and a GET change
    nothing (403); an enrolled administrator with a stale verification is refused for settings,
    the login address and user resets, and allowed after step-up; login address change from the
    screen (bad value refused, old address 404, admins emailed) and the public login page;
    coverage reset (user mailed, log names the actor), unlock, sign out everywhere; **`wp mdmfa
    status --format=json` equals the Policy tab's per-role users and set-up counts and the
    Coverage total**; the status, the `mdmfa_status` build and the settings export contain no
    login address, no key material, no factor data and no user names; cache vs `--fresh`;
    privacy export and erase.
  - E2E WooCommerce 12 tests, 370 assertions (unchanged). Fuzz, smoke, QR, lint, outbound grep 0,
    PHPStan L8 0, PHPCS 0, size check, `node --check` on both scripts.
- 2026-10-01, local, throwaway WordPress in a real browser (Chromium pane):
  - Nav handoff section 8 and admin UI handoff section 10, checked: 194 controls across the 8 tabs,
    **0 without a label**; every `widefat` table inside a focusable `role="region"`; every `th`
    scoped; no positive `tabindex`; one `h1`; badge contrast 4.76 (good), 4.84 (warn), 5.91
    (bad), 13.95 (neutral) against a 4.5 bar; confirm dialog opens with Cancel focused, Cancel
    removes it and returns focus, nothing submits; 0 console errors; no raw hex in the admin
    CSS except canonical token fallbacks.
  - **Suite mode with suite-core 1.5.1 started by an mu-plugin:** "MFA" under the MaxtDesign menu
    and gone from Users; suite stylesheet and script load on the page and not on the Dashboard;
    Overview lists `maxtdesign-mfa`; Settings link points at `admin.php?page=md-mfa`;
    `md_suite_status` carries the contribution with no login address.
- 2026-10-01, local: **Plugin Check on `plugin-test`: "No errors found"** with the P7 code.
- UNVERIFIED (P7): a real keyboard-only pass by a person (the checks above are programmatic);
  a stale suite-core (older than 1.3) winning the load race (guards are in place, not run);
  screen readers; the screens at narrow widths; multisite network admin.
- 2026-09-30, P6, CI run 36814321766 on `feat/email-code-side-doors` (`0787d6a`), **19/19 green**:
  - Unit: **278 tests, 1,521 assertions** on PHP 8.3, 8.4, 8.5. P6 adds 22: email code (single use,
    purpose and user binding, expiry, fifth miss destroys, 3/15 min and 10/day, filter validation),
    trusted device (off by default, per-user, expiry, max 10, password change revokes, lifetime),
    side doors (per-role, off, on, never re-enables what core disabled, XML-RPC modes, hourly
    log), Jetpack module filter, conflict filter.
  - **E2E core, PHP 8.3 + 8.5: 45 tests, 429 assertions.** P6 adds 15, the plan 4.3 side-door
    rows and the DoD: application password works for an enrolled Optional user with no second
    step and no session; refused (401) for a Required role, works when the owner allows it, off
    site-wide; account password never works as Basic auth; REST password endpoint refused (403
    `mdmfa_required`, no pending record, wrong password not distinguishable); XML-RPC refuses the
    password with a helpful error, accepts an application password, `allow` and `off` modes;
    creating an application password is 201 when fresh, 403 `mdmfa_stepup_required` when stale,
    201 after step-up, and 403 when authenticated by an application password; email code setup
    and sign-in (sent only on request, bound to its pending login, never names the slug); the
    fourth send in 15 minutes is refused across pending logins; trusted device skips the
    challenge, is HttpOnly + SameSite=Lax, is not a fresh verification, fails with a wrong
    password, and is revoked by a password change, by factor removal, and never set when the
    role disallows it; email recovery (GET changes nothing, forged POST 403, single use, never
    signs in, user mailed), staff 24 h wait, cancelled by a real sign-in, applied after the wait
    with a fresh grace period; not offered to staff by default.
  - **E2E WooCommerce, PHP 8.3 + 8.5: 12 tests, 370 assertions.** Adds: a customer turns on
    email codes on the Security tab, signs in on My Account with one, and resets by email; the
    mail and the result page never contain the slug or wp-login.php.
  - Fuzz (4M inputs, 0 crashes), smoke, QR, lint, outbound grep 0, PHPStan L8 0, PHPCS 0, size.
- 2026-09-30, local: **Plugin Check on `plugin-test`: "No errors found"** with the P6 code.
- 2026-09-30, local: core E2E (42 of 45; the 3 skipped need multiple server workers or bare `wp`)
  and the new WooCommerce test also passed against a throwaway WordPress (scratch MariaDB,
  `php -S`, WooCommerce 10.9.4 copied from `plugin-test`), removed after.
- UNVERIFIED (P6): Jetpack itself (the `jetpack_get_available_modules` block, SSO through the
  guard, `jetpack.*` XML-RPC) was not run; only the filter callback is unit-tested. Real mail
  delivery. The authorize-application.php step-up path has no E2E (the REST path does).
- 2026-09-30, P5, CI run 36790291991 on `feat/passkeys` (`a589250`), **19/19 jobs green**:
  - Unit: **256 tests, 1,413 assertions** on PHP 8.3, 8.4, 8.5; of these **129 WebAuthn tests**
    (CBOR, verifier negatives per check, all three algorithms) incl. **34 differential tests**
    against both oracles: ours never accepts what an oracle rejects; every case where we are
    stricter is listed and checked strictly (see Flags).
  - **Fuzz: 4,000,000 inputs** (1M fixed seed 20260930 + 1M random seed, on PHP 8.3 and 8.5),
    7 targets: **0 crashes, 0 hangs, slowest input 0.9 ms** (limit 250 ms).
  - **E2E core, PHP 8.3 + 8.5: 30 tests, 298 assertions.** P5 adds 6: add a passkey on My
    security (options: RP ID, algs -7/-257/-8, attestation none, random user handle), replayed
    registration adds nothing, passkey offered first as second factor, tampered signature refused,
    session stamped `passkey`; adding to an enrolled account refused on a stale session and allowed
    after step-up; passwordless (Ed25519) for an enabled role logs in once (wp_login once, stamp,
    log) and a replayed assertion fails; passwordless refused without UV, with a wrong userHandle,
    from a foreign origin, and for a role without passwordless (with the right message); counter
    anomaly flagged, logged, shown to the owner, not blocked by default; the module loads only
    on screens offering a passkey (deferred, once), never on the front end.
  - **E2E WooCommerce, PHP 8.3 + 8.5: 11 tests, 320 assertions.** Adds: customer adds a passkey on
    the Security tab (codes shown once) and finishes a My Account sign-in with it, never touching
    wp-login.php or the slug. The Security tab now loads the passkey module (by design: it offers
    a passkey); still no plugin CSS.
  - Smoke (single + multisite), QR decode, lint, outbound grep 0, PHPStan L8 0, PHPCS 0, size check
    (passkey-js 1,838 / 3,072 B raw, 977 / 1,536 B gzip), `node --check`.
- 2026-09-30, local: **Plugin Check on `plugin-test` (WP 7.1.2, PHP 8.3.29): "No errors found"**
  with the P5 code (plugin inactive; dev folders excluded per `.distignore`).
- 2026-09-30, local: the P5 E2E tests were also run against a throwaway WordPress (scratch
  MariaDB on port 3399, `php -S`, removed after) via the new `MDMFA_E2E_WP_CMD` override.
- UNVERIFIED: real browsers and authenticators (Chrome, Safari, Firefox, Android, iOS, Windows
  Hello, YubiKey), conditional UI autofill, and the JS module's behaviour in a browser. Only a
  software authenticator over HTTP was tested; the module passed `node --check` only.
- Earlier phases (P4 CI run 36779146610, 17/17 green) are unchanged; every P2-P4 E2E test still
  passes at the slug and on My Account.
- 2026-09-30, local on PHP 8.3.29 (Local's build, see memory): unit suite green; **Plugin Check
  2.0.0 on `plugin-test` (WP 7.1.2): "No errors found", 0 warnings** after fixing 5 warnings
  (dev folders excluded per `.distignore`; plugin inactive).
- 2026-09-30: `plugin-deliverables.php .` PASSED 14/14; commit gate passed on every commit, no bypass.
- Not yet done: footprint audit with numbers (P5/P8), security audit (P8), compat matrix incl.
  multisite login location, Pressable/Batcache, block checkout new-account, coming-soon mode (P8),
  manual browser pass (activation on `plugin-test` is the operator's call).

## History
- [brief-maxtdesign-mfa.md](brief-maxtdesign-mfa.md): approved brief, FluentAuth teardown, v1 scope.
- [plan-maxtdesign-mfa.md](plan-maxtdesign-mfa.md): accepted build plan, phases P1-P9, decisions.
- [webauthn-library-eval.md](webauthn-library-eval.md): WebAuthn library comparison; in-house verifier.
  All three moved here from `projects/plugin/_handoffs/` on 2026-09-30; pointers remain there.

## Flags
- 2026-10-01 (P7): wp.org screenshots are not captured. The browser pane was hidden during the
  session and screenshots timed out; one of the Policy tab rendered correctly. Needs a visible
  browser, at P9.
- 2026-10-01 (P7, plan/handoff conflict): the admin UI handoff says every token fallback must be
  the canonical hex, and also that wp.org plugins must not hardcode purple. The focus ring uses
  `var(--md-suite-color-brand-bright, currentColor)` to satisfy both.
- 2026-10-01 (P7): plan section 8 lists "sessions" on My security and a `users.php` column.
  Neither is built: core's profile already has "Log out everywhere else", and Coverage is a tab.
- 2026-10-01 (P7): plan section 8 says every admin action emails the affected user. A reset
  does; unlock and sign out everywhere only log. Add mail there if wanted.
- 2026-10-01 (P7): multisite has no network settings screen (plan decision 6 defers it); each
  site has its own page.
- 2026-10-01 (P7): the status scans at most 1,000 users for unverified sessions and 5,000 for
  the enrolled lists; larger sites get `sessions_truncated`. Fine for the cache, worth a look in
  P8's footprint audit.
- 2026-09-30 (P6, needs operator decision): the plan says the conflict detector should "warn and
  do not co-enforce". Built as: warn, and keep enforcing this plugin's policy. The other reading
  (stand down when another 2FA plugin is active) would let any such plugin switch MFA off, so it
  was not built. Confirm or change.
- 2026-09-30 (P6): plan 4.3 lists "sign out everywhere" as a trusted-device revocation trigger.
  Core has no hook for destroying all sessions; since P7 the Coverage action does both.
- 2026-09-30 (P6): `WP_Application_Passwords::create_new_application_password()` does not check
  availability; only REST and the admin screen do. A plugin calling it directly can still create
  one for a Required role, but it will not authenticate while the role disallows them.
- 2026-09-30 (P6): E2E needs `WP_ENVIRONMENT_TYPE=local` because core only supports application
  passwords over https or in a local environment.
- 2026-09-30 (P5): differential findings kept as documented divergences (we are stricter):
  `lbuchs/webauthn` 2.2 accepts an origin that only ends with the RP host (suffix trick), a
  subdomain or other port origin, `crossOrigin: true`, BS without BE, and trailing bytes after
  authenticatorData/assertion data. `web-auth/webauthn-lib` 5.3.9 accepts a `webauthn.get`
  clientData on registration and vice versa (its default `supportedTypes`), and `crossOrigin: true`
  when no topOrigin is set (`CheckTopOrigin` returns early).
- 2026-09-30 (P5): the fuzzer's "fixed seed" fixes the mutations, not the key material (the
  software authenticator uses `random_bytes`), so accept/reject counts vary slightly per run. A
  failure prints the exact reproducer bytes, so reproduction does not depend on the seed.
- 2026-09-30 (P5): an enrolled user could add a second factor from a stale session (true of TOTP
  since P2 as well). Now needs a fresh step-up. Not in the plan; recorded as a decision above.
- 2026-09-30 (P5): Plugin Check on `plugin-test` prints a `_load_textdomain_just_in_time` notice
  from `maxtdesign-usmaps-pro` (loads its text domain before `init`). Not this plugin; noted for
  that project.
- 2026-09-30 (P4, plan error): plan 4.3 says the recovery-mode link works on the slug because the
  router sets `$pagenow`. WordPress handles that link in `wp_recovery_mode()->initialize()`
  (wp-settings.php:575), before regular plugins load (:582) and before `plugins_loaded` (:630), so
  no plugin can set `$pagenow` in time. The link is rewritten to `wp-login.php` via
  `recovery_mode_begin_url` and that action stays allow-listed. Verified in the WP 7.1.2 tree and
  by the E2E test.
- 2026-09-30 (P4): plan 5.2 asks for `Referrer-Policy: same-origin` on the slug; core's
  `wp_admin_headers()` on `login_init` replaces it with `strict-origin-when-cross-origin`, which
  also keeps the slug path from other origins. Kept core's header.
- 2026-09-30 (P4): plan decision 8 means sites without WooCommerce publish the slug wherever a
  logged-out login link appears (comment forms, Login/out block). The readme says so; P7's
  owner-set public login page is the fix for owners who care.
- 2026-09-30 (P4): the moved login needs the server to send unknown paths to `index.php` (standard
  Apache/nginx/managed hosting). Documented in the readme FAQ; recovery constants cover the rest.
- 2026-09-30: GitHub default branch is `chore/p1-ci-check` (operator repo setting).
- 2026-09-30 (P3): E2E ran in CI, not Studio; Store API new-account and coming-soon mode are P8.
- 2026-09-30 (P2): record burns on the 5th wrong code; setup typos count toward the per-record cap
  only; the guard resets the current user for the rest of a blocked request; the challenge accepts
  any enrolled factor.
- 2026-09-30: `wp-login.php` sets `$interim_login` after `login_form_{action}` fires.
- 2026-09-30: `php-stubs/wp-cli-stubs` 2.12 caps `wordpress-stubs` below 7.0 (improvement log).
- 2026-09-30: the registry row still cites `_handoffs/` paths for the brief and plan (improvement log).
