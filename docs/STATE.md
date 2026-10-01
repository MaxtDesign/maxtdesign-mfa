# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P6, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2-P6 folded into it, nothing on wp.org).

## Status
Build phase. `main` = P1-P5 (P5 `84dd781` PR #4, 2026-09-30). P6 is on
`feat/email-code-side-doors`, CI green (run 36814321766, 19/19 jobs), PR open for operator review:
- Email code factor (`Factors/EmailCode`): 6 digits, 10 min, 5 tries, bound to the pending login;
  3 sends / 15 min and 10 / day per user; on both challenge screens and both security screens.
- Trusted devices (`Auth/TrustedDevice`): per role, off everywhere by default, cookie `mdmfa_td`
  (selector:validator, validator stored as `wp_fast_hash`), max 10, 30 days; revoked on any
  password change (`wp_set_password`), any factor removal, reset, or "Forget all".
- Side doors (`Auth/SideDoors`): application passwords off / per role / on, step-up to create one
  (REST and authorize-application.php), use logged hourly; XML-RPC off / block passwords / allow;
  non-interactive password logins (REST token plugins) refused for users with a factor.
- Email recovery (`Flow/EmailRecovery`): requested from the challenge only, link on
  `admin-post.php` (never the slug), GET confirms nothing, POST confirms, staff wait 24 h, a real
  second-step sign-in cancels a waiting reset.
- Jetpack: optional WordPress.com sign-in block (`block_wpcom_sso`). Conflict detector: warns
  about Two Factor, WP 2FA, FluentAuth, Solid Security 2FA, miniOrange.
- `Factors/Reset` is the one reset path (CLI, recovery). `wp mdmfa status` and `user status` report
  the new state; `user reset --factor=email|trusted` added.
Not yet built: admin settings screens (every P6 option is settable only through the
`mdmfa_settings` option today), privacy tools, owner-set public login page (P7).

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

## Next actions
1. [operator] Review the P6 PR and approve the squash merge (`--delete-branch`).
2. [operator] Decide the conflict-detector reading (Flags, first item).
3. [operator] Manual passkey pass on real devices (still open from P5): activate on `plugin-test`,
   then Users, My security, Add a passkey. Junction-mounted: deactivate, never delete.
4. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (see Flags).
5. [session] P7 after operator go: settings screens (policy matrix, factors, side doors, recovery,
   activity, tools incl. conflict list and Jetpack status), step-up on settings and slug changes,
   privacy exporter/eraser (passkeys, email, trusted devices, log) and cookie text for
   `mdmfa_pending` and `mdmfa_td`, owner-set public login page, status contract.

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
- 2026-09-30 (P6, needs operator decision): the plan says the conflict detector should "warn and
  do not co-enforce". Built as: warn, and keep enforcing this plugin's policy. The other reading
  (stand down when another 2FA plugin is active) would let any such plugin switch MFA off, so it
  was not built. Confirm or change.
- 2026-09-30 (P6): plan 4.3 lists "sign out everywhere" as a trusted-device revocation trigger.
  Core has no hook for destroying all sessions, so it is not wired; password change, factor
  removal, reset and the "Forget all trusted devices" button are.
- 2026-09-30 (P6): plan step-up list includes "changing MFA settings or the login slug". Those
  screens are P7; the CLI is exempt by design. Step-up today covers removing a factor, adding one
  to an enrolled account, new recovery codes, turning email codes off, and application passwords.
- 2026-09-30 (P6): a role that is Required and allows only email has no in-login setup screen
  (the enroll screen offers passkey and authenticator only). Not a default; P7's policy screen
  should refuse that combination or the enroll screen should gain email.
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
