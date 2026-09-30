# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P5, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2-P5 folded into it, nothing on wp.org).

## Status
Build phase. `main` = P1-P4 (P2 PR #1, P3 PR #2, P4 `0a3a486` PR #3, all 2026-09-30). P5
(passkeys) is on `feat/passkeys`, CI green (run 36790291991, 19/19 jobs), PR open for operator
review: in-house WebAuthn verifier (`src/WebAuthn/`: restricted CBOR, COSE ES256/RS256/EdDSA,
authenticatorData, clientData, attestation "none"); passkeys stored in
`{base_prefix}mdmfa_credentials` with a random 32-byte user handle; passkey as second factor
(offered first) and at enrollment, on the slug and on My Account; add/remove on My security and
the Security tab; passkey step-up; passwordless sign-in for roles that enable it (off by default)
with conditional UI; counter-anomaly flag/log/action with opt-in block; `mdmfa-passkey.js`
(1,838 B raw / 977 B gzip) enqueued only while a passkey control renders.
Not yet built: email code / side-door settings (P6), admin settings screens, privacy tools,
owner-set public login page (P7).

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

## Next actions
1. [operator] Review the P5 PR and approve the squash merge (`--delete-branch`).
2. [operator] Manual passkey pass on real devices (plan P5 DoD lists Chrome, Safari, Android,
   Windows Hello, a YubiKey): activate on `plugin-test` (the login moves; `wp mdmfa slug get`
   prints it), then Users, My security, Add a passkey. `plugin-test.local` is https, so WebAuthn
   runs there. It is junction-mounted: deactivate, never delete.
3. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (see Flags).
4. [session] P6 after operator go: email code, side-door settings.
5. [session] P7: privacy exporter/eraser (include passkeys), owner-set public login page,
   settings screens (incl. per-role passwordless and `counter_anomaly_block`).

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
