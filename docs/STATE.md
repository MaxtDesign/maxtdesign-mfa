# STATE: maxtdesign-mfa
Updated: 2026-10-02 by session (review fixes and role-tie change merged)

## Latest staging evidence — 2026-10-02

Codex independently re-reviewed `6c2be3b`: both original findings closed; 327 tests / 1,711
assertions, PHPStan, PHPCS and asset budgets pass. Owner authorized the readme qualification
and staging installation. [Initial staging test](staging-mxo-20261002.md): artifact installed
and verified, activation succeeded, but Hosting Basic Authentication 1.0.5 returned HTTP 401
for fresh Required-role login before MFA enrollment. Activation rolled back; MFA remains
installed but inactive, protections preserved, synthetic user removed. Full E2E is blocked on
that integration. This supersedes the re-review-pending/install-not-yet-performed statements
below; distribution and beta restrictions remain unchanged.

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: **undecided** (built to the free wp.org shape:
no licensing code; not approved for WordPress.org and may never be listed). Version 0.1.0
(unreleased; nothing published anywhere).

## Status
Feature complete and reviewed. `main` = P1-P8, passkeys-beta (PR #8) and the fixes for both
findings of Codex's independent review (`dec193f`, PR #10, merged 2026-10-01 on the operator's
word): [fix report](review-fix-20261001.md). **The fixes have not been independently
re-reviewed yet; that is still the gate before any staging install.** The role-tie change is
merged too (`0c2b2dc`, PR #12, 2026-10-02; 42 required CI checks green).
**Distribution is undecided (operator, 2026-10-01): the plugin is not approved for
WordPress.org and may never go there; no SVN work, no wp.org submission and no 1.0 release
steps until the operator says where it ships.** Passkeys are an opt-in beta: off per role,
second step only, passkey-only sign-in behind `define( 'MDMFA_PASSKEY_ONLY_SIGNIN', true )`.
The handoff that started the fix session is [handoff-next-session.md](handoff-next-session.md).
What P8 produced:
- Reports: [security audit](security-audit-p8.md), [lanes review](review-p8.md),
  [footprint audit](footprint-audit-p8.md), [compatibility matrix](compat-matrix-p8.md).
- Result at `main`: 0 Critical, **1 High, 7 Medium** (security) and **4 Blocks** (review).
  After P8: **0 open Critical, High, Medium or Block.** 7 of 8 exploit tests fail on `main`
  and pass on this branch; the eighth (the lockout race) needs several server workers and
  failed in CI until fixed.
- Behaviour changes: multisite is network-activated only, with the strictest policy across a
  user's sites; first activation emails the login address and leaves the login alone on plain
  permalinks; email codes are 8 digits and bound to the confirmed address; every new method is
  announced by email; `wp mdmfa key status|export-define|rewrap` and `wp mdmfa recovery-codes`;
  My Account endpoint slug is `login-security`.
- Two more reviews before merge, by other models: Codex (`gpt-6-astra`, medium) found 3 issues,
  Claude Fable found 1 Medium and 6 Low; all fixed except two Lows put to the external reviewer.
  Neither found an exploitable flaw in the verifier. Recorded in the security audit.
- [External review brief](webauthn-review-brief.md) written: scope, design decisions, threat
  model, what was already done, where to look hardest, how to run everything.
Still required before 1.0: the operator's manual pass on real devices (passkeys and the settings
screens), then P9 proper. The external review is no longer a gate; the brief stays ready.

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
- 2026-10-01 (P8): multisite: `Network: true`; policy = strictest across the user's sites (read
  from each site's options table directly, never by switching blogs, which would re-enter the
  current-user lookup); an enrolled account is challenged on every site; passkeys count as
  enrolled whatever host they were registered for. Second-step attempts for one user run under
  a MySQL named lock, with the user's meta cache dropped inside it. The application-password
  exemption is per user. Email codes are 8 digits (plan 10.1). The login is not moved on plain
  permalinks at install. The Jetpack SSO flag is mirrored into the autoloaded login option.
  The privacy eraser anonymises log rows instead of deleting them.
- 2026-10-01 (review fix): on a network a user's effective configuration is the strictest of
  every site they belong to, setting by setting: a permission (email recovery, application
  passwords, account passwords over XML-RPC, trusted devices, passkey-only, each method) needs
  every site's consent; the longest recovery wait and the shortest trusted-device lifetime
  apply; grace is the shortest among the sites that set the winning policy. Same answer on
  every entry site. No cap on the number of sites. Still never switches blogs.
- 2026-10-01 (review fix): self-service security forms are bound to the screen that rendered
  them by nonce action (`mdmfa_account` in wp-admin, `mdmfa_account_wc` on My Account); the
  WooCommerce handler ignores every admin request.
- 2026-10-01 (operator): on one site, roles that tie on policy are combined the way sites are:
  a permission needs every tied role's consent, longest recovery wait, shortest grace. A role
  of lower rank still restricts nothing. Plan 4.1 amended in place.
- 2026-10-01 (operator): distribution channel is TBD. Not approved for WordPress.org and may
  never be listed there, depending on other work in progress. P9's SVN and submission steps
  are on hold. If the channel changes (private, Pro via `lic`, or bundled), the plugin shape in
  the wp-plugin skill changes with it: re-read the skill's shape table and hard rule 10 first.
- 2026-10-01 (operator): the conflict detector warns and keeps enforcing this plugin's policy
  when another two-step plugin is active. It never stands down.
- 2026-10-01 (operator): no paid external review. Passkeys ship as an opt-in beta, second step
  only; passkey-only sign-in behind `MDMFA_PASSKEY_ONLY_SIGNIN`. No "audited" or "reviewed"
  claim anywhere. Plan decision 4 amended in place. The beta label and the constant go when an
  independent review is recorded.

## Next actions
1. [operator] Decide the distribution channel (WordPress.org, private, Pro, or bundled). Until
   then nothing is released.
2. [operator] Manual pass on `plugin-test`: activate (the login moves and administrators are
   emailed the address; `wp mdmfa slug get` prints it), allow passkeys for your role under
   Users, Login security (MFA), Policy, add a passkey per device on Users, My security, sign in
   with it as the second step, and walk the settings tabs with the keyboard only.
   Junction-mounted: deactivate, never delete.
3. [operator] Say which UNVERIFIED matrix cells matter (connected Jetpack, Pressable, paid
   membership plugins, subdomain networks, block checkout new-account).
4. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check`.
5. [operator] Send `main` for independent re-review of the two findings with
   [review-fix-20261001.md](review-fix-20261001.md) (fix is `6a30b32` inside squash `dec193f`;
   the role-tie change is `0c2b2dc`). No staging install before the re-review (the review's
   `STAGING-E2E-PLAN.md` gate 1).
6. [session, optional] Mark the known compatibility failures as expected so the informational
   `compat` checks stop showing red (Wordfence, Ultimate Member, Limit Login Attempts Reloaded).
7. [session, only once a channel is chosen] Release preparation for that channel: screenshots
   if wp.org, remove the "Development build" readme paragraph, version triple, changelog,
   `release-gate.php` on the exact zip.

## External relationships
- Vendored libs: none. Runtime Composer deps: none. Path repositories: none.
- WooCommerce (optional): `wc_get_template`, `woocommerce_login_credentials`,
  `woocommerce_login_redirect` (applied), account endpoint hooks; tested 11.1.2.
- maxtdesign-cache: `md_cache_config` (slug in `exclude_paths`), fires `md_suite_content_changed`
  per URL on slug change, calls `md_cache_regenerate_config` if it ever exists (requested hook).
- Local test site: `plugin-test` (https://plugin-test.local, WP 7.1.2, PHP 8.3.29 since
  2026-09-30, WC 10.9.4). Plugin junction-mounted there on 2026-09-30, inactive.
- External services: none in use. wp.org SVN (account `slaacr`) only if that channel is chosen.
  The plugin makes no outbound HTTP.

## Verification state
- 2026-10-01, review fixes, `6a30b32`, local ([report](review-fix-20261001.md), files in
  [evidence/review-fix-20261001/](evidence/review-fix-20261001/)):
  - Unit: **324 tests, 1,691 assertions** on PHP 8.3.29 (19 new; 14 of them fail on `main`).
    PHPStan L8 0, PHPCS 0, size check pass (unchanged bytes), outbound grep 0.
  - E2E WooCommerce (WP 7.1.2, WC 10.9.4, disposable site): **18 tests, 488 assertions, pass**.
    The 6 new presenter tests: 4 fail on `main`, all pass on the fix.
  - E2E network (disposable subdirectory network, 2 sites): 74 tests, 785 assertions, 72 pass,
    1 skipped (recovery mode), 1 error that is the harness (a bare `wp` process on Windows).
    The 3 new network tests fail on `main` and pass on the fix.
  - The reviewer's own `reproduce.php`, unmodified, no longer reproduces either finding.
  - A separate read-only security pass on the diff: 0 Critical/High, 3 Medium, all fixed in
    the same commit (site cap, XML-RPC mode, role parity); Lows listed in the report.
  - CI on PR #10: every required job green (50 checks pass), including `e2e-wc` on the current
    WooCommerce release and `multisite`; the 3 informational compat jobs fail as before.
  - Role ties (`fix/role-tie-policy`): unit 327 tests, 1,711 assertions; PHPCS 0, PHPStan 0.
    No E2E of its own (pure policy arithmetic, covered by unit tests).
  - UNVERIFIED for this change: WooCommerce 11.x locally (CI ran the current release),
    real browsers, subdomain networks, object cache, concurrency, the MaxtOffroad stack.
- 2026-10-01, P8, CI run 36896784143 on `chore/p8-review` (`4fd4d74`, with the Codex and Fable
  fixes): **all 21 required jobs green**; 7 informational compatibility jobs, 4 green.
  - Unit: **302 tests, 1,589 assertions** on PHP 8.3, 8.4, 8.5.
  - **E2E core, PHP 8.3 + 8.5: 69 tests, 700 assertions** (5 multisite tests skipped).
    P8 adds 9 audit regression tests and the front-end query probe.
  - **E2E multisite (new job), PHP 8.3 + 8.5: 69 tests, 718 assertions** (recovery mode skipped:
    core does not run it on multisite). The whole core suite on a subdirectory network's main
    site, plus 5 cross-site tests.
  - E2E WooCommerce: 12 tests, 368 assertions. Fuzz 4M inputs, 0 crashes. Smoke single and
    multisite. QR, lint, outbound grep 0, PHPStan L8 0, PHPCS 0, size check.
  - Compatibility (informational job): Two Factor 0.17.0, Jetpack 16.2 (not connected), WP Super
    Cache 3.1.4 and W3 Total Cache 2.10.6 pass all 69. Wordfence 9.0.2 63 of 69, Ultimate Member
    2.14.0 55 of 69, Limit Login Attempts Reloaded 3.3.10 not conclusive; reasons in the
    [matrix](compat-matrix-p8.md), none a login-flow conflict.
- 2026-10-01, local, same code: full core suite on a real subdirectory network (66 run, 0
  failed) and on single site; WooCommerce 10.9.4 suite; **Plugin Check on `plugin-test`: "No
  errors found"**; the 8 audit regression tests against unfixed `main`: 7 fail (the findings
  were real), all pass on this branch.
- 2026-10-01, footprint ([report](footprint-audit-p8.md)): on 11 front-end page types with the
  plugin on vs off: 0 tags, 0 bytes, 0 references, 0 cookies, **0 plugin queries** (identical
  SQL sets). One settings read on the logged-out My Account login form. Lab only.
- UNVERIFIED: Lighthouse and field Core Web Vitals; the external WebAuthn review; real browsers
  and authenticators; subdomain and mapped-domain networks; connected Jetpack; hosted caches;
  a persistent object cache; screen readers and a human keyboard pass.
- Earlier phases, each green in CI at merge (details in git history of this file): P7 run
  36870781642 (admin screens; 194 controls, 0 unlabelled; suite mode with suite-core 1.5.1), P6
  run 36814321766 (side doors, email codes, trusted devices, recovery), P5 run 36790291991
  (passkeys; 129 verifier tests, 34 differential), P4 run 36779146610 (login location; 34-URL
  anonymous crawl with 0 occurrences of the address).

## History
- P8 reports: [security-audit-p8.md](security-audit-p8.md), [review-p8.md](review-p8.md),
  [footprint-audit-p8.md](footprint-audit-p8.md), [compat-matrix-p8.md](compat-matrix-p8.md).
- [brief-maxtdesign-mfa.md](brief-maxtdesign-mfa.md): approved brief, FluentAuth teardown, v1 scope.
- [plan-maxtdesign-mfa.md](plan-maxtdesign-mfa.md): accepted build plan, phases P1-P9, decisions.
- [webauthn-library-eval.md](webauthn-library-eval.md): WebAuthn library comparison; in-house verifier.
  All three moved here from `projects/plugin/_handoffs/` on 2026-09-30; pointers remain there.

## Flags
- 2026-10-01 (FIXED in `dec193f`, awaiting independent re-review; HIGH, from Codex's independent
  review of `242d761`): on multisite the network floor raised only the policy mode.
- 2026-10-01 (FIXED in `dec193f`, awaiting independent re-review; MEDIUM, same review): WooCommerce's
  handler could run wp-admin security forms. Real requests showed it needs a trigger: plain
  WooCommerce does not define `wc_add_notice()` in wp-admin, so the old handler stood down; any
  plugin calling `wc_load_cart()` there makes it fire. The reviewer's shim defined the function
  itself. Whether the MaxtOffroad stack has such a plugin is unchecked.
- 2026-10-01 (decided, merged in `0c2b2dc`, PR #12): role ties on one site used to be
  settled by the order the roles were stored in. They are combined now; see Locked decisions.
- 2026-10-01: PR #9 (handoff docs) closed as superseded; its commit reached `main` inside #10.
  PR #11 was closed by GitHub when #10's branch was deleted; #12 replaces it.
- 2026-10-01 (review fix): still per site on a network: passkey counter-anomaly blocking,
  lockout thresholds, email-code limits, log settings. Archived and spam sites still count.
- 2026-10-01 (review fix): the local harness under Git Bash needs `MSYS_NO_PATHCONV=1`, or
  `wp rewrite structure '/%postname%/'` is turned into a Windows path and posts 404.
- 2026-10-01: turning passkeys off by default changes what a fresh install offers. A Required
  role now sets up an authenticator app during sign-in; the passkey choice appears there only
  for roles the owner allowed. Existing passkeys keep counting as enrolled if a role is later
  switched off, so nobody drops to password-only.
- 2026-10-01 (P8, limitation): where another plugin keeps members out of wp-admin and there is no
  WooCommerce, members cannot reach a screen to manage their methods (found with Ultimate
  Member). Setup at sign-in still works. A front-end security panel is not in the plan.
- 2026-10-01 (P8): on multisite only super admins can reset, unlock or sign out other users,
  because core reserves `edit_user` for them. Site administrators see the Coverage tab but
  their actions are skipped with a notice.
- 2026-10-01 (P8): the multisite run found a bug in that day's own fix (reading another site's
  policy switched blogs and recursed during application-password checks, exhausting memory).
  It never reached `main`. Multisite needs its CI job; it has one now.
- 2026-10-01 (P8, plan error): plan 4.3 says application passwords are exempt "by design" with
  no word on scope. The exemption must be per user, not per request (audit High).
- 2026-10-01 (P8, plan error): plan 5.5 assumes the login address "is in every admin's email",
  but nothing sent it at activation. It is sent now.
- 2026-10-01 (P8): Codex needs the model named `gpt-6-astra`; plain `astra` is refused for a
  ChatGPT-account login. Its sandbox could not run the unit suite (it found PHP 8.2 on PATH).
- 2026-10-01 (P8): open Low items are listed at the end of the [security audit](security-audit-p8.md)
  and under Nits in the [review](review-p8.md).
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
  site has its own page. Since P8 one site can no longer weaken another.
- 2026-10-01 (P7): the status scans at most 1,000 users for unverified sessions and 5,000 for
  the enrolled lists; larger sites get `sessions_truncated`. Fine for the cache, worth a look in
  P8's footprint audit.
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
