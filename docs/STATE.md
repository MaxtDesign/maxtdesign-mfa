# STATE: maxtdesign-mfa
Updated: 2026-09-30 by session (Build P4, wp-plugin-dev)

## Identity
MaxtDesign MFA. Slug / text domain / repo `maxtdesign-mfa`; short code `mfa`; prefixes `mdmfa_`
(hooks, options, meta), `MDMFA_` (constants), tables `{$wpdb->prefix}mdmfa_*` except
`{$wpdb->base_prefix}mdmfa_credentials`; namespace `MaxtDesign\Mfa`. Registry row
`| MaxtDesign MFA |` in `C:/maxt/ops/sops/agent-sops/naming-registry.md` (active, unshipped).
Repo `MaxtDesign/maxtdesign-mfa` (public). Channel: wp.org via `slaacr`, free only, no licensing
code. Version 0.1.0 (unreleased; P2-P4 folded into it, nothing on wp.org).

## Status
Build phase. `main` = P1-P3 (P2 `5d454ce` PR #1, P3 `53ba496` PR #2, both 2026-09-30). P4 (login
location) is on `feat/login-location`, CI green, PR open for operator review: early routing
serves core login at a random slug; direct `wp-login.php` gets the theme's 404 and logged-out
`wp-admin` a minimal 404 (admin-ajax, admin-post, upgrade.php exempt); `/login`-style shortcuts
404; generated URLs point at the slug except postpass, confirmaction and recovery mode; logged-out
front-end login links go to the public login page (My Account on WC, else the slug); slug
validation, `wp mdmfa slug`, recovery constants, admin email + 24 h notice, cache signals.
Not yet built: passkeys (P5), email code / side-door settings (P6), admin settings screens,
privacy tools, owner-set public login page (P7).

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

## Next actions
1. [operator] Review the P4 PR and approve the squash merge (`--delete-branch`).
2. [operator] Set the repo default branch to `main` and delete `chore/p1-ci-check` (see Flags).
3. [operator] To try it on `plugin-test`: activate MaxtDesign MFA there. The login moves at once;
   the dashboard notice shows the new address for a day, and `wp mdmfa slug get` prints it. It is
   junction-mounted: deactivate, never delete, from WP admin.
4. [session] P5 on `feat/passkeys` after operator go: in-house WebAuthn verifier (plan 12), fuzz
   harness, differential tests vs both oracles, enrollment, second factor, passwordless +
   conditional UI, counter policy, `mdmfa-passkey.js` under 3,072 B / 1,536 B gzip.
5. [session] P7: privacy exporter/eraser, owner-set public login page, settings screens.

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
- 2026-09-30, P4, CI run 36779146610 on `feat/login-location`, **17/17 jobs green**:
  - Unit: **127 tests, 1,154 assertions** on PHP 8.3, 8.4, 8.5 (adds slug matching, format and
    reserved-name rules).
  - **E2E core, WordPress 7.1.2, pretty permalinks, PHP 8.3 + 8.5: 24 tests, 189 assertions.**
    P4 DoD: every plan 5.2 row returns its status (15 requests incl. wp-login.php GET/POST and
    actions, logged-out wp-admin, `/login` `/admin` `/dashboard`; none redirects to or prints the
    slug; admin-ajax, admin-post, upgrade.php still work); the slug serves core login with
    no-store, noindex, `$pagenow` = wp-login.php and `is_login()` true; admins log in at the slug
    and logout links follow; postpass, privacy confirmation (email never carries the slug) and the
    recovery-mode link work through wp-login.php; `wp mdmfa slug set` purges old + new URLs via
    `md_suite_content_changed`, emails admins, logs without the slug, 404s the old slug;
    `MDMFA_LOGIN_SLUG` and `MDMFA_DISABLE_LOGIN_LOCATION` work. All P2 tests pass at the slug.
  - **E2E WooCommerce 11.1.2, PHP 8.3 + 8.5: 10 tests, 280 assertions.** Adds the anonymous crawl:
    **34 front-end URLs** (home, posts, embed, password-protected post, pages, block checkout
    page, product, shop, cart, classic checkout, My Account, lost password, category, tag,
    product category, author, search, feeds, sitemaps, robots.txt, a 404, the old paths, REST
    incl. Store API cart, xmlrpc.php) with **0 occurrences of the slug** in bodies, redirects or
    Link headers; comment login links point at My Account. All P3 tests pass unchanged.
  - Smoke (single + multisite), QR decode, lint, outbound grep 0, PHPStan L8 0, PHPCS 0.
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
