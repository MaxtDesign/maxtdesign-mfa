# Plan: MaxtDesign MFA (`maxtdesign-mfa`)

Status: **ACCEPTED** by operator 2026-09-30: all section 16 decisions as recommended; PHP floor 8.3
(operator). Executor: `wp-architect` (Plan phase). Next: Build P1 (`wp-plugin-dev`); P1 creates
`docs/STATE.md`, which points back here.
Inputs: [brief](brief-maxtdesign-mfa.md) (approved, decisions locked), registry row `| MaxtDesign MFA |`,
[webauthn-library-eval](webauthn-library-eval.md), `wp-plugin` skill (SKILL.md, checklists/plan.md,
reference/architecture|security|performance.md), quality standard, plugin-root `CLAUDE.md`,
suite nav + admin UI handoffs (`C:/maxt/ops/sops/agent-sops/handoffs/`), suite-core 1.5.1 source.

Checklist `plan.md` worked in order: Orient (repo does not exist; row, brief, CLAUDE.md,
architecture read; commerce north-star not needed beyond WC login hooks: this plugin composes
nothing in the cart), API verification (sources below), floors from `plugin-versions.php`
(run 2026-09-30), Decompose (sections 3-10), Sequence (section 14), risks and decisions (15-16).

**Source basis (hard rule 4).** Every WordPress/WooCommerce claim below cites `file:line` in
WordPress **7.1.2** (`wordpress-7.1.2.zip`) and WooCommerce **11.1.2** (`woocommerce.11.1.2.zip`),
downloaded and read this session. Jetpack claims cite Jetpack **16.2** (`jetpack.latest-stable.zip`,
same day). maxtdesign-cache and suite-core claims cite the local repos at their current `main`.
Paths below are relative to each package root.

---

## 1. Summary

A free wp.org MFA plugin that owns the whole login path: TOTP, passkeys (second factor and
passwordless), recovery codes, owner-optional email code; per-role Off/Optional/Required with grace
and inline enrollment; **no WordPress session exists until the second factor passes**; staff and
customers complete challenge and enrollment on the site's own pages (core login at a moved slug,
WooCommerce My Account and checkout); side doors (application passwords, XML-RPC, plugin password
APIs, direct cookie issuers) are policed; the login moves to a random slug with the old paths
returning 404. Zero outbound HTTP, zero front-end bytes except a deferred passkey module on
challenge/enrollment screens, **zero REST routes** in v1 (all ceremonies are server-rendered form
posts). No licensing code.

Differentiators that are checkable (from the brief, now design-backed): the bypass guard (section
4.6) closes the WooCommerce reset auto-login and Jetpack SSO paths that form-hooking MFA plugins
miss; customer flows never touch `wp-login.php`; front-end footprint is measured, not claimed.

## 2. Floors (locked)

| Item | Value | Source |
|---|---|---|
| PHP | **8.3** (`Requires PHP: 8.3`; `composer.json` `config.platform.php` = `8.3.0`; CI matrix 8.3 / 8.4 / 8.5) | operator 2026-09-30; 8.2 EOL 2026-12-31; registry row already says 8.3 |
| WordPress | `Requires at least: 7.0`, `Tested up to: 7.1` | plugin-versions.php: current 7.1.2; newest API relied on is `wp_fast_hash` (functions.php:9363, 6.8+). Decision 13 |
| WooCommerce (optional) | integration floor 11.0, `WC tested up to: 11.1` | current 11.1.2 (requires WP 7.0 / PHP 7.4). Decision 13 |
| PHP extensions | `openssl` (passkeys ES256/RS256; fail closed with notice if absent). `sodium` optional: WP ships `wp-includes/sodium_compat/` (verified present, `lib/php72compat.php` defines the xchacha20poly1305 functions) | 7.1.2 tree |
| Runtime Composer deps | **none** (in-house WebAuthn verifier, section 12). Dev only: PHPUnit, PHPStan + WP stubs, `web-auth/webauthn-lib` and `lbuchs/webauthn` as differential test oracles | eval section 1 |

## 3. Decomposition: reuse vs build

Ownership: 100% MaxtDesign product under `projects/plugin/maxtdesign-mfa/`, public repo. Nothing
client-specific. No theme code.

| Capability | Decision | Why / primitive |
|---|---|---|
| Admin menu placement, UI styling | **Reuse opportunistically, do not vendor** suite-core (decision 1) | Vendoring suite-core 1.5.1 prints a 522-byte inline `<script id="md-suite-consent-fallback">` on **every front-end page** (`MdSuite_Admin.php:46` hooks `wp_head`; body at `:513-534`, measured this session) and registers a top-level "MaxtDesign" menu (`:52-77`) on strangers' sites. Nav handoff §4.4 says wp.org standalone utilities do not vendor and mount opportunistically. Guarded: `class_exists('MdSuite_Admin')` -> submenu under `MdSuite_Admin::MENU_SLUG` + `register_screen('md-mfa')`; else `add_users_page()` |
| Status contract for the MCP hub | Reuse `MdSuite_Status::contribute()` when present; own local read `MaxtDesign\Mfa\Status\Snapshot` + filter `mdmfa_status` always | contribute is in-memory; filter_snapshot discards input and rebuilds from contributions (`MdSuite_Status.php:52-58, 118-121`), so MFA contributes lazily from an `md_suite_status` filter at priority 5 (before suite-core's default 10). `MdSuite_Registry::register()` on `md_suite_loaded` |
| Suite render helpers (`render_page_header`, `render_status_badge`, `render_screen_tabs`...) | Use when present (`method_exists`), else byte-identical inline fallback markup | nav handoff §3.5, admin UI handoff §5 |
| REST endpoint blocking | **Not ours** (`dra`) | brief |
| Page caching | Integrate with `maxtdesign-cache` via its existing hooks; never duplicate | section 5.6 |
| Password hashing, CSPRNG, sodium, fast hash | Reuse core: `wp_hash_password`/`wp_check_password` (pluggable.php:2753/2843), `wp_fast_hash`/`wp_verify_fast_hash` (functions.php:9363/9386), `random_bytes`, `sodium_*` (+ core sodium_compat) | no crypto libs vendored |
| Session storage | Reuse `WP_Session_Tokens` (class-wp-session-tokens.php) + `attach_session_information` (:129) to mark MFA-verified sessions | no parallel session store |
| TOTP (RFC 6238) | Build (~150 LOC) | trivial, no dependency justified |
| QR code for TOTP enrollment | Build-time choice among vendored, dependency-free, GPL-compatible **server-side SVG** encoders; Build verifies license, size, deps before picking (candidates to evaluate, UNVERIFIED: a PHP port of Kazuhiko Arase's `qrcode-generator` (MIT), `bacon/bacon-qr-code` (BSD-2, has a dependency), `chillerlan/php-qrcode` (MIT, heavier)). No JS QR, no remote QR service | zero JS on enrollment; zero outbound HTTP |
| WebAuthn verifier | **Build in-house** (eval recommendation; decision 3). Library: in-house verifier (recommended, operator decision), see section 12 and `webauthn-library-eval.md` | |
| Email delivery | Reuse `wp_mail()` | no SMTP code |
| Rate limiting | Build, scoped to MFA factors only (brute-force/IP firewall is a non-goal) | section 10 |
| WP-CLI | Build `wp mdmfa` command group | escape hatch |

## 4. Auth state machine

### 4.1 States

`ANON` -> `FIRST_FACTOR_OK` (password verified, no session) -> `PENDING` (single-use pending
record + HttpOnly cookie) -> one of `CHALLENGE` (enrolled user) / `ENROLL` (Required, not
enrolled, grace expired or owner forces) / `GRACE_PROMPT` (Required, in grace: enroll or skip) ->
`COMPLETE` (blessed `wp_set_auth_cookie` + `wp_login`) -> `SESSION(verified)`.
Side states: `LOCKED` (per-user factor lockout), `EXPIRED` (pending TTL 10 min, or 5 failed
attempts on this pending record: back to `ANON`, password required again).
Users whose effective policy is Off, or Optional-and-not-enrolled, go `FIRST_FACTOR_OK` ->
`COMPLETE` directly (core behaviour unchanged).

Effective policy for a user = strictest across their roles on the current site (Required >
Optional > Off); super admins are always Required (multisite); filter `mdmfa_user_policy`.
`MDMFA_DISABLE` true -> every path behaves as core (section 11.4).

### 4.2 Interception point (verified)

- `wp_signon()` (wp-includes/user.php:41-139) calls `wp_authenticate()` (:110) then
  `wp_set_auth_cookie()` (:115) then fires `wp_login` (:138). `wp_authenticate()` runs
  `apply_filters('authenticate', null, $username, $password)` (pluggable.php:706). Core handlers:
  `wp_authenticate_username_password`, `_email_password`, `_application_password` at 20,
  `wp_authenticate_spam_check` at 99 (default-filters.php:516-519); `wp_signon` adds
  `wp_authenticate_cookie` at 30 (user.php:108).
- **MFA hooks `authenticate` at `PHP_INT_MAX`**: it sees the final verdict after every plugin
  (Jetpack brute force at 10, Jetpack sync logging at 1000, captcha/limit-login plugins). If the
  result is a `WP_User` who needs a second factor, the request never returns to `wp_signon`, so
  `wp_set_auth_cookie` (and `WP_Session_Tokens::create()` inside it, pluggable.php:1132-1133) never
  runs. **No session, no auth cookie, no `wp_login`, no `wp_login_failed`** (so limit-login plugins
  do not count a correct password as a failure).
- What happens instead depends on context (4.3). Interactive browser contexts: persist PENDING,
  set the pending cookie, `wp_safe_redirect()` to the context's challenge URL, `exit`.
  Non-interactive contexts: return a `WP_Error` (`mdmfa_required`) or pass through per policy.
- Context detection (set by earlier hooks in the same request, never from client input):
  `core` = `did_action('login_form_login')` (wp-login.php:565); `wc` = our
  `woocommerce_login_credentials` filter ran (class-wc-form-handler.php:1135, fires immediately
  before `wp_signon`); `frontend` = our neutral handler (4.4) is running; `xmlrpc` =
  `XMLRPC_REQUEST`; `rest` = `REST_REQUEST`; `apppass` = `application_password_did_authenticate`
  fired this request (user.php:497); `cli` = `WP_CLI`; `ajax` = `wp_doing_ajax()`; otherwise
  `unknown-post` (a browser POST from another plugin's form) or `unknown` (programmatic).

### 4.3 Paths

| Path | Behaviour |
|---|---|
| **Core login** (slug page, which is `wp-login.php` served at the slug, section 5) | Password POST -> interception -> redirect to `{slug}?action=mdmfa-verify` (or `mdmfa-enroll`). Custom actions are admitted by core because `login_form_{action}` has a filter (wp-login.php:503-505). Our `login_form_mdmfa-verify` handler renders with core `login_header()`/`login_footer()` (core styles, zero plugin CSS/JS for TOTP/email/recovery) and exits. `redirect_to`, `rememberme`, `interim-login`, `reauth` and the resolved secure-cookie flag are stored in the PENDING record, not the URL. Interim login (wp-auth-check iframe, functions.php:7593-7623) is supported: on success, emit the core interim success page (mirrors wp-login.php:1356-1366) |
| **WooCommerce My Account** | `WC_Form_Handler::process_login` on `wp_loaded`@20 (class-wc-form-handler.php:38, 1103-1164) -> `wp_signon` (:1135) -> interception (context `wc`) -> redirect to the My Account URL. When logged out, the shortcode renders `myaccount/form-login.php` (class-wc-shortcode-my-account.php:59-60); with a live pending cookie MFA swaps that template through the `wc_get_template` filter (wc-core-functions.php:320) for `templates/woocommerce/challenge.php` (theme-overridable at `{theme}/maxtdesign-mfa/`). Form markup uses WC classes (`woocommerce-form`, `woocommerce-form-row`), so the theme styles it. POST handled on `wp_loaded`@15 (before WC's @20 handlers). On success the redirect is `wp_validate_redirect( apply_filters('woocommerce_login_redirect', $stored, $user) )`, matching WC (:1156) |
| **WooCommerce checkout login** | Checkout login posts the same `login` fields (`templates/global/form-login.php`, hidden `redirect` at :50) to `process_login`: same as My Account with the stored redirect = checkout URL. Cart survives: guest cart merge runs on `wp_login` (WC hooks at wc-user-functions.php:1087, 1100), which fires at our completion |
| **Block checkout / Customer Account block** | They only link to `wp_login_url()` (AssetDataRegistry.php:104 `wpLoginUrl`; CustomerAccount.php:126). No inline login. Those URLs resolve to the public login page (section 5.3), so the slug is not published |
| **Front-end `wp_login_form()` and loginout block** | Core form action is `site_url('wp-login.php','login_post')` (general-template.php:832). Outside the login screen MFA rewrites that to a neutral handler `admin-post.php?action=mdmfa_login` (nopriv; admin-post.php:36-58) which calls `wp_signon()`; interception context `frontend` -> challenge on My Account (WC active) or the slug page. Decision 9 |
| **Other plugins' login forms** (membership, page builders) | `unknown-post` browser POST: same as frontend. `ajax` logins: return `WP_Error('mdmfa_required')` whose message links to the challenge URL (the pending record already exists); no exit inside AJAX. Covered in the test matrix |
| **Passwordless passkey** | Login page (core slug and My Account) shows "Sign in with a passkey" and enables conditional mediation (`autocomplete="username webauthn"`) when passwordless is allowed for any role. Request options are embedded server-side with a **stateless** challenge (`HMAC(key, random16 or ts)`), so anonymous page views write nothing. The module fills a hidden field and submits the form; the server verifies HMAC + age <= 5 min + single use (insert into `mdmfa_pending` kind `wa_used`), resolves the credential, checks userHandle ownership, requires UV, then checks that the user's policy allows passwordless. It then runs `wp_authenticate_user` (user.php:203, which is where account-state plugins veto) and the multisite spam check, then completes. If the user's role does not allow passwordless, the response is "sign in with your password first" and no session is created |
| **Trusted device** (owner setting, off for staff by default) | After FIRST_FACTOR_OK, a valid `mdmfa_td` cookie (selector:validator, validator hashed with `wp_fast_hash`) for this user skips the second factor. Revoked on password change (`after_password_reset`, `profile_update`), factor reset, and "sign out everywhere" |
| **Inline enrollment / grace** | Required + not enrolled: in grace -> GRACE_PROMPT (enroll now, or skip with days left shown); grace over -> ENROLL (no skip). Enrollment runs in the same pending context (the user is not logged in yet): TOTP (QR SVG + secret + confirm code), passkey (module), recovery codes shown once and confirmed. Grace clock starts at the first login after the policy applies (`mdmfa_grace_started`), not at activation |
| **Step-up** | Removing a factor, regenerating recovery codes, changing MFA settings or the login slug, and creating application passwords require a factor verified within the last 10 minutes on this session (session field `mdmfa.verified_at`), else a re-verify form (PRG) |
| **Application passwords** | Global off: `wp_is_application_passwords_available` -> false (user.php:5177). Per role: `wp_is_application_passwords_available_for_user` (user.php:5212). Default: allowed for roles whose policy is not Required, off for Required roles unless the owner allows it per role. Use is logged via `application_password_did_authenticate` (user.php:497). App passwords are exempt from the second factor by design (a revocable, scoped API credential); the admin screen states this |
| **XML-RPC** | Full off: `xmlrpc_enabled` false (class-wp-xmlrpc-server.php:223; note that it only disables authenticated methods, per the docblock at :205-221). Default: interception returns `WP_Error` for **password** auth by MFA-subject users in `XMLRPC_REQUEST` (surfaces as 403 through `login()` at :295-330, filterable at :325); app-password auth follows the app-password policy. Jetpack server-to-site `jetpack.*` calls are unaffected: Jetpack's `require_jetpack_authentication()` removes **all** `authenticate` filters and installs only its own (jetpack-connection `class-manager.php:387-397`) |
| **REST** | Cookie auth needs a valid session + nonce (rest-api.php `rest_cookie_check_errors`), and no session exists pre-MFA, so it is covered. Core REST never accepts plain passwords; app passwords arrive via `determine_current_user` -> `wp_validate_application_password` (default-filters.php:522; user.php:521-547), under app-password policy. Plugins that take username+password over REST (JWT-style token endpoints) hit our interception in `REST_REQUEST` context: blocked for MFA-subject users by default (`mdmfa_allow_noninteractive_password`) |
| **WP-CLI, cron** | No login occurs; unaffected. `wp mdmfa` commands are the escape hatch |
| **Recovery mode** (`enter_recovery_mode` link) | Link built from `wp_login_url()` (class-wp-recovery-mode-link-service.php:94, 116) and handled only when `$pagenow === 'wp-login.php'` (:74), which the slug router sets. Known limit: if MFA itself is the paused plugin, that recovery session logs in without MFA. Needs the admin's mailbox + password + a live fatal error. Documented, not mitigated |

### 4.4 Completion routine (the only blessed session creator)

`Auth\Completion::complete(WP_User $u, string $factor, PendingRecord $p)`: claim the pending row
(`DELETE ... WHERE token_hash = %s` and require `rows_affected === 1`, atomic single use) ->
request flag `blessed` -> `wp_set_auth_cookie($u->ID, $p->remember, $p->secure)`, and our
`attach_session_information` callback (class-wp-session-tokens.php:129) stamps
`mdmfa => {verified_at, factor}` on the new session -> clear `user_activation_key` (parity with
user.php:117-127) -> `do_action('wp_login', $u->user_login, $u)` (parity with :138) -> fire
`mdmfa_login_completed` -> redirect (or interim success page).

### 4.5 Pending record and cookie

Cookie `mdmfa_pending` = 32 random bytes, base64url; `HttpOnly`, `Secure` when the login URL is
https, `SameSite=Lax`, path `COOKIEPATH`, session lifetime. Server row stores `sha256(token)`
only. Every challenge form carries `mdmfa_form = HMAC(key, token_hash || form_purpose)`. This is
CSRF binding for logged-out posts, where WordPress nonces are shared by all anonymous users and so
are weak. Pending TTL 10 min; 5 factor attempts per record.

### 4.6 Bypass guard (direct cookie issuers)

Verified direct issuers that skip any form hook:
- WooCommerce **logs the user in after a My Account password reset** (`wc_set_customer_auth_cookie()`,
  class-wc-shortcode-my-account.php:424, "@since 9.4.0 This will log the user in", :25 of that
  docblock). For enrolled users this is an email-only login: a real MFA bypass.
- WC new-account auto-login: classic checkout (class-wc-checkout.php:1262), Store API checkout
  (StoreApi/Routes/V1/Checkout.php:1023), order-confirmation CreateAccount block (:178),
  registration (class-wc-form-handler.php:1283). All go through `wc_set_customer_auth_cookie`
  (wc-user-functions.php:312-314).
- Jetpack SSO (WordPress.com sign-in): `wp_set_auth_cookie($user->ID, true)` (jetpack-connection
  `sso/class-sso.php:1221`). It also removes Two Factor's `wp_login` hook when WP.com 2FA is on
  (:1207-1217), treating WP.com 2FA as sufficient.
- Jetpack Account Protection leaked-password flow: `wp_set_auth_cookie` after an emailed code
  (`class-password-detection.php:512`, hooked on `wp_authenticate_user`,
  `class-account-protection.php:182`).

Guard: on `set_auth_cookie` (pluggable.php:1154, which receives the session `$token`), if the user
is MFA-subject (enrolled, or Required past grace), the call is not `blessed`, and the token's
session has no `mdmfa` stamp, then: destroy that session token, return false from
`send_auth_cookies` for this call (pluggable.php:1189; no cookie leaves the server), create a
PENDING record (first factor = `guard:{source}`), and install a one-shot `wp_redirect` filter
(pluggable.php:1500) that rewrites the caller's redirect to our challenge (original target kept as
`redirect_to`). Core's own re-issue after a password change passes the **existing** token
(user.php:2935-2964), which is already stamped, so it passes. New WC customers are not enrolled and
are in grace, so they pass. Filter `mdmfa_allow_direct_auth_cookie($allow, $user, $source)`.
Every trip logs `bypass_blocked` and fires `mdmfa_bypass_blocked`.

## 5. Login location

### 5.1 Serving the slug: early routing, not a rewrite rule

Choice: detect the request path on `plugins_loaded` priority 1 (pluggable is loaded at
wp-settings.php:612, before `plugins_loaded` at :630). If it equals `home path + slug`, set
`$GLOBALS['pagenow'] = 'wp-login.php'`, and on `wp_loaded` declare
`global $error, $interim_login, $action, $user_login;` then `require ABSPATH . 'wp-login.php'`
and exit. `wp-login.php`'s own `require __DIR__ . '/wp-load.php'` (wp-login.php:12) is safe to
re-enter: wp-config is `require_once` (wp-load.php:47-50). The only side effect is that
`error_reporting()` is re-applied. The functions in `wp-login.php` read those three globals
(wp-login.php:42, 326).

Why not a rewrite rule: it needs `flush_rewrite_rules` on every slug change, fails with plain
permalinks, runs the main query first, and leaves `$pagenow` wrong. Core depends on
`$pagenow === 'wp-login.php'` in `is_protected_endpoint()` (load.php:1181-1183),
`wp_is_site_protected_by_basic_auth()` (load.php:2029), the recovery link service (:74),
script-loader (functions.wp-scripts.php:378) and l10n (l10n.php:141). Early routing keeps all of
these correct.

Known gap: `is_login()` is `stripos(wp_login_url(), $_SERVER['SCRIPT_NAME'])` (load.php:1336-1338).
On the slug, `SCRIPT_NAME` is `/index.php`, so it returns false. Build sets `SCRIPT_NAME` to the slug
path on routed requests (then `is_login()` is true). This needs a test that nothing else regresses;
if it does, drop it and document the gap.

### 5.2 404 rules (operator: 404, not redirect)

| Request | Response |
|---|---|
| `wp-login.php`, any method, unless allow-listed below | 404 on `init`@1 with `nocache_headers()` (functions.php:1509 sends `no-store, private`), rendered through the theme's 404 template, so it looks like any other missing URL |
| Allow-list on `wp-login.php` | `action=postpass` POST (password-protected posts; post-template.php:1826 posts there and the form is public, so routing it via the slug would publish the slug); `action=confirmaction` with `request_id` + `confirm_key` (privacy request emails go to non-users) |
| Logged-out `wp-admin/*` | 404 on `init`@1, before `auth_redirect()` (called at wp-admin/admin.php:104, which would otherwise redirect to the login URL, pluggable.php:1343-1348). Minimal static 404 body (theme templates are unsafe while `is_admin()` is true); filter `mdmfa_admin_404_html` |
| Exempt `wp-admin` entry points | `admin-ajax.php` (public `nopriv` AJAX, admin-ajax.php:178-207), `admin-post.php` (`nopriv` handlers incl. ours, admin-post.php:36-58), `upgrade.php`, `maint/repair.php` (only when `WP_ALLOW_REPAIR`). Static assets never reach PHP |
| Core shortcuts `/login`, `/login.php`, `/admin`, `/dashboard`, `/wp-admin` | `remove_action('template_redirect','wp_redirect_admin_locations',1000)` (default-filters.php:688; function at canonical.php:1039-1070, which would redirect to `wp_login_url()` and leak the slug). They fall through to the normal 404 |
| The slug itself | Served as core login + `nocache_headers()` + `Referrer-Policy: same-origin` + `X-Robots-Tag: noindex, nofollow` (core already adds `wp_robots_sensitive_page`, wp-login.php:49, and frame options on `login_init`, default-filters.php:398) + `define('DONOTCACHEPAGE', true)` |

### 5.3 Generated URLs

| Generator | Treatment |
|---|---|
| `login_url` (general-template.php:697) | Logged-out front-end context -> **public login page** (WC My Account when present, else the slug; owner-overridable; decision 8). Admin / logged-in / `$pagenow === 'wp-login.php'` -> slug. Affects `wp_loginout` (:616), comment "log in to reply" (comment-template.php:1817, 1936, 2625), admin bar (admin-bar.php:1309), block `wpLoginUrl`, CustomerAccount block, and `auth_redirect` (moot, it 404s first) |
| `site_url` / `network_site_url` (link-template.php:3560 / :3767) with path `wp-login.php...` | Slug, except `action=postpass` and `action=confirmaction` (kept on `wp-login.php`, allow-listed), and front-end `login_post` form actions (neutral handler, 4.3). Covers `wp_logout_url` (:652), `wp_registration_url` (:715), `wp_lostpassword_url` (:892-918), wp-login's own forms (wp-login.php:670, 891, 1027, 1161, 1514) and redirects (:961-963, 1109), core reset email (**user.php:3395**, `network_site_url(...,'login')`), new-user email (pluggable.php:2390), wp-activate (wp-activate.php:152, 207) |
| `lostpassword_url` | WC already points it at the My Account endpoint except on the core form (wc-account-functions.php:22-49); leave it |
| Privacy confirm email (user.php:4926-4933 uses `wp_login_url()`) | `user_request_action_email_content` (:5005) rewrites `###CONFIRM_URL###` to the `wp-login.php?action=confirmaction` form before core substitutes it (:5008) |
| Hardcoded strings outside filters: `wp-signup.php:545` (`http://` + domain + `wp-login.php`), `ms-functions.php:1700` and `wp-admin/includes/schema.php:1304` (default welcome-email template `BLOG_URLwp-login.php`), `ms-functions.php:1941` (`LOGINLINK` = `wp_login_url()`, filtered) | Multisite only. Filter the welcome email (`update_welcome_email`/`update_welcome_user_email`) to replace `wp-login.php` with the slug. `wp-signup.php:545` is display text after signup (goes to the new site owner); accepted and documented |

Honest framing (readme + admin): the slug removes scanner noise. It is not a security boundary.
It becomes public when the owner links it, when core registration is open (register link on the
login page), or when a user shares it. MFA is the boundary.

### 5.4 Slug lifecycle

Generated on activation: 12 chars from `[a-z0-9]` via `random_int` (about 62 bits), a bare token
with no fixed prefix, so a scanner learns nothing from its shape. The owner can set their own slug. Validation: `sanitize_title`, 4-64 chars, and it must not collide with an existing
post/page/term path, a rewrite rule, a reserved WP path (`wp-admin`, `wp-content`, `wp-json`,
`feed`...), or the My Account page. On change: admin notice + email to all admins with the new URL,
cache purge of old and new URLs (5.6), `mdmfa_login_slug_changed`. Change requires step-up.

### 5.5 Lost-slug recovery

`define('MDMFA_LOGIN_SLUG', 'x')` overrides the stored slug. `define('MDMFA_DISABLE_LOGIN_LOCATION', true)`
restores `wp-login.php` and leaves MFA on. `wp mdmfa slug get|set <slug>|reset`. `MDMFA_DISABLE`
turns everything off (11.4). The slug is also in every admin's email from 5.4.

### 5.6 Caches

- **maxtdesign-cache**: the drop-in already excludes `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`,
  `/wp-json` (Settings.php:24-34). Slug handling: (1) our responses send `no-store`, which
  `RequestPolicy::is_storable_response` rejects (RequestPolicy.php:78-81), so a slug page is never
  stored; (2) **404s are storable** (RequestPolicy.php:22). A 404 cached at a path before it became
  the slug would shadow the login page from the drop-in before WP loads. So on every slug change
  MFA fires `do_action('md_suite_content_changed', ['url' => $url])` for the old and new URLs,
  which cache purges per URL (SuitePurgeBridge.php:40, 61-66); (3) add the slug to
  `exclude_paths` via `md_cache_config` (Settings.php:159). The config file only regenerates when
  cache's own option changes (Plugin.php:53-54), so this takes effect on the next regeneration.
  **Request to the cache owner (flag, do not reach in):** a public `md_cache_regenerate_config`
  action. MFA calls it `is_callable`/`has_action`-guarded when it exists.
- **Others**: `DONOTCACHEPAGE` + `nocache_headers()` on slug, challenge and enrollment responses;
  `litespeed_control_set_nocache` action when LiteSpeed is active; WP Rocket
  `rocket_cache_reject_uri` filter. Batcache (Pressable) and host edge caches are UNVERIFIED for
  `no-store` handling: test matrix.

## 6. Data model

Prefixes from the registry row (`mdmfa_`, `MDMFA_`). Schema version option `mdmfa_db_version`;
installer `dbDelta` on activation and on `plugins_loaded` when the version differs.

### 6.1 Tables

| Table | Scope | Columns (Build finalizes types) |
|---|---|---|
| `{base_prefix}mdmfa_credentials` (decision 5: registry says `{$wpdb->prefix}`; users and user meta are network-global, so passkeys must be too; identical on single site) | user | `id` BIGINT UNSIGNED PK AI; `user_id` BIGINT UNSIGNED, index; `cred_hash` CHAR(64) UNIQUE (sha256 of credential ID); `cred_id` VARCHAR(1400) base64url (spec cap 1023 bytes); `public_key` TEXT (COSE, base64url); `alg` SMALLINT; `sign_count` INT UNSIGNED; `transports` VARCHAR(191); `aaguid` CHAR(36); `be` TINYINT; `bs` TINYINT; `rp_id` VARCHAR(253), index with `user_id`; `name` VARCHAR(191); `created_at`, `last_used_at` DATETIME (GMT); `flagged` TINYINT (counter anomaly) |
| `{prefix}mdmfa_pending` | site | `token_hash` CHAR(64) PK; `kind` VARCHAR(16) (`login`, `email_code`, `recovery_link`, `wa_used`); `user_id` BIGINT UNSIGNED NULL; `payload` TEXT (JSON: context, redirect_to, remember, secure, interim, first_factor, code hash, attempts); `created_at`, `expires_at` INT UNSIGNED, index |
| `{prefix}mdmfa_log` | site | `id` PK; `user_id` NULL; `event` VARCHAR(32) (enrolled, factor_removed, challenge_ok, challenge_fail, locked, unlocked, recovery_used, admin_reset, bypass_blocked, slug_changed, policy_changed, counter_anomaly); `factor` VARCHAR(16); `context` VARCHAR(16); `ip` VARBINARY(16) truncated by default (/24 v4, /48 v6; decision 11); `actor_id` NULL; `created_at` INT UNSIGNED, index. Purged by daily cron (`mdmfa_purge`) at retention (default 90 days) |

### 6.2 User meta (network-global on multisite by nature)

`mdmfa_totp` `{ct, nonce, kid, created, last_step}` (secret encrypted, see 6.5); `mdmfa_recovery`
`{hashes: [...10 wp_hash_password], created}`; `mdmfa_email` `{enabled, confirmed_at}`;
`mdmfa_user_handle` (32 random bytes base64url, never the user ID); `mdmfa_enrolled` (`'1'`
index flag for counting); `mdmfa_grace_started` (int); `mdmfa_failures` `{count, window_start,
locked_until, lock_level}`; `mdmfa_trusted` (list, max 10, `{selector, validator_hash, expires,
ua_label}`); `mdmfa_prefs` `{default_factor}`.

### 6.3 Options

`mdmfa_login` (autoload **on**, small: `{enabled, slug, public_login, allow_core_register}`, read on
every request with zero added queries because it is autoloaded); `mdmfa_settings` (autoload
**off**: role policy matrix, factor toggles, grace days, trusted-device settings, side-door
policy, lockout thresholds, log retention, IP mode); `mdmfa_db_version`; `mdmfa_key_check`
(key id fingerprint only); `mdmfa_activated_at`; `mdmfa_notices`.

### 6.4 Other state

Transients `mdmfa_ipthrottle_{hash}` (per-IP soft throttle, best effort) and
`mdmfa_status_cache` (15 min). Cookies: `mdmfa_pending`, `mdmfa_td`, all strictly necessary
(security), declared in `wp_add_privacy_policy_content`. Cron: `mdmfa_purge` daily (expired pending
rows, log retention, expired trusted devices). Constants read: `MDMFA_DISABLE`,
`MDMFA_DISABLE_LOGIN_LOCATION`, `MDMFA_LOGIN_SLUG`, `MDMFA_ENCRYPTION_KEY`.

### 6.5 Encryption

`sodium_crypto_aead_xchacha20poly1305_ietf_encrypt`, AAD = `"mdmfa:totp:v1:" . user_id`, so a
ciphertext cannot be moved to another user. Key precedence: `MDMFA_ENCRYPTION_KEY` (base64, 32
bytes) -> HKDF-SHA256 over the `AUTH_KEY` and `SECURE_AUTH_KEY` **constants** (info
`mdmfa-totp-v1`). If the salts are not constants (core then stores them in the DB), show an admin
warning that encryption gives no protection against a DB dump and recommend the constant. `kid` =
first 8 bytes of sha256(key) is stored with each ciphertext. On mismatch, TOTP for that user
reports "unreadable (key changed)" and the user falls back to other factors or recovery.
Rotation: `wp mdmfa key status`, `wp mdmfa key rewrap --from=<old|salts> --to=<constant|salts>`
(decrypt with old, encrypt with new, per-user, resumable). Admin guidance: "before rotating
salts, define `MDMFA_ENCRYPTION_KEY` via `wp mdmfa key export-define`". CLI only, because the key
never renders in a browser.

### 6.6 Uninstall / delete obligations

`uninstall.php`: drop the three tables (per site on multisite; credentials once via
`base_prefix`); delete all `mdmfa_*` options and transients; `delete_metadata('user', 0, $key, '',
true)` for each user meta key; clear `mdmfa_purge` cron; strip the `mdmfa` field from sessions is
not needed (sessions expire; the stamp is inert). User deletion (`deleted_user`,
`wpmu_delete_user`) removes that user's credentials rows and pending rows. Privacy: exporter
(factors present, names and dates of passkeys, log rows) and eraser (log rows; factor data removed
with the account) registered on `wp_privacy_personal_data_exporters`/`_erasers`. Deactivation
removes nothing and instantly restores core login (documented: anyone able to deactivate plugins
can turn MFA off).

## 7. Integration points

### 7.1 Hooks consumed (verified, file:line)

| Hook | Where | Use |
|---|---|---|
| `authenticate` @PHP_INT_MAX | pluggable.php:706 | interception (4.2) |
| `woocommerce_login_credentials` | class-wc-form-handler.php:1135 | context flag `wc` |
| `login_form_mdmfa-verify`, `login_form_mdmfa-enroll`, `login_form_mdmfa-recover` | wp-login.php:565 (admitted by :503-505) | core-path screens |
| `login_init` | wp-login.php:540 | slug-page headers, error-state setup |
| `set_auth_cookie` / `send_auth_cookies` | pluggable.php:1154 / :1189 | bypass guard |
| `attach_session_information` | class-wp-session-tokens.php:129 | stamp verified sessions |
| `wp_redirect` | pluggable.php:1500 | guard's one-shot redirect capture |
| `application_password_did_authenticate`, `wp_authenticate_application_password_errors` | user.php:497, :478 | context + per-request veto |
| `wp_is_application_passwords_available(_for_user)` | user.php:5177, :5212 | app-password policy |
| `xmlrpc_enabled`, `xmlrpc_login_error` | class-wp-xmlrpc-server.php:223, :325 | XML-RPC policy + message |
| `login_url`, `logout_url`, `register_url` | general-template.php:697, 663, 715 | 5.3 |
| `site_url`, `network_site_url` | link-template.php:3560, 3767 | 5.3 |
| `user_request_action_email_content` | user.php:5005 | confirmaction URL |
| `template_redirect` (remove `wp_redirect_admin_locations`) | default-filters.php:688 | 5.2 |
| `plugins_loaded`@1, `init`@1, `wp_loaded` | wp-settings.php:630, 779, 801 | routing, 404s, slug include |
| `wc_get_template` | wc-core-functions.php:320 | My Account challenge swap |
| `wp_loaded`@15 | before WC's @20 (class-wc-form-handler.php:37-41) | WC challenge POST |
| `after_password_reset`, `profile_update`, `password_reset` | user.php:3524, :3537; WC fires `after_password_reset` too (class-wc-shortcode-my-account.php:416) | revoke trusted devices |
| `wp_authenticate_user` (applied, not hooked) | user.php:203 | passwordless account-state veto |
| `md_suite_status`@5, `md_suite_loaded` | suite-core | contract + registry (guarded) |
| `md_cache_config`; fire `md_suite_content_changed` | maxtdesign-cache Settings.php:159; SuitePurgeBridge.php:40 | 5.6 |
| `jetpack_get_available_modules` (only if the owner turns on "Block WordPress.com sign-in") | jetpack-status class-modules.php:319 | decision 10 |

### 7.2 Hooks exposed

Actions: `mdmfa_challenge_started($user, $context)`, `mdmfa_factor_verified($user, $factor,
$context)`, `mdmfa_factor_failed($user, $factor, $reason)`, `mdmfa_login_completed($user,
$factor, $context)`, `mdmfa_enrolled($user, $factor)`, `mdmfa_factor_removed($user, $factor,
$actor_id)`, `mdmfa_user_locked($user, $until)`, `mdmfa_user_unlocked($user, $actor_id)`,
`mdmfa_recovery_code_used($user, $remaining)`, `mdmfa_bypass_blocked($user, $source)`,
`mdmfa_passkey_counter_anomaly($user, $credential_row_id)`, `mdmfa_login_slug_changed()` (no
slug in args; readers call the getter under capability).
Filters: `mdmfa_user_policy`, `mdmfa_allowed_factors`, `mdmfa_allow_direct_auth_cookie`,
`mdmfa_allow_noninteractive_password`, `mdmfa_challenge_url`, `mdmfa_public_login_url`,
`mdmfa_webauthn_origins`, `mdmfa_webauthn_rp_id`, `mdmfa_lockout_thresholds`,
`mdmfa_trusted_device_lifetime`, `mdmfa_email_code_message`, `mdmfa_admin_404_html`,
`mdmfa_manage_capability`, `mdmfa_status`. No filter can turn a Required user's factor off
without leaving a log row.

### 7.3 Status contract (read-only; never secrets)

`Snapshot::build()`: plugin + schema version; `disabled` (MDMFA_DISABLE), `login_location`
(enabled bool; **not** the slug), `key_source` (constant|salts|db) + `key_ok`; per role: policy,
allowed factors, grace days, users, enrolled, by factor, in grace, overdue; active lockouts; 24h
challenge failures; bypass blocks (24h); app-password and XML-RPC policy; unverified live sessions
for Required roles. Cached 15 min (`mdmfa_status_cache`); `wp mdmfa status [--fresh] [--format=json]`.
No REST route (suite model: a same-site reader handles network exposure).

## 8. Admin surface

Operator capability: meta-cap `mdmfa_manage` mapped to `manage_options` (filter
`mdmfa_manage_capability`; multisite network settings use `manage_network_options`). Resetting
another user's factors needs `mdmfa_manage` + `edit_user` on that user; a super admin can only
be reset by a super admin. Every admin action is logged and emails the affected user.

| Screen | Where | Content |
|---|---|---|
| Settings `md-mfa` (tabs `?tab=`: Policy, Factors, Login location, Side doors, Recovery, Activity, Tools) | suite submenu when suite-core is present, else Users -> "Login security (MFA)" | Policy = role x {Off/Optional/Required, allowed factors, passwordless, grace}; Login location = slug, public login page, cache notes, copyable URL; Side doors = app passwords + XML-RPC matrices, Jetpack status/warnings; Activity = log (`WP_List_Table`); Tools = key status, conflict detector (Two Factor, WP 2FA, FluentAuth, Solid Security 2FA, miniOrange: warn and do not co-enforce), export settings |
| Coverage | tab or `users.php` column + filter | enrolled/factors/grace/locked per user; bulk "require re-enrollment", "unlock", "sign out everywhere" (admin-post, nonce, cap) |
| My security | `profile.php?page=mdmfa-account` (own screen), linked from profile | enroll/remove TOTP, passkeys, email code, recovery codes, trusted devices, sessions |
| Profile summary | `show_user_profile`/`edit_user_profile` | server-rendered status box + link; **no assets** |

Asset gate: capture every `add_*_page()` return and compare `$hook_suffix` exactly (nav handoff
§4.6). Saves: `admin-post.php` PRG with `check_admin_referer` + `current_user_can('mdmfa_manage')`
+ step-up where 4.3 says. Notice codes in the query (no raw text).

**Admin UI approach (decision 2), recommendation: server-rendered WP-native + suite class shapes
+ small vanilla modules.** Numbers from the 7.1.2 tree: `@wordpress/components` =
`components.min.js` 836,689 B (271,687 gz) + `react-dom.min.js` 131,835 B + `style.min.css`
108,784 B + 20 declared deps (`script-loader-packages.php`). Those bytes come from core, but they
are still parsed on our screen and require a Node build toolchain. Reasons for server-rendered: a
settings screen that can lock the owner out must work when JS fails; WCAG 2.2 AA is easier with
native forms; it looks WP-native on a stranger's site and inherits suite styling when suite-core
is present (Tier-2 pattern, admin UI handoff §7.1); no build step. Enterprise-grade comes from the
policy matrix design, honest empty/degraded states, badges, confirm dialogs and step-up, not from
React. Own CSS <= 4 KB; admin JS modules (confirm dialog when suite JS is absent, copy-to-clipboard,
passkey enrollment) <= 8 KB total, each file size-checked.

## 9. Front-end surface (exact) and the measurement

| Page | Plugin output |
|---|---|
| Every normal front-end page | **Nothing**: 0 bytes, 0 requests, 0 added DB queries (autoloaded `mdmfa_login` only) |
| Core slug page, TOTP/email/recovery challenge, enrollment without passkeys | core login CSS/JS only; plugin adds 0 CSS, 0 JS; the QR is an inline SVG (content) |
| My Account / checkout challenge + enrollment + My Account "Security" endpoint | WC/theme-styled markup; 0 plugin CSS/JS unless passkeys are offered |
| Any screen offering passkeys (login with passwordless on; challenge with a passkey factor; passkey enrollment) | one deferred `mdmfa-passkey.js` (vanilla ES module, no deps, no jQuery): budget **<= 3,072 B minified, <= 1,536 B gzip**, loaded only on those screens; options passed as a `data-` attribute, no inline script |
| Admin (our screens only) | <= 4 KB CSS, <= 8 KB JS as above; zero on other admin screens |

Necessary-footprint record (quality standard §1): need = the WebAuthn browser API has no no-JS
path; alternatives rejected = a JS-free passkey flow (impossible), core `wp-*` packages (hundreds
of KB); loading condition = listed screens only; cost = 1 request, <= 3 KB.

Proof (P5 and P8, recorded in STATE.md with date, tool versions and numbers):
`tools/js-size-check.php` and `tools/css-size-check.php` (copy the pattern from
`maxtdesign-cookie-consent/tools/`) fail CI over budget. Network audit on Studio of home, single,
archive, shop, product, cart, checkout, My Account (logged out and in): plugin requests = 0, and
on the passkey screens exactly 1. Query Monitor: 0 plugin queries on those pages. Lighthouse CLI
mobile active vs inactive on the same page types (LCP/INP-lab/CLS, noting that TBT is not INP).
Admin: our screens load our assets; two unrelated admin screens load none.

## 10. Security surface

### 10.1 Inputs -> sinks

| Input | Validation | Sink / protection |
|---|---|---|
| `log`/`pwd`/`username`/`password` | core | untouched; we only see the verdict |
| `mdmfa_code` (TOTP 6 digits, email 8 digits, recovery 16 base32 with separators stripped) | regex per factor, length | `hash_equals` (TOTP), `wp_check_password` (recovery), `wp_verify_fast_hash` (email) |
| `mdmfa_form` (HMAC) | `hash_equals` | CSRF binding for logged-out posts |
| `mdmfa_pending`, `mdmfa_td` cookies | length + base64url charset | sha256 -> prepared lookup |
| WebAuthn `credential` JSON (hidden field, <= 16 KB) | strict JSON decode, then the verifier's restricted CBOR (section 12) | parameterized lookup by `cred_hash` |
| `redirect_to` / WC `redirect` | stored server-side; `wp_validate_redirect` at use (pluggable.php:1632, 1729) | never reflected unescaped |
| Admin settings arrays | per-field allow-list (`sanitize_key` for roles and factors, `absint` for ranges, slug validator 5.4) | options API |
| Passkey `name` | `sanitize_text_field`, 64 chars | `esc_html` at output |
| Log output | stored raw | `esc_html` at output |

### 10.2 State changes

Logged-out: HMAC form token + pending cookie + attempt cap. Logged-in self-service: `wp_nonce_field`
+ `check_admin_referer` (WC endpoint: nonce + `is_user_logged_in` + own-user check) + step-up for
removals. Admin: nonce + `mdmfa_manage` (+ `edit_user`). No GET mutations; the only GET with an
effect is the email recovery link, which asks for confirmation on a POST form.

### 10.3 REST routes

**None in v1.** WebAuthn ceremonies are form posts; the status contract is local PHP. If a later
phase adds any route, it needs a real `permission_callback` and an args schema.

### 10.4 Headers and crypto

Slug/challenge/enrollment: `nocache_headers`, `Referrer-Policy: same-origin`, frame options
(`send_frame_options_header`, functions.php:7282) on WC challenge pages too. All secrets from
`random_bytes`; all comparisons `hash_equals`; secrets never logged; the status contract and CLI
never print TOTP secrets, recovery codes, keys or the slug (except `wp mdmfa slug get`, which is
server access by definition).

### 10.5 Outbound HTTP

None. Grep gate in CI: `wp_remote_|curl_|file_get_contents\(\s*['"]https?|fsockopen|wp_safe_remote_`
= 0 hits outside `tests/`. No FIDO MDS.

## 11. Rate limiting, lockout, recovery

### 11.1 Throttles

| Scope | Limit | Store |
|---|---|---|
| Per pending record | 5 factor attempts, then the record is burned (password again) | `mdmfa_pending.payload` |
| Per user, consecutive second-factor failures across records | after 5: backoff 30s doubling; at 20: lock 1 h; repeat lock: 24 h. Cap far below NIST's 100 (SP 800-63B-4). Success resets | `mdmfa_failures` user meta (authoritative; survives object-cache eviction) |
| Email code sends | 3 per 15 min, 10 per day per user; code TTL 10 min, 5 attempts | user meta + pending row |
| Per IP (passwordless finish, email-recovery request) | 30 per 10 min soft throttle | transient (best effort) |
| TOTP replay | reject a step <= `last_step`; window +/-1 step | `mdmfa_totp.last_step` |

A lock blocks second-factor attempts only (an attacker needs the password to reach it). Locked
users and admins are emailed. Unlock: admin (Coverage), `wp mdmfa unlock <user>`, or expiry.

### 11.2 Recovery ladder

1. Another factor (users are nudged to hold 2+: TOTP + passkey, or passkey on 2 devices).
2. Recovery codes: 10 x 16 base32 (80 bits each), `wp_hash_password`-hashed (NIST requires an
   approved password hash under 112 bits), single use, warn at <= 3, regenerate needs step-up.
3. Email recovery (owner setting; default **off** for staff roles, on for customer): from the
   challenge screen only (after the password, so no enumeration), link TTL 1 h -> confirmation
   POST -> waiting period (staff 24 h, customer 0; decision 12) -> factors reset -> re-enroll at
   next login. Notices to the user and to admins for staff roles.
4. Admin reset (Coverage) -> the user's factors are cleared and grace restarts.
5. Server escape hatch (11.4).

### 11.3 NIST alignment (stated, not claimed as compliance)

Email code off for staff by default (SP 800-63B-4: email SHALL NOT be used for out-of-band
authentication). Passkeys give the phishing-resistant AAL2 option. Recovery codes = look-up
secrets. Readme makes no compliance claim beyond "helps meet".

### 11.4 Escape hatch

`define('MDMFA_DISABLE', true)` in wp-config: no interception, no guard, no login location, and a
red notice on every admin screen for admins. `wp mdmfa disable-check`, `wp mdmfa user reset
<user> [--factor=...]`, `wp mdmfa unlock <user>`, `wp mdmfa slug get|set|reset`, `wp mdmfa key
status|rewrap|export-define`, `wp mdmfa status`, `wp mdmfa recovery-codes <user> --yes` (prints
once). **Every release** runs an escape-hatch test (P8 and the gate checklist).

## 12. WebAuthn

**Library: in-house verifier (recommended, operator decision 3)**, see
[webauthn-library-eval.md](webauthn-library-eval.md). "none" attestation only; ES256, RS256,
EdDSA (EdDSA last in `pubKeyCredParams`; via sodium or core sodium_compat); about 1,000-1,500 LOC;
no Composer runtime deps. `web-auth/webauthn-lib` and `lbuchs/webauthn` are **require-dev test
oracles only** (must not appear in the zip; the gate's zip extraction proves it). Fallback, only
if the operator prefers schedule: vendored lbuchs v2.2.0 with the eval's 5-item patch set.

Requirements the verifier must meet (acceptance tests in P5):
- Restricted CBOR: major types 0-5 and 7 only, definite lengths, depth limit, length vs remaining
  checks, reject tags/indefinite/floats/duplicate map keys; binary-safe `strlen`/`substr`, no
  `mb_*`.
- COSE -> SPKI for EC2 P-256, RSA, OKP Ed25519; `openssl_verify(...) === 1` only.
- authenticatorData: rpIdHash vs configured rpId; UP always; **UV required for passwordless**,
  preferred for second factor; never take the UV requirement from the client; reject BE=0 with
  BS=1; store BE/BS and update BS; signCount unsigned 32-bit, policy per eval §5.3 (both 0 ->
  skip; regression -> flag + `mdmfa_passkey_counter_anomaly`, owner setting to also block).
- clientDataJSON: type, challenge (`hash_equals`), origin **exact** scheme+host+port allow-list
  from `site_url()` and `home_url()` (never `HTTP_HOST`/`X-Forwarded-*`), `crossOrigin` true
  rejected. rpId from the configured host (`mdmfa_webauthn_rp_id` filter; https required except
  localhost).
- Usernameless: resolve the credential by `cred_hash`, then **verify userHandle ==
  `mdmfa_user_handle` of the owning user**; no user-existence signal in responses or
  `allowCredentials` shape (CVE-2024-39912 lesson).
- Challenge: stateless HMAC for login (4.3), server-side single-use record at finish; enrollment
  challenge bound to the session.
- Credential ID <= 1023 bytes; excludeCredentials on enrollment; per-user passkey cap 20.
- Multisite subdomain networks: distinct rpId per site; URL-change warning (passkeys orphan).
- Work items: fuzzing of the CBOR/COSE parsers (php-fuzzer or a seeded random-mutation harness in
  CI), differential tests against both oracles on shared ceremony fixtures, and an **external
  review before 1.0**. No "audited" claim anywhere until that review is recorded (decision 4).

## 13. Compatibility test matrix

Run in P8 on Studio (WP 7.1.2 target; the Studio `maxtoffroad` site is on 7.0.2 and must be
updated first, or use a fresh Studio site: **not** a junction-mounted one for zip installs, per
plugin-root CLAUDE.md). PHP 8.3 and 8.5. Each cell: login (password + each factor), passwordless,
enrollment, 404s, slug leak scan, lockout + escape hatch.

| Target | Specific checks |
|---|---|
| Single site, plain permalinks + pretty permalinks | slug routing, `/login` shortcuts 404 |
| Subdirectory install (`home` != `siteurl`) | slug path, rpId/origins, `network_site_url` rewrites |
| Multisite subdirectory + subdomain | super admin Required, per-site policy, base_prefix credentials, wp-signup/wp-activate, welcome email |
| WooCommerce 11.1.2 classic My Account + checkout; block cart/checkout; Customer Account block; coming-soon mode (LaunchYourStore) | challenge on My Account, reset auto-login conversion (4.6), checkout new-account guard pass, `wpLoginUrl` not the slug, cart merge after login |
| Jetpack 16.2: connection, SSO (with and without WP.com 2FA), Account Protection, Brute Force (WAF) | `jetpack.*` XML-RPC unaffected, SSO guarded or blocked, leaked-password flow converted, brute force at `authenticate`@10 coexists |
| Pressable (Batcache, edge cache, Jetpack preinstalled) | `no-store` honored (UNVERIFIED today), 404 pages not serving cached login, MyPressable unaffected (outside WordPress) |
| maxtdesign-cache | drop-in never serves slug or challenge; pre-cached 404 at a new slug purged |
| WP Rocket, LiteSpeed Cache, W3 Total Cache, WP Super Cache, Cloudflare APO | exclusions honored |
| Membership: MemberPress, Paid Memberships Pro, Ultimate Member (incl. AJAX login), WooCommerce Memberships/Subscriptions | `unknown-post`/`ajax` paths, redirects preserved |
| Security: Limit Login Attempts Reloaded, Solid Security (2FA off), Wordfence (firewall only) | no double 2FA, failure counters sane |
| Other 2FA plugin active (Two Factor 0.17.0, WP 2FA) | conflict notice, no co-enforcement |
| Mobile app (XML-RPC + app passwords), REST client with app password, JWT-style plugin | side-door policies |
| Privacy tools, password-protected posts, recovery mode link | allow-listed `wp-login.php` actions |
| Suite: suite-core present (Signal, Cache) vs absent; stale suite-core winning the loader | opportunistic mount, `method_exists` guards, no front-end script from MFA itself |

## 14. Phases

Executors: build = `wp-plugin-dev`; review = `wp-reviewer` + `wp-security-auditor` + `wp-perf-qa`;
gate/release = `wp-release-engineer` (operator pushes). Branch per phase (`feat/{slug}`), PR
squash + delete.

| # | Scope | Depends | Definition of done (observable) | Executor |
|---|---|---|---|---|
| P1 | Scaffold: repo `maxtdesign-mfa` (public), header (`Requires PHP: 8.3`, `Requires at least: 7.0`, `Tested up to: 7.1`), PSR-4 `MaxtDesign\Mfa`, `strict_types`, composer (`config.platform.php` 8.3.0, no runtime deps), **deliverable set: readme.txt (wp.org format, `== Security ==`, `slaacr` disclosure, honest login-location framing), SECURITY.md (template), docs/STATE.md (tracking-notes standard; Next action 1 = operator acceptance of this plan), .distignore (root-anchored)**, `uninstall.php`, installer + schema v1 (3 tables), settings model with defaults, crypto service (6.5), `MDMFA_DISABLE`, WP-CLI skeleton, CI (PHPUnit + PHPStan L8 on 8.3/8.4/8.5, outbound-HTTP grep, size-check scaffolds) | plan accepted | `plugin-deliverables.php` PASS; commit gate passes with no bypass; activate -> 3 tables + options exist; uninstall test leaves 0 `mdmfa_` rows/tables/meta; crypto round-trip + wrong-AAD rejection tests; PHPStan L8 clean | wp-plugin-dev |
| P2 | Core auth: policy engine, interception (4.2), pending records, completion (4.4), session stamp, TOTP + QR SVG, recovery codes, challenge/enroll/grace screens on `wp-login.php` (login location not yet active), throttles + lockout, bypass guard, self-service "My security" (TOTP, recovery codes), WP-CLI reset/unlock/status | P1 | Integration tests: session count unchanged and no auth cookie after a correct password for an enrolled user; `wp_login` fires exactly once at completion; pending single use under 2 concurrent requests; 6th attempt burns the record; lock at 20; TOTP replay rejected; guard blocks a direct `wp_set_auth_cookie` for an enrolled user and passes core's re-issue on password change; interim login works; escape-hatch test | wp-plugin-dev |
| P3 | Customer path: My Account + checkout challenge/enroll (`wc_get_template` swap), WC reset auto-login conversion, My Account "Security" endpoint, front-end neutral handler (`admin-post` `mdmfa_login`), `unknown-post`/`ajax` handling | P2 | E2E on Studio with WC 11.1.2: customer never loads `wp-login.php` (server log); reset -> challenge, not a session; checkout login returns to checkout with the cart; new-account checkout still logs in; 0 plugin CSS/JS on these pages | wp-plugin-dev |
| P4 | Login location: routing (5.1), 404 rules + allow-list (5.2), URL rewrites (5.3), slug lifecycle + collision checks + admin email (5.4), recovery constants/CLI (5.5), cache integration (5.6), `SCRIPT_NAME`/`is_login()` test | P2 (P3 for the public login page) | Automated request matrix: every row of 5.2 returns the stated status; anonymous crawl of 30 front-end URLs (incl. block checkout, comments, password-protected post) contains 0 occurrences of the slug; privacy confirm and postpass work; recovery-mode link works; slug change purges maxtdesign-cache URLs | wp-plugin-dev |
| P5 | Passkeys: in-house verifier (12), fuzz harness, differential tests vs both oracles, enrollment (admin + My Account), second factor, passwordless + conditional UI, counter policy, `mdmfa-passkey.js` under budget | P2, P3, decision 3 | Verifier suite green incl. differential corpus (accept/reject parity); fuzz run of N iterations (N set in Build, recorded) with 0 crashes/hangs; size-check PASS <= 3,072 B; passwordless requires UV; userHandle mismatch rejected; manual on Chrome, Safari (iCloud Keychain), Firefox, Android, Windows Hello, a YubiKey | wp-plugin-dev |
| P6 | Email code, trusted devices, side doors (app passwords, XML-RPC, non-interactive password APIs), Jetpack detection + optional SSO block, email recovery flow, step-up, conflict detector | P2 | Side-door matrix tests (4.3 rows) pass; email send limits enforced; trusted device revoked on password reset; step-up enforced on each listed action | wp-plugin-dev |
| P7 | Admin UX completion (decision 2): policy matrix, coverage, activity log, tools, suite mount/fallback, status contract + suite contribute, privacy exporter/eraser + policy text, readme + screenshots | P2-P6 | Nav handoff §8 + admin UI handoff §10 checklists pass; keyboard pass; `wp mdmfa status --format=json` matches the admin counts; contract contains no secret or slug (test) | wp-plugin-dev |
| P8 | Review + evidence: lanes review, source-to-sink security audit (0 open Critical/High), footprint audit (9), compat matrix (13), escape-hatch test, **external WebAuthn review commissioned and its findings closed** before 1.0 | P1-P7 | Review + audit reports in `docs/`; numbers in STATE.md; matrix results table; external review report recorded | wp-reviewer, wp-security-auditor, wp-perf-qa |
| P9 | Gate + release: version triple, changelog, `release-gate.php` exit 0 on the exact tree (zip preflight, SBOM from the zip), wp.org submission via `slaacr`, SVN | P8 | `RELEASE GATE PASSED` marker; the zip contains 0 dev oracles (extraction); SVN revision in STATE.md; registry row updated to shipped | wp-release-engineer |

## 15. Risks

1. **Lockout** (worst case): escape hatch + CLI + constants; a release-blocking test in every gate.
2. **Custom-login-form ecosystem**: `unknown-post`/`ajax` heuristics may mis-route an exotic form.
   Mitigated by `mdmfa_is_interactive_login`-style filters and the matrix; the unknown case is a
   clear error with a working link, never a silent session.
3. **Exiting inside `authenticate`**: callers that use `wp_authenticate()` only to check a
   password (for example a "confirm password" dialog in the browser) would be redirected.
   Mitigation: only `core`/`wc`/`frontend`/`unknown-post` contexts exit; a logged-in user
   re-checking their own password is passed through.
4. **Bypass guard over-blocking** a legitimate direct login (SSO or magic-link plugins): logged,
   filterable, admin notice naming the source.
5. **In-house WebAuthn** parsing risk (eval §8): fuzz, differential, external review, no audited claim.
6. **Slug leakage** by owners (menus, links): documented; admin shows where the public login
   page points.
7. **`is_login()` false on the slug** if the `SCRIPT_NAME` approach regresses something.
8. **Salt rotation** makes TOTP unreadable: the constant key path, rewrap CLI, admin warning.
9. **Pressable/Batcache/edge behaviour** is UNVERIFIED: matrix; fallback exclusions documented.
10. **Recovery mode** can pause MFA for that session (4.3): documented.
11. **Deactivation turns MFA off**: inherent to plugins; documented; the activity log records
    `deactivated_plugin` for MFA itself.
12. **maxtdesign-cache regenerate hook** does not exist yet: interim mitigation via `no-store` + URL purge.

## 16. Operator decisions (numbered; recommendation first)

**All accepted as recommended, operator 2026-09-30.**

1. **suite-core: do not vendor; integrate opportunistically** (brief said vendor). Reason: 522 B
   inline script on every front-end page + a "MaxtDesign" top-level menu on strangers' sites;
   nav handoff §4.4.
2. **Admin UI: server-rendered WP-native + suite class shapes + small vanilla modules** (not
   `@wordpress/components`, not vendored suite-core). Numbers in section 8.
3. **WebAuthn: in-house verifier** per eval (fallback: lbuchs v2.2.0 + patch set).
4. **1.0 on wp.org waits for the external WebAuthn review.** Alternative: ship 1.0 with passkeys
   hidden behind "preview" until the review; not recommended (it confuses the differentiator).
5. **Credentials table on `$wpdb->base_prefix`** (network-global) and site tables on
   `$wpdb->prefix`; update the registry wording from `{$wpdb->prefix}mdmfa_*`.
6. **Multisite v1**: per-site policy, super admins always Required, network settings screen deferred.
7. **Grace default 7 days** for Required roles, then forced inline enrollment; existing sessions
   are not killed at activation (shown in status as "unverified sessions").
8. **Public login page**: logged-out front-end login links resolve to WC My Account (WC sites) or
   the slug (non-WC), owner-overridable.
9. **Front-end `wp_login_form()` posts to a neutral `admin-post` handler**, not the slug.
10. **Jetpack SSO**: do not accept WordPress.com 2FA as satisfying MFA (the guard enforces our
    challenge after SSO); offer "Block WordPress.com sign-in", default **off**.
11. **Log IPs truncated** (/24, /48), 90-day retention; full-IP opt-in.
12. **Email recovery**: off for staff roles by default; when on, 24 h waiting period for staff,
    none for customers; email-code factor allowed for customers by default, off for staff.
13. **Floors**: `Requires at least: 7.0` (tested 7.1), WooCommerce integration floor 11.0 (tested 11.1).
14. **Lockout numbers**: 5 per pending record; backoff from 5; lock 1 h at 20; 24 h on repeat.
15. **Trusted devices**: available, off at install for every role; 30-day lifetime when enabled.

## 17. Brief corrections and flags found in verification

- The core **password reset email is in `user.php:3395`** (`retrieve_password()`), not
  `pluggable.php`. `pluggable.php:2390` is the new-user notification. Both use
  `network_site_url(..., 'login')`, so the `network_site_url` filter (link-template.php:3767) is
  required as well as `site_url`.
- **"Logged-out wp-admin = 404" must exempt `admin-ajax.php`, `admin-post.php`, `upgrade.php`**;
  otherwise public AJAX (WooCommerce, forms) breaks. The brief did not say so.
- **`action=postpass` and `action=confirmaction` cannot move to the slug** without publishing it
  (post-template.php:1826 public form; privacy emails to non-users via user.php:4933). They stay
  on an allow-listed `wp-login.php`.
- **WooCommerce logs users in after a My Account password reset** (since 9.4.0,
  class-wc-shortcode-my-account.php:424), and Jetpack SSO (class-sso.php:1221) plus Account
  Protection (class-password-detection.php:512) set auth cookies directly. Form-level MFA misses
  all three; the guard (4.6) is required, not optional.
- The brief's "Jetpack: only detect and warn" is too weak: the guard enforces MFA after SSO, and
  Jetpack's own XML-RPC auth strips all `authenticate` filters (class-manager.php:387-397), so
  blocking password XML-RPC does not break Jetpack.
- **Vendoring suite-core breaks this plugin's zero-footprint statement** (MdSuite_Admin.php:46,
  513-534, 522 B measured) and contradicts nav handoff §4.4.
- **maxtdesign-cache stores 404s** (RequestPolicy.php:22) and has no public config-regenerate hook
  (Plugin.php:53-54): request filed above; interim mitigation designed.
- "Rate-limit state in transients" changed: per-user counters in user meta (authoritative); only
  per-IP soft limits use transients. Two tables added (`mdmfa_pending`, `mdmfa_log`).
- `is_login()` is false on any custom slug served through `index.php` (load.php:1336-1338); every
  login-hider shares this. Planned fix in 5.1.
- webauthn-library-eval uses `md_mfa_webauthn_origins`; the registry prefix makes it
  `mdmfa_webauthn_origins`. Its platform pin is 8.2; the locked floor is 8.3.
- UNVERIFIED and not re-checked: the brief's FluentAuth claims (teardown by another session);
  Pressable Batcache/edge handling of `no-store`; QR library candidates' licenses and sizes.
- Shared-asset observations for the improvement log (not edited here): `_handoffs/README.md`
  says the directory is pointer-only, yet the brief and this plan live there by instruction;
  suite-core's admin JS is 7,080 B vs "~4.4KB" in the admin UI handoff §7.2; suite-core's consent
  fallback defaults to `{analytics:true, ads:true}` when no consent tool is present
  (MdSuite_Admin.php:530), which is a compliance question for suite-core's owner.
