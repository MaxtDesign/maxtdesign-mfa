# Brief: MaxtDesign MFA

Status: **APPROVED** by operator 2026-09-30. Registry row in agent-sops. Plan ACCEPTED 2026-09-30.
Next: Plan phase (`plan-maxtdesign-mfa.md` beside this file). No folder or repo yet.

## Problem

MaxtDesign sites need multi-factor login for staff and customers, run entirely on our own site,
with no WordPress.com account (the Jetpack / Pressable prompt is unacceptable) and no default
`wp-login.php` address for bots to hit. Existing options fail our standard:

| Option | Why it fails (operator, 2026-09-30, unless marked) |
|---|---|
| WP 2FA | Closest feature fit, but its front-end setup adds jQuery |
| Two Factor (0.17.0, 2026-09-25) | No built-in role enforcement, no customer integration; removed its own WebAuthn ("loss of browser support"), now a separate add-on |
| Wordfence Login Security | Permanently closed |
| FluentAuth (3.0.3, free, 10k+) | Code teardown 2026-09-30 (below). Solid 2FA engineering, but fails on footprint, outbound HTTP, scope, and customer flow |

### FluentAuth teardown (code read of the wp.org 3.0.3 zip, 2026-09-30)

Credit where due: AES-256-GCM TOTP secrets, a dedicated factor table, careful app-password and
XML-RPC handling, passkeys, role enforcement. It is competent. It fails our standard on:

1. **Login-page footprint:** `login_helper.js` 14,560 B + `login_helper.css` 6,104 B, enqueued in
   the head (not deferred) wherever its forms or challenge render. Loaded only on those pages,
   not site-wide, but about 20x our 1KB inline budget. Optional Google One Tap adds a script from
   `accounts.google.com`.
2. **Admin weight:** a 1,438,053 B SPA bundle declaring a **jQuery** dependency, plus core editor
   and media library enqueued on its screen; rewrites the admin footer text; schedules hourly and
   daily cron.
3. **Outbound HTTP:** social login (Google, GitHub, Facebook), an integrity checker that registers
   with `dash.fluentauth.com`, wp.org file downloads for scanning, and an opt-in that posts name and
   email to FluentAuth. The readme says these are opt-in; I did not trace every trigger.
4. **Scope:** a security suite (scanner, integrity checker, social login, magic links, login
   customizer, system emails, activity log), not an MFA plugin.
5. **Customers:** zero `woocommerce_` hooks. The challenge renders through `login_form_{action}`
   on `wp-login.php`, so a customer logging in from My Account likely lands on the core login
   screen for the second step (inferred from code, not live-verified).
6. **No login-location feature** found.

Conclusion: a build is justified. Our differentiation is real and checkable: under 1KB,
customer challenge on the site's own pages, moved login, zero outbound HTTP, MFA-only scope.

WordPress core has no 2FA or passkeys and no merge proposal was found (research 2026-09-30).
Nothing upstream to wait for.

## Shape, layer, reuse

- **Shape:** free wp.org plugin. **Free only**; Pro deferred indefinitely (operator). No licensing
  code, not even the `Pro\License` stub, until a Pro exists.
- **Layer:** standalone Layer-3, PSR-4 `MaxtDesign\Mfa`. WordPress-first; WooCommerce enhances
  (My Account and checkout login) but is not required. ~~Vendors `suite-core`~~ Superseded by plan decision 1 (2026-09-30):
  does not vendor suite-core, integrates only when already present. Never `commerce-core`.
- **Reuse:** nothing in the fleet owns login. REST blocking stays with REST API Control (`dra`),
  not duplicated. Page caching (`maxtdesign-cache`) must never cache the login location.

## Registry row (draft)

| Field | Value |
|---|---|
| Display / Plugin Name | MaxtDesign MFA |
| Slug / text domain / repo | `maxtdesign-mfa` (public repo, wp.org) |
| Short code | `mfa` |
| Prefixes | hooks/options/meta `mdmfa_`, constants `MDMFA_`, tables `{$wpdb->prefix}mdmfa_*` |
| Namespace | `MaxtDesign\Mfa` |
| PHP floor | 8.3 (operator 2026-09-30; 8.2 EOL 2026-12-31) |
| Justification | `mdmfa_` instead of `md_mfa_`: operator choice 2026-09-30, same compact form as `dra`'s `mdra_`. `maxtdesign-auth` / `mda` is taken by the `@maxtdesign/auth` npm lib |

## v1 scope

1. **Factors:** TOTP, passkeys (WebAuthn), recovery codes, email code (owner setting).
   Passkeys work **both** as a second factor and as passwordless sign-in (operator, 2026-09-30).
   Passwordless is an owner setting per role; a passkey login satisfies MFA on its own.
2. **Everyone:** admins, staff, and customers. Enrollment, challenge, and recovery work on the
   site's own pages (theme login, WooCommerce My Account, checkout) as well as the core login.
   Nobody is ever sent to WordPress.com.
3. **Per-role policy:** Off / Optional / Required, allowed factors per role, grace period.
   Defaults: admin, editor, shop manager = Required; customer = Optional. Email code off for staff
   roles by default (NIST 800-63B-4 says email SHALL NOT be used as an out-of-band authenticator;
   recovery codes are an allowed exception). "Remember this device" is a setting, off for staff.
4. **No session before MFA:** password succeeds -> short-lived single-use pending token -> factor
   (or inline enrollment for Required roles) -> session. Rate limit + lockout per factor (NIST cap
   100 consecutive failures; ours will be far lower).
5. **Side doors:** application passwords off entirely or allowed per role; XML-RPC off entirely,
   default blocks XML-RPC auth for enrolled users. Warning that Jetpack and older mobile/remote
   publishing clients depend on XML-RPC.
6. **Custom login location** (see below).
7. **Recovery:** recovery codes, admin reset, optional email recovery (owner setting), and a
   lockout escape hatch that needs server access: `MDMFA_DISABLE` in `wp-config.php` + WP-CLI.
8. **Read surface for AI tools:** coverage per role, enrollment state, lockouts, via the suite-core
   status contract for the operator MCP hub. Never secrets. No MantleWP.

## Custom login location: yes, this plugin is the right place

The MFA plugin already has to own the login request path (branded challenge and enrollment
pages). A separate "hide login" plugin would compete for the same requests. One owner is safer.
**Honest framing:** this is obscurity. It removes bot noise and load. It is not a security
boundary; MFA is.

What it must do (checked against core 7.0.2 source on the Studio `maxtoffroad` site):
- Owner-set slug (for example `/team-access`). A random slug is generated on activation so no site
  is ever left at the default.
- `wp-login.php` and logged-out `wp-admin` return a 404 (operator, 2026-09-30: 404, not a redirect). Core's `auth_redirect()` would otherwise
  redirect logged-out `wp-admin` visits to the login URL, leaking it.
- Neutralise core's shortcut redirects (`/login`, `/admin`, `/dashboard`, `/login.php`),
  `wp_redirect_admin_locations` on `template_redirect`.
- Rewrite every generated URL: `login_url`, `logout_url`, `lostpassword_url`, `register_url`,
  and `site_url` / `network_site_url` for hardcoded `wp-login.php` paths (password reset email in
  `pluggable.php`, `action=postpass` for password-protected posts, interim login in admin).
- Tell `maxtdesign-cache` and known page caches to bypass the slug.
- Lost slug recovery: `wp-config` constant + WP-CLI prints it.

## Standards up front

- **Footprint:** zero site-wide. TOTP, email, and recovery challenges are server-rendered forms,
  no JS. Passkeys need the browser WebAuthn API, so a small deferred vanilla module loads only on
  the challenge and enrollment screens, with a byte budget and a size-check script. No jQuery,
  no fonts, no page-load queries beyond core auth. Admin assets on our own screens only.
- **Admin (operator direction 2026-09-30):** UX comes first in admin. Byte size is secondary there,
  and admins can tolerate some load delay, but it must still be professional/enterprise-grade
  performant. Hard limits that still apply: no jQuery (quality standard), assets only on our own
  screens, nothing leaks to the front end or other admin screens.
- **Outbound HTTP:** none. TOTP, passkeys (attestation checked locally, no FIDO metadata fetch),
  and recovery codes run locally; email uses `wp_mail()`. SMS is not in v1.
- **Data:** user meta `mdmfa_*` (TOTP secret encrypted with sodium, recovery codes hashed);
  table `mdmfa_credentials` for passkeys (lookup by credential ID); rate-limit state in
  transients; options `mdmfa_settings`. `uninstall.php` removes all of it.
- **Compliance:** helps sites meet PCI DSS 4.0.1 8.4.x and NIST 800-63B-4 AAL2 (phishing-resistant
  option = passkeys). Readme makes no compliance claim beyond what is verified. PCI applicability
  to a given store's admin is UNVERIFIED and site-specific.

## Non-goals

SMS (later, only as owner-supplied provider); social login; magic-link login; brute-force/IP
firewall; REST endpoint blocking (`dra`); hosting-dashboard logins (MyPressable is outside
WordPress; we can only detect Jetpack's WordPress.com sign-in and warn, to verify in Plan); Pro.

## Risks

- **Lockout** is the worst failure mode. Every release needs an escape-hatch test.
- **Encryption key:** deriving from `wp-config` salts means rotating salts breaks every TOTP
  secret. Plan offers an `MDMFA_ENCRYPTION_KEY` constant and re-wrap on rotation.
- **WebAuthn library:** must be vendored, GPL-compatible, small, and audited. Choice in Plan.
- **Host and plugin compatibility** with a moved login (Pressable, Jetpack, caches, membership
  plugins) needs a test matrix.
- **Crowded category:** FluentAuth may already be close. Differentiation must be real
  (zero footprint, customer-first, no upsell), not just a claim.

## Operator decisions (2026-09-30)

FluentAuth torn down (above); passkeys as second factor and passwordless; old `wp-login.php` = 404.
Remaining gate: operator approval of this brief, then the registry row.

## Phase sequence (handed to Plan)

1. Auth pipeline: pending-token flow, TOTP, recovery codes, per-role policy, core + My Account
   challenge (no JS), rate limit, escape hatch, WP-CLI.
2. Custom login location (all URL rewrites, 404s, caches, recovery).
3. Passkeys: library choice, enrollment + challenge module under budget, second-factor then
   passwordless (conditional UI / usernameless via the credential table).
4. Email code, trusted devices, app-password and XML-RPC controls, front-end enrollment UI.
5. Status contract for the MCP hub, deliverable set, security audit, footprint audit, wp.org.

## Sources

- Two Factor: https://wordpress.org/plugins/two-factor/
- FluentAuth: https://wordpress.org/plugins/fluent-security/
- NIST SP 800-63B-4 (26 Aug 2025): https://pages.nist.gov/800-63-4/sp800-63b.html
- PCI DSS MFA summary (secondary): https://www.logintc.com/mfa-compliance/pci-dss/
- Core source: `wp-includes/canonical.php` `wp_redirect_admin_locations()`,
  `general-template.php` URL filters, `pluggable.php` reset email (WP 7.0.2, Studio `maxtoffroad`)
