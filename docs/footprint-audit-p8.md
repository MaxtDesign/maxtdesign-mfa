# Footprint audit (P8): maxtdesign-mfa

Date: 2026-10-01. Site: throwaway WordPress 7.1.2 on PHP 8.3.29 (`php -S`, MariaDB 10.4),
theme Twenty Twenty-Five, WooCommerce 10.9.4 active, 118 to 300 users, no object cache.
Standard: MaxtDesign quality standard section 1 and plan section 9 (zero front-end CSS, JS,
HTTP and queries on normal pages).

## Front end, plugin active vs inactive

Method: for each URL, five requests per state after a warm-up, with `SAVEQUERIES` and an
output buffer counting `<script>`, `<link>` and `<style>` tags, references to the plugin, and
cookies. Query totals vary by a few between runs (WooCommerce's scheduler), so the decisive
check is the exact set of SQL statements with the plugin on and off, twice each.

| Page | Plugin tags added | Plugin references in HTML | Plugin cookies | Bytes added | Plugin queries |
|---|---|---|---|---|---|
| Home | 0 | 0 | 0 | 0 | 0 |
| Single post | 0 | 0 | 0 | 0 | 0 |
| Page | 0 | 0 | 0 | 0 | 0 |
| Shop | 0 | 0 | 0 | 0 | 0 |
| Product | 0 | 0 | 0 | 0 | 0 |
| Cart | 0 | 0 | 0 | 0 | 0 |
| Checkout | 0 | 0 | 0 | 0 | 0 |
| Search, feed, 404 | 0 | 0 | 0 | 0 | 0 |
| My Account, logged out (a login screen) | 0 | 0 | 0 | 0 | 1 |

- SQL set comparison on a page and on the shop: the sets are identical with the plugin on and
  off, apart from one WooCommerce Action Scheduler row lookup that comes and goes on its own.
- The one query on My Account is the read of the plugin's settings to decide whether to offer
  passkey sign-in on the login form. It runs only where a login form renders.
- **Finding, fixed in this phase:** at the base commit every anonymous request read the
  non-autoloaded `mdmfa_settings` option (1 query), because core asks whether application
  passwords are available on every request. Regression tests: `SideDoorsTest`
  (unit) and `LoginFlowTest::test_front_end_requests_run_no_plugin_queries` (end to end, six
  page types).

## Screens that load a plugin asset

| Screen | Asset | Raw | Gzip | Budget |
|---|---|---|---|---|
| Any screen offering a passkey | `assets/front/mdmfa-passkey.js`, deferred, footer, 1 request | 1,838 B | 977 B | 3,072 / 1,536 |
| Users, Login security (MFA) | `assets/admin/mdmfa-admin.css` | 3,506 B | 1,054 B | 4,096 |
| Users, Login security (MFA) | `assets/admin/mdmfa-admin.js`, deferred | 1,754 B | 740 B | 8,192 |

Verified end to end: the passkey module is absent from the login page unless a role allows
passkey-only sign-in, absent from every front-end page, and present exactly once where a
passkey control renders. The admin assets are absent from the Dashboard, Users, Plugins and
My security screens. No inline `<style>` or `<script>` in the plugin's markup. No jQuery, no
web fonts, no outbound HTTP (CI grep).

## Server cost

- Status snapshot build: 229 ms at 300 users, cached 15 minutes; runs only on the plugin's
  admin screens, WP-CLI and a suite status read.
- Sign-in: one settings read, plus on a network one option row per other site the user
  belongs to.

## Not measured

- Lighthouse and Core Web Vitals. Lighthouse is not installed here, and with zero bytes, tags
  and requests added to front-end pages there is nothing for it to attribute. Field INP is
  unverified by definition (no field data: the plugin is unreleased).
- A persistent object cache.

## Quality standard record

Performance and footprint: PASS on the measured surfaces, with the note above. Lab only.
