# Compatibility matrix (P8): maxtdesign-mfa

Date: 2026-10-01. Plan section 13. "Suite" means the core end-to-end suite
(`--testsuite e2e`) unless stated.

| Target | How it was run | Result |
|---|---|---|
| Single site, pretty permalinks, PHP 8.3 and 8.5 | CI | Pass |
| Single site, plain permalinks | Local: suite with `permalink_structure` empty | Pass for login location, 404 rules and flows on a server that routes unknown paths to `index.php`. REST tests use `/wp-json/` paths and do not apply. On Apache without rewrite rules the address cannot resolve, so installation now leaves the login unmoved (tested). |
| Multisite, subdirectory, plugin network-active | Local network and CI job `multisite`: whole suite on the main site plus `MultisiteTest` | Pass. Core does not run recovery mode on multisite, so that test is skipped there. Site administrators cannot reset other users (core reserves `edit_user` for super admins). |
| Multisite, subdomain or mapped domains | Not run | UNVERIFIED. Passkeys are bound to a site's host; the account stays challenged on other hosts with its other methods or a recovery code. |
| Subdirectory install (`home` differs from `siteurl`) | Not run | UNVERIFIED |
| WooCommerce 11.1.2, classic My Account and checkout | CI `e2e-wc` | Pass |
| WooCommerce 10.9.4 (below the declared floor) | Local | Pass, 11 of 11 run |
| WooCommerce block checkout new-account, coming-soon mode | Not run | UNVERIFIED |
| suite-core 1.5.1 started by another plugin | Local, by hand | Pass (menu, styles, registry, status) |
| A stale suite-core winning the load race | Not run | UNVERIFIED (guards in place) |
| Two Factor, Limit Login Attempts Reloaded, Wordfence, Jetpack (not connected), Ultimate Member, Paid Memberships Pro, WP Super Cache, W3 Total Cache | CI job `compat`: the suite with each plugin active | See the run recorded in STATE.md |
| Jetpack connected: SSO with and without WordPress.com two-step, Account Protection | Not run (needs a WordPress.com connection) | UNVERIFIED |
| Pressable, Batcache, Cloudflare APO, LiteSpeed, WP Rocket | Not run (hosted or paid) | UNVERIFIED |
| maxtdesign-cache | Not run in this phase; P4 tests the purge signal | UNVERIFIED for the drop-in |
| Mobile app over XML-RPC, REST with an application password, a JWT-style endpoint | CI: `SideDoorTest`, `AuditRegressionTest` with a fixture endpoint | Pass. The real mobile app was not used. |
| Privacy tools, password-protected posts, recovery mode link | CI | Pass |
| Escape hatch `MDMFA_DISABLE` | CI `LoginFlowTest` | Pass |
| Real browsers and authenticators | Not run | UNVERIFIED |
