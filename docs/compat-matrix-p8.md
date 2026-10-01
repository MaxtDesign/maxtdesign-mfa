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
| Two Factor 0.17.0 | CI job `compat`, run 36883628284: the suite with the plugin active | Pass, 69 tests. The conflict notice shows; both plugins enforce their own users. |
| Jetpack 16.2, not connected | Same | Pass, 69 tests. Found and fixed: our module filter read the settings on every request. |
| WP Super Cache 3.1.4, W3 Total Cache 2.10.6 (default settings, page cache not configured) | Same | Pass, 69 tests. With page caching switched on: UNVERIFIED. |
| Wordfence 9.0.2 | Same | 63 of 69. The 6 failures are application-password and XML-RPC tests: Wordfence disables application passwords by default. Login, challenge, lockout, location and admin tests pass. |
| Limit Login Attempts Reloaded 3.3.10 | Same | Not conclusive. The suite sends wrong passwords on purpose from one address, so the plugin locks the runner out and later sign-ins fail. Tests before the lockout pass, including "a correct password is not counted as a failure". Needs a run with the address allow-listed. |
| Ultimate Member 2.14.0 | Same | 55 of 69. Ultimate Member redirects non-administrators out of wp-admin, so tests that open Users, My security as a subscriber, author or editor fail. Sign-in and the challenge work. See the limitation below. |
| Paid Memberships Pro, MemberPress, WooCommerce Memberships | Not run (not installable from wordpress.org in CI, or paid) | UNVERIFIED |
| Jetpack connected: SSO with and without WordPress.com two-step, Account Protection | Not run (needs a WordPress.com connection) | UNVERIFIED |
| Pressable, Batcache, Cloudflare APO, LiteSpeed, WP Rocket | Not run (hosted or paid) | UNVERIFIED |
| maxtdesign-cache | Not run in this phase; P4 tests the purge signal | UNVERIFIED for the drop-in |
| Mobile app over XML-RPC, REST with an application password, a JWT-style endpoint | CI: `SideDoorTest`, `AuditRegressionTest` with a fixture endpoint | Pass. The real mobile app was not used. |
| Privacy tools, password-protected posts, recovery mode link | CI | Pass |
| Escape hatch `MDMFA_DISABLE` | CI `LoginFlowTest` | Pass |
| Real browsers and authenticators | Not run | UNVERIFIED |

## Limitation found

On a site that keeps members out of wp-admin (Ultimate Member and similar) and does not run
WooCommerce, members have no screen to manage their own methods: My security lives in wp-admin,
and the only front-end equivalent is the WooCommerce My Account tab. Setup during sign-in still
works for Required roles. A shortcode or block for the security panel would close this; it is
not in the plan.
