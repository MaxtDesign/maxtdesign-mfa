# Fix report: independent review findings F1 and F2

Written 2026-10-01. Fix commit `6a30b32` on branch `fix/independent-review-findings`, on top of
`main` `f179387` (the code the review examined as `242d761`). The review itself is outside the
repo and was not changed: `C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-review-20261001/`.

This is the author's fix and verification record. It is not a re-review, not staging
acceptance and not a security audit. Passkeys stay an opt-in beta; nothing here loosens that.

## F1 (High): a lenient site weakened another site's staff on a network

**What was wrong.** `Policy::effective()` asked the other sites of the network for one thing, the
policy mode, and raised the current site's mode to it. Everything else (setup period, email
recovery and its wait, application passwords, trusted devices, methods) still came from the
site being visited. An administrator of a strict site who was also a customer of a lenient one
was Required there, and could still reset every factor by email at once, get seven days of
password-only sign-in afterwards, and authenticate with an application password.

**What it does now.** Every site the user belongs to contributes the role configuration that
governs them there, and the result is the strictest of those, setting by setting
(`Policy::strictest()`):

| Setting | Rule across the user's sites |
|---|---|
| Policy | the strictest (Required > Optional > Off); super admins Required |
| Email recovery, application passwords, account passwords over XML-RPC, trusted devices, passkey-only sign-in | allowed only if every site allows it |
| Each method a user may set up (authenticator app, passkey, emailed code) | allowed only if every site allows it; recovery codes always |
| Recovery wait | the longest |
| Trusted-device lifetime | the shortest |
| Setup period (grace) | the shortest among the sites that set the winning policy |

The answer is the same whichever site the user signs in on. Two sites of equal rank keep each
other's restrictions; neither cancels the other. Site-level switches are folded in before the
comparison (`Policy::site_rules()`): a site whose application-password mode is "on for everyone"
or whose XML-RPC mode is "allow passwords" cannot open that door for a member of a site that
keeps it shut.

Readers that now get the network-wide answer: `EmailRecovery::allowed()` and the wait in
`EmailRecovery::handle()`, `Policy::grace_remaining()` (so the grace that restarts after a
reset), `SideDoors::app_passwords_for_user()`, the XML-RPC password path in
`Interceptor`, `TrustedDevice::allowed()` and `::lifetime()`, `EmailCode::allowed()`,
`Passkeys` (allowed, passkey-only), `Policy::allows()`.

Other sites are still read without switching blogs (one direct query per site, cached for the
request), because this runs inside the current-user lookup when an application password is
checked.

**Decisions made here, for the reviewer to weigh.**

- Grace is taken only from sites that set the winning policy. A setup period configured on a
  site that does not require setup is not a rule about anything; counting it would let an
  Optional shop with "0 days" remove the setup period a Required site grants.
- If the sites share no strong method (one allows only an authenticator app, the other only a
  passkey), a Required user may still set up an authenticator app. Otherwise nobody in that
  position could enroll. It is the rule `Settings::sanitize_role()` already applies to a role.
  It is weaker than the passkey-only site's own rule.
- A membership with no role counts with that site's "roles added later" configuration, the
  same as on a single site.
- The site being visited always counts, member or not. That can only add restrictions.

## F2 (Medium): WooCommerce's handler could run wp-admin's security forms

**What was wrong.** `SecurityEndpoint::handle_post()` (hook `wp_loaded`) and
`AccountPage::handle()` (hook `load-{page}`) accepted the same fields and the same nonce action.
`wp_loaded` fires first, on wp-admin requests too.

**What the real request showed.** On WordPress 7.1.2 with WooCommerce 10.9.4 and nothing else,
the defect does not fire: the old handler returned early because `wc_add_notice()` does not
exist in wp-admin. WooCommerce loads its notice functions on front-end requests only
(`class-woocommerce.php`, `frontend_includes()`). The reviewer's probe defined that function
itself, which is why it reproduced there. It does fire as soon as anything calls
`wc_load_cart()` in wp-admin, which is public WooCommerce API documented to work "in all
contexts": with a three-line fixture doing that, unfixed `main` enrolls the user, redirects to
`mdmfa_notice=setup_expired` and shows no recovery codes, exactly as the review says. So the
finding is real, but it depended on another plugin; the plugin was being protected by an
accident of WooCommerce's loading order. Whether the MaxtOffroad stack has such a plugin was
not checked.

**What it does now.** Each presenter's forms carry their own nonce action
(`SecurityActions::NONCE_ADMIN`, `NONCE_WC`), set by the presenter when it renders
`SecurityView`. The WooCommerce handler returns on any admin request and accepts only its own
nonce; the wp-admin page accepts only its own. A post is run by exactly one handler, and a form
posted at the other screen is refused (403 in wp-admin, "This form expired" on My Account).
Nonce, login, own-account-only and step-up checks are unchanged; neither handler takes a user
from the request.

## Second look by a separate agent

A read-only security pass over the diff (wp-security-auditor, no shared context) found no
Critical or High and three Medium issues, all fixed in the same commit:

| | Finding | Now |
|---|---|---|
| M1 | The 50-site cap in `other_sites()` failed open: a 51st, stricter site was ignored | No cap; every site is read. Unit test with 60 memberships |
| M2 | The XML-RPC "allow passwords" mode was still per site | Folded into the combination; unit and network E2E test |
| M3 | Other sites' roles were read from raw capability keys, the current site's from registered roles, so two sites could disagree about each other | Other sites' roles are filtered by that site's `user_roles` option; unit test |

Left as they are, by choice:

- `counter_anomaly_block` (passkey counter anomalies), lockout thresholds, email-code limits
  and log settings are per site.
- Archived, spam and deleted-flag sites still contribute (stricter only).
- `mdmfa_user_policy` runs after the combination and can lower anyone, including a super admin
  (as before this change).
- The per-request cache is not dropped when a role or another site's settings change inside
  the same request.
- On one site, when two of a user's roles tie on policy, the first role still supplies the
  rest (plan 4.1). The network combination does not have that order dependence; a single site
  still does. Worth an operator decision.

## Evidence

Files in [evidence/review-fix-20261001/](evidence/review-fix-20261001/). All local, 2026-10-01,
PHP 8.3.29, plugin installed from a zip built with `.distignore`, never junctioned.

| Check | Unfixed `main` `f179387` | Fix `6a30b32` |
|---|---|---|
| New unit tests (`NetworkPolicyTest` 12, `PresenterDispatchTest` 7) | 14 of 19 fail | 19 pass |
| Whole unit suite | 305 tests (before this branch) | **324 tests, 1,691 assertions, pass** |
| Reviewer's `reproduce.php`, unmodified | both findings reproduce (review's own JSON) | neither: WooCommerce handler saves nothing, wp-admin holds 10 codes; grace 0, recovery off, wait 24 h, application passwords off |
| `SecurityPresentersTest`, real WordPress 7.1.2 + WooCommerce 10.9.4 | 4 of 6 fail | 6 pass |
| Whole `e2e-wc` suite, same site | not run | **18 tests, 488 assertions, pass** |
| `MultisiteTest`, real subdirectory network (2 sites) | 3 of 8 fail | 8 pass |
| Whole `e2e` suite on that network | not run | 74 tests, 785 assertions: 72 pass, 1 skipped (recovery mode, not available on multisite), 1 error |
| PHPCS / PHPStan level 8 | | 0 / 0 |
| Byte budgets (`tools/size-check.php`) | | pass; unchanged: front CSS 0 B, passkey JS 977 B gzip, admin CSS 1,054 B gzip, admin JS 740 B gzip |
| Outbound HTTP grep in shipped code | | 0 hits |

The one error in the network run is `LoginLocationTest::test_slug_change_purges_caches...`: the
test starts a bare `wp` process, which does not exist on this Windows machine. It is a known
local limitation of the harness and passes in CI. PHPUnit's two warnings in that run are the same
failed process start.

What the request-level tests cover:

- **wp-admin with WooCommerce active** (with and without WooCommerce's notice functions loaded
  in wp-admin): first authenticator setup shows ten codes once on the wp-admin page, one
  `enrolled` log row with context `account`, a reload or resubmission shows none and changes
  nothing; step-up refusal, wrong code, right code and new recovery codes all redirect to or
  render on the wp-admin page, one `recovery_regenerated` row; first passkey (allowed for the
  role in the test only) shows ten codes once; no WooCommerce notice is queued by any of it.
- **My Account**: the same journey for a customer, context `wc`, never touching wp-admin.
- **Cross-posting**: each screen refuses the other's form and a forged nonce.
- **Network, through both sites' login pages**: strict administrator who is also a member of a
  lenient shop: email recovery not offered and a forged request mails nothing; application
  password refused over REST on both sites, also when the shop turns them on for everyone;
  account password over XML-RPC refused on both when the shop allows it; no setup period and a
  forged skip starts no session. A shop-only member gets all of the shop's leniency (so the
  fixture is not vacuous) and completes an immediate recovery. Two Required sites with
  conflicting settings: recovery completed through the shop waits the other site's 48 hours,
  then resets, and the setup period that restarts is the stricter one.

## The four principles (quality standard, section 4)

- **Performance and footprint: PASS for what changed, lab only.** No assets, no front-end
  work. The front-end query probe (0 plugin queries on anonymous page types) passes in the
  network run. On a network, evaluating a user's policy costs one query per other site they
  belong to (as before; the row count per query went from 1 to 2) and is no longer capped at
  50 sites. It runs at sign-in, when a credential or session cookie is checked and on the
  plugin's own screens, not on anonymous page views. Field data: UNVERIFIED.
- **Security: PASS for the two findings, within the scope tested.** Evidence above. Not a
  formal audit; the remaining per-site settings are listed above.
- **Compliance and truthful operation: PASS.** The readme's multisite answer and changelog
  line now say what the code does. No "audited" or "reviewed" claim added. No data collection
  changed.
- **Accessibility: NOT APPLICABLE.** No markup changed except a nonce value.

## Not verified

- WooCommerce 11.x. The local copy is 10.9.4, below the plugin's documented 11.0 floor. CI's
  `e2e-wc` job installs the current release; its result on this branch is the evidence for 11.x.
- Whether any plugin on the MaxtOffroad stack calls `wc_load_cart()` in wp-admin.
- Real browsers. The tests post what the forms contain over HTTP; no JavaScript ran, and the
  passkey is a software authenticator.
- Subdomain and mapped-domain networks, a persistent object cache, networks whose main site is
  not site 1, concurrent requests (the local server has one worker).
- Block checkout, hosted caches, connected Jetpack: untouched by this change, still unverified.
- Shared staging and production: nothing was installed anywhere but two disposable local sites.
