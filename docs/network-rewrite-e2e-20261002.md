# Rewrite lifecycle and authentication follow-up — 2026-10-02

The existing-subsite reactivation gap is fixed. A disposable two-site network reproduced
the customer Security page returning 404 with a saved version marker but no endpoint
rule. The final implementation repaired it automatically and returned 200 on both sites.

## Implementation and review

Activation still invalidates the current site's marker. `SecurityEndpoint::maybe_flush()`
now runs on `wp_loaded`, after endpoint registration and before request routing. It
records the actual installed rule and query with the endpoint version and slug. On
subsequent requests it checks that one entry in WordPress's cached rewrite rules. A
missing or changed entry triggers a soft rebuild; an intact entry does not.

This also handles existing subsites whose activation hook did not run. No network-wide
site loop, new network option, frontend asset, external request or authentication-policy
change is introduced. A version-only legacy marker is upgraded on first use. Plain
permalinks and absent WooCommerce need no endpoint rewrite repair. Existing option
cleanup covers the richer marker. Authorization and sensitive-factor handling are
unchanged.

An earlier network-generation prototype repaired the route but added a database read
on ordinary network pages. It was discarded before packaging. The final network probe
recorded zero plugin settings reads and zero MFA SQL statements. The actual rule and
query are public routing metadata, not user or factor data.

## Validation and scope

- 334 unit tests / 1,764 assertions; PHPStan, PHPCS and asset budgets pass.
- New `RewriteLifecycleTest` exercises actual inactive rule regeneration, reactivation,
  HTTP access, marker persistence, and no additional flush while the saved rule exists.
- Disposable network: WordPress 7.1.2, WooCommerce 11.0.0, PHP 8.3.29, MySQL 8.0.35.
  Both main site and existing subsite recover. The standalone lifecycle test initially
  passed 12 assertions; the expanded suite adds explicit no-repeat-flush assertions.
- Core authentication/admin/network run: 42 of 43 passed initially. The one failure
  expected the CI administrator email address; after aligning the disposable fixture,
  that staff-recovery delay/cancellation test passed (14 assertions). No product fix
  was needed for that mismatch.
- The separate single-site WooCommerce suite passes all 19 tests / 495 assertions:
  customer/admin presenters, checkout login and cart preservation, a synthetic COD
  new-account order, email recovery, and software-authenticator passkeys. An earlier
  network run had four fixture assumptions (product name and single-site admin URLs);
  those are retained as failed evidence, not reported as network checkout passes.
- Hosted staging on WooCommerce 11.1.2 / PHP 8.3.35: staff enrollment, no pre-MFA session,
  wrong-code rejection, login/logout and access restrictions pass. Customer enrollment,
  automatic rewrite repair, invalid-nonce rejection, recovery regeneration, old-code
  rejection, exactly-one concurrent recovery success and replay rejection pass.
- Exact tested ZIP SHA-256:
  `34a49e047173de3b85fd2be36582c03e128a1e0eb27da45c333835b488cdd44c`.
  Artifact/SBOM gate passed, all 94 hosted files matched, and packaged files matched
  the source tree byte-for-byte. No test fixture shipped.

Private evidence and the final WooCommerce run/cleanup results:
`C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-network-20261002/REPORT.md`.
Earlier failed fixture runs are retained and distinguished from final results.

## Four-pillar limits

Security passes within the exercised scope, including role/grace enforcement,
cross-site restrictions, email recovery, trusted-device revocation and privacy
export/erase. Mail was captured by a disposable sink; real email deliverability is
unverified. Local PHP's single worker does not prove a concurrency race; actual hosted
parallel recovery requests supply the concurrency evidence.

The change adds no frontend assets or requests. Existing budgets remain 0 B frontend
CSS and 977 B gzip for optional passkey JavaScript. The measured ordinary network page
has zero MFA queries; representative hosted performance, browser main-thread cost and
field metrics remain unverified. This is not a sitewide performance certification.

No real customer, payment or fulfillment data was used. Retention/privacy and
accessibility acceptance beyond the recorded tests remain incomplete. Physical-device
passkeys, actual browser/Basic-auth-dialog behavior, visual/keyboard/screen-reader
coverage and the rest of the hosted checkout/cache matrix still require evidence.
Passkeys remain opt-in beta. Production and distribution are not approved.
