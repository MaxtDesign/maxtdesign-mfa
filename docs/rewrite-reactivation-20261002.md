# Customer Security endpoint after reactivation

Historical first fix. The subsequent [network follow-up](network-rewrite-e2e-20261002.md)
supersedes the single-site limitation and moves the completed soft flush to `wp_loaded`.

The hosted staging retest of `4f16fc4` found an authenticated customer receiving a 404
at My Account > Security. The saved endpoint version was `2`, but the saved rewrite
rules had no MFA endpoint. A manual soft flush restored the page. Evidence is in
`C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-staging-retest-20261002/REPORT.md`.

## Change

`Installer::activate()` now deletes the current site's endpoint rewrite marker after
installation succeeds. The existing `SecurityEndpoint::maybe_flush()` then performs
one soft flush on a subsequent `init`, after WooCommerce registers its endpoints.
Activation does not flush early, change policy or remove account data. Ordinary
requests retain the marker and do not repeatedly flush.

This is deliberately scoped to the current site's activation lifecycle. Network
reactivation of already-installed subsites is not established by this change: the
network activation hook does not run once for every subsite. That separate lifecycle
remains unverified and must not be described as fixed by the single-site test.

## Local validation

- PHPUnit: 334 tests, 1,764 assertions, PHP 8.3.29.
- Two added regressions cover a stale marker after an inactive rule rebuild and
  preservation of the marker on ordinary upgrade checks.
- PHPStan, PHPCS, `git diff --check` and asset-size checks pass.
- No frontend assets or requests added; frontend CSS remains 0 B. Existing optional
  passkey JavaScript remains 977 B gzip. No new per-request work is introduced.
- Artifact gate passed for ZIP SHA-256
  `4958dceba97b6f33e36b19e42d79a839ba6d02bc73ae30e7909e3a6298abb42c` (94 files).
  The two existing no-vendor/autoloader warnings are expected for the plugin's own
  autoloader and zero runtime Composer dependencies.

The package contains the working-tree fix atop `4f16fc4`; it is not that commit alone.
The exact patch and its digest are retained in the private evidence directory
`C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-rewrite-fix-20261002/`.

## Hosted validation

See the final `REPORT.md` in that evidence directory for the hosted lifecycle,
authentication and customer recovery results and cleanup state. Source checks do not
substitute for those results. No production deployment or distribution approval is
implied. Full E2E, visual accessibility, hosted performance and compliance acceptance
remain incomplete; the previous staging matrix and passkey beta restrictions apply.
