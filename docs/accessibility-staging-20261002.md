# Accessibility fixes: protected staging verification

Date: 2026-10-02. Source candidate: `a93728d` on `codex/mfa-rewrite-lifecycle`.
The owner authorized installation and the three changed-behavior checks after the
[local accessibility follow-up](accessibility-followup-20261002.md).

## Artifact and target

- Protected target: `https://maxtoffroad.mystagingwebsite.com`, theme `maxtoffroad`.
- ZIP: `maxtdesign-mfa-0.1.0.zip`, 94 files; SHA-256
  `8d6fb66de8f1e83eeaa5ddf648cf6c00c058f9894608f1d93eead0bc65667413`.
- Deliverable, artifact/vendor and SBOM gates passed. Generic vendor/autoload warnings
  reflect this plugin's intentional lack of runtime dependencies. The builder's
  duplicate ZIP-extension warning did not prevent artifact verification.
- Every artifact file matched the clean source candidate and the installed file
  manifest. Browser-served passkey JS also matched its artifact hash:
  `d0d52928e880f783e85fe29a649bbc4a6af57ea39402aa5be3d6ee58d37f00e2`.
- Private evidence:
  `C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-accessibility-staging-20261002/`.
  Primary records: `results.json`, `browser-results.json`, `artifact-manifest.json`,
  `build/release-gate.json`, SBOM and `themed-passkey-failure-320.png`.

## Results

**PASS — core login presentation through the real hosting gate.** A new synthetic
account with a temporary, read-only role reached required enrollment. The actual
passkey script handled a deterministic browser-fixture `NotAllowedError` by exposing
and focusing an alert with negative tabindex. An invalid TOTP setup submission marked
the input invalid and connected it to `login_error`. Chrome's accessibility tree
included the rejection explanation in that textbox's description. Valid setup and
recovery-code acknowledgement then reached the authenticated security page.

**PASS — actual theme security page.** On My Account > Security, the same failure
feedback received focus. Shift+Tab returned to the passkey button, Enter retried, and
the second failure focused the message again. At 320 CSS pixels the document had no
horizontal overflow; the full-page screenshot was visually inspected and showed the
focused error. Input values were masked in the screenshot. No authenticator credential
was created by the cancellation fixture.

**PASS — resolved WooCommerce template copy, with a route limitation.** Hosting Basic
Authentication routes pending sign-ins to the core MFA presenter, so a live pending
WooCommerce challenge is not exercised under this gate. Without weakening the gate,
WP-CLI rendered the actual resolved `myaccount/form-login.php` replacement using an
inert email-challenge state: no pending record and no usable form token. There is no
theme override; the installed template says eight digits and does not say six. This
is hosted template-render evidence, not a hosted WooCommerce email-login E2E pass.
The complete local WooCommerce email/recovery regression remains the flow evidence.

Chrome version: 152.0.7977.85, headless. Browser HTTP credentials supplied the real
hosting Basic-auth credentials; its native login dialog was not exercised. Browser
routing blocked third-party requests and non-MFA POSTs. No payment or order was
submitted, and no broad performance/payment test was repeated.

## Restoration

The new candidate remains installed **but inactive**. The synthetic account, its
WooCommerce session and temporary role were removed. MFA settings and active-plugin
list match the initial snapshot; role-definition hash and MU-plugin hashes match.
Mail remains blocked, noindex and disabled cron remain enabled, and anonymous access
still returns 401. Wrong-password access also returned 401 during the test. Installed
artifact bytes still match after cleanup. No real user's policy/factors were changed;
the temporary policy entry applied only to the synthetic role. Production was not used.

## Quality and remaining acceptance

- **Security — PASS within scope:** access gate negative checks, exact artifact/script
  identity, synthetic-role isolation and cleanup; no security-policy relaxation.
- **Frontend footprint — PASS within scope:** the existing conditional script is
  1,850 raw / 985 gzip bytes. No new asset or request introduced by these fixes. This
  verifies the served script, not a new full active/inactive waterfall.
- **Performance — UNVERIFIED for new timing/field claims:** no CWV or main-thread
  measurements were made. Prior performance findings and stopping points still apply.
- **Accessibility — PASS for observed keyboard, focus, accessible-description and
  sampled layout behavior; UNVERIFIED for actual screen-reader speech, physical
  passkeys, native Basic-auth dialogs, theme-wide contrast and overall conformance.**
- **Privacy/operational controls — PASS within scope:** synthetic data, guarded mail,
  origin-restricted browser requests and verified cleanup. No blanket compliance claim.

Physical-device passkeys and actual assistive-technology announcements need the
operator's device/browser setup. Prepare a fresh scoped fixture for that session;
these automated fixtures have already been removed. Do not reuse exposed test codes
or leave MFA active awaiting an unscheduled manual check. Distribution, merge/release
approval and passkeys-beta gates are not satisfied merely by this staging result.
