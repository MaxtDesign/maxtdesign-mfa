# MFA interaction and accessibility follow-up

Date: 2026-10-02. Base: `5452f8b`, branch `codex/mfa-rewrite-lifecycle`.

Subsequent hosted result: source commit `a93728d` was installed and tested on protected
staging, then left inactive with fixtures removed. See
[staging verification](accessibility-staging-20261002.md); the local-only status below
describes the state when this initial review completed.
Scope: enrollment, challenge, recovery-code login and error feedback in the core
WordPress and WooCommerce presenters. No checkout/payment matrix or general
performance audit was repeated.

## Findings and fixes

1. **Passkey cancellation/failure feedback lacked accessible semantics and focus.**
   Reproduced in both presenters: the real passkey module revealed an ordinary
   paragraph while focus stayed on the button. The shared error now has an alert
   role and negative tabindex; an explicit failure reveals and focuses it. It does
   not add a tab stop. Conditional mediation and aborted superseded requests retain
   their existing silent behavior.
2. **Core code errors were detached from the automatically focused input.** After
   a rejected enrollment or recovery code, the field had neither an error description
   nor an invalid state. Core's notice is not an alert in WordPress 7.1.2. The presenter
   now connects the input to `login_error` when an actual error notice exists and
   marks a rejected code invalid. Informational messages do not produce a dangling
   description or invalid state. WooCommerce already focused its error alert in the
   tested theme; that behavior is preserved.
3. **WooCommerce requested a six-digit email code although eight digits are issued.**
   Corrected the instruction to eight digits and extended the existing email-flow
   regression. TOTP instructions still correctly request six digits.

## Evidence

Private evidence directory:
`C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-accessibility-20261002/`.

- `before-results.json` and `after-results.json`: real Chrome 152 browser flows on the
  existing disposable single-site WordPress 7.1.2/WooCommerce fixture, using core
  login styles and Twenty Twenty-Five for My Account. No staging or production change.
- Both presenters completed enrollment, recovery-code acknowledgement, a fresh
  challenge, invalid recovery-code submission and successful recovery-code login.
  Keyboard actions exercised Tab, Space and Enter; input values were supplied by
  the harness. This is automated keyboard evidence, not a human assistive-tech pass.
- Chrome accessibility trees reported no unnamed textbox/button/checkbox/radio/select
  controls on the sampled screens. No duplicate IDs or horizontal document overflow
  were found in those samples. Recovery error screens at 320 CSS pixels were captured
  and visually inspected; core input focus and WooCommerce error focus were visible.
- Before/after browser evidence verifies that passkey errors changed from no role/
  no focus to `role=alert`, `tabindex=-1` and focused. Cancellation was a deterministic
  `NotAllowedError` from a browser fixture invoking the actual shipped handler, not
  a physical authenticator or operating-system passkey dialog.
- Core invalid-code input changed to `aria-describedby=login_error` and
  `aria-invalid=true`. The WooCommerce email instruction changed to eight digits.
- Unit suite: **334 tests, 1,764 assertions**. Targeted core E2E: **2 tests, 44
  assertions**; WooCommerce email/recovery E2E: **1 test, 49 assertions**. All passed.
- PHPStan, PHPCS and asset-size gate passed. No new frontend CSS or request. The
  existing conditional passkey module is **1,850 raw bytes / 985 gzip bytes**, up
  8 gzip bytes from the previous candidate; ordinary pages still do not load it.

Harness preparation initially stopped on Windows CLI boolean/path API differences,
then one browser assertion expected the verification wording on the enrollment
screen. These were fixture corrections. An initial unit run omitted the previously
required `OPENSSL_CONF`, causing software-authenticator key-generation failures;
the same source passed after restoring that environment setting. The failed unit
output is retained as `unit-missing-openssl-conf.txt`.

Synthetic users created by these checks were removed. Settings and active-plugin
lists were restored, the disposable PHP server stopped, and MFA left inactive.
Existing local test fixtures remain private. Mail used the existing local sink;
outbound WordPress HTTP remained blocked. Secrets and recovery codes were not
written to browser result files or screenshots.

## Quality and acceptance limits

- **Security: PASS within changed scope.** Attribute values remain escaped; no
  authentication, authorization, token, recovery-consumption or storage rule changed.
  Existing authentication regressions passed.
- **Frontend footprint: PASS within changed scope.** No new asset/dependency/request;
  the necessary failure-focus behavior adds 8 gzip bytes to the already conditional
  passkey module. No sitewide JavaScript, CSS or licensing call added.
- **Performance: PASS for the existing asset budget; UNVERIFIED for timing/field
  metrics.** No query/network path was added. Prior hosted measurements remain scoped
  to their exact artifact; this is not a new CWV or hosted waterfall pass.
- **Accessibility: PASS for the specific browser/DOM/keyboard checks above;
  UNVERIFIED for native screen-reader speech, physical passkeys, browser Basic-auth
  dialogs, all admin settings, theme overrides, contrast across themes, and broader
  WCAG conformance.** No blanket accessibility or legal-compliance certification.
- **Privacy/operational controls: PASS within scope.** Synthetic data, local mail sink,
  outbound blocking and fixture cleanup. Wider compliance obligations are unchanged
  and are not certified by this review.

These changes are local source changes, not a new hosted install or release artifact.
Staging retains the previously tested candidate, installed but inactive. Distribution
and passkeys-beta gates remain. The next manual session should verify physical-device
passkeys and actual assistive-tech announcements; completed payment/performance work
does not need a new broad pass for these changes.
