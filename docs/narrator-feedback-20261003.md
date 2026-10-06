# Narrator passkey feedback follow-up

October 3, 2026. Owner's detailed Windows Narrator observation supersedes the earlier apparent pass: after Add a passkey opens Windows Security, cancellation displays the error but Narrator reads the button rather than the error. Repeated group announcements occur within/around the native prompt; their source is not established. This is an open accessibility defect, not a verified fix.

Candidate on isolated branch codex/mfa-narrator-feedback, based on PR #15 head e1bb0a0:
- Render an empty, persistent alert region with aria-atomic, rather than revealing a prepopulated hidden paragraph.
- Insert escaped localized error text using textContent after rejection; clear it on each explicit retry so repeated failures cause a new text update.
- Associate each passkey button with its own alert using aria-describedby. If native dialog dismissal restores focus to the button, its accessible description includes the failure. Keep the explicit error focus and silent AbortError/conditional handling.

Guidance: https://www.w3.org/WAI/WCAG21/Techniques/aria/ARIA19 recommends an initially empty alert container whose text is populated for errors. Native Windows dialog timing remains a hypothesis, not a proven root cause.

Validation: actual PHP Fragments output and shipped JS in Chrome 152, with deterministic rejected WebAuthn calls for create/get. Ten checks passed for initial empty alerts, repeated cancellation, error focus, and button descriptions after simulated focus restoration. This is browser semantics evidence, NOT Windows Security or native Narrator speech. Fixture code and results: C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-narrator-fix-20261003/. PHP syntax and targeted PHPCS passed; first PHPCS run found CRLF introduced by the edit script, corrected to LF. Size gate passed: optional JS 2039 raw / 1055 gzip bytes (+189 raw / +70 gzip), within existing 3072/1536 budgets; no new asset/request/dependency or frontend CSS. Full CI and native retest remain pending for this new delta.

Staging manual session was ended and all cleanup checks passed: MFA inactive, temporary user/role removed, original settings/plugins/MU hashes restored, host gate/noindex/cron/mail guards preserved. No real factors reset. Do not reactivate until a fresh test identity is verified and only its isolated role is required; preserve the baseline password-only access for real staging accounts during the attended test. The old green CI/artifact applies to e1bb0a0, not this new candidate. No deploy, push, merge or release performed.

Quality: security PASS for scoped escaping/text-only DOM changes, no auth policy/code changes; performance/footprint PASS for bounded additional bytes, no timing/field claim; accessibility FAIL on the prior candidate, remediation authored but native acceptance UNVERIFIED; broader compliance and native prompt behavior UNVERIFIED.

## Native retest on October 6

The owner reports Windows Narrator announced the cancellation error on two consecutive attempts on the fresh-login enrollment screen (Create a passkey). This is a PASS for the targeted repeated-error announcement, superseding the pending speech result above for that scenario. A prior account-page cancellation was also reported to announce the error, but the repeated-pair confirmation was on enrollment. Exact Windows/Narrator/Chrome versions were not collected; native prompt group chatter and other screen-reader flows remain unverified.

Tested candidate 1466f39, installed from the 94-file ZIP with SHA256 0970405f13f30cd026ce8f397efbc46dbe586d5106d97c40dd9ae7ce942d993f. Deliverable/artifact gates and ZIP-derived SBOM passed. Installed files and HTTP-served JS matched the candidate. Only the synthetic role required MFA; real roles retained the preceding inactive/password-only behavior. After the browser was closed, server inspection confirmed zero test passkeys, no TOTP and an enrollment decision: cancelling had not created a credential. The owner then confirmed two consecutive cancellation announcements. No enrollment secret or credential value is included in this report.

The prior PR #15 green CI applies to e1bb0a0. This new follow-up still needs its own CI/review; no production approval, general accessibility conformance or external WebAuthn audit is implied.

Cleanup completed after the native test: MFA inactive; fixture account/role removed; original settings, active-plugin list, role hash and MU hashes restored; anonymous HTTP 401, noindex, disabled cron and blocked mail retained. Production unchanged.
