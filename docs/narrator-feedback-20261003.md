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
