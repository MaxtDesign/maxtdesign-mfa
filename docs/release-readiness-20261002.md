# Release readiness: candidate 3f3dbe3

Written 2026-10-02 by Claude Code, continuing Codex's scoped release review
(`C:/maxt/projects/website/owned/maxtoffroad/docs/handoffs/mfa-release-review-20261002.md`).
This records the change set, the artifact, what was reviewed and tested, the gates that are
still open, and a rollout and rollback proposal for the owner to accept or change.

Nothing here authorizes anything. The branch was pushed and PR #15 opened on the owner's word
(2026-10-03); no merge, tag, publication, production activation or policy change was made. Passkeys stay an opt-in beta; distribution stays undecided.

## Candidate

| | |
|---|---|
| Branch | `fix/mfa-release-candidate`, PR #15 (was the local branch `codex/mfa-rewrite-lifecycle`); supersedes PR #14 |
| Runtime commit | `3f3dbe3` (later commits on the branch are documentation only) |
| Base | `main` `6c2be3b` |
| Artifact | `_build/maxtdesign-mfa-0.1.0.zip`, 94 files, SHA-256 `14bfa5e86e47e8adeee755f5511238060ebf5bd7fd2f0f1793cb44b742d956d9` |
| Manifest | [evidence/release-candidate-20261002/artifact-manifest.json](evidence/release-candidate-20261002/artifact-manifest.json): every file's SHA-256; all 94 match `3f3dbe3` byte for byte; no `tests/`, `vendor/`, `docs/`, `tools/` or `stubs/` path shipped |
| Zip preflight | PASS (0 failed, 2 expected warnings: no vendor directory and no Composer autoloader, because the plugin has its own autoloader and no runtime dependencies) |

The artifact was built with `C:/maxt/projects/plugin/_build/build-dist.php` and checked with
`preflight-vendor.php`. `release-gate.php` was not run: the distribution channel is undecided,
and STATE holds the release gate until the operator names one. No SBOM was generated.

This zip replaces Codex's tested zip (`8d6fb66d…`, built from `a93728d`). It differs from it
in two shipped files only: `readme.txt` and `src/WooCommerce/SecurityEndpoint.php`.

## Change set against main

| Commit | Author | What |
|---|---|---|
| `2d6b29f` | Codex | docs: readme multisite qualification, first staging record |
| `078533d` `092c9a7` | Claude | fix: sign-in behind the host's Basic-auth gate (PR #14) |
| `4f16fc4` | Claude | docs: gate fix report and evidence |
| `5452f8b` | Codex | fix: repair missing My Account Security rewrites across reactivation, including existing subsites |
| `a93728d` | Codex | accessibility: error described by and invalid state on the code field, passkey error announced and focused, 8-digit email guidance on My Account |
| `f47f4b6` `f341ba8` | Codex | docs: staging accessibility record, owner acceptance summary |
| `54edebd` | Claude | docs: readme no longer says customers never use the core screen |
| `3f3dbe3` | Claude | fix: an endpoint rebuild that finds no rule is retried once a day, not on every request |

Runtime files changed against `main`: 14 (337 lines added, 27 removed). Two Codex commit
subjects (`a93728d`, `f47f4b6`) do not follow Conventional Commits; a squash merge replaces
them with one message.

## Review of Codex's runtime changes

Read line by line against the source they touch (`git diff 4f16fc4 f47f4b6 -- src assets templates`).
This is one reviewer's read, not an audit.

- **Rewrite repair (`SecurityEndpoint::maybe_flush`, `Installer::activate`).** Sound in the
  normal case: it checks one saved rule against core's cached rules, so an intact rule costs
  array lookups on autoloaded options and no query; activation drops the marker so the next
  request repairs the rule after WooCommerce has registered its endpoints; existing subsites
  repair themselves on their first request. **One defect, fixed in `3f3dbe3`:** when a rebuild
  could not produce the endpoint rule (another plugin filtering the rules, a changed endpoint
  mask), no marker was written, so every page view rebuilt the rules and wrote an option. A
  rebuild that finds no rule is now recorded and retried after a day. A new E2E test filters the
  rule away and counts rebuilds over real requests: 4 on Codex's version, 1 on the fix, and a
  second one only after the day has passed.
- **Accessibility (`Fragments`, `LoginScreens`, passkey module).** Sound. The code field points
  `aria-describedby` at core's `login_error` notice only when an error (not an informational
  message) was rendered, which matches the id core uses in WordPress 7.1.2; `aria-invalid` only
  for a rejected code. The passkey error gets `role="alert"`, `tabindex="-1"` and focus on
  failure. Escaping is unchanged. The passkey module grew by a few bytes and stays inside its
  budget.
- **WooCommerce copy.** "6-digit" became "8-digit" for emailed codes, which is what the plugin
  sends.

## Review of the theme hunk

`C:/maxt/projects/website/owned/maxtoffroad`, branch `feat/wp-conversion`, HEAD `274a3c7`. The
stylesheet `wp/themes/maxtoffroad/assets/css/woocommerce.css` has two uncommitted hunks. Only the
second is MFA's; the first (fitment table `nowrap` and `vertical-align`) belongs to other work.

The MFA hunk is saved on its own as
[evidence/release-candidate-20261002/theme-mfa-hunk.patch](evidence/release-candidate-20261002/theme-mfa-hunk.patch)
(SHA-256 `1d1e505a…`); it applies cleanly by itself to the committed stylesheet. It is scoped
to the `woocommerce-mdmfa-security` body class, which WooCommerce adds on that endpoint
(`wc-template-functions.php:371`); it changes margins and makes labels with a `for` attribute
block-level, which leaves the step-up radio labels (no `for`) alone. No new file or request.
Sound. To commit it alone: `git apply --cached` that patch in the site repo, then commit.
Nothing in the site repo was staged, committed or changed by this review.

## Evidence

| Evidence | Covers | Where |
|---|---|---|
| Local, `3f3dbe3`, disposable site (WP 7.1.2, WooCommerce 10.9.4, PHP 8.3.29) | `e2e-wc` 20 tests, 502 assertions, pass. Gate tests with the real Hosting Basic Authentication 1.0.5: 8 pass, 1 skipped. Whole `e2e` with WooCommerce off: 83 tests, 74 pass, 8 skipped (network), 1 harness error (bare `wp` process on Windows) | [evidence/release-candidate-20261002/](evidence/release-candidate-20261002/) |
| Local, `3f3dbe3` | Unit 334 tests, 1,764 assertions; PHPCS 0; PHPStan level 8 0 | this session |
| CI on PR #14 (`4f16fc4`), attempt 2 | every required job green (lint, PHPStan, PHPUnit 8.3/8.4/8.5, QR, fuzz, guards, smoke single and multisite, `e2e`, `e2e-wc` and multisite E2E on 8.3 and 8.5). Attempt 1 failed in the PHP setup action ("Could not setup wp-cli") before any test; so did `main`'s run for `6c2be3b` | GitHub run 37013264005 |
| Codex, hosted staging, `a93728d` | staff and customer enrollment and login, no pre-MFA session, rewrite repair, concurrent recovery, checkout return with cart, cache isolation, zero ordinary-route assets, accessibility attributes | `docs/network-rewrite-e2e-20261002.md`, `docs/accessibility-staging-20261002.md`, private reports under `C:/maxt/pilots/aimasters-maxtoffroad-operations/` |
| Owner | desktop and mobile checks "both work" (no device, OS, browser or screen-reader detail recorded) | STATE |

The hosted evidence is for `a93728d`. The delta to `3f3dbe3` (the rewrite retry bound and the
readme sentence) is covered by local tests only.

## Open release gates

1. **CI on the actual merge candidate.** Running on PR #15 since the push on 2026-10-03; its
   result is the evidence for `5452f8b..3f3dbe3`.
2. **Merge acceptance.** Someone other than the authors should review the combined diff. The
   gate fix had a separate read-only pass; Codex's changes had only my read above.
3. **Native screen-reader check** of the error announcement, focus after a failed passkey, and
   the recovery-code acknowledgement, on the setup that will actually be used. Not done.
4. **Independent review of the WebAuthn verifier.** Not done. Passkeys stay off by default,
   passkey-only sign-in stays behind `MDMFA_PASSKEY_ONLY_SIGNIN`, the beta label stays, and no
   "reviewed" or "audited" claim may be made.
5. **Owner decisions:** target site, cohort, roles, setup period, allowed methods, whether
   customers are in scope, and the distribution channel. If the channel is wp.org, a Pro add-on
   or bundling, `release-gate.php` (with the SBOM from the zip) runs on the exact artifact first.
6. **Production email.** Delivery of emailed codes and recovery links has only been seen in
   local sinks and blocked staging mail. Prove it on the real delivery path before relying on
   either.
7. **Hosted spot check of the `3f3dbe3` delta**, if the owner wants hosted evidence for it: one
   request to My Account > Security after activation, then confirm the marker holds a rule.

## Proposed rollout (for the owner to accept or change)

This is Codex's proposal, checked against the source. It is not a recorded owner policy.

1. **Before activation.** Out-of-band access works (host console and WP-CLI) and a restore path
   is tested. Record the plugin version and zip hash, active plugins, the theme hunk, and the
   current `mdmfa_settings` if any. Run `wp mdmfa key status` and keep its output private; do not
   run `wp mdmfa key export-define` in a shared terminal, because it prints the key. Do not
   rotate salts: the authenticator secrets are encrypted with a key that may derive from them.
2. **Install** the approved zip, compare installed files with the manifest, apply only the MFA
   theme hunk. **Activate.** Activation moves the login to a random address and emails it to
   administrators; read it privately with `wp mdmfa slug get`.
3. **Pilot cohort:** staff only, authenticator app plus recovery codes, attended. Customers
   Optional or Off, passkeys off, emailed codes as already configured per role. While keeping an
   existing administrator session and the host console open, prove: fresh enrollment, a wrong
   code refused, a correct code signs in, log out and back in, a recovery code works once and is
   refused the second time, My Account > Security loads for a customer.
4. **Stop** on a lockout, a routing failure, a session without the second step, a data
   isolation failure, or a new front-end footprint or performance regression. Keep the evidence,
   revert only the change that was made.

## Rollback

All commands and constants below exist in `3f3dbe3` (`src/Cli`, `LoginLocation`, `Plugin`).

| Situation | Action |
|---|---|
| Access broken | From the host console: `wp plugin deactivate maxtdesign-mfa` (with `--url` on a network). Logins go back to core; data stays. |
| Only the moved login is the problem | `define( 'MDMFA_DISABLE_LOGIN_LOCATION', true );` keeps MFA and puts the login back at `wp-login.php`. `wp mdmfa slug get` prints the address. |
| One user locked out | `wp mdmfa unlock <user>`; `wp mdmfa recovery-codes <user>` issues new codes and prints them, so run it privately; `wp mdmfa user reset <user>` removes the user's methods. |
| Emergency, everything else failed | `define( 'MDMFA_DISABLE', true );` makes every login password-only. Record it as an incident, it weakens protection; remove it after recovery (`wp mdmfa disable-check` reports it). |
| Theme spacing | Reverse only the MFA hunk (`git apply -R` of the patch) after checking nothing else changed in it. |

Do not uninstall (it deletes factor data), rotate salts, overwrite the database, or delete a
junction-mounted plugin as a routine rollback. Afterwards confirm login works, the expected
policy is in force, and front-end pages still load no plugin assets.

## Quality standard (section 4)

- **Performance and footprint: PASS for what changed, lab only.** The retry bound removes a
  possible per-request rules rebuild; an intact rule still costs no query. No asset changed
  except a few bytes in the passkey module, inside its budget. Field Core Web Vitals:
  UNVERIFIED.
- **Security: PASS within the scope tested.** Not an audit. WebAuthn verifier review open.
- **Compliance and truthful operation: PASS.** The readme now matches the gate flow. No claim
  of review, audit or accessibility conformance is made.
- **Accessibility: PARTIAL.** Attributes, focus and keyboard checked by tests and Codex's
  hosted run; native screen readers UNVERIFIED.
