# Lanes review (P8): maxtdesign-mfa

Date: 2026-10-01. Base: `main` at `6bb10f5`. Reviewer: `wp-reviewer`, wp-plugin
`checklists/review.md`. Tooling at review time: PHPStan level 8 clean, PHPCS clean, unit suite
green, deliverables 14/14. Findings came from reading against the WordPress 7.1.2 and
WooCommerce source; each Block was then reproduced by a test before its fix.

Verdict at base: not releasable, 4 Blocks. After this phase: **0 open Blocks.**

## Block

| # | Finding | Resolution |
|---|---|---|
| 1 | Multisite: the second factor could be skipped by signing in on a sibling site (per-site activation, a site with policy Off, or a passkey bound to another site's address). | `Network: true`; strictest policy across the user's sites; enrolled accounts challenged everywhere; passkeys count whatever their site. Verified on a real subdirectory network (`MultisiteTest`, plus the whole core suite on the network's main site). |
| 2 | Activation could lock the owner out: plain permalinks on Apache leave the new address unresolvable; first activation never emailed the address. | On plain permalinks the login is not moved and a notice says why; first activation emails every administrator the address and the way back. |
| 3 | The Tools tab told owners to define `MDMFA_ENCRYPTION_KEY`, which made every authenticator unreadable; the plan's key commands did not exist. | `wp mdmfa key export-define` pins the current key; secrets written under the salts are read and re-encrypted under a newly defined key; `wp mdmfa key status` and `rewrap`; the copy now says what to run. `wp mdmfa recovery-codes` added. |
| 4 | One settings query on every anonymous page view (core asks about application passwords on every request). | The settings are read only when the answer matters. Measured: identical query sets with the plugin on and off (see footprint audit). |

## Fix before merge

| # | Finding | Resolution |
|---|---|---|
| 5 | Setup period never started through the bypass guard | Fixed |
| 6 | Recovery mode ended on a 404 | `entered_recovery_mode` redirects to the login address while recovery mode is active |
| 7 | Public login page still leaked the address after a failed login | Fixed |
| 8 | `map_meta_cap` was strictly typed on a hook any plugin can trigger | Now `mixed` |
| 9 | Removing a user from one site deleted their passkeys network-wide | Cleanup only on `wpmu_delete_user` on a network; tested |
| 10 | Lockout counter not atomic | Per-user lock; concurrency test |
| 11 | Switching a role to Required left application passwords on | Turned off on the transition, with a notice |
| 12 | Logging in again as yourself was recorded as a blocked bypass | The exemption no longer applies on login forms |
| 13 | Non-Secure cookie for third-party login forms on https | Fixed |
| 14 | Login links lost their return address | `redirect_to` is carried to the public login page and honoured on My Account |
| 15 | Multisite URL rewriting ignored the site asked for | The address is read from the site the URL belongs to; subsite paths collide with a chosen address |
| 16 | Endpoint slug `security` shadowed child pages | Default is now `login-security` |
| 17 | Status snapshot and Coverage were N+1 | Caches primed in bulk; Coverage reuses the snapshot's total |
| 18 | Test gaps | Added: audit regression suite, multisite suite, settings validation, context binding, email binding, network policy. Still without unit tests: Router, UrlRewriter, ChallengeFlow, Interceptor, Completion, BypassGuard (covered end to end only) |

## Nits

Done: email code is 8 digits; a policy-relaxed plain login logs `password_only`; the code field
accepts a hyphen; a recovery request works during a lock; `reset --factor=trusted|recovery`
no longer mails "set it up again"; passkey names are cut on characters, not bytes.

Open: the `upgrade.php` and `repair.php` exemptions in the Router are dead code; the schema
version is bumped even if `dbDelta` failed; expired trusted devices are pruned on read, not by
the daily job; `Command` and `UserCommand` duplicate a user lookup; counts on Coverage use
`__()` where `_n()` would be better; an AJAX login refusal fires `wp_login_failed` for a
correct password; the "Development build" paragraph in the readme goes at P9.

## Praise (reviewer's words, shortened)

Single use is enforced by the database, not by PHP. Hook callbacks are defensively typed and
every plugin-table query is prepared. Admin mutations are uniform. The recovery link changes
nothing on GET. The WebAuthn verifier is strict. STATE.md is honest about what is unverified.
