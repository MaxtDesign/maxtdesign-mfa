# External review brief: the passkey verifier in MaxtDesign MFA

Prepared 2026-10-01 for an independent security reviewer. Owner contact: security@maxtdesign.com.

## 1. What we are asking for

An independent review of the code that verifies passkey (WebAuthn) registrations and sign-ins in
a WordPress plugin, before its first public release. We wrote this verifier ourselves instead of
bundling a library, so nobody outside the project has examined it. The project's release rule
is that version 1.0 does not ship until someone independent has.

We want to know one thing above all: **can anyone register or use a passkey they should not be
able to, or sign in as someone else, by controlling what the browser sends?**

Deliverable: a written report with findings ranked by severity, each with the affected code, a
way to reproduce it, and a suggested fix; plus a short statement of what was reviewed and what
was not. We will fix findings and ask for a re-check of the fixes.

## 2. The product in one paragraph

MaxtDesign MFA is a free WordPress plugin (GPL-2.0-or-later, to be distributed on
WordPress.org) that adds a second sign-in step: authenticator app, passkey, emailed code or
recovery code, with a policy per user role. Passkeys can be a second step after the password,
or, for roles the site owner allows, the only step ("passkey-only sign-in"). The plugin makes
no outbound network requests; everything is verified on the site's own server. PHP 8.3 or
newer, WordPress 7.0 or newer.

## 3. Scope

Repository: `https://github.com/MaxtDesign/maxtdesign-mfa` (public). Review the commit on `main`
that contains this file.

### In scope (about 1,300 lines of verifier, 870 lines of callers, 16 lines of JavaScript)

| File | Lines | Role |
|---|---|---|
| `src/WebAuthn/Cbor.php` | 267 | Restricted CBOR decoder |
| `src/WebAuthn/CoseKey.php` | 230 | COSE public key to a verifier (ES256, RS256, EdDSA); builds DER by hand |
| `src/WebAuthn/AuthenticatorData.php` | 116 | Parses authenticatorData |
| `src/WebAuthn/ClientData.php` | 63 | Checks clientDataJSON (type, challenge, origin, crossOrigin) |
| `src/WebAuthn/Verifier.php` | 130 | The two ceremonies: `register()` and `assert()` |
| `src/WebAuthn/CredentialJson.php` | 177 | Parses the JSON the browser posts |
| `src/WebAuthn/Options.php` | 104 | Builds creation and request options |
| `src/WebAuthn/RelyingParty.php` | 86 | RP ID and allowed origins |
| `src/WebAuthn/ByteString.php`, `RegisteredCredential.php`, `AssertionResult.php`, `VerificationException.php` | 121 | Value objects |
| `src/Factors/Passkeys.php` | 437 | Challenges, registration, second-step and passkey-only verification, counter policy |
| `src/Factors/PasskeyStore.php` | 251 | Credential storage and the per-user handle |
| `src/Frontend/PasskeyLogin.php` | 183 | The passkey-only sign-in endpoint |
| `assets/front/mdmfa-passkey.js` | 16 | Browser module: calls `navigator.credentials`, posts the result |
| `src/Support/Base64Url.php` | 49 | Encoding used throughout |

### Useful context, not the focus

- `src/Flow/ChallengeFlow.php`, `src/Auth/Completion.php`, `src/Auth/PendingStore.php`: the
  sign-in state machine that calls the verifier and creates the session.
- `src/Auth/StepUp.php`, `src/Account/SecurityActions.php`: adding and removing passkeys.
- `docs/plan-maxtdesign-mfa.md` section 12 (the requirements the verifier was built to) and
  `docs/webauthn-library-eval.md` (why we did not bundle a library).

### Out of scope

The rest of the plugin (authenticator app, email codes, the moved login address, admin
screens). It has had internal audits (`docs/security-audit-p8.md`); you are welcome to report
anything you notice, but we are not asking you to cover it.

## 4. Design decisions you should know

These are deliberate. Tell us if any is unsafe.

1. **Attestation is not verified.** Options ask for `attestation: "none"`, and `attStmt` is
   ignored whatever `fmt` says. The plugin never claims or displays where a passkey came from.
2. **Algorithms:** ES256 (P-256), RS256 (2048 to 8192 bits), EdDSA (Ed25519), offered in that
   order. Signature checks go through OpenSSL (`openssl_verify(...) === 1`) and libsodium.
3. **Origin** must equal, exactly, the scheme, host and port of the site's configured URLs
   (`home_url()`, `site_url()`), never a request header. `crossOrigin: true` is refused.
   `topOrigin` is ignored.
4. **RP ID** is the host of the site URL. https is required, except on loopback hosts.
5. **User verification** is required for passkey-only sign-in and not for a second step (the
   password was the first step).
6. **Sign counter:** both zero means no counter. A counter that did not grow is flagged, logged
   and shown to the owner. It is refused when the passkey is not backup eligible (one copy, so
   it is a clone signal); for backup-eligible passkeys it is allowed unless the owner chose to
   refuse those too.
7. **Backup flags:** BS without BE is refused. BE and BS are stored; BS is updated on use.
8. **User handle:** 32 random bytes per user, never the user ID. For passkey-only sign-in the
   returned `userHandle` must equal the handle of the credential's owner.
9. **Credential IDs** are unique across all users (lookup plus a unique database key), at most
   1,023 bytes, and at most 20 passkeys per user.
10. **Challenges:**
    - Passkey-only sign-in: stateless, `nonce(16) | issued-at(8) | HMAC(16)`, valid under 300
      seconds, single use enforced by inserting a marker row (`INSERT IGNORE`) before the
      signature is checked.
    - Second step and setup during sign-in: stored in the pending sign-in record.
    - Adding a passkey while signed in, and step-up: stored in the WordPress session.
11. **CBOR:** definite lengths only, shortest-form arguments, no tags, floats or indefinite
    items, duplicate and numeric-text map keys refused, strings up to 64 KB, 256 items per
    container, depth 16, no trailing bytes.
12. **Extensions** are not requested; extension data is parsed for well-formedness only.

## 5. Threat model

Assume the attacker:

- controls every byte the browser posts (the credential JSON, form fields, cookies they hold);
- can load any public page and collect fresh challenges;
- may know a victim's password (that is the case a second step exists for);
- may own a legitimate account and passkey on the same site;
- cannot read the server's files, database or salts, and cannot break TLS.

What we care about, in order:

1. Signing in as another user, or satisfying another user's second step.
2. Registering a passkey onto an account without a fresh verification by its owner.
3. Replaying a captured registration or assertion.
4. Passing verification with a forged or malleable signature, a malformed key, or a
   wrong-origin or wrong-site assertion.
5. Crashing or stalling the server with crafted input (the parsers run before authentication).
6. Learning whether a username or email has an account, or a passkey.

## 6. What has already been done

So you can spend your time where it adds most.

- **Unit tests:** 129 for the verifier, with a rejection test per individual check, for all
  three algorithms (`tests/Unit/WebAuthn/`).
- **Differential tests:** 34 cases run through this verifier and through two established
  libraries, `web-auth/webauthn-lib` 5.3 and `lbuchs/webauthn` 2.2 (development dependencies
  only, never shipped). Ours never accepts what either rejects. Where ours is stricter, the
  case is listed and asserted (`tests/Unit/WebAuthn/DifferentialTest.php`).
- **Fuzzing:** a seeded mutation fuzzer over real ceremony bytes, 4 million inputs per CI run
  across 7 targets: 0 crashes, 0 hangs, slowest input under 1 ms (`tests/fuzz/fuzz.php`).
- **End-to-end tests** over HTTP against real WordPress, with a software authenticator standing
  in for browser and device (`tests/E2e/PasskeyTest.php`, `tests/Support/VirtualAuthenticator.php`):
  registration, replayed registration, second step, tampered signature, passkey-only sign-in,
  replayed assertion, no user verification, wrong user handle, foreign origin, role not allowed,
  counter anomaly.
- **Three internal reviews**, none of which found an exploitable flaw in the verifier:
  - a source-to-sink security audit (`docs/security-audit-p8.md`);
  - a review by OpenAI Codex (`gpt-6-astra`, medium effort) of the latest changes: 3 findings,
    none in the verifier, all fixed;
  - a review by a second model (Claude Fable) of the latest changes and of the verifier against
    WebAuthn Level 3 sections 7.1 and 7.2: 1 Medium and 6 Low, none exploitable in the verifier;
    its step-by-step table is reproduced in section 8.

All of these were produced by, or with, the same AI toolchain that wrote the code. That is the
reason for this brief.

## 7. Where we would like you to look hardest

These are the places we are least able to check ourselves, or where a reviewer already raised a
question we did not fully close.

1. **ES256 key and signature handling** (`CoseKey.php`). The SPKI and DER are built by hand
   from the COSE `x` and `y`. There is no on-curve check in PHP: we rely on OpenSSL rejecting
   an invalid point when it loads the key. Is that reliance sound on the OpenSSL versions PHP
   8.3 to 8.5 ship with (1.1.1 and 3.x)? Signatures are passed to OpenSSL as received (DER);
   is any malleability relevant here?
2. **RS256** (`CoseKey.php`). The size check is by byte length (a 2,041-bit modulus passes as
   2,048). The exponent must be non-zero and at most 8 bytes; an even exponent or 1 is left to
   OpenSSL. Padding is whatever `openssl_verify` uses with `OPENSSL_ALGO_SHA256` (PKCS#1 v1.5).
3. **The CBOR decoder** (`Cbor.php`), especially integer handling near 2^63, length checks
   against the remaining input, and anything that could differ from how an authenticator or
   another parser reads the same bytes.
4. **Passkey-only sign-in is not bound to the browser** (`Passkeys::login_challenge()`,
   `PasskeyLogin.php`). The challenge is an HMAC over a nonce and a timestamp; nothing ties it
   to the client that loaded the page. An attacker can obtain a challenge, sign it with their
   own passkey, and get a victim's browser to post it, signing the victim in as the attacker
   (login CSRF). WordPress's own password form has the same property, so we rated it Low and
   left it. We would like your view on whether to bind the challenge to a short-lived cookie.
5. **`PasskeyStore::user_handle()`** creates a new handle when the stored one is malformed.
   If that ever happened to a user who already has passkeys, their passkey-only sign-in would
   stop working (their second-step use would not). Should it fail closed instead?
6. **The counter policy** (decision 6 above). Is refusing non-backup-eligible passkeys on a
   non-growing counter, while allowing backup-eligible ones, the right default?
7. **Challenge lifetime and single use** across the three storage places (decision 10),
   including two requests racing with the same challenge. Second-step attempts for one user are
   serialised with a MySQL named lock (`Lockout::with_lock()`); on a database without named
   locks they run unlocked and a log entry says so.
8. **Subdomain and mapped-domain multisite.** A passkey is bound to one site's host. On another
   site of the network the account stays challenged but cannot use that passkey. This
   configuration has not been run.
9. **The browser module** (`mdmfa-passkey.js`): it reads options from a `data-` attribute,
   calls `navigator.credentials.create` or `.get`, and writes the JSON result into a hidden
   field. It has only been syntax-checked, never run in a real browser by us.

## 8. Specification coverage (from the second internal review)

Registration, WebAuthn Level 3 section 7.1:

| Step | Status |
|---|---|
| Parse clientDataJSON, `type` is `webauthn.create` | Implemented; strict JSON, 8 KB cap |
| Challenge matches | Implemented; constant-time; single use is the caller's job (section 7, item 7) |
| Origin | Implemented; exact match against configured origins |
| `topOrigin`, `crossOrigin` | `crossOrigin: true` refused; `topOrigin` ignored |
| Decode attestationObject | Implemented; `fmt` not restricted (attestation is not relied on) |
| rpIdHash, UP, UV by policy, BE and BS consistency | Implemented |
| Algorithm is one that was offered | Implemented against a fixed list |
| Client extension results | Skipped; none requested |
| Attestation statement and trust path | Skipped by policy |
| Credential ID length and uniqueness | Implemented; unique database key closes the check-then-insert race |
| Store ID, key, counter, transports, BE, BS | Implemented; the stored ID is the one inside authenticatorData, and `id` must equal `rawId` |

Assertion, section 7.2:

| Step | Status |
|---|---|
| Credential belongs to the user and RP | Implemented for second step and step-up; passkey-only sign-in uses an empty allow list by design |
| `userHandle` identifies the owner | Implemented; required for passkey-only sign-in |
| clientDataJSON `type` is `webauthn.get`, challenge, origin, `crossOrigin` | Implemented |
| rpIdHash, UP | Implemented |
| UV | Required for passkey-only sign-in only |
| BE and BS | Consistency enforced; BS updated; a change of BE is not checked |
| Extensions | Parsed for well-formedness only |
| Signature over `authData || SHA-256(clientDataJSON)` | Implemented for the three algorithms |
| Signature counter | Implemented per decision 6 |
| Attested credential data present in an assertion | Refused (stricter than the specification) |
| Trailing bytes | Refused |

## 9. How to run everything

Requirements: PHP 8.3 or newer with `sodium`, `openssl` and `mbstring`; Composer.

```
git clone https://github.com/MaxtDesign/maxtdesign-mfa.git
cd maxtdesign-mfa
composer install
```

| What | Command |
|---|---|
| Verifier unit and differential tests | `vendor/bin/phpunit --testsuite unit --filter WebAuthn` |
| Whole unit suite (302 tests) | `vendor/bin/phpunit` |
| Fuzzer (iterations, optional seed) | `php tests/fuzz/fuzz.php 1000000` |
| Static analysis, level 8 | `vendor/bin/phpstan analyse --memory-limit=2G` |
| Coding standards | `vendor/bin/phpcs` |

The fuzzer prints the exact input for any failure. Note that its seed fixes the mutations but
not the test keys, so accept and reject counts vary a little between runs.

The end-to-end tests need a running WordPress. The simplest way to see them run is the public
CI on GitHub (`.github/workflows/ci.yml`, jobs "End-to-end"). To run them locally, the job's
steps are a complete recipe: install WordPress with WP-CLI, copy the plugin in, copy
`tests/e2e-fixtures/mdmfa-e2e-fixtures.php` into `mu-plugins`, define `MDMFA_E2E_FIXTURES`,
serve with `php -S ... tests/e2e-fixtures/router.php`, set `MDMFA_E2E_URL` and `WP_PATH`, then
`vendor/bin/phpunit --testsuite e2e`.

To craft your own inputs, `tests/Support/VirtualAuthenticator.php` produces registration and
assertion responses for all three algorithms and has "knobs" for every field (type, origin,
challenge, flags, counter, trailing bytes, tampered signature, user handle).

To try it with a real browser: install the plugin on an https WordPress site, open Users, My
security, and add a passkey. Passkey-only sign-in is off by default; turn it on for a role under
Users, Login security (MFA), Policy.

## 10. What we have not verified

- Any real browser or authenticator (Chrome, Safari, Firefox, Android, iOS, Windows Hello,
  hardware security keys), including autofill sign-in (conditional mediation).
- The OpenSSL behaviours listed in section 7, items 1 and 2, across versions.
- Subdomain and mapped-domain networks.
- Anything in this brief's "we believe" or "by design" statements: they are ours, not proven.

## 11. Practical details

- Reporting: privately to security@maxtdesign.com. Please do not open public issues for
  findings.
- We acknowledge within 3 business days (the plugin's published security policy, `SECURITY.md`).
- Timing, fee and whether and when the report may be published are for you and the owner to
  agree; nothing in this brief settles them.
- The plugin makes no "audited" or "reviewed" claim anywhere until your report is recorded, and
  any such wording afterwards would be agreed with you first.
