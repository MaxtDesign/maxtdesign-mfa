# WebAuthn library evaluation for MaxtDesign MFA

Date: 2026-09-30. Status: research only, no product code written. Feeds the "WebAuthn library" open item in [brief-maxtdesign-mfa.md](brief-maxtdesign-mfa.md) (line 143, "Choice in Plan").

Scope: server-side WebAuthn for a free wp.org plugin (PHP 8.3+, WP 7.1, GPLv2+), passkeys as second factor and as usernameless/passwordless login (discoverable credentials), zero outbound HTTP, vendored + prefixed.

Evidence levels used below: **VERIFIED** = read from the primary source (Packagist metadata API, GitHub repo/advisory, cloned source, wp.org SVN) on 2026-09-30. **UNVERIFIED** = not confirmed from a primary source; treat as a lead, not a fact.

## 1. Recommendation (short)

**Write a minimal in-house verifier** (attestation "none" only; ES256 + RS256 + EdDSA; about 1,000 to 1,500 lines of library code), using lbuchs/WebAuthn as the reading reference and web-auth/webauthn-lib as a **dev-only** differential test oracle that never ships in the zip. Commission an external review of that module before 1.0.

Fallback if schedule wins over ownership: vendor **lbuchs/webauthn v2.2.0**, prefixed with Strauss, with a small documented patch set (section 4). Do not ship web-auth/webauthn-lib, madwizard/webauthn or firehed/webauthn.

## 2. Comparison table

| | web-auth/webauthn-lib (Spomky) | lbuchs/webauthn | madwizard/webauthn | firehed/webauthn | In-house minimal verifier |
|---|---|---|---|---|---|
| License | MIT (GPLv2+ compatible) VERIFIED | MIT VERIFIED | MIT VERIFIED | MIT VERIFIED | GPLv2+ (ours) |
| Latest version + date | 5.3.9, 2026-09-10 VERIFIED | v2.2.0, 2024-07-04; last commit 2025-09-05 (README + demo only) VERIFIED | v1.0.0, 2025-02-14 (last commit same day) VERIFIED | 0.9.1, 2026-03-15; commits to 2026-08-11 VERIFIED | n/a |
| PHP floor | >=8.2 | >=8.0 | ^7.2 or ^8.0 | ^8.2 | 8.3 |
| Direct Composer deps | 15 packages (see 3.1) VERIFIED | **0** VERIFIED | 12 packages incl. guzzlehttp/guzzle, symfony/cache, 5 sop/* libs VERIFIED | 2 (firehed/cbor, sop/asn1) VERIFIED | 0 |
| Transitive tree | Estimated 25 to 30 packages (Symfony serializer, property-access, property-info, uid, clock, polyfills, phpdocumentor/reflection-docblock and its deps, brick/math, pki-framework, cbor-php, cose-lib). Estimate from Packagist require maps, not a composer resolve. UNVERIFIED count | 0; about 2,975 lines total in src (cloned, counted) VERIFIED | Large; about 13,600 lines in its own src alone VERIFIED, plus Guzzle/Symfony tree | Small; about 3,850 lines own src VERIFIED | About 1,000 to 1,500 lines (estimate; FluentAuth's equivalent is 1,859 lines incl. heavy comments) |
| Required PHP extensions | json, openssl (hard); mbstring via cbor-php and pki-framework; gmp strongly suggested by cbor-php for untrusted input; sodium for EdDSA VERIFIED | openssl, mbstring (hard); sodium or sodium_compat for EdDSA VERIFIED | json, openssl, **sodium (hard require)** VERIFIED | **gmp (hard)**, hash, openssl VERIFIED | openssl; sodium only for EdDSA (WP core's sodium_compat covers it) |
| ES256 / RS256 / EdDSA | Yes / Yes / Yes (EdDSA needs sodium) VERIFIED via cose-lib suggest map | Yes / Yes / Yes (EdDSA via sodium or OpenSSL ed25519) VERIFIED in source | UNVERIFIED per algorithm (docs do not list them) | ES256 yes, RS256 "limited", EdDSA **no** VERIFIED (Packagist README) | Yes / Yes / Yes (we write them) |
| Discoverable credentials | Yes VERIFIED (docs) | Yes (`$requireResidentKey`) VERIFIED | UNVERIFIED | Yes (autofill flow listed) VERIFIED | Yes |
| signCount handling | Yes; configurable counter checker UNVERIFIED detail | Spec rule: skip only if both are 0, else require strictly greater, throws on regression VERIFIED in source | UNVERIFIED | UNVERIFIED | We define policy (see 5.3) |
| UV / BE / BS flags | Yes VERIFIED (advisory context) | UP + UV enforced on create and get; BE/BS exposed as getters, no BE/BS consistency check VERIFIED in source | UNVERIFIED | UNVERIFIED | Yes, incl. BE=0 with BS=1 rejection |
| Outbound HTTP in code | MDS fetch is optional (web-token/jwt-library suggested for it), not on the none path UNVERIFIED that no HTTP class ships in the base lib | **Yes**: `queryFidoMetaDataService()` uses curl / file_get_contents to mds.fidoalliance.org, only if called VERIFIED | **Yes**: Guzzle is a hard dependency for metadata service VERIFIED | None found in composer.json (no HTTP client dep) VERIFIED | None |
| Maintenance | Very active (releases through Sep 2026, fast advisory turnaround) VERIFIED | Dormant: no code change since 2024-07-04 VERIFIED | Dormant: 1 commit in 2025, prior in 2024/2023 VERIFIED | Active but pre-1.0, 1 maintainer, 20 stars, about 9.7k installs VERIFIED | Ours |
| Security history | 5 GHSA advisories (see 3.2) incl. CVE-2024-39912, CVE-2026-30964; also CVE-2021-38299 (older, UNVERIFIED details). Visible, handled disclosures. VERIFIED | 0 published advisories; no audit found. Our read found a defense-in-depth origin-suffix bug (4.1) VERIFIED | 0 advisories found; no audit found UNVERIFIED completeness | 0 advisories; no audit found | None yet; needs one |
| Scoping difficulty | **Hard**: Symfony polyfills declare global functions (cannot be prefixed), serializer/property-info use reflection and docblock parsing, Symfony 8.x needs PHP 8.4 so `config.platform.php` must pin 8.3 | **Easy**: one PSR-4 namespace, no deps, no globals | Hard: Guzzle + PSR + Symfony cache + abandoned sop/* | Medium: small, but sop/asn1 is from the archived sop family and gmp is a host-compat blocker | None needed (our own namespace) |

## 3. Candidate notes

### 3.1 web-auth/webauthn-lib 5.3.9 (Spomky)

- Direct requires (Packagist p2 metadata, 2026-09-30): ext-json, ext-openssl, paragonie/constant_time_encoding, phpdocumentor/reflection-docblock, psr/clock, psr/event-dispatcher, psr/log, spomky-labs/cbor-php ^3.4, symfony/clock, symfony/uid, spomky-labs/pki-framework ^1.0, symfony/property-info, symfony/property-access, symfony/serializer, symfony/deprecation-contracts, web-auth/cose-lib ^4.8.
- Sub-deps checked: cose-lib 4.8.2 (2026-09-15) needs brick/math + pki-framework; cbor-php 3.4.2 (2026-09-15) needs brick/math + symfony/polyfill-php81 + ext-mbstring and warns that **without ext-gmp, decoding a bignum tag from untrusted input is quadratic** (a DoS consideration on shared hosts); pki-framework 1.6.3 (2026-09-12) needs brick/math + ext-mbstring; symfony/serializer 7.4.20 needs polyfill-ctype + polyfill-php84, 8.1.8 needs PHP >= 8.4.1.
- It is the most complete and best-maintained PHP implementation, and the only one with a public, active advisory stream. It is also a framework, not a verifier: most of the tree exists for serialization, PSR events and Symfony integration that a WP plugin will not use. It conflicts with our zero-footprint and "small dependency tree" constraints and multiplies the scoping surface.
- Best use for us: **require-dev only**, as a test oracle (feed the same ceremonies to it and to our verifier and assert identical accept/reject).

### 3.2 web-auth advisory history (VERIFIED on GitHub advisories)

| ID | Title | Severity | Affected / patched |
|---|---|---|---|
| GHSA-875x-g8p7-5w27 / CVE-2024-39912 | Enumeration of valid usernames (empty allowCredentials when user not found) | Moderate 6.9 | >=4.5.0 <4.9.0 / 4.9.0 |
| GHSA-f7pm-6hr8-7ggm / CVE-2026-30964 | allowed_origins collapsed to host-only, bypassing exact origin validation | Moderate 5.4 | >=5.2.0 <5.2.4 / 5.2.4 |
| GHSA-h4fw-6r7f-w494 (no CVE) | User verification downgrade via client override policy | Low 2.1 | >=5.3.0 <5.3.1 / 5.3.1 |
| GHSA-q683-8468-r6h6 | Sensitive HTTP headers in INFO logs (Symfony authenticator) | Moderate | UNVERIFIED versions |
| GHSA-gq4g-fpc9-vjfq | Empty-secret fake credential generator predictable | Low | UNVERIFIED versions |
| CVE-2021-38299 | Improper access control in webauthn-framework | UNVERIFIED (NVD page did not render) | UNVERIFIED |

Lessons we carry into our own design regardless of library: exact origin match (scheme + host + port), never let the client downgrade UV, and do not leak user existence through allowCredentials shape.

### 3.3 lbuchs/webauthn v2.2.0

- Zero Composer dependencies, one namespace `lbuchs\WebAuthn`, about 2,975 lines (WebAuthn.php is 714 lines; CBOR decoder, ByteBuffer, AuthenticatorData, 7 attestation format classes).
- Covers every required behavior: create/get ceremonies, resident keys, UP/UV enforcement, signCount per spec, BE/BS getters, ES256/RS256/EdDSA with sodium fallback (checks `function_exists('sodium_crypto_sign_verify_detached')`, which WP's sodium_compat satisfies).
- The processGet comments state steps 1 to 3 (allowCredentials membership, **userHandle ownership**, credential lookup) are "TO BE VERIFIED BY IMPLEMENTATION". For usernameless login this is the critical check and it is on us either way.
- Dormant: no code commit since 2024-07-04. 49 open issues on Packagist. No advisories, but also no evidence of an audit.
- WordPress precedent: both **Secure Passkeys** (2,000+ installs) and **WP 2FA** ship a renamed copy of this codebase (see section 6).

### 3.4 madwizard/webauthn v1.0.0

Rejected. Hard-requires Guzzle, symfony/cache, kevinrob/guzzle-cache-middleware and ext-sodium; depends on the sop/* family (x509, asn1, x501, crypto-*), which is the archived upstream Spomky forked into pki-framework; about 13,600 lines of its own code; last commit 2025-02-14. Its Guzzle dependency exists for FIDO MDS, which we must never call.

### 3.5 firehed/webauthn 0.9.1 (newest credible option found)

Rejected for now. Pre-1.0, single maintainer, low adoption (about 9.7k installs, 0 dependents), **hard-requires ext-gmp** (not guaranteed on shared hosting), no EdDSA, "limited" RS256 (Windows Hello TPM credentials historically use RS256), depends on sop/asn1. Worth re-checking at 1.0.

Other names seen in search but not evaluated in depth: laragear/webauthn (Laravel-bound, unsuitable), wpconsulting/passkey-bundle (Symfony bundle that itself requires lbuchs/webauthn ^2.2). UNVERIFIED beyond the search snippet.

### 3.6 In-house minimal verifier

What it must contain (none-attestation only):

| Unit | Est. lines | Risk notes |
|---|---|---|
| base64url + constant-time helpers | 40 | trivial |
| Restricted CBOR decoder: major types 0 to 5 and 7 (simple values), definite lengths only, depth limit, length-vs-remaining checks, reject indefinite, tags, floats, duplicate map keys | 180 to 250 | **Highest parsing risk**; fuzz it |
| COSE_Key parse to PEM/SPKI: EC2 P-256 (x,y 32 bytes, on-curve check via openssl_pkey_get_public), RSA (n,e to DER), OKP Ed25519 (32-byte raw) | 200 to 280 | DER building by hand; test vectors |
| authenticatorData parse: rpIdHash, flags (UP, UV, BE, BS, AT, ED), signCount (unsigned 32-bit), attestedCredentialData (AAGUID, credId length cap 1023, COSE key), trailing-bytes check | 150 to 220 | Integer handling on 32-bit PHP (unpack 'N') |
| clientDataJSON checks: type, challenge (hash_equals), origin exact allowlist, reject crossOrigin true, ignore tokenBinding | 100 to 150 | origin handling is where Spomky had a CVE |
| Registration ceremony (none; accept other fmt by ignoring attStmt, as FluentAuth does) | 120 to 160 | |
| Assertion ceremony incl. userHandle ownership, signature verify (openssl_verify === 1; sodium for EdDSA), counter policy | 150 to 200 | `openssl_verify` returns -1 on error: only `=== 1` is success |
| Options builders (create/get JSON) | 100 to 150 | |
| **Total** | **about 1,000 to 1,500** | plus about 1,500 lines of tests |

FluentAuth 3.0.3 measured for comparison (section 6): 1,859 lines in its WebAuthn directory, 2,750 with the passkey login and 2FA method glue.

What an audit needs: the CBOR decoder and COSE-to-PEM code (memory/length handling, malformed input), the ceremony step list mapped line-by-line to WebAuthn Level 3 section 7.1 and 7.2, origin/rpId derivation under proxies and multisite, the challenge store (single use, expiry, bound to session/user, stored server side), userHandle ownership in usernameless flow, counter policy, rate limiting, and the account-recovery path (a passkey system is only as strong as its fallback). Test inputs: published WebAuthn test vectors, fixtures from py_webauthn / SimpleWebAuthn / webauthn-lib test suites (UNVERIFIED which ones carry reusable fixtures under a compatible license), fuzzing of the CBOR decoder, and differential runs against webauthn-lib and lbuchs as require-dev.

## 4. Why not just vendor lbuchs (and what it would take if we do)

### 4.1 Finding in lbuchs `_checkOrigin()` (VERIFIED in source, v2.2.0 / master)

```php
return \preg_match('/' . \preg_quote($this->_rpId) . '$/i', $host) === 1;
```

This is a suffix match with no dot boundary: rpId `example.com` accepts host `evilexample.com`. Real browsers refuse to produce an assertion for an rpId that is not a registrable suffix of the calling origin, and the rpIdHash check still binds the credential to `example.com`, so this is **not remotely exploitable with a conforming browser**. It is still a defense-in-depth defect in the one check that exists to catch a malicious or non-browser client. Secure Passkeys' copy has already fixed it (`$host === $rpId || str_ends_with($host, '.' . $rpId)`), which confirms the upstream defect is known in the WP ecosystem but not upstreamed. Our requirement is stricter anyway: exact origin allowlist, not suffix matching.

### 4.2 Required patch set if vendoring lbuchs

1. Replace `_checkOrigin` with an exact scheme+host+port allowlist.
2. Delete `queryFidoMetaDataService()` (curl/file_get_contents to an external URL; wp.org review and Plugin Check are likely to flag raw curl, and it violates zero outbound HTTP even if never called).
3. Reject BE=0 with BS=1; make counter regression a policy hook, not a hard throw, if we want "flag, do not lock out".
4. Compare challenge with `hash_equals`.
5. Drop unused attestation formats (android-safetynet, tpm, apple, etc.) and root-cert loading to shrink surface; keep `none` (and `packed` self-attestation parsing only if we choose to ignore attStmt).

At that point we own a fork of a dormant codebase with no upstream to take fixes from. That is the core argument for writing the (smaller, none-only) verifier ourselves and using lbuchs as a reference instead.

## 5. Cross-cutting requirements (apply whichever path is chosen)

### 5.1 Host extensions on shared hosting

- **openssl**: needed for ES256/RS256 (`openssl_verify`). Required. Fail closed with an admin notice if missing (FluentAuth gates on `function_exists('openssl_verify')` the same way).
- **sodium**: bundled with PHP since 7.2 but can be disabled. WordPress core loads its own sodium_compat when `sodium_crypto_box` is missing (`wp-settings.php`, trunk line about 449 to 451, VERIFIED), so `sodium_crypto_sign_verify_detached` exists on every WP site. That is enough for EdDSA verification. Pure-PHP verify speed on shared hosts is UNVERIFIED; measure it (one verify per login, so likely acceptable).
- **gmp / bcmath**: not needed for the in-house path or lbuchs. Needed (hard) by firehed; suggested by the Spomky stack.
- **mbstring**: lbuchs hard-requires it; the in-house path can avoid it (use `strlen`/`substr` on binary strings; never `mb_*` on binary).

### 5.2 rpId and origin under subdirectory installs and proxies

- rpId is a host name only. A WordPress install in a subdirectory (`https://example.com/blog/`) has rpId `example.com`; the path is irrelevant. Ports are also not part of rpId.
- Derive rpId and expected origins from configured URLs (`site_url()` for wp-login, `home_url()` for front-end login), never from `$_SERVER['HTTP_HOST']` or `X-Forwarded-*`. That keeps a proxy or Host-header injection from choosing the rpId.
- Expected origin list: scheme + host + port of `site_url()` and `home_url()` (they can differ). Exact match. Provide one filter (e.g. `mdmfa_webauthn_origins`, name to be registered per naming rules) for unusual setups.
- Require an https origin except for `localhost` in dev. Do not rely on `is_ssl()` behind TLS-terminating proxies; use the configured URL scheme.
- Multisite: subdomain networks get a distinct rpId per site unless the owner opts into the parent domain; domain changes orphan existing passkeys, so the admin UI must warn before a URL change and recovery codes must exist.

### 5.3 signCount policy

Many synced passkey providers always report 0 (the spec allows this). Rule: if both stored and presented are 0, skip. If either is non-zero and presented <= stored, treat as a possible clone: recommended policy is log + fire an action + mark the credential for review rather than hard lock-out, owner-configurable. Store the counter as unsigned 32-bit.

### 5.4 Flags

Require UP always. Require UV for passwordless login (the passkey is the only factor). For second-factor use, UV "preferred" is acceptable. Record BE/BS at registration and update BS on each assertion (it can change when a credential is later synced). Reject BE=0 with BS=1. Never accept a client-supplied UV requirement (lesson from GHSA-h4fw-6r7f-w494).

## 6. What existing WordPress passkey plugins do

| Plugin | Implementation | Evidence |
|---|---|---|
| FluentAuth 3.0.3 (fluent-security) | **In-house**, no library. `app/Services/TwoFa/WebAuthn/` = 12 files, 1,859 lines (Cbor 210, CoseKey 290, AuthenticatorData 236, Assertion 180, Registration 159, ClientData 134, Ceremony 138, RelyingParty 125, PasskeyStore 239, UserHandle 78, Base64Url 55, exception 17). Plus PasskeyLogin 292 + PasskeyTwoFaMethod 597 of glue. ES256 + RS256 only; EdDSA deliberately omitted; attestation "none"; rpId from host with a `fluent_auth/webauthn_rp_id` filter; rejects impossible BE/BS; counter reuse fires an action rather than locking out. | VERIFIED (local extract, line counts via wc) |
| WebAuthn Provider for Two Factor 2.6.1 (sjinks) | Uses **madwizard/webauthn ^1.0.0**, prefixed with **Imposter** (typisttech/imposter-plugin) into `WildWolf\WordPress\TwoFactorWebAuthn\Vendor`, `config.platform.php` pinned to 8.1.31, classmap-authoritative autoloader, psalm taint analysis. 1,000+ installs, tested to 6.9.9. | VERIFIED (wp.org page + GitHub composer.json) |
| Secure Passkeys 1.3.0 | **Renamed copy of lbuchs/WebAuthn** under `Secure_Passkeys\Packages\Web_Authn` (same directory layout: attestation/, binary/, cbor/, web-authn.php), with the origin-suffix bug fixed. No upstream credit header seen in the fetched file. 2,000+ installs. | VERIFIED (wp.org SVN trunk) |
| WP 2FA (Melapress) | Passkeys in `includes/classes/Admin/Methods/passkeys/` with class-byte-buffer, class-chor-decoder, class-attestation-object, class-authenticator-data, class-web-authn, format/ ... The file set matches lbuchs' structure, so it appears to be a port of lbuchs; not diffed. vendor/ holds only a scoper config, clickatell and Freemius. | File listing VERIFIED; "port of lbuchs" is an inference, UNVERIFIED |
| Two Factor (core-team plugin) 0.17.0 | Removed its own WebAuthn; now a separate add-on (per the MFA brief). | From brief, not re-checked here |

Pattern: nobody in the WP ecosystem ships the Spomky stack; the field splits between lbuchs-derived copies and in-house verifiers.

## 7. Scoping / prefixing (if any third-party code ships)

- **Strauss** (BrianHenryIE, fork of Mozart): latest seen v0.30.0 (release page date read as 2024-09-16, which conflicts with its PHP 8.6 note; UNVERIFIED date). Runs as a Composer script, copies packages into e.g. `vendor-prefixed/` and rewrites namespaces and class names. Works well for single-namespace libs like lbuchs.
- **php-scoper** (humbug) 0.18.19, 2025-03-02: builds a scoped copy of the whole vendor tree; needs an explicit exclusion config for global functions and polyfills, and patchers for strings that name classes.
- **Imposter**: what sjinks uses; in-place namespace rewrite.
- Pitfalls: (1) global functions and constants (Symfony polyfills, sodium_compat) cannot be namespaced, so two plugins shipping different versions still collide on first-loaded-wins; (2) class names in strings, docblocks, attributes and serializer metadata are missed by naive rewriting (the Spomky stack is full of them); (3) Composer's `autoload.files` dedupe is global (see suite-lib negotiating loader memory), so prefixed file-autoloads must be required explicitly; (4) **hard rule 9**: any Composer `path` repository must carry `"symlink": false`, and the built zip must pass `php C:/maxt/ops/runbooks/preflight-vendor.php <plugin-dir> --zip <built.zip>`; prefixed output must be verified by extracting the zip, not the working tree; (5) pin `config.platform.php` to 8.3 so Composer never resolves a PHP 8.4-only release (Symfony 8.x) into a PHP 8.3 plugin.
- The in-house path needs none of this, which is itself a reason to prefer it.

## 8. Risks of the recommendation

1. **We own crypto-adjacent parsing code.** A bug in CBOR or COSE handling is an auth bypass or a DoS. Mitigation: none-attestation only, strict restricted CBOR, fuzzing, differential tests against webauthn-lib and lbuchs, external review before 1.0.
2. **No public track record.** "Audited" in the brief cannot be claimed until an external review is done and recorded. Until then the security claim is UNVERIFIED and the readme must not imply otherwise.
3. **Spec drift.** WebAuthn Level 3 changes (hints, related origins, signal APIs) land in browsers; a small in-house verifier has to track them manually. Mitigation: annual review task; watch the webauthn-lib changelog and advisories as an early-warning feed.
4. **Attestation "none" means no authenticator provenance.** Owners cannot restrict to specific hardware (e.g. only YubiKeys). Acceptable for consumer passkeys; document it; revisit only with an offline-bundled trust store, never MDS fetch.
5. **EdDSA via sodium_compat is pure PHP** on hosts without ext-sodium. Performance UNVERIFIED; measure. ES256 covers essentially every platform authenticator, so EdDSA can be advertised last in pubKeyCredParams.
6. **Estimate risk.** 1,000 to 1,500 lines is an estimate from FluentAuth and lbuchs sizes, not a build. FluentAuth landed at 1,859 with verbose comments.
7. **Fallback risk (lbuchs)**: dormant upstream, local patch set, and the WP ecosystem already carries divergent copies; any upstream fix would have to be hand-merged.

## 9. Sources

- Packagist: https://packagist.org/packages/web-auth/webauthn-lib , https://packagist.org/packages/lbuchs/webauthn , https://packagist.org/packages/madwizard/webauthn , https://packagist.org/packages/firehed/webauthn
- Packagist metadata API: https://repo.packagist.org/p2/web-auth/webauthn-lib.json , https://repo.packagist.org/p2/web-auth/cose-lib.json , https://repo.packagist.org/p2/spomky-labs/cbor-php.json , https://repo.packagist.org/p2/spomky-labs/pki-framework.json , https://repo.packagist.org/p2/symfony/serializer.json
- web-auth advisories: https://github.com/web-auth/webauthn-framework/security/advisories , https://github.com/advisories/GHSA-875x-g8p7-5w27 , https://github.com/advisories/GHSA-f7pm-6hr8-7ggm , https://github.com/advisories/GHSA-h4fw-6r7f-w494 , https://nvd.nist.gov/vuln/detail/CVE-2024-39912 , https://nvd.nist.gov/vuln/detail/CVE-2021-38299 (page did not render; UNVERIFIED)
- lbuchs: https://github.com/lbuchs/WebAuthn , https://github.com/lbuchs/WebAuthn/commits/master , https://github.com/lbuchs/WebAuthn/blob/master/src/WebAuthn.php (cloned and read locally)
- madwizard: https://github.com/madwizard-org/webauthn-server (cloned; composer.json and git log read locally)
- firehed: https://github.com/Firehed/webauthn-php (cloned; composer.json and git log read locally)
- WordPress core sodium_compat: https://github.com/WordPress/wordpress-develop/tree/trunk/src/wp-includes/sodium_compat , https://raw.githubusercontent.com/WordPress/wordpress-develop/trunk/src/wp-settings.php
- WP plugins: https://wordpress.org/plugins/two-factor-provider-webauthn/ , https://github.com/sjinks/wp-two-factor-provider-webauthn/blob/master/composer.json , https://wordpress.org/plugins/secure-passkeys/ , https://plugins.svn.wordpress.org/secure-passkeys/trunk/src/packages/web-authn/ , https://plugins.svn.wordpress.org/wp-2fa/trunk/includes/classes/Admin/Methods/passkeys/ , https://plugins.svn.wordpress.org/wp-2fa/trunk/vendor/
- FluentAuth 3.0.3: local extract (session scratchpad), `app/Services/TwoFa/WebAuthn/`
- Scoping tools: https://github.com/BrianHenryIE/strauss/releases , https://github.com/humbug/php-scoper/releases
- Spec: https://www.w3.org/TR/webauthn-3/ (ceremony step references; not re-read in this session)
