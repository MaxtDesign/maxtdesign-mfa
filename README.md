# MaxtDesign MFA

Multi-factor authentication and a moved login address for WordPress and WooCommerce: TOTP,
recovery codes, passkeys in beta (a second step only, until the verifier has an independent review), an optional email code, and per-role
Off / Optional / Required policy for staff and customers. Free, on WordPress.org, with no outbound
HTTP and no front-end weight on normal pages.

**Status:** development (0.1.0, unreleased). TOTP, passkeys, emailed codes, recovery codes,
trusted devices, email recovery and the side-door policy (application passwords, XML-RPC, REST
password logins) work on the core login screen and on WooCommerce My Account and checkout, and the
login moves to a random address. Settings live under Users, Login security (MFA). Feature complete;
review, compatibility testing and the external passkey review come before a release.

- WordPress.org readme: [readme.txt](readme.txt)
- Security policy and private reporting: [SECURITY.md](SECURITY.md) (security@maxtdesign.com)
- Build plan: [docs/plan-maxtdesign-mfa.md](docs/plan-maxtdesign-mfa.md)
- Current state: [docs/STATE.md](docs/STATE.md)

## Development

Requires PHP 8.3+ and Composer. The plugin itself has no Composer runtime dependencies; `vendor/`
holds dev tools only and never ships.

```
composer install
composer lint       # WordPress Coding Standards
composer analyse    # PHPStan level 8
composer test       # PHPUnit
composer size-check # byte budgets for shipped CSS/JS
```

The WebAuthn verifier has its own seeded mutation fuzzer (`php tests/fuzz/fuzz.php [iterations]
[seed]`) and differential tests against two oracle libraries (dev-only Composer packages).

CI runs all of these on PHP 8.3, 8.4 and 8.5, plus the fuzzer (two million inputs per run),
end-to-end tests over HTTP (core login and WooCommerce, with a software passkey authenticator), and an activation and uninstall smoke test against
WordPress and MySQL (`tests/smoke/run.sh`).

License: GPL-2.0-or-later.
