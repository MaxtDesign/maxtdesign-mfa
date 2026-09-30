# MaxtDesign MFA

Multi-factor authentication and a moved login address for WordPress and WooCommerce: TOTP,
passkeys (second factor and passwordless), recovery codes, an optional email code, and per-role
Off / Optional / Required policy for staff and customers. Free, on WordPress.org, with no outbound
HTTP and no front-end weight on normal pages.

**Status:** development (0.1.0, unreleased). TOTP and recovery codes work on the core login screen;
passkeys, the WooCommerce customer path and the moved login address are still in progress.

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

CI runs all of these on PHP 8.3, 8.4 and 8.5, plus an activation and uninstall smoke test against
WordPress and MySQL (`tests/smoke/run.sh`).

License: GPL-2.0-or-later.
