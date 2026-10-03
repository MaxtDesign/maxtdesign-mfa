# MaxtOffroad staging: initial installation test, 2026-10-02

Owner authorized the readme clarification, staging installation and beginning E2E testing after independent re-review. Runtime reviewed at `6c2be3b`; both original findings closed. Fresh independent checks: 327 tests / 1,711 assertions, PHPStan, PHPCS and byte budgets passed.

The readme now explains the Required-user TOTP fallback, limits the shortest-grace rule to governing-policy sites, and distinguishes enrollment permissions from existing credentials.

ZIP 0.1.0 passed the artifact gate and SBOM generation: 93 files, SHA-256 `6851e443d6e7dc4efe0292d59b8fd393253620a99f374cbe23351cb09582e9c4`. Installed bytes matched the ZIP. Stage: WP 7.1.2, PHP 8.3.35, WooCommerce 11.1.2, persistent object cache, database named locks available. Access gate, mail containment, noindex, disabled cron and independent SSH/WP-CLI recovery were checked before activation.

**FAIL: fresh staff login with Hosting Basic Authentication 1.0.5.** The gate authenticates WordPress credentials on `plugins_loaded` before the interactive login context exists. MFA refuses the noninteractive Required-role login; the gate returns HTTP 401 without a WordPress or pending-MFA cookie. A synthetic administrator returned HTTP 200 before activation and again after deactivation with the same credentials.

**Current stage state: MFA installed but inactive.** Original active-plugin order and inventoried MU-plugin hashes preserved; anonymous requests still 401; mail guard/noindex/cron protections intact. Test user deleted, MFA purge unscheduled. New plugin tables/options remain; no uninstall or broad database restore. Production untouched.

The full E2E run is blocked by this integration. Reproduce and resolve it in isolation without bypassing MFA or removing the staging access barrier, then independently recheck fresh login before continuing enrollment, recovery, checkout, cache and real-device tests. Passkeys remain opt-in beta. Distribution/release authority unchanged.

Private evidence and scoped backup: `C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-staging-20261002/REPORT.md`. Independent re-review: `C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-independent-rereview-20261002/REVIEW.md`. These local paths are evidence references, not shipped files.
