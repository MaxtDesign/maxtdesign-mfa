# Evidence: release candidate 3f3dbe3

Recorded 2026-10-02. Record: [../../release-readiness-20261002.md](../../release-readiness-20261002.md).

| File | What it is |
|---|---|
| `artifact-manifest.json` | Every file in `maxtdesign-mfa-0.1.0.zip` with its SHA-256, compared with `3f3dbe3` |
| `zip-preflight.txt` | `preflight-vendor.php` run against that zip |
| `e2e-wc.txt` | Whole `e2e-wc` suite, disposable WooCommerce site |
| `gate-real.txt` | `HttpAuthGateTest` with the real Hosting Basic Authentication 1.0.5 |
| `e2e.txt` | Whole `e2e` suite with WooCommerce off (CI's configuration) |
| `theme-mfa-hunk.patch` | The MFA-only hunk of the MaxtOffroad theme stylesheet, standalone against site commit `274a3c7` |

Output is trimmed to test names, summaries and the first lines of each failure. No secrets,
codes, passwords or login addresses are in these files.
