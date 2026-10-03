# Evidence: sign-in behind the host's access gate

Recorded 2026-10-02. Report: [../../http-auth-gate-20261002.md](../../http-auth-gate-20261002.md).
The staging evidence that found the problem is separate and unchanged, outside this repo.

| File | What it is |
|---|---|
| `before-fix-real-gate.txt` | `HttpAuthGateTest` against unfixed `main` `6c2be3b` with the real Hosting Basic Authentication 1.0.5, disposable site |
| `before-fix-standin-gate.txt` | The same against the fixture's stand-in gate |
| `after-fix-real-gate.txt` | `HttpAuthGateTest` on `092c9a7` with the real gate plugin |
| `after-fix-e2e.txt` | Whole `e2e` suite on `092c9a7`, WooCommerce off (CI's configuration); gate tests use the stand-in |
| `after-fix-e2e-wc.txt` | Whole `e2e-wc` suite on `092c9a7` |
| `after-fix-checks.txt` | Unit suite, PHPCS, PHPStan, byte budgets, outbound-HTTP grep on `092c9a7` |
| `plugin-test-local.txt` | `HttpAuthGateTest` on plugin-test.local with the real gate plugin, and the state of that site afterwards |

Output is trimmed to test names, summaries and the first lines of each failure. No secrets,
codes, passwords or login addresses are in these files.
