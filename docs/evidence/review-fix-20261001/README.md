# Evidence: fixes for independent review findings F1 and F2

Recorded 2026-10-01 on two disposable local sites (scratch MariaDB, PHP's built-in server);
the plugin was installed from a zip built with `.distignore`. Report: [../../review-fix-20261001.md](../../review-fix-20261001.md).
The original review evidence is separate and unchanged, outside this repo.

| File | What it is |
|---|---|
| `before-fix-unit.txt` | The 19 new unit tests against unfixed `main` `f179387` |
| `before-fix-e2e-wc.txt` | `SecurityPresentersTest` against unfixed `main`, WordPress 7.1.2 + WooCommerce 10.9.4 |
| `before-fix-e2e-multisite.txt` | `MultisiteTest` against unfixed `main`, subdirectory network |
| `after-fix-checks.txt` | Unit suite, PHPCS, PHPStan, byte budgets, outbound-HTTP grep on `6a30b32` |
| `after-fix-e2e-wc.txt` | Whole `e2e-wc` suite on `6a30b32` |
| `after-fix-e2e-multisite.txt` | Whole `e2e` suite on the network on `6a30b32` |
| `reviewer-probe-after-fix.txt` | The reviewer's `reproduce.php`, unmodified, on `6a30b32` |

E2E output is trimmed to test names, summaries and the first lines of each failure. No
secrets, codes or login addresses are in these files.
