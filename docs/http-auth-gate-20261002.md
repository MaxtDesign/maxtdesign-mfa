# Fix report: staff could not sign in behind the host's access gate

Written 2026-10-02. Branch `fix/http-auth-gate`, fix commits `078533d` and `092c9a7`, on top of
`main` `6c2be3b`. Found by the first staging installation
([staging-mxo-20261002.md](staging-mxo-20261002.md)); private evidence of that run is outside
the repo at `C:/maxt/pilots/aimasters-maxtoffroad-operations/mfa-staging-20261002/`.

This is the author's fix and verification record, for independent review. It is not a
re-review, not staging acceptance and not a security audit. Shared staging was not touched:
the plugin is still installed and inactive there. Passkeys stay an opt-in beta.

## What went wrong

Hosting Basic Authentication 1.0.5 (class `Pressable_Basic_Auth`) is an access gate inside
WordPress, not a web-server password. On `plugins_loaded` priority 1, for every request of a
browser that is not logged in, it takes the HTTP Basic credentials, calls `wp_authenticate()`,
answers 401 if that fails, and otherwise calls `wp_set_current_user()` and
`wp_set_auth_cookie()`.

No login form exists at that point, so `Interceptor::authenticate` saw an unknown,
non-interactive password login. For an account that needs a second step it returned a
`WP_Error`. The gate read that as a wrong password and answered 401. On every request, forever:
staff could not reach setup or the challenge.

Reproduced locally with the same plugin file (copied from the staging evidence) on unfixed
`main`: administrator and editor accounts get 401 on every page; a subscriber gets 200.

## What it does now

A password that a **known gate** authenticates from the request's own Basic credentials is a
login context of its own (`http-auth`, class `Auth\HttpAuth`):

1. **Wrong or missing credentials:** unchanged. `wp_authenticate()` fails, the gate answers 401.
2. **Correct password, account needs no second step:** unchanged. The gate signs the user in.
3. **Correct password, account needs the second step, any ordinary page:** a pending sign-in is
   created and the browser is redirected to the challenge or setup screen. No session. The gate
   asks again on every request, so the browser's existing pending sign-in is reused rather than
   replaced; the form the user is filling in stays valid.
4. **The second step's own pages** (the login page with `action=mdmfa-verify` or
   `mdmfa-enroll`, and the emailed recovery link on `admin-post.php`): the gate's check is
   allowed to succeed, because otherwise the gate would answer 401 on the very page the user
   must reach. Nothing comes of it: the user is reset to "nobody" the moment the gate sets it
   (first listener on `set_current_user`), and `BypassGuard` destroys the session token and
   withholds the cookie, whatever the policy says. The page then renders for a logged-out
   visitor holding a pending sign-in, exactly as it does without a gate.
5. **Finishing the second step** is still the only way to a session (`Completion`), and it
   returns the browser to the page the gate interrupted.

Against the owner's constraints:

| Constraint | How it is met |
|---|---|
| Keep the staging access barrier | The gate is not bypassed, skipped or reconfigured. Every request still needs a valid WordPress password; anonymous and wrong-password requests get the gate's 401 on every URL, including the second step's pages. |
| Keep MFA enforcement | A correct password never yields a session or an authenticated request. Tested on every step. |
| No exemption for Basic Auth | Basic credentials are treated as a password login, with the same decision, pending record, lockout and completion as the login form. |
| No weaker staff policy, no disabled protection | Policy code is untouched. |
| No reliance on existing login cookies | Every test starts from a browser with no cookies. |

## Decisions for the reviewer to weigh

- **Only known gates.** The pass-through in step 4 returns a `WP_User` from the `authenticate`
  filter. That is only safe for a caller known to do nothing with it but start a session, so it
  is granted only when `wp_authenticate()` was called by a class or function on a short list:
  `Pressable_Basic_Auth` by default, extendable with the `mdmfa_http_auth_gates` filter (an
  empty array switches the integration off). The caller is read from the backtrace. Any other
  code that authenticates Basic credentials on a page request gets the old refusal, on every
  URL. This names a third-party class in the plugin; the alternative was to trust every caller.
- **Trusted devices are not used behind a gate.** Completing a login at `plugins_loaded`
  priority 1 would fire `wp_login` before other plugins have initialised and before permalinks
  exist. The code is asked for instead. Trusted devices are off by default.
- **Staff and customers both get the core challenge screen** behind a gate, not My Account's.
  The gate decides before WooCommerce can build a URL.
- **The second step's pages are recognised from the raw request**, because the gate runs before
  WordPress routes anything. The action must match exactly as core will read it (a posted value
  wins), and a login URL whose action core would replace (`key`, `checkemail`) does not count.

## Second look by a separate agent

A read-only security pass on `078533d` (no shared context) found no Critical or High, one
Medium and five Low. It found no path from the gate plus a correct password to a session.

| | Finding | Now (`092c9a7`) |
|---|---|---|
| M1 | The pass-through applied to any caller of `wp_authenticate()` with matching Basic credentials, not only the gate | Known gates only (above); unit and E2E test |
| L1 | The action was normalised before comparison; core does not normalise it, and replaces it for `key`/`checkemail` | Exact match; unit and E2E tests with the near misses |
| L2 | A trusted-device login completed at `plugins_loaded` could fatal with WooCommerce | Not attempted behind a gate |
| L3 | Other `set_current_user` listeners ran as the user before the reset | The reset runs first |
| L4 | A third-party Basic caller changed behaviour on installs without a gate | Gone with M1: unknown callers are refused as before |
| L5 | No log row for the gate path | One `gate_password` row per pending sign-in |

Left as is: a client that sends a correct password but keeps no cookies creates one pending
row per request (10 minute lifetime, purged by maintenance). It needs the correct password.

## Evidence

Files in [evidence/http-auth-gate-20261002/](evidence/http-auth-gate-20261002/). All local,
2026-10-02, PHP 8.3.29. On the disposable site the plugin is installed from a zip built with
`.distignore`; on plugin-test.local it runs from the working tree through its junction.

| Check | Unfixed `main` `6c2be3b` | Fix `092c9a7` |
|---|---|---|
| Gate tests, disposable site (WP 7.1.2 + WooCommerce 10.9.4), **real Hosting Basic Authentication 1.0.5** | 5 of 8 fail (staff get 401) | 8 pass, 187 assertions; 1 skipped (needs the fixture gate) |
| Gate tests, same site, fixture stand-in gate | 5 of 9 fail | 9 pass, 202 assertions |
| Gate tests on **plugin-test.local** (WP 7.1.2, WooCommerce 10.9.4, MySQL 8.0.35, nginx, 14 other plugins active), real gate | not run | 7 pass, 173 assertions; 2 not run there (need test fixtures) |
| Whole `e2e` suite, WooCommerce off (CI's configuration) | not run | 83 tests, 912 assertions: 74 pass, 8 skipped (network tests), 1 error that is the harness (a bare `wp` process on Windows) |
| Whole `e2e-wc` suite | not run | 18 tests, 488 assertions, pass |
| Unit suite | 327 tests | **332 tests, 1,761 assertions, pass** |
| PHPCS / PHPStan level 8 | | 0 / 0 |
| Byte budgets | | pass, unchanged |
| Outbound HTTP grep in shipped code | | 0 hits |

What the gate tests do, each from a browser with no cookies:

- **Anonymous and invalid credentials:** 401 with a Basic challenge and no cookie on seven URLs,
  including the challenge, setup and recovery URLs; a wrong password starts no pending sign-in.
- **Account with no second step:** 200 and a session, as without the plugin.
- **Fresh staff enrollment and the next login:** a new administrator is redirected to setup,
  gets no session on the setup screen, cannot use wp-admin, sets up an authenticator app, sees
  recovery codes, and gets a session only after acknowledging them, landing on the page the
  gate interrupted. In a new browser the password leads to the challenge and the code signs in.
- **No session before the second step:** for enrolled staff, thirteen other URLs requested
  mid-challenge (wp-admin, profile, admin-ajax, REST, the bare login page, six near misses of
  the second step's URLs) serve nothing as the user, set no cookie and keep the same pending
  sign-in; the session count stays 0; a wrong code fails; the right code signs in.
- **Past the setup period:** no skip is offered and a forged skip starts no session.
- **Logout:** the gate's logout ends the session; the next visit asks for the code again.
- **Recovery:** the emailed link is refused without the password, works in another browser
  that answers the gate, signs nobody in, and resets the factors.
- **A gate nobody vouched for:** refused on every URL, as before the fix.
- **No gate:** Basic credentials on a page request change nothing; the login form is as it was.

## The four principles (quality standard, section 4)

- **Performance and footprint: PASS for what changed, lab only.** No assets. On a site with no
  gate the new code is one comparison inside the existing `authenticate` callback, and only
  when a password was just authenticated. Behind a gate, a pending staff browser costs one
  indexed lookup of its pending row per request until the second step is done. The front-end
  query probe (0 plugin queries on anonymous pages) passes. Field data: UNVERIFIED.
- **Security: PASS within the scope tested.** Evidence above; not a formal audit.
- **Compliance and truthful operation: PASS.** The readme says what works behind such a
  prompt and what differs. No new data is collected; one log event name is new.
- **Accessibility: NOT APPLICABLE.** No markup changed.

## Not verified

- The MaxtOffroad stage itself: WooCommerce 11.1.2, PHP 8.3.35, a persistent object cache,
  WordPress.com's own mu-plugins, and whatever order its plugins load in. Locally the gate
  loads before this plugin (alphabetical order), the harder case.
- A real browser's Basic-auth dialog and cached credentials, including what it does after the
  gate's 401 on logout. The tests send the header the way a browser does once the user has
  answered the prompt.
- On plugin-test.local the recovery test and the unvouched-gate test did not run (they need
  test fixtures that were not installed on that site). Both pass on the disposable site.
- Other gates of this kind. None was tested; they are refused by default.
- Multisite behind a gate, passkeys behind a gate (beta, off by default), concurrency.

## plugin-test.local afterwards

Both plugins deactivated, my copy of the gate plugin removed, the seven synthetic users of
each run deleted; active plugins and users identical to the snapshot taken before; anonymous
home 200. Two things remain from the plugin's first activation there: its tables and options,
and the "login address" mail to the site's administrators in Local's Mailpit.
