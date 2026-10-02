=== MaxtDesign MFA ===

Contributors: slaacr
Donate link: https://github.com/sponsors/MaxtDesign
Tags: two-factor, mfa, passkeys, 2fa, login security
Requires at least: 7.0
Tested up to: 7.1
Stable tag: 0.1.0
Requires PHP: 8.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Multi-factor login for staff and customers on your own site: authenticator apps, recovery codes, per-role policy, and passkeys in beta.

== Description ==

**Development build.** Version 0.1.0 is feature complete: authenticator apps (TOTP), passkeys, emailed codes and recovery codes on the WordPress login screen and on WooCommerce My Account and checkout, a moved login address, and settings screens for all of it. It has not had its security review yet, so please do not rely on it to protect a live site until a release says it is ready.

MaxtDesign MFA adds a second factor to WordPress and WooCommerce logins, and runs entirely on your own site. Nobody is ever sent to WordPress.com or any other outside service to sign in.

What the finished plugin does:

* **Factors:** authenticator apps (TOTP), single-use recovery codes, an optional emailed code, and passkeys (beta, as a second step after the password).
* **Per-role policy:** Off, Optional or Required for each role, with a grace period and enrollment right inside the login flow.
* **No session before the second factor.** WordPress does not create a login session until the second factor passes.
* **Customers stay on your pages.** WooCommerce customers complete the challenge and enrollment on My Account and checkout, never on the WordPress login screen.
* **Side doors covered:** application passwords, XML-RPC, and plugins that log users in directly are checked against the same policy.
* **Moved login address.** The login moves to a random address and the old `wp-login.php` returns a 404. This cuts bot noise. It is not a security boundary on its own; the second factor is.
* **Escape hatch:** `define( 'MDMFA_DISABLE', true );` in `wp-config.php`, plus WP-CLI commands, if you ever lock yourself out.

What it does not do:

* No outbound HTTP. The plugin never calls home, never loads remote scripts, and never checks anything with an outside service.
* No front-end weight on normal pages: zero CSS, zero JavaScript, zero extra requests. The only script it will ever load is a small passkey module, and only on screens that offer a passkey.
* No jQuery, anywhere.

This plugin helps sites work toward requirements such as PCI DSS 8.4 and NIST SP 800-63B. It makes no compliance claim on its own; whether it meets a requirement depends on your site and your assessor.

== Installation ==

1. Upload the plugin and activate it.
2. The login moves to a random address and `wp-login.php` returns a 404. A notice in the dashboard shows the new address for a day after activation: bookmark it. `wp mdmfa slug get` prints it at any time.
3. Administrators, editors and shop managers are asked to set up an authenticator app at their next login, with 7 days of grace. Everyone else can turn it on under Users, My security.
4. Run `wp mdmfa status` to confirm the plugin installed its tables and settings.

== Frequently Asked Questions ==

= I locked myself out. What now? =

Add `define( 'MDMFA_DISABLE', true );` to `wp-config.php`. Logins go back to password only and every admin screen shows a red notice until you remove the line. `wp mdmfa disable-check` tells you whether the constant is active.

= Does it send any data anywhere? =

No. The plugin makes no outbound HTTP requests. Emailed codes, when you turn them on, go through your site's own `wp_mail()`.

= I lost the login address. How do I get in? =

Any of these works:

* Run `wp mdmfa slug get` on the server.
* Add `define( 'MDMFA_LOGIN_SLUG', 'your-address' );` to `wp-config.php` to set the address yourself.
* Add `define( 'MDMFA_DISABLE_LOGIN_LOCATION', true );` to put the login back at `wp-login.php` and keep two-step verification on.
* Search your email: administrators get the new address every time it changes.

= Does the moved login need special server setup? =

It adds no rewrite rules. The server has to send unknown paths to WordPress's `index.php`, which is the standard setup for Apache (the WordPress `.htaccess` rules), nginx (`try_files`) and managed hosts. A site on plain permalinks may not have that, so the plugin leaves the login at `wp-login.php` there and says so; choose another permalink setting, then turn the moved login on under Login location. Every administrator is emailed the new address when the login moves. Password-protected posts, privacy request confirmations and recovery-mode links keep using `wp-login.php`, because they are sent to people who should not learn the login address.

= Is the moved login address a security feature? =

It removes noise from bots that hammer `wp-login.php`. The address becomes known the moment you link to it or share it, so treat the second factor as the protection, not the address.

= Why are passkeys "beta"? =

The code that checks passkeys was written for this plugin instead of using an existing library, and it has not had an independent security review yet. It has its own tests, is compared against two established libraries and is fuzzed on every change, but nobody outside the project has examined it. So:

* Passkeys are off until you turn them on for a role (Users, Login security (MFA), Policy).
* A passkey is a second step after the password. It never replaces the password, so a mistake in the passkey code alone cannot sign anyone in.
* Signing in with a passkey and no password exists but is switched off. A site owner who accepts the risk can turn it on with `define( 'MDMFA_PASSKEY_ONLY_SIGNIN', true );` in `wp-config.php`.

Authenticator apps, recovery codes and emailed codes do not depend on that code. If you find a problem, see the Security section below.

= Does it work on multisite? =

Yes, network-activated only. Each site has its own settings page and its own login address. Sign-in sessions are valid across the whole network, so the plugin combines the settings of the sites a user belongs to, and an account that has two-step verification is asked for it on every site. Email recovery, application passwords and trusted devices require every site's permission. The longest recovery wait applies; the setup period is the shortest among the sites that set the user's highest policy level (Required > Optional > Off).

Permissions to enroll a method are combined the same way, with one exception: if a Required user's sites or tied roles have no authenticator-app or passkey method in common, authenticator-app enrollment remains available so the user can complete setup. This can allow it despite one site's passkey-only enrollment preference. Enrollment permissions do not revoke existing authenticator apps or passkeys. Recovery codes remain available. Visiting a site the user does not belong to can add restrictions from that site's settings. Only super admins can reset or unlock other users.

= Does it work behind my host's password prompt (HTTP Basic authentication)? =

Yes, with the one this was built for. Some hosts put a password prompt in front of a staging site that checks your WordPress username and password; WordPress.com and Pressable call theirs Hosting Basic Authentication. The prompt keeps doing its job: nobody gets past it without a valid password. A valid password alone still does not sign in an account that needs two-step verification. You are sent to the code screen, or to setup, and the session starts only after that.

Two things differ behind such a prompt. Trusted devices are not used, so the code is asked for at every sign-in. And only that plugin is recognised: any other code that checks a password this way is refused for accounts that need the second step, as before. A developer can vouch for another gate with the `mdmfa_http_auth_gates` filter.

= Where are the settings? =

Under Users, Login security (MFA). Each user manages their own methods under Users, My security, and customers under My Account, Security.

= Do application passwords skip two-step verification? =

Yes, by design. An application password is a separate, revocable password for one app, and apps cannot answer a second step. That is why roles that must use two-step verification have no application passwords unless you allow them, and why creating one needs a recent verification.

= Where are the encryption keys? =

Authenticator secrets are encrypted with a key derived from your `wp-config.php` salts, or from a dedicated `MDMFA_ENCRYPTION_KEY` constant if you define one. The key never appears in the admin screens.

== Security ==

Found a security issue? Please report it privately to security@maxtdesign.com rather than posting in a public support thread. We aim to acknowledge reports within 3 business days and will agree a disclosure timeline with you.

Please include the plugin version, steps to reproduce, and the impact as you understand it. We will credit you in the changelog unless you would rather stay anonymous, and we ask that you do not test against a site you do not own.

This plugin is published on WordPress.org by the account `slaacr`, which is MaxtDesign. The account name predates the brand and WordPress.org does not support renaming accounts, so the two names differ. Anything published under `slaacr` is ours.

== Changelog ==

= 0.1.0 =
* New: plugin foundation. Database tables for passkeys, pending logins and the activity log; default per-role settings; encryption service for authenticator secrets; the `MDMFA_DISABLE` escape hatch.
* New: two-step verification on the WordPress login screen with authenticator apps (TOTP) and single-use recovery codes. No login session exists until the second step passes.
* New: per-role policy with a grace period, and setup right inside the login flow for roles that require it.
* New: protection against code guessing (5 tries per sign-in, growing delays, a lock after 20 wrong codes) and against replaying a code.
* New: blocks plugins that log users in directly (for example an auto-login after a password reset) until the second step passes.
* New: Users, My security, to set up or remove an authenticator app and create recovery codes, with a fresh code required for changes.
* New: WooCommerce customers finish the second step on My Account, including logins from checkout, which return to checkout with the cart intact. Customers never see the WordPress login screen.
* New: a WooCommerce password reset no longer logs an enrolled customer straight in; it asks for the second step first.
* New: My Account, Security tab for customers to manage their authenticator app and recovery codes.
* New: front-end login forms (the core login form and the Login/out block) sign in without passing through wp-login.php.
* New: the login moves to a random address. `wp-login.php` and logged-out `wp-admin` return a 404, the `/login` and `/admin` shortcuts no longer redirect there, and every link WordPress builds points at the new address. On WooCommerce stores, logged-out visitors are sent to My Account instead, so browsing the store never reveals it.
* New: lost-address recovery through `wp mdmfa slug get|set|reset`, the `MDMFA_LOGIN_SLUG` and `MDMFA_DISABLE_LOGIN_LOCATION` constants, and an email to every administrator when the address changes.
* New: the login address is kept out of page caches (no-store, DONOTCACHEPAGE, LiteSpeed and WP Rocket exclusions, MaxtDesign Cache purge on change).
* New: `wp mdmfa status`, `wp mdmfa disable-check`, `wp mdmfa unlock` and `wp mdmfa user status|reset`.
* New: passkeys. Add one on My security or the My Account Security tab, or during setup at sign-in, and use it as your second step. Works with phone, computer and security-key passkeys (ES256, RS256 and Ed25519). Verification happens on your server; nothing is sent anywhere.
* New: passkeys are in beta. They are off until you turn them on for a role, and they work as a second step after the password. The passkey code has not had an independent security review yet.
* New: passkey-only sign-in exists but is switched off; a site owner can enable it with the `MDMFA_PASSKEY_ONLY_SIGNIN` constant. It needs a passkey that checks your fingerprint, face or screen lock.
* New: a passkey that reports an unexpected counter (a sign it may have been copied) is flagged on the security screen and logged. Sites can choose to block it.
* New: adding a second method to an account that already has one needs a verification in the last 10 minutes, the same as removing one.
* New: the passkey script (under 1 KB compressed) loads only on screens that offer a passkey. Every other page stays free of plugin CSS and JavaScript.
* New: emailed sign-in codes for roles that allow them (customers by default, never staff by default). A code works for 10 minutes, 5 tries, and is tied to the sign-in it was sent for. At most 3 are sent in 15 minutes and 10 in a day.
* New: trusted devices, off for every role until the owner turns them on. A trusted device skips the second step for 30 days. Changing the password or removing a method forgets every trusted device, and a trusted sign-in still has to confirm before sensitive changes.
* New: application passwords follow the role policy. Roles that must use two-step verification have none unless the owner allows them, and creating one needs a verification in the last 10 minutes.
* New: XML-RPC refuses account passwords for users with two-step verification and says to use an application password. The owner can also switch XML-RPC logins off, or allow passwords.
* New: plugins that take a username and password over the REST API are refused for users with two-step verification.
* New: email recovery from the sign-in challenge, for roles that allow it (customers by default). The emailed link opens a confirmation page first, staff accounts wait 24 hours, and signing in normally cancels a pending reset.
* New: an optional block for WordPress.com sign-in (Jetpack), and a warning when another two-step verification plugin is active.
* New: settings under Users, Login security (MFA): a policy table per role (Off, Optional or Required, allowed methods, passkey-only sign-in, days to set up, trusted devices), login location, side doors, recovery, and factor options. Every save is validated; a Required role always keeps a method that can be set up at sign-in.
* New: Coverage tab showing who is set up, who is overdue and who is locked, with reset, unlock and "sign out everywhere" for the users you select.
* New: Activity tab with the security log, a retention setting, and shortened network addresses by default.
* New: Tools tab with the encryption key status, a warning when another two-step verification plugin is active, and a settings export that holds no secrets.
* New: administrators who have a second step must have confirmed it in the last 10 minutes to change settings, change the login address or reset other users.
* New: a public login page of your choice, so login links shown to visitors do not have to reveal the login address.
* New: privacy tools. Suggested privacy policy text, a personal data export (methods, passkey names and dates, log entries, never secrets) and erasure of log entries.
* New: `wp mdmfa status` reports policy and counts per role, lockouts and side doors, with no secrets, user names or login address in it.
* New: works behind Hosting Basic Authentication, the password prompt some hosts put in front of staging sites. A correct password leads to the second step, never straight to a session.
* New: on a multisite network the strictest settings among a user's sites apply everywhere (policy, setup period, email recovery and its wait, application passwords, trusted devices, sign-in methods), and the plugin is network-activated only.
* New: first activation emails the new login address to every administrator. On plain permalinks the login is not moved.
* New: `wp mdmfa key status`, `export-define` and `rewrap`, so the encryption key can be pinned or replaced without breaking authenticator apps, and `wp mdmfa recovery-codes` for a locked-out owner.
* New: changing an account's email address switches its email codes off until the new address is confirmed, and closes email recovery for a day.
* New: every method added to an account is announced to the account's owner by email.
* Changed: emailed codes are 8 digits and no longer appear in the email subject.
* Security: an application password no longer exempts another account's password in the same request; the old login path can no longer be reached by mixing actions; a failed front-end login no longer redirects to the login address; application password creation is guarded on every route; second-step attempts for one account are processed one at a time.
* New: published security contact and vulnerability disclosure policy (security@maxtdesign.com), and a note that the WordPress.org account `slaacr` is MaxtDesign.
