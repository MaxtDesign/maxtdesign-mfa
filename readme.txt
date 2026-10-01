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

Multi-factor login for staff and customers on your own site: TOTP, passkeys, recovery codes and per-role policy. No outbound HTTP.

== Description ==

**Development build.** Version 0.1.0 works with authenticator apps (TOTP), passkeys, emailed codes and recovery codes on the WordPress login screen and on WooCommerce My Account and checkout, and moves the login to a random address. The settings screens are still being built, so the per-role options use their defaults for now. It has not had its security review yet, so please do not rely on it to protect a live site until a release says it is ready.

MaxtDesign MFA adds a second factor to WordPress and WooCommerce logins, and runs entirely on your own site. Nobody is ever sent to WordPress.com or any other outside service to sign in.

What the finished plugin does:

* **Factors:** authenticator apps (TOTP), passkeys (as a second factor or as passwordless sign-in), single-use recovery codes, and an optional emailed code.
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

No rewrite rules and no permalink change. The server has to send unknown paths to WordPress's `index.php`, which is the standard setup for Apache (the WordPress `.htaccess` rules), nginx (`try_files`) and managed hosts. Password-protected posts, privacy request confirmations and recovery-mode links keep using `wp-login.php`, because they are sent to people who should not learn the login address.

= Is the moved login address a security feature? =

It removes noise from bots that hammer `wp-login.php`. The address becomes known the moment you link to it or share it, so treat the second factor as the protection, not the address.

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
* New: optional passkey-only sign-in for roles you choose (off by default). It needs a passkey that checks your fingerprint, face or screen lock.
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
* New: published security contact and vulnerability disclosure policy (security@maxtdesign.com), and a note that the WordPress.org account `slaacr` is MaxtDesign.
