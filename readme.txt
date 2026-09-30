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

**Development build.** Version 0.1.0 is the foundation of the plugin: its database tables, settings, encryption service and WP-CLI status command. It does not change how anyone logs in yet. Please do not rely on it to protect a site until a release says it does.

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
2. Nothing changes at login in this development build. Run `wp mdmfa status` to confirm the plugin installed its tables and settings.

== Frequently Asked Questions ==

= I locked myself out. What now? =

Add `define( 'MDMFA_DISABLE', true );` to `wp-config.php`. Logins go back to password only and every admin screen shows a red notice until you remove the line. `wp mdmfa disable-check` tells you whether the constant is active.

= Does it send any data anywhere? =

No. The plugin makes no outbound HTTP requests. Emailed codes, when you turn them on, go through your site's own `wp_mail()`.

= Is the moved login address a security feature? =

It removes noise from bots that hammer `wp-login.php`. The address becomes known the moment you link to it or share it, so treat the second factor as the protection, not the address.

= Where are the encryption keys? =

Authenticator secrets are encrypted with a key derived from your `wp-config.php` salts, or from a dedicated `MDMFA_ENCRYPTION_KEY` constant if you define one. The key never appears in the admin screens.

== Security ==

Found a security issue? Please report it privately to security@maxtdesign.com rather than posting in a public support thread. We aim to acknowledge reports within 3 business days and will agree a disclosure timeline with you.

Please include the plugin version, steps to reproduce, and the impact as you understand it. We will credit you in the changelog unless you would rather stay anonymous, and we ask that you do not test against a site you do not own.

This plugin is published on WordPress.org by the account `slaacr`, which is MaxtDesign. The account name predates the brand and WordPress.org does not support renaming accounts, so the two names differ. Anything published under `slaacr` is ours.

== Changelog ==

= 0.1.0 =
* New: plugin foundation. Database tables for passkeys, pending logins and the activity log; default per-role settings; encryption service for authenticator secrets; `wp mdmfa status` and `wp mdmfa disable-check`; the `MDMFA_DISABLE` escape hatch. No login behaviour changes yet.
* New: published security contact and vulnerability disclosure policy (security@maxtdesign.com), and a note that the WordPress.org account `slaacr` is MaxtDesign.
