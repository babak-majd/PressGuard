=== PressGuard ===
Contributors: babakmajd
Tags: security, firewall, waf, two-factor, malware-scanner
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Complete, free WordPress security — firewall (WAF), login protection & 2FA, hardening, malware & integrity scanning, roles & activity, SSL, and more.

== Description ==

PressGuard is a complete, free and open-source WordPress security plugin. It aims to match the capability of the big paid plugins — with nothing locked behind a premium tier — while staying light and fully transparent.

**Firewall (WAF)**
* Two levels: an in-WordPress firewall and an optional Extended WAF that runs before WordPress via `auto_prepend_file`.
* Anomaly-scored rules (adapted from the OWASP Core Rule Set approach) for SQLi, XSS, LFI/traversal and RCE, with learning / detection / enabled modes.
* Per-IP rate limiting, User-Agent blocking (with verified good-bot allowlisting), and a local "Under Attack" JavaScript challenge.
* Behavioural per-IP risk scoring that blocks an address misbehaving across many signals.
* Custom rules and absolute IP allow/deny lists in Expert mode.

**Login protection**
* Custom login URL, progressive lockout, generic error messages, user-enumeration blocking.
* Two-factor authentication (TOTP) with backup codes and replay protection.
* Optional breached-password screening via HaveIBeenPwned (k-anonymity — your passwords never leave the site).

**Hardening**
* Disable the file editor and XML-RPC, hide the WordPress version, send security headers.
* Block PHP execution in uploads and deny access to sensitive files via `.htaccess`.

**Scanning & audit**
* Malware signature scan of every file (including all `.htaccess` files) plus WordPress core integrity against the official checksums.
* Resumable, AJAX-driven scan that keeps running on the server even if you close the tab.
* Security audit with a 0–100 score and actionable findings; file-permission checker with a confirmed, reversible fix.

**Internal protection**
* Custom roles & a full capability editor, plus per-plugin access control.
* Activity log (logins, content, plugins/themes, users/roles) with filters, and new-IP login observation.

**SSL / HTTPS**
* Force HTTPS, fix mixed content, HSTS.
* Free Let's Encrypt certificates via ACME (HTTP-01, or DNS-01 for wildcards — automatic with Cloudflare, or manual TXT records for any provider), with auto-renew.

**Integrations & compatibility**
* Optional Cloudflare integration (one-click free security settings, Under Attack sync).
* Works alongside WooCommerce, Elementor, Gutenberg, page-cache plugins, and PressPilot.

**Privacy & localization**
* No mandatory cloud service. Full import/export of settings (secrets excluded).
* Translation-ready; ships with English, Persian, Russian, Arabic, Hindi and German, with full RTL support.

== Installation ==

1. Upload the `pressguard` folder to `/wp-content/plugins/`, or install the ZIP from Plugins → Add New.
2. Activate the plugin.
3. Run the Setup Wizard (PressGuard → Setup Wizard) to apply a recommended secure baseline in one click.

== Frequently Asked Questions ==

= Is it really free? =
Yes. Every feature is free and open-source. There is no premium tier.

= Will the firewall break my site? =
The firewall defaults to "learning" mode, which only logs. Review the Activity Log, then switch to "enabled" when you are comfortable. Admin editing, WooCommerce, Elementor and Gutenberg are exempt from body rule-matching to avoid false positives.

= Does it send my data anywhere? =
No mandatory cloud. Optional lookups (breached-password, core checksums, geolocation) are explicitly opt-in or use privacy-preserving techniques.

== Changelog ==

= 0.1.0 =
* Initial release: firewall (basic + extended), login protection + TOTP 2FA, hardening, malware & integrity scanning, audit, file permissions, roles & access, activity log, SSL/ACME issuance, Cloudflare integration, alerts, country blocking, behavioural risk scoring, import/export, setup wizard, and WooCommerce/Elementor/Gutenberg/cache/PressPilot compatibility.
