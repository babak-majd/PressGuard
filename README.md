# PressGuard

Complete, free & open-source WordPress security — firewall (WAF), login protection & 2FA, hardening, malware & core-integrity scanning, roles & activity, SSL, and more. Nothing less than the big paid plugins, fully free.

## Features

- **Firewall (WAF)** — two levels (in-WordPress + Extended via `auto_prepend_file`), anomaly-scored rules for SQLi/XSS/LFI/RCE, learning→detection→enabled modes, per-IP rate limiting, User-Agent blocking with verified good-bot allowlisting, local "Under Attack" challenge, and behavioural per-IP risk scoring.
- **Login** — custom login URL, progressive lockout, generic errors, anti-enumeration, TOTP 2FA + backup codes, optional breached-password screening (HaveIBeenPwned k-anonymity).
- **Hardening** — disable file editor / XML-RPC, hide version, security headers, block PHP in uploads and protect sensitive files via `.htaccess`.
- **Scanning & audit** — all-files + `.htaccess` malware signatures, core checksum verification, resumable AJAX scan (survives tab close via cron), 0–100 security audit, file-permission checker with a confirmed fix.
- **Internal protection** — custom roles & capability editor, per-plugin access control, activity log with filters and new-IP observation.
- **SSL** — force HTTPS, mixed-content fix, HSTS, and free Let's Encrypt issuance (ACME HTTP-01 / DNS-01 — automatic Cloudflare or manual TXT for any provider) with auto-renew.
- **Integrations** — optional Cloudflare (free security settings + Under Attack sync); compatible with WooCommerce, Elementor, Gutenberg, page caches and PressPilot.
- **Expert & tools** — custom WAF rules, absolute IP allow/deny lists, full settings import/export, setup wizard.
- **i18n** — English, Persian, Russian, Arabic, Hindi, German (RTL-ready). No mandatory cloud.

## Install (development)

```bash
docker compose up -d
docker compose run --rm wpcli wp plugin activate pressguard
# http://localhost:8099/wp-admin  (admin / adminpass)
```

## Quality

```bash
composer install
composer lint      # PHPCS (WordPress standard)
composer analyse   # PHPStan
```

## License

GPL-2.0-or-later.

If it saves you time: [buy me a coffee](https://bobclub.ir/coffee) ☕
