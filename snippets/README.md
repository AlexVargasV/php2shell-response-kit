# Snippets

Copy-paste building blocks for developers and admins. **None of them replace updating PHP**; they reduce exposure while you patch or make sure you never ship a vulnerable build again.

| File | What it does | Use it when |
|---|---|---|
| [`php-ini-mitigation.ini`](php-ini-mitigation.ini) | `session.upload_progress` off, `expose_php` off, smaller bodies | Always, until patched (and `expose_php = Off` forever) |
| [`php-fpm-pool-hardening.conf`](php-fpm-pool-hardening.conf) | Same at pool level (cannot be overridden by `ini_set`) plus worker recycling | PHP-FPM hosts |
| [`nginx-block-multipart.conf`](nginx-block-multipart.conf) | Rejects `multipart/form-data` except on allowed paths / trusted networks | nginx; see the table below |
| [`apache-block-multipart.conf`](apache-block-multipart.conf) | Same for Apache / LiteSpeed (`.htaccess` or vhost) | Apache, LiteSpeed, cPanel |
| [`cloudflare-waf-rule.md`](cloudflare-waf-rule.md) | Same at the Cloudflare edge | Sites behind Cloudflare |
| [`docker-build-guard.Dockerfile`](docker-build-guard.Dockerfile) | `docker build` fails if the image ships a vulnerable PHP | Any Docker image with PHP |
| [`runtime-guard.php`](runtime-guard.php) | `php2shell_status()` for health checks and monitoring | Laravel, Symfony, custom apps |
| [`wordpress/php2shell-site-health.php`](wordpress/php2shell-site-health.php) | Adds a critical/good test to **Tools → Site Health** | WordPress (as an mu-plugin) |

## Does blocking multipart fit my application?

Blocking `multipart/form-data` removes the usual delivery vehicle for the exploit, but it also blocks every legitimate file upload that is not allow-listed.

| Application | Fit | Why |
|---|---|---|
| Brochure sites, blogs, APIs without uploads | **Good** | Nobody uploads; block everything |
| WordPress where only editors upload | **Good** with the WordPress paths and/or office IPs | Front-end forms with file fields (contact forms, WooCommerce) need extra paths |
| WooCommerce / membership with customer uploads | **Partial** | Add each upload endpoint; test checkout and account pages |
| Moodle, LMS, ticketing, any app where users submit files | **Poor** | Many forms are multipart (assignment submission, course settings with file pickers). Use trusted networks only for admin, or rely on `session.upload_progress = Off` + WAF and patch fast |
| Laravel / Symfony apps | **Depends** | List your upload routes (`/livewire/upload-file`, API upload routes) |

Always test: one normal page view, one login, one legitimate upload, one form submission. Watch the logs for a few hours after enabling.

## Verify any change

```bash
# should be 403 for a non-upload path when the block is active
curl -s -o /dev/null -w '%{http_code}\n' -F probe=1 https://example.com/
# web SAPI view of the ini setting (temporary file, delete afterwards)
echo '<?php var_dump(ini_get("session.upload_progress.enabled"), PHP_VERSION);' > public/ini-check.php
```
