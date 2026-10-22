# php2shell response checklist (printable version of the self-assessment)

Answer each question, then follow the branch. The interactive version with the same logic is in [`docs/index.html`](docs/index.html).

## A. Where does your PHP run?

- [ ] **Managed / shared hosting** → the provider patches. Go to **E1**.
- [ ] **VPS / dedicated / cPanel / Plesk that I administer** → continue with **B**.
- [ ] **Containers or PaaS where I control the image** → continue with **B**, patch by rebuilding the image.
- [ ] **I don't know** → find out first (who do you pay for hosting, and do you have root?).

## B. Which PHP version serves web requests? (phpinfo, not `php -v`)

- [ ] 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or newer, or a distro package whose changelog names both CVEs → go to **E2**.
- [ ] 8.2–8.5 but an older patch level → **vulnerable**, continue with **C**.
- [ ] 8.1 / 8.0 / 7.x or older → **vulnerable with no fix**, continue with **C** and plan a branch upgrade today.
- [ ] I don't know → check now; assume vulnerable until proven otherwise.

## C. How is PHP executed, and from where is it reachable?

- [ ] mod_php or PHP-FPM / LiteSpeed / FastCGI, **public** → **CRITICAL**. Go to **D**.
- [ ] Same SAPIs, **internal network only** → **HIGH**. Go to **D**, next business hours at the latest.
- [ ] CLI / cron only, no web server → **LOW**. Update with the next package run.

## D. Can you patch today?

- [ ] **Yes** → update, **restart php-fpm / apache / lsws / container**, confirm the version in phpinfo, go to **E2**.
- [ ] **Needs a window** → escalate: unauthenticated pre-application RCE with public exploits outweighs a restart. Meanwhile do **D2**.
- [ ] **App can't run on a patched branch** → do **D2** now, then treat migration as an incident (8.3 or 8.4; or a backporting vendor such as CloudLinux alt-php).

### D2. Interim mitigations (partial, not a fix)

- [ ] `session.upload_progress.enabled = Off` in php.ini or the FPM pool, then restart workers (`ini_set` does not work).
- [ ] WAF rules updated on/after 21 Oct 2026 (Cloudflare managed rules, ModSecurity / Imunify360 ≥ 8.83).
- [ ] `post_max_size` and `upload_max_filesize` as small as the app tolerates.
- [ ] Optional, breaks uploads: reject `multipart/form-data` at the web server.
- [ ] Do **not** rely on `memory_limit = -1` without memory monitoring.

## E1. Managed hosting

- [ ] PHP info page shows a fixed version, or the provider's status page says the rollout reached your server.
- [ ] `session.upload_progress.enabled` shows **Off** in the PHP options.
- [ ] If nothing changed after 48 h: ticket quoting CVE-2026-109618 and CVE-2026-109619.
- [ ] Go to **E2**.

## E2. Look back at the exposure window (20 Oct 2026 onward)

Run `scripts/php2shell-check.sh` (root, read-only) or check by hand:

- [ ] No `segfault` for php-fpm / apache / httpd / lsphp in `journalctl -k` or `dmesg`.
- [ ] No burst of `Allowed memory size … exhausted` or `exited on signal 11` in PHP / web error logs.
- [ ] No spike of 5xx in access logs; no `.php` executed from uploads / cache / image folders with HTTP 200.
- [ ] No new `.php` files in upload, cache or temp directories; no PHP tags inside images or `.txt`.
- [ ] No changes to `index.php`, `wp-config.php`, `config.php`, `.htaccess`, `.user.ini` you did not make.
- [ ] No unknown cron entries, SSH keys, systemd units, SUID binaries, `/etc/ld.so.preload`.
- [ ] No unknown admin users or API tokens in the application.
- [ ] No unexplained CPU or outbound connections.

All clear → **done**; keep the report. Anything found → **F**.

## F. If you found something

1. [ ] Preserve: copy the evidence folder and logs off the host.
2. [ ] Contain: maintenance page / firewall, kill unknown processes, remove persistence.
3. [ ] Rotate: database, application secrets, admin passwords, SSH keys on the host, any API tokens it stored.
4. [ ] Patch, then redeploy from a known-good source or a backup before 20 Oct 2026.
5. [ ] Check every other PHP host you run, and anything the compromised host could reach with stored credentials.
6. [ ] Record the timeline.
