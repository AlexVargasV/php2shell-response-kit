# php2shell (CVE-2026-109618 / CVE-2026-109619): what it is, why you must update, and how to check if you were hit

> **TL;DR** — On 21 October 2026 the PHP project shipped emergency releases for two critical bugs, nicknamed **php2shell**, that let an **unauthenticated** attacker run code on a PHP web server **before your application even starts**. Default configurations are vulnerable. Public exploit tooling exists and attacks were seen hours before the patch. Update to **PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35** today. If you run 8.1 or older there is no official fix: upgrade the branch. If you cannot patch within hours, apply the mitigations in section 6 and run the check script in `scripts/`.

---

## 1. Quick facts

| | |
|---|---|
| Name | php2shell |
| CVE IDs | CVE-2026-109618 ("RCE via OOM corruption"), CVE-2026-109619 ("RCE via stale global state") |
| Severity | CVSS v4.0 **9.2 (Critical)** for each. The 10.0 figure that circulated during the leak was wrong. |
| Class | Use-after-free in the PHP engine, triggered by a fatal error (typically crossing `memory_limit`) at the wrong moment |
| Authentication required | **No** |
| User interaction | None |
| Affected | Every PHP version since **5.4 (2012)** up to and including 8.5.11, 8.4.26, 8.3.35 and 8.2.34 |
| Fixed in | **8.5.12, 8.4.27, 8.3.36, 8.2.35** (released 2026-10-21 14:00 UTC) |
| Unsupported branches | 8.1 and older get **no official fix** from php.net. Some vendors backport. |
| Confirmed exploitable on | Apache `mod_php` (default settings, unauthenticated) and **PHP-FPM**. Any long-lived worker model (LiteSpeed `lsphp`, FastCGI) should be treated as affected. |
| Exploit status | Technical details leaked on 2026-10-20, RCE confirmed publicly the same day, exploit tooling public. Cloudflare observed attacks from **07:43 UTC on 21 October**, before the fix was released. |

---

## 2. What the bugs actually are (short version)

Both bugs share one root cause: when PHP aborts a request with a **fatal error**, typically because the request crossed `memory_limit`, some internal engine state is not cleaned up correctly.

- **CVE-2026-109618 — "RCE via OOM corruption".** A request that hits `memory_limit` at the wrong instant can leave partially initialised internal data behind. PHP later treats that data as valid and memory gets corrupted. Public write-ups show the practical trigger is the **session upload-progress handler**, reached with an ordinary `multipart/form-data` request. The same path can also **leak freed worker memory back to the client inside a `PHPSESSID` cookie**, which is how attackers defeat ASLR. The leak works even if your code never calls `session_start()`.
- **CVE-2026-109619 — "RCE via stale global state".** A fatal error at the wrong point can leave internal pointers referencing memory that belonged to a **previous request**. The next request handled by the same worker reuses freed memory. Combined with an OPcache type confusion this gives code execution.

Chained, the two give **unauthenticated remote code execution** against a stock PHP install. Because the bugs live in the engine's request handling, **they fire before any application code runs**. WordPress, Moodle, Magento, Laravel, a plain `index.php`: it does not matter what you host, and application-level maintenance modes do not help.

---

## 3. Why you must update (and not just "harden")

1. **It is pre-authentication and pre-application.** There is no login, plugin, or route to disable. If PHP parses the request, you are exposed.
2. **Default configurations are vulnerable.** You did not misconfigure anything.
3. **Exploit tooling is public and scanners are already running.** Attacks were logged before the patch existed. Every unpatched host on the internet is being probed.
4. **The mitigations are partial.** Turning off `session.upload_progress` removes the best-known trigger path for one bug. It does not remove the root cause. Raising `memory_limit` to unlimited removes the OOM trigger but lets a single request eat all RAM.
5. **A compromised PHP worker runs as your web user.** That means read access to `wp-config.php`, `config.php`, `.env`, database credentials, API keys, and every file your site can read. Attackers typically drop a web shell, add an admin user, and install a cron job or miner within minutes.
6. **There is no fix for 8.1 and older.** If you are still on 7.x or 8.0/8.1 you are now permanently exposed until you upgrade the branch. PHP 8.2 itself leaves security support on 31 December 2026, so 8.3 or newer is the sensible target.

---

## 4. Timeline

| Date (UTC) | Event |
|---|---|
| 2024 | A PHP core developer finds the first signs of the OOM problem during the first external audit. |
| 2026-07-30 | Calif begins a PHP audit under the "Patch the Planet" program. |
| 2026-08-11 | Calif reports an unconditional RCE. OpenAI reports the same root cause the same day. |
| 2026-08-24 | Wiz Research reports further attack vectors. |
| 2026-09-18 | OpenAI reports further attack vectors. |
| 2026-10-20 ~15:00 | CVE IDs begin circulating online with wrong release time and score. |
| 2026-10-20 19:30 | PHP publishes its pre-announcement early and moves the release forward to 21 October. |
| 2026-10-20 ~20:00 | A proof-of-concept video is published by mistake. Independent researchers confirm RCE. |
| 2026-10-21 07:41 | A vendor publishes patched container images early, breaking the embargo. |
| 2026-10-21 07:43 | Cloudflare observes the first attacks. |
| 2026-10-21 14:00 | Coordinated release of 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. |
| 2026-10-21 19:00 | CloudLinux ships first patched `alt-php` packages. AlmaLinux, Debian, Ubuntu and others publish advisories the same day. |

---

## 5. Step 1 — Find out what you are running

The version that matters is the one **serving web requests**, not necessarily the one `php -v` prints in your shell. Check both.

**Shell (every PHP binary on the box):**

```bash
php -v | head -1
for b in /usr/bin/php* /usr/local/bin/php /opt/alt/php*/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php \
         /opt/plesk/php/*/bin/php /opt/remi/php*/root/usr/bin/php /usr/local/lsws/lsphp*/bin/php; do
  [ -x "$b" ] && echo "$b -> $($b -r 'echo PHP_VERSION, " ", PHP_SAPI;' 2>/dev/null)"
done
```

**Web (what the browser actually hits):** create a temporary file `whoami-php.php` containing `<?php echo PHP_VERSION, ' / ', PHP_SAPI;` in your web root, open it in a browser, **then delete it**.

**Docker / Compose:**

```bash
for c in $(docker ps -q); do printf '%s: ' "$(docker inspect -f '{{.Name}}' $c)"; docker exec $c php -v 2>/dev/null | head -1 || echo "(no php)"; done
```

**Distribution packages with backported fixes.** Debian, Ubuntu, RHEL/Alma/Rocky and SUSE usually keep their *own* version numbers and backport the patch. On Ubuntu 24.04 the fixed package is still named `8.3.6-0ubuntu0.24.04.N`, so **do not judge by the version string alone**. Check the package changelog or the distro advisory:

```bash
apt changelog php8.3-cli 2>/dev/null | grep -iE 'CVE-2026-10961[89]' | head   # Debian/Ubuntu
rpm -q --changelog php | grep -iE 'CVE-2026-10961[89]' | head                  # RHEL family
```

Or run `scripts/php2shell-check.sh`, which does all of the above.

---

## 6. Step 2 — Patch (per platform)

Always restart the PHP workers after updating: `php-fpm`, `apache2`/`httpd`, `lsws`, or the container. A patched binary on disk does nothing while old workers are still running.

### Debian / Ubuntu (distro packages)

```bash
sudo apt update && sudo apt install --only-upgrade 'php*' && sudo systemctl restart php*-fpm apache2 2>/dev/null
```

Confirm with `apt changelog` (see section 5). If you use the Ondřej Surý PPA / Sury repo you will get the upstream version numbers (8.3.36 etc.).

### RHEL / AlmaLinux / Rocky / CentOS Stream

```bash
sudo dnf update 'php*' && sudo systemctl restart php-fpm httpd
```

Remi repository users: `dnf update php* --enablerepo=remi-*` once the module is published.

### Docker (official `php` images)

```bash
docker pull php:8.3-fpm   # or 8.4-fpm, 8.5-fpm, 8.3-apache ...
docker compose build --pull && docker compose up -d
docker exec <container> php -v
```

Pin to the fixed tag (`php:8.3.36-fpm`) if your build uses explicit versions.

### cPanel / WHM (EasyApache 4 or CloudLinux PHP Selector)

Run **WHM → EasyApache 4 → Update** or `yum update ea-php*`; on CloudLinux also `yum update alt-php*`. CloudLinux published patched `alt-php` packages on 21 October at 19:00 UTC; Imunify360 ruleset 8.83 blocks the known exploit pattern as an interim measure (deny on ModSecurity/Coraza, log-only on LiteSpeed).

### Plesk

**Tools & Settings → Updates** → install PHP updates, or `plesk installer update`. Restart `plesk-php*-fpm`.

### Windows (IIS / XAMPP / WAMP)

Download the fixed build from windows.php.net, replace the PHP directory, restart IIS / Apache.

### Managed shared hosting (Hostinger, Namecheap, SiteGround, etc.)

The provider patches the platform. Check your control panel's **PHP info** page for the version; if it still shows an old build after 48 hours, open a ticket quoting both CVE IDs. Make sure `session.upload_progress.enabled` shows **Off** in the PHP options. Hostinger, for instance, disabled it platform-wide, deployed WAF rules in deny mode, and is rolling the patched versions out automatically; VPS customers must patch themselves.

### Still on PHP 8.1, 8.0 or 7.x?

There is **no official fix**. Options, in order of preference:

1. Upgrade the application to a supported PHP branch (8.3 or 8.4). Most modern frameworks and CMS already support them.
2. Use a vendor that backports (CloudLinux `alt-php`, some Linux distributions for their LTS releases).
3. If neither is possible, apply **all** mitigations in section 7, put a WAF in front, and plan the migration as an incident, not a project.

---

## 7. Step 3 — If you cannot patch right now: mitigations and their limits

| Mitigation | What it does | Limits |
|---|---|---|
| `session.upload_progress.enabled = Off` in `php.ini` / the FPM pool, then **restart workers** | Removes the best-known trigger path for CVE-2026-109618 | Partial. Does not fix the root cause. `ini_set()` in code does **not** work; it must be in the ini / pool config. |
| Keep `post_max_size` and `upload_max_filesize` as small as your app allows | Reduces the attacker's room to drive memory usage | Partial |
| Reject `multipart/form-data` requests at the web server (nginx `if`, Apache `RewriteRule` → 403) | Blocks the practical delivery vehicle | Breaks every file upload on the site (media library, product images, assignment uploads) |
| WAF rules (Cloudflare managed rules, ModSecurity / Imunify360 ruleset ≥ 8.83) | Blocks known exploit patterns | Signature-based; variants will appear |
| `memory_limit = -1` | Removes the OOM trigger | **Dangerous**: a single request can consume all server memory. Only with strict monitoring, and only briefly. |
| Take PHP read-only / offline (reject non-GET/HEAD with 503, or stop PHP-FPM behind a static maintenance page) | Fully closes the hole | Site is down for writes/logins |

None of these replace the update.

---

## 8. Step 4 — Was I compromised?

Because exploitation forces a fatal error inside a PHP worker, successful **and unsuccessful** attempts leave traces. Look for, since **20 October 2026**:

**Crash evidence (the strongest php2shell-specific signal)**
- `segfault` / `general protection` lines for `php-fpm`, `apache2`, `httpd`, `lsphp` in `dmesg` or `journalctl -k`
- `child <pid> exited on signal 11` in the PHP-FPM log
- Bursts of `PHP Fatal error: Allowed memory size of N bytes exhausted` in error logs without a corresponding deploy
- Spikes of HTTP 500 / 502 / 503 in access logs

**Web log evidence**
- `multipart/form-data` POSTs to pages that never take uploads, especially to `index.php` or random paths
- Requests from scanner user agents (`Go-http-client`, `python-requests`, `curl`, `zgrab`, `nuclei`) followed by 5xx responses
- Subsequent GET/POST requests to new `.php` files under `uploads/`, `cache/`, `tmp/`, or image directories

**File system evidence**
- New `.php` files in upload, cache, or temp directories
- PHP code inside `.ico`, `.png`, `.jpg`, `.txt` or `.svg` files
- Modified `index.php`, `wp-config.php`, `config.php`, `.htaccess`, `.user.ini` (look for `auto_prepend_file`)
- Files owned by the web user outside the web root; executables in `/tmp`, `/var/tmp`, `/dev/shm`
- One-line PHP files larger than 4 KB (packed/obfuscated code)

**Persistence evidence**
- New cron entries, SSH `authorized_keys`, systemd units, `/etc/ld.so.preload`, new SUID binaries
- Unknown admin users or API tokens inside the application
- Processes running from `/tmp` or from deleted binaries; CPU pegged by something that is not your app (miners)

The script in `scripts/php2shell-check.sh` automates every item above, is **read-only**, and writes an evidence folder you can hand to an incident responder.

---

## 9. If you find something

1. **Preserve first, clean second.** Copy the evidence folder and relevant logs off the box before touching anything.
2. **Contain.** Put the site behind a maintenance page or firewall, kill suspicious processes, remove the web shell and the persistence (cron, keys, units).
3. **Assume credentials are burned.** Rotate database passwords, application secrets (`.env`, salts, API keys), admin passwords, and any SSH keys stored on the host.
4. **Patch**, then rebuild from a known-good source if the code base was modified (restore from a backup predating 20 October, or redeploy from git and verify checksums).
5. **Check lateral exposure.** Anything that host could reach with stored credentials (databases, object storage, mail, CI/CD tokens) needs review.
6. **Document** the timeline for your own records and for any disclosure obligations that apply to you.

---

## 10. FAQ

**My site is only reachable on the LAN. Am I safe?** Less exposed, not safe. Anyone on that network, or any SSRF in another app, can reach it. Patch.

**I only use PHP from the command line (cron jobs, scripts).** The attack needs a web-facing worker. CLI-only hosts are not remotely exploitable through this path, but update anyway: it is the same engine bug.

**I disabled `session.upload_progress` years ago. Am I covered?** Only for the best-known trigger of one of the two bugs. Not covered. Patch.

**My distro version string still says 8.3.6 after updating.** Normal for Debian/Ubuntu/RHEL backports. Check the package changelog for the CVE IDs.

**Does a WAF make me safe?** It buys time against the current exploit pattern. It is not a fix.

**I'm on managed hosting and can't choose the patch level.** Your provider does it. Verify via the PHP info page and confirm `session.upload_progress.enabled = Off`. Open a ticket if nothing changes within 48 hours.

---

## 11. References

- PHP Foundation: [Today's PHP security release and how we're strengthening PHP security](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- Sansec: [PHP2Shell: Critical PHP RCE](https://sansec.io/research/php2shell)
- CISA: [Critical vulnerabilities in PHP require immediate patching](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- Qualys: [PHP announces critical security release for two vulnerabilities](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)
- Huntress: [php2shell: leaked critical PHP vulnerabilities](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- Help Net Security: [PHP2Shell: Critical PHP vulnerabilities patched](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/)
- BleepingComputer: [PHP ships emergency patches for critical PHP2Shell flaws](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)
- AlmaLinux: [php2shell patched packages released](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)
- MassiveGrid: [How to patch PHP for CVE-2026-109618/109619 on every platform](https://massivegrid.com/blog/how-to-patch-php-cve-2026-109618-109619-every-platform/)
- Hostinger: [Hostinger deploys protections against php2shell](https://www.hostinger.com/blog/protecting-php2shell/)

*Last updated 2026-10-22. Corrections welcome via pull request.*
