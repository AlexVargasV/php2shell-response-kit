# Is my distribution's PHP package fixed?

Linux distributions usually **backport** security fixes into the PHP version they shipped instead of moving to the upstream release. Ubuntu 24.04, for example, keeps reporting `8.3.6` after the fix. So for distro packages:

- the upstream version number (8.3.36 etc.) is **not** the test;
- the test is the package **changelog / advisory** naming CVE-2026-109618 and CVE-2026-109619;
- after updating, **restart** PHP-FPM / Apache, or the old code keeps running.

This page deliberately lists **where and how to check**, not package version numbers: those differ per release and per day, and a wrong number in a table like this would make someone believe they are safe. Always read the vendor's own advisory.

| Distribution | Official advisory page | Check on the host |
|---|---|---|
| Ubuntu | `https://ubuntu.com/security/CVE-2026-109618` (and `…109619`) | `pro fix CVE-2026-109618` · `apt changelog php8.3-cli \| grep -E 'CVE-2026-10961[89]'` |
| Debian | `https://security-tracker.debian.org/tracker/CVE-2026-109618` | `apt changelog php8.2-cli \| grep -E 'CVE-2026-10961[89]'` |
| RHEL | `https://access.redhat.com/security/cve/CVE-2026-109618` | `dnf updateinfo list --cve CVE-2026-109618` · `rpm -q --changelog php-cli \| grep -E 'CVE-2026-10961[89]'` |
| AlmaLinux / Rocky | AlmaLinux published a php2shell advisory on 2026-10-21; Rocky errata at `https://errata.rockylinux.org/` | `dnf updateinfo list --cve CVE-2026-109618` |
| SUSE / openSUSE | `https://www.suse.com/security/cve/CVE-2026-109618/` | `zypper list-patches --cve=CVE-2026-109618` |
| Alpine | `https://security.alpinelinux.org/vuln/CVE-2026-109618` | `apk version -v php83` (package names `php82`, `php83`, `php84`…) |
| Amazon Linux | `https://alas.aws.amazon.com/` | `dnf updateinfo list --cve CVE-2026-109618` |
| CloudLinux `alt-php` / cPanel `ea-php` | CloudLinux / cPanel release notes (first patched alt-php packages 2026-10-21 19:00 UTC) | `yum update 'alt-php*' 'ea-php*'` then compare with upstream numbers (they follow upstream) |
| Ondřej Surý PPA / packages.sury.org | Uses **upstream** numbering | Expect 8.x.y ≥ the fixed versions |
| Remi (RHEL family) | Uses **upstream** numbering | Expect 8.x.y ≥ the fixed versions |
| Docker official `php` images | Uses **upstream** numbering | Tags `8.5.12`, `8.4.27`, `8.3.36`, `8.2.35` and later |

## Unsupported branches inside a supported distro

Some long-term distro releases ship a PHP branch that php.net no longer supports (Ubuntu 22.04 ships 8.1, for example). The distro may still backport the fix for its own package during its support period. If the advisory lists your release as fixed, you are covered **for this CVE**, but you are on a branch the wider ecosystem is leaving; plan the move in [MIGRATION.md](MIGRATION.md).

If the advisory says *needs triage*, *deferred*, *ignored* or *end of life* for your release, treat the host as vulnerable.

## After updating

```bash
# confirm the package, then restart the service that actually runs PHP
systemctl restart 'php*-fpm' 2>/dev/null; systemctl restart apache2 httpd 2>/dev/null
# confirm the restart happened after the package install
ps -o lstart= -p "$(pgrep -o php-fpm || pgrep -o apache2 || pgrep -o httpd)"
```

Then verify through the web SAPI ([`runtime-guard.php`](../snippets/runtime-guard.php) reports `distro_build: true` for these builds, so read its `reason` together with the changelog).
