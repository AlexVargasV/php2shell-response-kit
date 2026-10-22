# php2shell response kit

Practical material for **CVE-2026-109618 / CVE-2026-109619** ("php2shell"), the two critical PHP engine bugs patched on 21 October 2026 that give unauthenticated remote code execution on web-facing PHP before any application code runs.

**Fixed versions: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35.** Branches 8.1 and older receive no official fix.

| | What it is | Who it is for |
|---|---|---|
| [**GUIDE.md**](GUIDE.md) | The full explanation: what the bugs are, why updating is the only real fix, timeline, how to find your version, how to patch on every platform, interim mitigations and their limits, indicators of compromise, what to do if you find something, FAQ, references. | Anyone who owns or administers a PHP site |
| [**docs/index.html**](docs/index.html) | Self-assessment form: eight questions, one prioritised action plan. Runs entirely in the browser, no data leaves the page. Open the file locally or publish it with GitHub Pages. | People who want to know "what should *I* do?" in two minutes |
| [**CHECKLIST.md**](CHECKLIST.md) | The same decision flow as a printable checklist. | Teams, tickets, change requests |
| [**scripts/php2shell-check.sh**](scripts/php2shell-check.sh) | Read-only Linux triage script. Finds vulnerable PHP binaries and containers, risky ini settings, worker segfaults and OOM bursts, web log anomalies, web shells, odd files and persistence. Writes a report and an evidence folder. | Sysadmins, DevOps, incident responders |
| [**LINKEDIN-POST.md**](LINKEDIN-POST.md) | Ready-to-paste announcement text (English and Spanish). | Spreading the word |

## Quick start

**1. Am I vulnerable?** Check the version that serves web requests (phpinfo, control panel, or `docker exec <c> php -v`), not only `php -v` in a shell. Anything below the fixed versions, or on 8.1/older, is vulnerable.

**2. Patch and restart workers.** See [GUIDE.md § 6](GUIDE.md#6-step-2--patch-per-platform). A patched binary does nothing while old `php-fpm` / `apache2` / `lsphp` workers keep running.

**3. Can't patch right now?** `session.upload_progress.enabled = Off` in php.ini / the FPM pool, restart workers, WAF rules on. Partial mitigation only. See [GUIDE.md § 7](GUIDE.md#7-step-3--if-you-cannot-patch-right-now-mitigations-and-their-limits).

**4. Was I hit?** On each Linux host:

```bash
curl -fsSLO https://raw.githubusercontent.com/OWNER/php2shell-response-kit/main/scripts/php2shell-check.sh
sudo bash php2shell-check.sh                 # auto-detects web roots
sudo bash php2shell-check.sh -w /var/www/site -d 30   # explicit web root, 30-day window
```

Read `~/php2shell-triage-<date>/report.txt`. Any **CRITICAL** item means act now; the evidence folder next to it is what you hand to whoever helps you.

The script is read-only: it never modifies, deletes, uploads or "cleans" anything.

## Notes on the check script

- Requires bash, coreutils, grep, find, awk. Run as root for full coverage (`journalctl`, `/proc`, other users' crontabs).
- Works on Debian/Ubuntu, RHEL/Alma/Rocky, cPanel, Plesk, CloudLinux, LiteSpeed, and detects Docker containers on the host. Inside a container, run it with `-w /var/www/html` and ignore the host-level sections.
- Web shell signatures describe *behaviour* (user input fed to code execution, decode-then-execute chains, obfuscation), not malware families, and are assembled from fragments so that antivirus engines do not quarantine the scanner itself. Scores of 1–2 are normally legitimate libraries (PDF generators, mailers, template engines). Scores of 6 or more deserve a look every time.
- A clean result lowers the probability of compromise; it does not prove it. The script cannot inspect worker memory or logs your provider does not expose.

## Contributing

Corrections and platform-specific additions are welcome as pull requests. Please keep the script read-only and dependency-free.

## License

MIT. See [LICENSE](LICENSE).
