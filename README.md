# php2shell response kit

Practical material for **CVE-2026-109618 / CVE-2026-109619** ("php2shell"), the two critical PHP engine bugs patched on 21 October 2026 that give unauthenticated remote code execution on web-facing PHP before any application code runs.

**Fixed versions: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35.** Branches 8.1 and older receive no official fix.

Pick your entry point:

- **"Am I at risk and what do I do?"** → [self-assessment form](docs/index.html) or [CHECKLIST.md](CHECKLIST.md)
- **"I run servers"** → [GUIDE.md](GUIDE.md) and [`scripts/php2shell-check.sh`](scripts/php2shell-check.sh); many servers → [`fleet/`](fleet/README.md)
- **"I write the code / own the pipeline"** → [DEVELOPERS.md](DEVELOPERS.md)
- **"I'm stuck on PHP 8.1 or older"** → [guides/MIGRATION.md](guides/MIGRATION.md)
- **"I work with an AI assistant"** → [ai/CONTEXT.md](ai/CONTEXT.md) and [ai/PROMPTS.md](ai/PROMPTS.md)

### Everything in the kit

**For everyone**

| | What it is | Who it is for |
|---|---|---|
| [**GUIDE.md**](GUIDE.md) | The full explanation: what the bugs are, why updating is the only real fix, timeline, how to find your version, how to patch on every platform, interim mitigations and their limits, indicators of compromise, what to do if you find something, FAQ, references. | Anyone who owns or administers a PHP site |
| [**docs/index.html**](docs/index.html) | Self-assessment form: eight questions, one prioritised action plan. Runs entirely in the browser, no data leaves the page. Open the file locally or publish it with GitHub Pages. | People who want to know "what should *I* do?" in two minutes |
| [**CHECKLIST.md**](CHECKLIST.md) | The same decision flow as a printable checklist. | Teams, tickets, change requests |
| [**guides/DISTROS.md**](guides/DISTROS.md) | How to tell whether your distribution's PHP package carries the backported fix, per distro. | Anyone on distro packages |

**For server admins**

| | What it is | Who it is for |
|---|---|---|
| [**scripts/php2shell-check.sh**](scripts/php2shell-check.sh) | Read-only Linux triage script. Finds vulnerable PHP binaries and containers, risky ini settings, worker segfaults and OOM bursts, web log anomalies, web shells, odd files and persistence. Writes a report, an evidence folder and an AI hand-off. | Sysadmins, DevOps, incident responders |
| [**fleet/**](fleet/README.md) | Run the triage on many servers over plain SSH or Ansible and collect a summary. | Teams with more than a couple of servers |
| [**scripts/php-exposure-inventory.sh**](scripts/php-exposure-inventory.sh) | One GET per site to list which of *your* domains advertise a vulnerable PHP version. | Agencies and freelancers with many sites |
| [**snippets/**](snippets/README.md) | Interim mitigations: php.ini, PHP-FPM pool, nginx, Apache/LiteSpeed, Cloudflare. | Anyone who can't patch this hour |

**For developers**

| | What it is | Who it is for |
|---|---|---|
| [**DEVELOPERS.md**](DEVELOPERS.md) | Entry point: the 15-minute checklist for repositories, images and pipelines. | Developers, tech leads |
| [**scripts/php-pin-scan.sh**](scripts/php-pin-scan.sh) + [**action.yml**](action.yml) | Repository scanner and GitHub Action: fails when Dockerfiles, compose, composer, CI or PaaS configs pin a vulnerable or unsupported PHP. | CI/CD owners |
| [**guides/MIGRATION.md**](guides/MIGRATION.md) | Getting off PHP 8.1 or older: tools (composer why-not, PHPCompatibility, PHPStan, Rector), what breaks per branch, framework minimums, rollout. | Teams stuck on unsupported PHP |
| [**examples/**](examples/) | GitHub and GitLab CI jobs, Renovate and Dependabot configs that turn the next PHP release into a pull request. | Same |
| [**snippets/runtime-guard.php**](snippets/runtime-guard.php), [**docker-build-guard**](snippets/docker-build-guard.Dockerfile), [**WordPress Site Health check**](snippets/wordpress/php2shell-site-health.php) | Fail the build, flag the health check, or show a red Site Health item when PHP is vulnerable. | Same |

**For AI-assisted work**

| | What it is | Who it is for |
|---|---|---|
| [**ai/CONTEXT.md**](ai/CONTEXT.md) | Context file for AI agents: verified facts, decision rules, commands, how to read the script output, known false positives, and mandatory safety rules. Attach it to any AI conversation about php2shell. | People working with Claude, ChatGPT, Copilot, Cursor, Gemini… |
| [**ai/PROMPTS.md**](ai/PROMPTS.md) | Ready-to-paste prompts: agent with shell access (step-by-step with approval gates), chat-only analysis of the script report, follow-up from the form, management summary, multi-server roll-up. | Same |
| [**AGENTS.md**](AGENTS.md) | Picked up automatically by coding agents that open this repository; points them to the context file and the rules. | Coding agents |

**Sharing**

| | What it is | Who it is for |
|---|---|---|
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

**5. Want an AI to help read the results?** The script also writes `ai-handoff.md`: an analyst prompt with the report and key evidence embedded. Paste it into your assistant together with [`ai/CONTEXT.md`](ai/CONTEXT.md). Run with `-R` to redact hostname, IPs, usernames, emails and key fingerprints first. The self-assessment form has a matching **Copy prompt for an AI assistant** button.

The script is read-only: it never modifies, deletes, uploads or "cleans" anything.

## Notes on the check script

- Requires bash, coreutils, grep, find, awk. Run as root for full coverage (`journalctl`, `/proc`, other users' crontabs).
- Works on Debian/Ubuntu, RHEL/Alma/Rocky, cPanel, Plesk, CloudLinux, LiteSpeed, and detects Docker containers on the host. Inside a container, run it with `-w /var/www/html` and ignore the host-level sections.
- Web shell signatures describe *behaviour* (user input fed to code execution, decode-then-execute chains, obfuscation), not malware families, and are assembled from fragments so that antivirus engines do not quarantine the scanner itself. Scores of 1–2 are normally legitimate libraries (PDF generators, mailers, template engines). Scores of 6 or more deserve a look every time.
- `-R` redacts hostname, IPv4/IPv6 addresses, `/home/<user>` paths, e-mail addresses and SSH key fingerprints in `ai-handoff.md` (not in `report.txt`, which stays complete for you).
- A clean result lowers the probability of compromise; it does not prove it. The script cannot inspect worker memory or logs your provider does not expose.

## Use it in your pipeline

```yaml
# .github/workflows/php2shell.yml
on: [pull_request, push]
jobs:
  pin-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWNER/php2shell-response-kit@main   # pin to a commit SHA
```

Full example with scheduling and a build guard: [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Contributing

Corrections and platform-specific additions are welcome as pull requests. Please keep every script read-only and dependency-free, and run the test suite before opening a PR:

```bash
bash tests/run.sh
shellcheck -S warning scripts/*.sh fleet/*.sh tests/run.sh
```

## License

MIT. See [LICENSE](LICENSE).
