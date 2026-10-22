# php2shell for developers

Patching servers closes today's hole. These steps make sure your **repositories, images and pipelines** do not reopen it, and that the next PHP security release reaches production by itself.

## The 15-minute version

1. **Scan your repositories** for vulnerable PHP pins (Dockerfiles, compose, composer, CI, PaaS configs):
   ```bash
   bash scripts/php-pin-scan.sh /path/to/your/repo
   ```
2. **Add the GitHub Action** so pull requests that pin a vulnerable PHP fail: copy [`examples/github-workflow.yml`](examples/github-workflow.yml) to `.github/workflows/php2shell.yml`. GitLab: [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml).
3. **Pin an explicit patched tag** in Dockerfiles (`php:8.3.36-fpm-bookworm`, not `php:8.3-fpm`) and add the [build guard](snippets/docker-build-guard.Dockerfile) so `docker build` fails on a vulnerable base.
4. **Turn on Renovate or Dependabot** for base images ([`examples/renovate.json`](examples/renovate.json), [`examples/dependabot.yml`](examples/dependabot.yml)) so the next PHP release arrives as a pull request.
5. **Still on 8.1 or older?** Follow [`guides/MIGRATION.md`](guides/MIGRATION.md). There is no other fix.

## Tools in this kit

| Tool | What it answers | Where |
|---|---|---|
| `php-pin-scan.sh` | Does this repository pin a vulnerable / unsupported PHP? | [`scripts/php-pin-scan.sh`](scripts/php-pin-scan.sh) |
| GitHub Action | Same, on every pull request, with annotations and a job summary | [`action.yml`](action.yml) |
| Build guard | Does the image I just built ship a patched PHP? | [`snippets/docker-build-guard.Dockerfile`](snippets/docker-build-guard.Dockerfile) |
| Runtime guard | Is the PHP serving my web requests patched? (health checks, monitoring) | [`snippets/runtime-guard.php`](snippets/runtime-guard.php) |
| WordPress Site Health test | Same, inside **Tools → Site Health** | [`snippets/wordpress/`](snippets/wordpress/php2shell-site-health.php) |
| Exposure inventory | Which of my sites advertise a vulnerable PHP version? | [`scripts/php-exposure-inventory.sh`](scripts/php-exposure-inventory.sh) |
| Server triage | Is this host exposed, attacked, backdoored? | [`scripts/php2shell-check.sh`](scripts/php2shell-check.sh) |
| Fleet runner | Run the triage on N servers and collect the reports | [`fleet/`](fleet/README.md) |
| Interim mitigations | nginx / Apache / Cloudflare / FPM / php.ini | [`snippets/`](snippets/README.md) |

## `php-pin-scan.sh` in detail

```text
php-pin-scan.sh [-f text|github|json] [-s] [-x REGEX] [DIR]
  -f  text (default), github (annotations + job summary), json
  -s  strict: warnings count as failures
  -x  extra path regex to exclude
exit 0 = clean, 1 = failures, 2 = usage error
```

What it reads and how it judges each pin:

| Source | Example | Judged as |
|---|---|---|
| Dockerfile `FROM`, compose / k8s `image:` | `php:8.3.35-fpm`, `wordpress:6.8-php8.1-fpm` | Runtime: exact vulnerable → **FAIL**, ≤ 8.1 → **FAIL**, floating `8.3-fpm` → WARN, patched → OK |
| Dockerfile `ARG/ENV PHP_VERSION=` | `ARG PHP_VERSION=8.2.30` | Runtime |
| Distro packages in Dockerfiles | `php8.1-fpm`, `apk add php83`, `module enable php:remi-8.1` | Distro: depends on backports → WARN / INFO |
| App images without PHP in the tag | `drupal:11`, `wordpress:latest` | WARN: verify inside the image |
| `composer.json` `require.php` | `~8.1.0 \|\| ^7.4` | FAIL if no supported branch is admitted |
| `composer.json` `config.platform.php` | `8.1.2` | WARN / INFO (affects dependency resolution only) |
| `.php-version`, `.tool-versions`, DDEV, Lando | `8.1` | Local env: WARN |
| CI (`.github/workflows`, `.gitlab-ci.yml`, CircleCI…) | `php-version: ['8.1','8.3']` | Old branches → INFO (fine for libraries), exact vulnerable → WARN |
| Laravel Sail | `sail/runtimes/8.1` | Runtime |
| App Engine / Platform.sh / Upsun / Vapor / Bref | `runtime: php83` | Provider-managed: WARN, confirm rollout |

Known blind spots: Helm values split into `repository:` + `tag:`, versions computed in shell scripts, images built from private bases that hide PHP behind a custom name. Pair the scanner with the build guard to cover them.

## Health checks

```php
require __DIR__ . '/runtime-guard.php';
$s = php2shell_status();      // patched, version, branch, required, distro_build, sapi, upload_progress, reason
```

Wire it into your monitoring behind authentication, or expose only a boolean. Distro builds report `distro_build: true` and may show `patched: false` while carrying a backport; confirm with [`guides/DISTROS.md`](guides/DISTROS.md).

## Hardening that outlives this CVE

- `expose_php = Off` everywhere: stop advertising your version.
- Recycle PHP-FPM workers (`pm.max_requests`) and keep request bodies small.
- Rebuild images on a schedule even without code changes, so base-image fixes ship.
- Keep the PHP branch inside its support window; put the end date in your roadmap (8.2 ends 2026-12-31).
- Subscribe to `php-announce` and your OS vendor's security list.
