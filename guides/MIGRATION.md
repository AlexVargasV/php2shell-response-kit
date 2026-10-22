# Getting off PHP 8.1 (or older) because of php2shell

PHP 8.1, 8.0, 7.x and older will **never** get an official fix for CVE-2026-109618 / CVE-2026-109619. If your application runs on one of them, the remediation is a branch upgrade. This guide is the shortest safe path.

## 1. Pick the target branch

| Branch | Security support ends | Recommendation |
|---|---|---|
| 8.1 | 2025-12-31 (already ended) | Leave now |
| 8.2 | 2026-12-31 | Only as a stepping stone: it expires in weeks |
| 8.3 | 2027-12-31 | Good target when a dependency is not 8.4-ready |
| **8.4** | 2028-12-31 | **Default target** for most applications |
| 8.5 | 2029-12-31 | Fine if your whole stack already supports it |

Moving from 8.1 straight to 8.3 or 8.4 is normal. You do not need to deploy 8.2 in between; you only need to fix what each step deprecates or removes (section 4).

## 2. Find out what blocks you (30 minutes)

Run these from the project root. None of them change code.

**Which dependencies refuse the target version?**

```bash
composer why-not php 8.4.0        # alias: composer prohibits php 8.4.0
```

Every package listed needs an upgrade (or a replacement) before you can switch.

**Static compatibility check (PHPCompatibility for PHP_CodeSniffer).** The last stable release (9.3.5, 2019) predates PHP 8, so use the 10.x line, which is still marked development:

```bash
composer require --dev "phpcompatibility/php-compatibility:^10.0.0@dev" dealerdirect/phpcodesniffer-composer-installer
vendor/bin/phpcs -p --standard=PHPCompatibility --runtime-set testVersion 8.4- \
  --extensions=php --ignore=vendor/,node_modules/ .
```

`8.4-` means "8.4 and above". For WordPress plugins/themes use `--standard=PHPCompatibilityWP` (package `phpcompatibility/phpcompatibility-wp`).

**Static analysis against the target version (PHPStan):**

```neon
# phpstan.neon
parameters:
    phpVersion: 80400
    level: 5
    paths: [src]
```

**Lint and test under the real target, without installing anything on your machine:**

```bash
docker run --rm -v "$PWD":/app -w /app php:8.4-cli \
  sh -c 'find . -path ./vendor -prune -o -name "*.php" -print0 | xargs -0 -n1 -P4 php -l | grep -v "No syntax errors"'
docker run --rm -v "$PWD":/app -w /app php:8.4-cli vendor/bin/phpunit
```

## 3. Let tools do the mechanical part (Rector)

```bash
composer require --dev rector/rector
```

```php
<?php
// rector.php
use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([__DIR__ . '/src', __DIR__ . '/tests'])
    ->withPhpSets(php84: true);    // or php83: true
```

```bash
vendor/bin/rector process --dry-run   # review the diff
vendor/bin/rector process
```

Rector fixes things like implicitly nullable parameters, `${}` interpolation and dynamic property declarations. Review every change; run the test suite afterwards.

## 4. What usually breaks, branch by branch

The official lists are the reference: [8.2](https://www.php.net/manual/en/migration82.php) · [8.3](https://www.php.net/manual/en/migration83.php) · [8.4](https://www.php.net/manual/en/migration84.php) · [8.5](https://www.php.net/manual/en/migration85.php). The items below are the ones that show up most in real code bases.

**8.1 → 8.2**
- Dynamic properties are deprecated. Declare the property, or add `#[\AllowDynamicProperties]` to the class as a stop-gap.
- `"${var}"` and `"${expr}"` string interpolation is deprecated. Use `"{$var}"`.
- `utf8_encode()` / `utf8_decode()` are deprecated. Use `mb_convert_encoding()`.
- Partially supported callables such as `"self::method"` or `[$this, 'parent::method']` are deprecated.
- `strtolower()` / `strtoupper()` are no longer locale-sensitive.

**8.2 → 8.3**
- `get_class()` and `get_parent_class()` without arguments are deprecated.
- Incrementing or decrementing non-numeric strings and `null` now raises deprecations in more cases.
- `assert_options()` is deprecated.

**8.3 → 8.4**
- Implicitly nullable parameters are deprecated: `function f(Foo $x = null)` must become `function f(?Foo $x = null)`. This is the most frequent warning in older code bases and libraries; Rector fixes it.
- `E_STRICT` is deprecated (the level no longer exists); `trigger_error()` with `E_USER_ERROR` is deprecated.
- IMAP, OCI8, PDO_OCI and pspell are no longer bundled; install them from PECL if you use them.
- `mysqli_ping()`, `mysqli_kill()` and `mysqli_refresh()` are deprecated.
- The default bcrypt cost of `password_hash()` rose from 10 to 12 (stronger, slightly slower logins).

Deprecations do not break production by themselves; they become errors in PHP 9. Log them (`error_reporting = E_ALL`, `log_errors = On`) in staging and fix them before they pile up.

## 5. Framework and CMS minimums

Always confirm on the project's own requirements page; versions move.

| Platform | Notes |
|---|---|
| Moodle | 4.5: PHP 8.1–8.3 · 5.1: PHP 8.2–8.4 · 5.2: PHP 8.3–8.4 ([docs](https://docs.moodle.org/en/PHP)) |
| WordPress | Core runs on 8.3/8.4; wordpress.org recommends 8.3 or newer. Themes and plugins are the usual blockers: scan them with PHPCompatibilityWP and update before switching |
| Laravel | 11 and 12 require PHP 8.2+; upgrading from 9/10 is a framework upgrade too |
| Symfony | 6.4 LTS runs on 8.1+ (works on 8.3/8.4); 7.x requires 8.2+ |
| Drupal | 11 requires PHP 8.3+ |
| Magento / Adobe Commerce | Check the system requirements page of your exact 2.4.x patch |

## 6. Roll it out

1. **Branch + container:** change the base image (or the server's PHP) only in a branch: `FROM php:8.4.27-fpm-bookworm`.
2. **CI:** run the test suite on the target; add [`php-pin-scan`](../scripts/php-pin-scan.sh) so nobody re-pins an old version.
3. **Staging with production data:** log deprecations, click through logins, uploads, payments, cron jobs, mail.
4. **Deploy** with the previous image tagged for instant rollback. Restart all PHP workers.
5. **Verify through the web SAPI:** phpinfo, [`runtime-guard.php`](../snippets/runtime-guard.php), or the WordPress [Site Health check](../snippets/wordpress/php2shell-site-health.php).
6. **Raise `config.platform.php`** in `composer.json` to the new runtime, if you use it.

On managed hosting, step 1 is a dropdown in the control panel (for example *Advanced → PHP Configuration*). Take a backup first; most panels let you switch back in a minute.

## 7. If you really cannot migrate this week

- Use a vendor that backports security fixes to old branches: your OS vendor for the PHP it shipped (see [DISTROS.md](DISTROS.md)), CloudLinux `alt-php`, or a commercial extended-support offering for PHP.
- Apply every interim measure in [`snippets/`](../snippets/README.md) and put a WAF in front.
- Treat the migration as an open incident with an owner and a date, not as backlog.
