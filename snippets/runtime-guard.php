<?php
/**
 * php2shell runtime guard — framework-agnostic.
 *
 * Reports whether the PHP that is ACTUALLY serving web requests is patched for
 * CVE-2026-109618 / CVE-2026-109619. The web SAPI is the source of truth: the
 * CLI can be a different binary with a different php.ini.
 *
 * Use it from a health-check route, a monitoring endpoint, or an admin page:
 *
 *   require __DIR__ . '/runtime-guard.php';
 *   $s = php2shell_status();
 *   if (!$s['patched']) { error_log('php2shell: ' . $s['reason']); }
 *
 * Laravel:  Route::get('/health/php2shell', fn () => response()->json(php2shell_status()))->middleware('auth');
 * Symfony:  return new JsonResponse(php2shell_status());   // behind a firewall rule
 *
 * Do not expose the full array publicly: it reveals your PHP version. For an
 * unauthenticated uptime check return only true/false.
 *
 * Limitation: distro packages (Debian, Ubuntu, RHEL...) may carry the fix
 * while keeping an older version number. In that case 'patched' is false but
 * 'distro_build' is true: confirm with the package changelog (guides/DISTROS.md).
 */

declare(strict_types=1);

if (!function_exists('php2shell_status')) {
    /**
     * @return array{patched: bool, version: string, branch: string, required: ?string,
     *               supported_branch: bool, distro_build: bool, sapi: string,
     *               upload_progress: bool, reason: string}
     */
    function php2shell_status(): array
    {
        $fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
        $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $required = $fixed[$branch] ?? null;
        $supported = version_compare($branch, '8.2', '>=');
        // Distro packages live in /usr/bin or /usr/sbin and/or carry an extra
        // version suffix; upstream builds (Docker official, CloudLinux alt-php,
        // source builds) live in /usr/local or /opt and use upstream numbering.
        $distro = PHP_EXTRA_VERSION !== ''
            || (PHP_BINARY !== '' && preg_match('#^/usr/s?bin/#', PHP_BINARY) === 1);
        $uploadProgress = filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOLEAN);

        if (!$supported) {
            $patched = false;
            $reason = 'PHP ' . PHP_VERSION . ' is an unsupported branch with no official fix; migrate to 8.3 or 8.4';
        } elseif ($required === null) {
            $patched = true;
            $reason = 'branch ' . $branch . ' is newer than the affected ones';
        } elseif (version_compare(PHP_VERSION, $required, '>=')) {
            $patched = true;
            $reason = 'PHP ' . PHP_VERSION . ' is patched';
        } else {
            $patched = false;
            $reason = 'PHP ' . PHP_VERSION . ' < ' . $required
                . ($distro ? ' (distro build: verify backport in the package changelog)' : '');
        }
        if (!$patched && $uploadProgress) {
            $reason .= '; session.upload_progress.enabled is ON (interim mitigation missing)';
        }

        return [
            'patched'          => $patched,
            'version'          => PHP_VERSION,
            'branch'           => $branch,
            'required'         => $required,
            'supported_branch' => $supported,
            'distro_build'     => $distro,
            'sapi'             => PHP_SAPI,
            'upload_progress'  => $uploadProgress,
            'reason'           => $reason,
        ];
    }
}
