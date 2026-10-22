<?php
/**
 * Plugin Name:  php2shell Site Health check
 * Description:  Adds a test to Tools → Site Health that flags PHP builds vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619).
 * Version:      1.0.0
 * Requires PHP: 7.0
 * License:      MIT
 *
 * Install as a must-use plugin: copy this file to wp-content/mu-plugins/.
 * It only reads PHP_VERSION and one ini value; it stores nothing and makes no
 * network requests.
 */

if (!defined('ABSPATH')) {
    exit;
}

add_filter('site_status_tests', function ($tests) {
    $tests['direct']['php2shell'] = array(
        'label' => 'php2shell (CVE-2026-109618 / CVE-2026-109619)',
        'test'  => 'php2shell_site_health_test',
    );
    return $tests;
});

function php2shell_site_health_test()
{
    $fixed    = array('8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12');
    $branch   = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $required = isset($fixed[$branch]) ? $fixed[$branch] : null;
    $upload   = filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOLEAN);

    $result = array(
        'label'       => 'PHP is patched for php2shell',
        'status'      => 'good',
        'badge'       => array('label' => 'Security', 'color' => 'blue'),
        'description' => '<p>' . sprintf('This site runs PHP %s.', esc_html(PHP_VERSION)) . '</p>',
        'actions'     => '',
        'test'        => 'php2shell',
    );

    if (version_compare($branch, '8.2', '<')) {
        $result['label']        = 'PHP branch has no fix for php2shell';
        $result['status']       = 'critical';
        $result['badge']['color'] = 'red';
        $result['description'] .= '<p>PHP ' . esc_html($branch) . ' will not receive a fix for CVE-2026-109618 / CVE-2026-109619, which allow unauthenticated remote code execution. Switch to PHP 8.3 or 8.4 in your hosting panel after checking theme and plugin compatibility.</p>';
    } elseif ($required !== null && version_compare(PHP_VERSION, $required, '<')) {
        $result['label']        = 'PHP may be vulnerable to php2shell';
        $result['status']       = 'critical';
        $result['badge']['color'] = 'red';
        $result['description'] .= '<p>The fixed release for this branch is PHP ' . esc_html($required) . '. Update PHP, or ask your host to confirm the fix. Some Linux distributions backport the fix without changing the version number; in that case your host can confirm it from the package changelog.</p>';
        if ($upload) {
            $result['description'] .= '<p><code>session.upload_progress.enabled</code> is <strong>On</strong>. Until PHP is updated, ask your host to turn it Off; it is the best-known trigger path.</p>';
        }
    }

    return $result;
}
