# =============================================================================
#  Build-time guard: make `docker build` FAIL if the base image ships a PHP
#  that is vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619).
#
#  Copy the RUN line into your own Dockerfile right after FROM. It works with
#  any image that has the php CLI. For distro packages that carry backports
#  without changing the version (Debian/Ubuntu/RHEL), use the scanner and the
#  distro advisory instead (guides/DISTROS.md).
# =============================================================================

# Prefer an explicit patched tag so bots (Renovate / Dependabot) can bump it:
FROM php:8.3.36-fpm-bookworm

RUN php -r '$fixed=["8.2"=>"8.2.35","8.3"=>"8.3.36","8.4"=>"8.4.27","8.5"=>"8.5.12"]; \
  $b=PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION; \
  if (version_compare($b,"8.2","<")) { fwrite(STDERR,"php2shell: PHP ".PHP_VERSION." is an unsupported branch with no fix\n"); exit(1); } \
  if (isset($fixed[$b]) && version_compare(PHP_VERSION,$fixed[$b],"<")) { fwrite(STDERR,"php2shell: PHP ".PHP_VERSION." is vulnerable, need >= ".$fixed[$b]."\n"); exit(1); } \
  echo "php2shell: PHP ".PHP_VERSION." OK\n";'

# Interim hardening shipped with the image (see snippets/php-ini-mitigation.ini)
COPY snippets/php-ini-mitigation.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
