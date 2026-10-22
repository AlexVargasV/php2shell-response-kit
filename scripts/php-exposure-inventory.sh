#!/usr/bin/env bash
# =============================================================================
#  php-exposure-inventory.sh — triage a list of YOUR OWN sites for php2shell
#  (CVE-2026-109618 / CVE-2026-109619) from the outside.
#
#  For each domain it makes ONE ordinary GET request to the home page and
#  records what the server discloses: HTTP status, Server, X-Powered-By (PHP
#  version when expose_php is On), PHP session cookie, CMS hints. It then
#  classifies the disclosed PHP version. It sends no payloads and does not
#  attempt to trigger the vulnerability.
#
#  ONLY USE IT ON DOMAINS YOU OWN OR ADMINISTER.
#
#  Usage:  php-exposure-inventory.sh -i domains.txt [-o results.csv] [-t SECONDS] [-d DELAY]
#     -i  file with one domain or URL per line (# comments allowed)
#     -o  CSV output (default: php2shell-inventory-<date>.csv)
#     -t  timeout per request in seconds (default 15)
#     -d  delay between domains in seconds (default 1)
#
#  Limits: most well-configured servers hide the PHP version (expose_php Off),
#  CDNs strip headers, and distro builds keep old version strings while
#  carrying backported fixes. "unknown" means "go check phpinfo / the panel",
#  not "safe". Treat this as a prioritisation list, not a verdict.
# =============================================================================
set -u
LC_ALL=C; export LC_ALL

FIXED_85="8.5.12"; FIXED_84="8.4.27"; FIXED_83="8.3.36"; FIXED_82="8.2.35"
IN=""; OUTF="php2shell-inventory-$(date +%F).csv"; TMO=15; DELAY=1
usage() { sed -n '2,26p' "$0" | sed -E 's/^# ?//'; exit 2; }
while getopts "i:o:t:d:h" o; do
  case $o in
    i) IN="$OPTARG" ;; o) OUTF="$OPTARG" ;; t) TMO="$OPTARG" ;; d) DELAY="$OPTARG" ;; *) usage ;;
  esac
done
[ -n "$IN" ] && [ -r "$IN" ] || usage
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

UA="php2shell-inventory/1.0 (site owner self-check)"
vge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

verdict() { # verdict VERSION -> echo STATUS|NOTE
  local v="$1" mj mn br fx
  [ -z "$v" ] && { echo "UNKNOWN|version hidden: check phpinfo or the hosting panel"; return; }
  mj="${v%%.*}"; mn="$(printf '%s' "$v" | cut -d. -f2)"; br="$mj.$mn"
  if [ "$mj" -lt 8 ] || { [ "$mj" -eq 8 ] && [ "$mn" -le 1 ]; }; then
    echo "UNSUPPORTED|PHP $br has no official fix (a vendor backport may exist)"; return
  fi
  case "$br" in 8.5) fx=$FIXED_85 ;; 8.4) fx=$FIXED_84 ;; 8.3) fx=$FIXED_83 ;; 8.2) fx=$FIXED_82 ;; *) echo "PATCHED|branch newer than affected ones"; return ;; esac
  if vge "$v" "$fx"; then echo "PATCHED|>= $fx"
  else echo "VULNERABLE?|$v < $fx (distro builds may carry a backport: verify on the server)"; fi
}

csv() { local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

echo "domain,url,http_status,server,x_powered_by,php_version,status,note,php_session_cookie,cms_hint,checked_at" > "$OUTF"
printf '%-32s %-6s %-12s %-14s %s\n' "DOMAIN" "HTTP" "PHP" "STATUS" "NOTE"
printf '%-32s %-6s %-12s %-14s %s\n' "------" "----" "---" "------" "----"

NV=0; NU=0; NP=0; NK=0
while IFS= read -r line || [ -n "$line" ]; do
  d="$(printf '%s' "$line" | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
  [ -z "$d" ] && continue
  case "$d" in http://*|https://*) url="$d" ;; *) url="https://$d/" ;; esac
  host="$(printf '%s' "$url" | sed -E 's#^https?://##; s#/.*$##')"

  hdr="$(curl -sS -o /dev/null -D - -L --max-redirs 5 --max-time "$TMO" -A "$UA" "$url" 2>/dev/null | tr -d '\r')"
  if [ -z "$hdr" ] && [ "${url#https://}" != "$url" ]; then
    url="http://${url#https://}"
    hdr="$(curl -sS -o /dev/null -D - -L --max-redirs 5 --max-time "$TMO" -A "$UA" "$url" 2>/dev/null | tr -d '\r')"
  fi
  if [ -z "$hdr" ]; then
    printf '%-32s %-6s %-12s %-14s %s\n' "$host" "-" "-" "UNREACHABLE" "no response"
    printf '%s,%s,,,,,UNREACHABLE,no response,,,%s\n' "$(csv "$host")" "$(csv "$url")" "$(date -u +%FT%TZ)" >> "$OUTF"
    sleep "$DELAY"; continue
  fi
  # keep only the last response of the redirect chain
  last="$(printf '%s\n' "$hdr" | awk 'BEGIN{RS=""} {b=$0} END{print b}')"
  status="$(printf '%s\n' "$last" | awk 'NR==1{print $2}')"
  server="$(printf '%s\n' "$last" | grep -i '^server:' | head -1 | cut -d: -f2- | sed -E 's/^[[:space:]]+//')"
  xpb="$(printf '%s\n' "$hdr" | grep -i '^x-powered-by:' | grep -i 'php' | tail -1 | cut -d: -f2- | sed -E 's/^[[:space:]]+//')"
  ver="$(printf '%s' "$xpb" | grep -oiE 'php/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2)"
  sess="$(printf '%s\n' "$hdr" | grep -iqE '^set-cookie:[[:space:]]*(PHPSESSID|MoodleSession|laravel_session)=' && echo yes || echo no)"
  cms=""
  printf '%s\n' "$hdr" | grep -iqE '^link:.*wp-json|^x-redirect-by:[[:space:]]*wordpress' && cms="WordPress"
  printf '%s\n' "$hdr" | grep -iqE '^set-cookie:[[:space:]]*MoodleSession' && cms="Moodle"
  printf '%s\n' "$hdr" | grep -iqE '^x-drupal-|^x-generator:[[:space:]]*drupal' && cms="Drupal"
  printf '%s\n' "$hdr" | grep -iqE '^set-cookie:[[:space:]]*laravel_session' && cms="Laravel"
  printf '%s\n' "$hdr" | grep -iqE '^x-magento-' && cms="Magento"
  IFS='|' read -r st note < <(verdict "$ver")
  case "$st" in VULNERABLE*) NV=$((NV+1)) ;; UNSUPPORTED) NU=$((NU+1)) ;; PATCHED) NP=$((NP+1)) ;; *) NK=$((NK+1)) ;; esac
  printf '%-32s %-6s %-12s %-14s %s\n' "$host" "${status:--}" "${ver:-hidden}" "$st" "$note${cms:+ [$cms]}"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv "$host")" "$(csv "$url")" "$(csv "$status")" "$(csv "$server")" "$(csv "$xpb")" \
    "$(csv "$ver")" "$(csv "$st")" "$(csv "$note")" "$sess" "$(csv "$cms")" "$(date -u +%FT%TZ)" >> "$OUTF"
  sleep "$DELAY"
done < "$IN"

echo
echo "Vulnerable?: $NV   Unsupported: $NU   Patched: $NP   Unknown/unreachable: $NK"
echo "CSV written to: $OUTF"
echo "Next: for every VULNERABLE?/UNSUPPORTED/UNKNOWN row, confirm the real version on the server or panel (GUIDE.md section 5)."
echo "Tip: once patched, set expose_php = Off so the version is no longer advertised."
