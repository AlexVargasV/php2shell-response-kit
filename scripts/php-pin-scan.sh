#!/usr/bin/env bash
# =============================================================================
#  php-pin-scan.sh — find PHP version pins in a code repository and flag the
#  ones that leave you exposed to php2shell (CVE-2026-109618 / CVE-2026-109619).
#
#  Looks at: Dockerfiles / Containerfiles (FROM, ARG/ENV, distro php packages),
#  compose / Kubernetes / CI YAML (image:), composer.json (require.php and
#  config.platform.php), .php-version, .tool-versions, GitHub Actions
#  (php-version, matrix), DDEV, Lando, Platform.sh / Upsun, Google App Engine,
#  Laravel Sail, Laravel Vapor, Bref / Serverless.
#
#  Usage:  php-pin-scan.sh [-f text|github|json] [-s] [-x REGEX] [DIR]
#     -f  output format: text (default), github (workflow annotations + job
#         summary), json
#     -s  strict: warnings (floating tags, digest pins, unverifiable pins)
#         count as failures
#     -x  extra path regex to exclude (.git, vendor, node_modules always are)
#  Exit:   0 = no failures, 1 = failures found, 2 = usage error
#
#  Read-only. Needs only bash, grep, sed, awk, find, sort.
# =============================================================================
set -u
LC_ALL=C; export LC_ALL

FIXED_85="8.5.12"; FIXED_84="8.4.27"; FIXED_83="8.3.36"; FIXED_82="8.2.35"
PATCH_DATE="2026-10-21"

FORMAT=text; STRICT=0; EXTRA_EX=""
usage() { sed -n '2,22p' "$0" | sed -E 's/^# ?//'; exit 2; }
while getopts "f:sx:h" o; do
  case $o in
    f) FORMAT="$OPTARG" ;;
    s) STRICT=1 ;;
    x) EXTRA_EX="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
ROOT="${1:-.}"
[ -d "$ROOT" ] || { echo "not a directory: $ROOT" >&2; exit 2; }
case "$FORMAT" in text|github|json) ;; *) usage ;; esac
ROOT="${ROOT%/}"

RES=()   # LEVEL \t file \t line \t found \t message
add() { RES+=("$1"$'\t'"$2"$'\t'"$3"$'\t'"$4"$'\t'"$5"); }
rel() { local p="$1"; p="${p#"$ROOT"/}"; printf '%s' "$p"; }

vge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }   # $1 >= $2
fixed_for() {
  case "$1" in
    8.5) echo "$FIXED_85" ;; 8.4) echo "$FIXED_84" ;;
    8.3) echo "$FIXED_83" ;; 8.2) echo "$FIXED_82" ;;
    *) echo "" ;;
  esac
}

# classify RAW CONTEXT  ->  sets CL_LEVEL and CL_MSG
#   CONTEXT: runtime  (image or version you deploy)
#            managed  (provider-patched runtime: App Engine, Platform.sh, Vapor, Bref)
#            distro   (php packages installed from an OS repository)
#            dev      (local dev environment: .php-version, DDEV, Lando, .tool-versions)
#            ci       (test matrix)
#            platform (composer config.platform.php)
classify() {
  local raw="$1" ctx="$2" v mj mn br fx dots
  v="$(printf '%s' "$raw" | grep -oE '[0-9]+(\.[0-9]+){0,2}' | head -1)"
  if [ -z "$v" ]; then
    CL_LEVEL=WARN
    CL_MSG="no PHP version in '$raw': resolves to whatever is current at build time; rebuild after $PATCH_DATE and pin an explicit version"
    return
  fi
  case "$v" in
    *.*) ;;
    [78][0-9]) v="${v:0:1}.${v:1:1}" ;;          # php81 / php-83 compact forms
    [5-9])
      CL_LEVEL=WARN
      CL_MSG="major-only pin ($v): safe only if built after $PATCH_DATE; pin an explicit X.Y.Z"
      return ;;
    *) CL_LEVEL=INFO; CL_MSG="could not interpret '$raw'"; return ;;
  esac
  mj="${v%%.*}"; mn="$(printf '%s' "$v" | cut -d. -f2)"; br="$mj.$mn"
  if [ "$mj" -lt 8 ] || { [ "$mj" -eq 8 ] && [ "$mn" -le 1 ]; }; then
    case "$ctx" in
      ci)       CL_LEVEL=INFO; CL_MSG="tests unsupported branch $br (fine in a library's compatibility matrix, not as the version you deploy)" ;;
      platform) CL_LEVEL=WARN; CL_MSG="platform.php=$v resolves dependencies for unsupported branch $br; raise it as part of the migration (guides/MIGRATION.md)" ;;
      dev)      CL_LEVEL=WARN; CL_MSG="local environment on unsupported branch $br: you develop against a PHP you cannot deploy safely (guides/MIGRATION.md)" ;;
      distro)   CL_LEVEL=WARN; CL_MSG="distro package for branch $br: fixed only if your OS vendor backported it (guides/DISTROS.md); plan the migration" ;;
      *)        CL_LEVEL=FAIL; CL_MSG="PHP $br has NO official php2shell fix; migrate to 8.3 or 8.4 (guides/MIGRATION.md)" ;;
    esac
    return
  fi
  fx="$(fixed_for "$br")"
  if [ -z "$fx" ]; then CL_LEVEL=OK; CL_MSG="branch $br is newer than the affected ones"; return; fi
  dots="$(printf '%s' "$v" | tr -cd . | wc -c | tr -d ' ')"
  if [ "$dots" -ge 2 ]; then
    if vge "$v" "$fx"; then CL_LEVEL=OK; CL_MSG="$v is patched"; return; fi
    case "$ctx" in
      ci)       CL_LEVEL=WARN; CL_MSG="CI pinned to vulnerable $v; use $br (latest patch) or >= $fx" ;;
      dev)      CL_LEVEL=WARN; CL_MSG="local environment pinned to vulnerable $v; bump to >= $fx" ;;
      platform) CL_LEVEL=INFO; CL_MSG="platform.php=$v only affects dependency resolution; make sure the runtime is >= $fx" ;;
      *)        CL_LEVEL=FAIL; CL_MSG="$v is VULNERABLE; bump to >= $fx and rebuild/redeploy" ;;
    esac
  else
    case "$ctx" in
      ci|platform|dev) CL_LEVEL=OK; CL_MSG="floating $br (resolves to the latest patch release)" ;;
      managed) CL_LEVEL=WARN; CL_MSG="provider-managed $br: confirm the provider rolled out $fx (check phpinfo on the deployed app)" ;;
      distro)  CL_LEVEL=INFO; CL_MSG="distro package $br: rebuild the image so it picks up the patched package (guides/DISTROS.md)" ;;
      *)       CL_LEVEL=WARN; CL_MSG="floating $br: safe only if pulled/built after $PATCH_DATE; rebuild with --pull and prefer an explicit $fx tag" ;;
    esac
  fi
}

# check_image FILE LINE REF CONTEXT
check_image() {
  local f="$1" n="$2" ref="$3" ctx="${4:-runtime}" name tag dig="" nm ver=""
  ref="${ref%%[[:space:]]*}"; ref="${ref//\"/}"; ref="${ref//\'/}"
  [ -z "$ref" ] && return 0
  case "$ref" in *'$'*) return 0 ;; esac            # variable: reported via ARG/ENV
  case "$ref" in *@sha256:*) dig=1; ref="${ref%%@*}" ;; esac
  name="${ref%:*}"; tag="${ref##*:}"
  if [ "$name" = "$ref" ]; then tag=""; fi
  case "$tag" in */*) name="$ref"; tag="" ;; esac
  nm="${name##*/}"
  if printf '%s' "$tag" | grep -qiE 'php-?[0-9]'; then
    ver="$(printf '%s' "$tag" | grep -oiE 'php-?[0-9]+(\.[0-9]+){0,2}' | head -1 | sed -E 's/^[Pp][Hh][Pp]-?//')"
  elif printf '%s' "$nm" | grep -qiE 'php'; then
    ver="${tag:-latest}"
  elif printf '%s' "$nm" | grep -qiE '^(wordpress|drupal|joomla|matomo|moodle|nextcloud|mediawiki|phpmyadmin|magento)$'; then
    add WARN "$f" "$n" "$ref" "application image with bundled PHP and no PHP version in the tag: patched only if upstream rebuilt it after $PATCH_DATE; pull, recreate, verify with 'php -v' inside"
    return 0
  else
    return 0
  fi
  classify "$ver" "$ctx"
  if [ -n "$dig" ] && [ "$CL_LEVEL" != OK ]; then
    CL_MSG="$CL_MSG; digest-pinned: the digest must belong to an image built after $PATCH_DATE"
  fi
  add "$CL_LEVEL" "$f" "$n" "$ref${dig:+@sha256:…}" "$CL_MSG"
}

# allows_supported CONSTRAINT -> 0 if a composer constraint admits some PHP >= 8.2
allows_supported() {
  local c alt
  c="$(printf '%s' "$1" | sed 's/||/|/g')"
  local IFS='|'
  for alt in $c; do
    alt="$(printf '%s' "$alt" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]*,[[:space:]]*/ /g')"
    [ -z "$alt" ] && continue
    if printf '%s' "$alt" | grep -qE '<[[:space:]]*(7([.][0-9x*]+)*|8|8[.][0-2]|8[.][0-2][.]0)([[:space:]]|$)'; then continue; fi
    if printf '%s' "$alt" | grep -qE '<=[[:space:]]*(7([.][0-9x*]+)*|8[.][01]([.][0-9x*]+)?)([[:space:]]|$)'; then continue; fi
    if printf '%s' "$alt" | grep -qE '^[\^~=v]?[[:space:]]*[5-7]([.]|$)'; then continue; fi
    if printf '%s' "$alt" | grep -qE '^~[[:space:]]*8[.][01][.][0-9]+'; then continue; fi
    if printf '%s' "$alt" | grep -qE '^=?[[:space:]]*v?8[.][01]([.][0-9x*]+)?$'; then continue; fi
    return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
FILES=()
while IFS= read -r -d '' f; do
  if [ -n "$EXTRA_EX" ] && printf '%s' "$f" | grep -qE -- "$EXTRA_EX"; then continue; fi
  FILES+=("$f")
done < <(find "$ROOT" \( -name .git -o -name vendor -o -name node_modules \) -prune -o -type f -print0 2>/dev/null)

for f in "${FILES[@]}"; do
  r="$(rel "$f")"; base="${f##*/}"; lb="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"

  # --- Dockerfile / Containerfile -------------------------------------------
  case "$lb" in
    dockerfile|dockerfile.*|*.dockerfile|containerfile|containerfile.*)
      while IFS=: read -r n line; do
        ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--[^[:space:]]+[[:space:]]+)*//')"
        check_image "$r" "$n" "$ref" runtime
      done < <(grep -nE '^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]' "$f")
      while IFS=: read -r n line; do
        val="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*(ARG|ENV)[[:space:]]+[A-Za-z_]+[= ][[:space:]]*//; s/["'"'"']//g')"
        classify "$val" runtime; add "$CL_LEVEL" "$r" "$n" "$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//')" "build variable: $CL_MSG"
      done < <(grep -nE '^[[:space:]]*(ARG|ENV)[[:space:]]+[A-Za-z_]*PHP[A-Za-z_]*VERSION[= ][[:space:]]*["'"'"']?[0-9]' "$f")
      # distro packages: php8.1-fpm (Debian/Ubuntu/Sury), php81 (Alpine), remi / module streams
      seen=""
      while IFS=: read -r n tok; do
        b="$(printf '%s' "$tok" | grep -oE '[0-9]+\.?[0-9]+' | head -1)"
        case " $seen " in *" $b "*) continue ;; esac
        seen="$seen $b"
        classify "$b" distro; add "$CL_LEVEL" "$r" "$n" "$tok" "$CL_MSG"
      done < <(
        grep -noE '(php[0-9]\.[0-9]+-[a-z]+|php[78][0-9](-[a-z]+)?([[:space:]]|$)|remi-php[78][0-9])' "$f" | sed -E 's/[[:space:]]+$//'
        awk '/module[[:space:]]+(enable|install|reset|switch-to)/ && match($0, /php:(remi-)?[0-9]+\.[0-9]+/) { print NR ":" substr($0, RSTART, RLENGTH) }' "$f"
      )
      ;;
  esac

  # --- YAML: compose, Kubernetes, CI, PaaS -------------------------------------
  case "$lb" in
    *.yml|*.yaml)
      ctx=runtime
      case "$r" in
        .github/workflows/*|*/.github/workflows/*|.gitlab-ci.yml|*/.gitlab-ci.yml|bitbucket-pipelines.yml|.circleci/*|azure-pipelines*.yml|.drone.yml|.woodpecker*) ctx=ci ;;
      esac
      while IFS=: read -r n line; do
        ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]-]*image:[[:space:]]*//; s/[[:space:]]*#.*$//')"
        check_image "$r" "$n" "$ref" "$ctx"
      done < <(grep -nE '^[[:space:]-]*image:[[:space:]]*["'"'"']?[^[:space:]]+' "$f")
      # Laravel Sail runtimes
      while IFS=: read -r n tok; do
        classify "${tok##*/}" runtime; add "$CL_LEVEL" "$r" "$n" "$tok" "Laravel Sail runtime: $CL_MSG"
      done < <(grep -noE 'sail/runtimes/[0-9]+\.[0-9]+' "$f")
      # GitHub Actions / generic CI: php-version, php-versions, matrix php
      if [ "$ctx" = ci ]; then
        while IFS=: read -r n line; do
          val="${line#*:}"
          case "$val" in *'${{'*) continue ;; esac
          for v in $(printf '%s' "$val" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'); do
            classify "$v" ci; add "$CL_LEVEL" "$r" "$n" "php $v" "$CL_MSG"
          done
        done < <(grep -nE '^[[:space:]-]*(php-version|php-versions|php|php_version)[[:space:]]*:[[:space:]]*[^[:space:]]' "$f")
      fi
      case "$r" in
        .ddev/config.yaml|*/.ddev/config.yaml)
          while IFS=: read -r n line; do
            classify "${line#*:}" dev; add "$CL_LEVEL" "$r" "$n" "$(printf '%s' "$line" | tr -d ' ')" "DDEV: $CL_MSG"
          done < <(grep -nE '^php_version:' "$f") ;;
      esac
      case "$lb" in
        .lando.yml|.lando.*.yml)
          while IFS=: read -r n line; do
            classify "${line#*:}" dev; add "$CL_LEVEL" "$r" "$n" "$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//')" "Lando: $CL_MSG"
          done < <(grep -nE '^[[:space:]]+php:[[:space:]]*["'"'"']?[0-9]' "$f") ;;
        .platform.app.yaml|applications.yaml|config.yaml)
          while IFS=: read -r n tok; do
            classify "${tok#*php:}" managed; add "$CL_LEVEL" "$r" "$n" "$tok" "Platform.sh/Upsun: $CL_MSG"
          done < <(grep -noE "type:[[:space:]]*[\"']?php:[0-9]+\.[0-9]+" "$f") ;;
        app.yaml)
          while IFS=: read -r n tok; do
            classify "${tok##*php}" managed; add "$CL_LEVEL" "$r" "$n" "$tok" "Google App Engine: $CL_MSG"
          done < <(grep -noE '^runtime:[[:space:]]*php[0-9]+' "$f") ;;
        vapor.yml)
          while IFS=: read -r n tok; do
            classify "${tok##*php-}" managed; add "$CL_LEVEL" "$r" "$n" "$tok" "Laravel Vapor: $CL_MSG"
          done < <(grep -noE "php-[0-9]+\.[0-9]+" "$f") ;;
        serverless.yml|serverless.yaml)
          while IFS=: read -r n tok; do
            classify "${tok##*php-}" managed; add "$CL_LEVEL" "$r" "$n" "$tok" "Bref/Serverless: $CL_MSG"
          done < <(grep -noE 'php-[0-9]{2}' "$f" | sort -u -t: -k2,2) ;;
      esac
      ;;
  esac

  # --- composer.json -------------------------------------------------------------
  if [ "$lb" = composer.json ]; then
    while IFS=$'\t' read -r n kind val; do
      if [ "$kind" = platform ]; then
        classify "$val" platform; add "$CL_LEVEL" "$r" "$n" "config.platform.php: $val" "$CL_MSG"
      else
        if allows_supported "$val"; then
          add OK "$r" "$n" "require.php: $val" "constraint admits a supported branch"
        else
          add FAIL "$r" "$n" "require.php: $val" "constraint excludes every PHP branch that has a php2shell fix; widen it as part of the migration (guides/MIGRATION.md)"
        fi
      fi
    done < <(awk '
      { line=$0 }
      line ~ /"platform"[[:space:]]*:[[:space:]]*\{[^}]*"php"[[:space:]]*:/ {
        v=line; sub(/.*"platform"[[:space:]]*:[[:space:]]*\{[^}]*"php"[[:space:]]*:[[:space:]]*"/, "", v); sub(/".*/, "", v)
        printf "%d\tplatform\t%s\n", NR, v; next }
      line ~ /"[A-Za-z_-]+"[[:space:]]*:[[:space:]]*\{/ { k=line; sub(/^[^"]*"/, "", k); sub(/".*/, "", k); ctx=k }
      line ~ /"php"[[:space:]]*:[[:space:]]*"/ && (ctx=="require" || ctx=="platform") {
        v=line; sub(/.*"php"[[:space:]]*:[[:space:]]*"/, "", v); sub(/".*/, "", v)
        printf "%d\t%s\t%s\n", NR, ctx, v }
      line ~ /\}/ { ctx="" }
    ' "$f")
  fi

  # --- .php-version / .tool-versions ---------------------------------------------
  case "$lb" in
    .php-version)
      v="$(head -1 "$f" | tr -d '[:space:]')"
      [ -n "$v" ] && { classify "$v" dev; add "$CL_LEVEL" "$r" 1 "$v" ".php-version: $CL_MSG"; } ;;
    .tool-versions)
      while IFS=: read -r n line; do
        classify "${line#php}" dev; add "$CL_LEVEL" "$r" "$n" "$line" ".tool-versions: $CL_MSG"
      done < <(grep -nE '^php[[:space:]]+[0-9]' "$f") ;;
  esac
done

# strict mode: warnings are failures
if [ "$STRICT" -eq 1 ]; then
  for i in "${!RES[@]}"; do
    case "${RES[$i]}" in WARN$'\t'*) RES[i]="FAIL${RES[$i]#WARN}" ;; esac
  done
fi

NF=0; NW=0; NI=0; NO=0
for e in "${RES[@]+"${RES[@]}"}"; do
  case "${e%%$'\t'*}" in FAIL) NF=$((NF+1)) ;; WARN) NW=$((NW+1)) ;; INFO) NI=$((NI+1)) ;; OK) NO=$((NO+1)) ;; esac
done

sorted() {
  for e in "${RES[@]+"${RES[@]}"}"; do
    case "${e%%$'\t'*}" in FAIL) p=1 ;; WARN) p=2 ;; INFO) p=3 ;; *) p=4 ;; esac
    printf '%s\t%s\n' "$p" "$e"
  done | sort -t$'\t' -k1,1n -k3,3 -k4,4n | cut -f2-
}

case "$FORMAT" in
  text)
    if [ ${#RES[@]} -eq 0 ]; then
      echo "php-pin-scan: no PHP version pins found under $ROOT"
    else
      sorted | awk -F'\t' '{ printf "%-5s %s:%s\n      found: %s\n      %s\n\n", $1, $2, $3, $4, $5 }'
    fi
    echo "php-pin-scan: $NF failure(s), $NW warning(s), $NI info, $NO ok$([ "$STRICT" -eq 1 ] && echo ' (strict mode)')"
    ;;
  github)
    gh_esc() { printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' -e 's/:/%3A/g' -e 's/,/%2C/g'; }
    pre="${ROOT#./}"; [ "$pre" = "." ] && pre=""
    sorted | while IFS=$'\t' read -r lv file line found msg; do
      case "$lv" in FAIL) t=error ;; WARN) t=warning ;; INFO) t=notice ;; *) continue ;; esac
      file="${pre:+$pre/}$file"
      printf '::%s file=%s,line=%s,title=php2shell %s::%s (%s)\n' "$t" "$(gh_esc "$file")" "$line" "$lv" "$msg" "$found"
    done
    echo "php-pin-scan: $NF failure(s), $NW warning(s), $NI info, $NO ok"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### php2shell pin scan"
        echo
        echo "**$NF failure(s), $NW warning(s), $NI info, $NO ok** — fixed versions: 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35"
        echo
        if [ ${#RES[@]} -gt 0 ]; then
          echo "| Level | Location | Found | Message |"
          echo "|---|---|---|---|"
          sorted | awk -F'\t' '{ gsub(/\|/, "\\|"); printf "| %s | `%s:%s` | `%s` | %s |\n", $1, $2, $3, $4, $5 }'
        fi
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    ;;
  json)
    js() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g'; }
    printf '{"root":"%s","strict":%s,"counts":{"fail":%d,"warn":%d,"info":%d,"ok":%d},"findings":[' \
      "$(js "$ROOT")" "$([ "$STRICT" -eq 1 ] && echo true || echo false)" "$NF" "$NW" "$NI" "$NO"
    first=1
    while IFS=$'\t' read -r lv file line found msg; do
      [ -z "$lv" ] && continue
      [ $first -eq 1 ] && first=0 || printf ','
      printf '{"level":"%s","file":"%s","line":%s,"found":"%s","message":"%s"}' "$lv" "$(js "$file")" "${line:-0}" "$(js "$found")" "$(js "$msg")"
    done < <(sorted)
    printf ']}\n'
    ;;
esac

[ "$NF" -gt 0 ] && exit 1
exit 0
