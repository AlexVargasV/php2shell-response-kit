#!/usr/bin/env bash
# Test suite for the php2shell response kit. Runs locally and in CI.
#   bash tests/run.sh
set -u
cd "$(dirname "$0")/.." || exit 2
FX=tests/fixtures
PASS=0; FAILS=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAILS=$((FAILS+1)); printf '  FAIL  %s\n' "$1"; }
expect_exit() { # expect_exit CODE DESC CMD...
  local want="$1" desc="$2"; shift 2
  "$@" >/dev/null 2>&1; local got=$?
  [ "$got" -eq "$want" ] && ok "$desc (exit $got)" || bad "$desc: expected exit $want, got $got"
}
expect_grep() { # expect_grep PATTERN DESC CMD...
  local pat="$1" desc="$2"; shift 2
  "$@" 2>/dev/null | grep -qE -- "$pat" && ok "$desc" || bad "$desc: /$pat/ not found"
}
expect_nogrep() {
  local pat="$1" desc="$2"; shift 2
  "$@" 2>/dev/null | grep -qE -- "$pat" && bad "$desc: /$pat/ unexpectedly found" || ok "$desc"
}
SCAN=(bash scripts/php-pin-scan.sh)

echo "syntax"
for s in scripts/*.sh fleet/*.sh tests/run.sh; do bash -n "$s" && ok "bash -n $s" || bad "bash -n $s"; done

echo "php-pin-scan: vulnerable fixture"
expect_exit 1 "fails on vulnerable repo" "${SCAN[@]}" $FX/vulnerable
expect_grep 'FAIL +Dockerfile:2'                "exact vulnerable FROM tag"            "${SCAN[@]}" $FX/vulnerable
expect_grep 'FAIL +Dockerfile:3'                "vulnerable ARG PHP_VERSION"           "${SCAN[@]}" $FX/vulnerable
expect_grep 'FAIL +docker-compose.yml:3'        "8.1 compose image"                    "${SCAN[@]}" $FX/vulnerable
expect_grep 'FAIL +docker-compose.yml:5'        "php version inside app image tag"     "${SCAN[@]}" $FX/vulnerable
expect_grep 'FAIL +composer.json:4'             "composer constraint without fix"      "${SCAN[@]}" $FX/vulnerable
expect_grep 'WARN +composer.json:9'             "composer platform 8.1"                "${SCAN[@]}" $FX/vulnerable
expect_grep 'WARN +.php-version:1'              ".php-version 8.1"                     "${SCAN[@]}" $FX/vulnerable
expect_grep 'WARN +.ddev/config.yaml:3'         "DDEV php_version"                     "${SCAN[@]}" $FX/vulnerable
expect_grep 'WARN +.github/workflows/test.yml'  "CI exact vulnerable version"          "${SCAN[@]}" $FX/vulnerable
expect_grep 'WARN +Containerfile:2'             "dnf module stream"                    "${SCAN[@]}" $FX/vulnerable
expect_nogrep 'composer:2'                      "non-PHP images ignored"               "${SCAN[@]}" $FX/vulnerable
expect_nogrep 'mariadb'                         "database image ignored"               "${SCAN[@]}" $FX/vulnerable

echo "php-pin-scan: patched fixture"
expect_exit 0 "passes on patched repo" "${SCAN[@]}" $FX/patched
expect_exit 0 "passes on patched repo in strict mode" "${SCAN[@]}" -s $FX/patched
expect_nogrep '^(FAIL|WARN|INFO)'               "no findings besides OK"               "${SCAN[@]}" $FX/patched
expect_nogrep 'ghcr.io/acme/app'                "non-PHP app image ignored"            "${SCAN[@]}" $FX/patched

echo "php-pin-scan: floating fixture"
expect_exit 0 "floating pins only warn"         "${SCAN[@]}" $FX/floating
expect_exit 1 "strict mode fails on floating"   "${SCAN[@]}" -s $FX/floating
expect_grep 'digest-pinned'                     "digest pin noted"                     "${SCAN[@]}" $FX/floating
expect_grep 'Google App Engine'                 "App Engine runtime"                   "${SCAN[@]}" $FX/floating
expect_grep 'drupal:11'                         "app image without PHP tag"            "${SCAN[@]}" $FX/floating
expect_grep 'found: php83$'                     "alpine package"                       "${SCAN[@]}" $FX/floating

echo "php-pin-scan: library fixture"
expect_exit 0 "old branches in CI matrix are informational" "${SCAN[@]}" $FX/library

echo "php-pin-scan: output formats"
expect_grep '^::error file=tests/fixtures/vulnerable/Dockerfile,line=2' "github annotations with repo-relative path" "${SCAN[@]}" -f github $FX/vulnerable
if python3 -c 1 >/dev/null 2>&1; then PY=python3; else PY=python; fi
if "${SCAN[@]}" -f json $FX/vulnerable | "$PY" -c 'import json,sys; d=json.load(sys.stdin); assert d["counts"]["fail"]>=5' 2>/dev/null; then ok "json is valid and counts failures"; else bad "json output"; fi
expect_exit 2 "usage error on missing dir"      "${SCAN[@]}" /nonexistent/dir

echo "php-pin-scan: this repository (excluding fixtures)"
expect_exit 0 "kit itself has no vulnerable pins" "${SCAN[@]}" -x '/tests/fixtures/' .

echo "php2shell-check: smoke test on a benign web root"
OUT="$(mktemp -d)"
bash scripts/php2shell-check.sh -w "$FX/webroot" -d 3650 -o "$OUT/t" -R >/dev/null 2>&1
[ -s "$OUT/t/report.txt" ] && ok "report written" || bad "report missing"
grep -q 'PHP file(s) in data directories' "$OUT/t/report.txt" 2>/dev/null && ok "PHP in uploads detected" || bad "PHP in uploads not detected"
[ -s "$OUT/t/ai-handoff.md" ] && ok "ai-handoff written" || bad "ai-handoff missing"
grep -q 'Redacted: yes' "$OUT/t/ai-handoff.md" 2>/dev/null && ok "redaction flag recorded" || bad "redaction flag missing"
h="$(hostname 2>/dev/null)"; if [ -n "$h" ] && grep -qF "$h" "$OUT/t/ai-handoff.md"; then bad "hostname leaked in redacted hand-off"; else ok "hostname redacted"; fi
fences=$(grep -c '^```' "$OUT/t/ai-handoff.md"); [ $((fences % 2)) -eq 0 ] && ok "markdown fences balanced" || bad "unbalanced fences"
rm -rf "$OUT"

echo "self-assessment form"
if command -v node >/dev/null 2>&1; then
  JS="tests/.form-check.js"; sed -n '/<script>/,/<\/script>/p' docs/index.html | sed '1d;$d' > "$JS"
  node --check "$JS" 2>/dev/null && ok "form JavaScript parses" || bad "form JavaScript syntax"
  rm -f "$JS"
else
  echo "  skip  node not installed"
fi
grep -q 'https\?://' <(grep -oE '<script[^>]+src=[^>]+>' docs/index.html) && bad "form loads external scripts" || ok "form is self-contained"

echo "PHP snippets"
if command -v php >/dev/null 2>&1; then
  for f in snippets/runtime-guard.php snippets/wordpress/php2shell-site-health.php; do
    php -l "$f" >/dev/null 2>&1 && ok "php -l $f" || bad "php -l $f"
  done
  php -r 'require "snippets/runtime-guard.php"; $s=php2shell_status(); exit(isset($s["patched"],$s["reason"])?0:1);' && ok "runtime guard returns a status" || bad "runtime guard"
else
  echo "  skip  php not installed"
fi

echo "version consistency"
for f in GUIDE.md ai/CONTEXT.md CHECKLIST.md docs/index.html scripts/php2shell-check.sh scripts/php-pin-scan.sh scripts/php-exposure-inventory.sh snippets/runtime-guard.php snippets/wordpress/php2shell-site-health.php snippets/docker-build-guard.Dockerfile; do
  miss=""; for v in 8.5.12 8.4.27 8.3.36 8.2.35; do grep -q "$v" "$f" || miss="$miss $v"; done
  [ -z "$miss" ] && ok "$f lists all fixed versions" || bad "$f missing:$miss"
done

echo
echo "passed: $PASS   failed: $FAILS"
[ "$FAILS" -eq 0 ]
