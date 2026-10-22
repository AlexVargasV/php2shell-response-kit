#!/usr/bin/env bash
# =============================================================================
#  fleet/run-ssh.sh — run scripts/php2shell-check.sh on many servers over SSH
#  and collect every report and AI hand-off in one local folder.
#
#  Usage:  fleet/run-ssh.sh -H hosts.txt [-o results-dir] [-R] [-d DAYS] [-q]
#     -H  file with one SSH destination per line: host, user@host or
#         ssh://user@host:port  (# comments allowed). ~/.ssh/config aliases work.
#     -o  local results directory (default: php2shell-fleet-<date>)
#     -R  pass -R to the check (redacted ai-handoff.md)
#     -d  look-back window in days (default 30)
#     -q  pass -q (skip signature scan on big sites)
#
#  Per host it: streams the check script over SSH (no scp needed), runs it with
#  sudo -n when available (read-only), streams back report.txt, ai-handoff.md
#  and evidence/ as a tarball, and removes only the uploaded script. The
#  evidence folder stays on the host as well.
#
#  Requirements: key-based SSH (BatchMode), bash on the remote side.
# =============================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="$HERE/../scripts/php2shell-check.sh"
HOSTS=""; OUT="php2shell-fleet-$(date +%F)"; PASS=(); DAYS=30
usage() { sed -n '2,22p' "$0" | sed -E 's/^# ?//'; exit 2; }
while getopts "H:o:Rd:qh" o; do
  case $o in
    H) HOSTS="$OPTARG" ;; o) OUT="$OPTARG" ;; R) PASS+=(-R) ;; d) DAYS="$OPTARG" ;; q) PASS+=(-q) ;; *) usage ;;
  esac
done
[ -n "$HOSTS" ] && [ -r "$HOSTS" ] || usage
[ -r "$CHECK" ] || { echo "check script not found: $CHECK" >&2; exit 2; }
mkdir -p "$OUT"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30)
REMOTE_DIR=/tmp/php2shell-triage
SUMMARY="$OUT/SUMMARY.md"
{
  echo "# php2shell fleet triage — $(date '+%F %T %Z')"
  echo
  echo "| Host | Verdict | Critical | High | Medium | Files |"
  echo "|---|---|---|---|---|---|"
} > "$SUMMARY"

while IFS= read -r line || [ -n "$line" ]; do
  h="$(printf '%s' "$line" | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')"
  [ -z "$h" ] && continue
  safe="$(printf '%s' "$h" | sed -E 's#^ssh://##; s#[^A-Za-z0-9._-]+#_#g')"
  dir="$OUT/$safe"; mkdir -p "$dir"
  echo "==> $h"

  if ! "${SSH[@]}" "$h" 'cat > /tmp/php2shell-check.sh && chmod 700 /tmp/php2shell-check.sh' < "$CHECK" 2> "$dir/ssh-error.txt"; then
    echo "    unreachable (see $dir/ssh-error.txt)"
    echo "| \`$h\` | UNREACHABLE | | | | |" >> "$SUMMARY"; continue
  fi
  # shellcheck disable=SC2029  # PASS and DAYS are expanded locally on purpose
  "${SSH[@]}" "$h" "if [ \"\$(id -u)\" = 0 ]; then S=''; elif sudo -n true 2>/dev/null; then S='sudo -n'; else S=''; echo 'warning: no passwordless sudo, running unprivileged' >&2; fi;
     \$S bash /tmp/php2shell-check.sh -o $REMOTE_DIR -d $DAYS ${PASS[*]:-} >/dev/null 2>&1;
     \$S tar -C $REMOTE_DIR -czf - report.txt ai-handoff.md evidence 2>/dev/null;
     rm -f /tmp/php2shell-check.sh" > "$dir/triage.tgz" 2> "$dir/run-stderr.txt"
  if tar -xzf "$dir/triage.tgz" -C "$dir" 2>/dev/null && [ -s "$dir/report.txt" ]; then
    rm -f "$dir/triage.tgz"
    v="$(grep -m1 '^VERDICT:' "$dir/report.txt" | sed 's/^VERDICT: //')"
    c="$(grep -m1 '^Critical:' "$dir/report.txt")"
    nc="$(printf '%s' "$c" | awk '{print $2}')"; nh="$(printf '%s' "$c" | awk '{print $4}')"; nm="$(printf '%s' "$c" | awk '{print $6}')"
    echo "    $c"
    echo "| \`$h\` | ${v%%.*} | $nc | $nh | $nm | [report]($safe/report.txt) · [ai-handoff]($safe/ai-handoff.md) |" >> "$SUMMARY"
  else
    echo "    triage failed (see $dir/run-stderr.txt)"
    echo "| \`$h\` | FAILED | | | | [stderr]($safe/run-stderr.txt) |" >> "$SUMMARY"
  fi
done < "$HOSTS"

{
  echo
  echo "Next: give an AI assistant ai/CONTEXT.md plus the ai-handoff.md files and use the"
  echo "'Multiple servers' prompt in ai/PROMPTS.md to build a per-host action table."
} >> "$SUMMARY"
echo
echo "Summary: $SUMMARY"
