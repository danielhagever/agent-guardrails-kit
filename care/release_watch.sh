#!/bin/sh
# Release watch: when the installed Claude Code version changes, re-run the
# smoke test and post the result. Hook semantics have changed between releases
# before; this is how a client finds out the day it happens, not the day an
# agent does something the policy should have blocked.
#
#   guardrails/care/release_watch.sh          (cron it daily; exits 0 when nothing changed)
set -e
G=$(cd "$(dirname "$0")/.." && pwd)
PY=$("$G/hooks/_python.sh")
STATE="$G/.last_claude_version"
CUR=$(claude --version 2>/dev/null | head -1 || true)
[ -n "$CUR" ] || { echo "claude not on PATH; nothing to compare"; exit 0; }
LAST=$(cat "$STATE" 2>/dev/null || true)
if [ "$CUR" = "$LAST" ]; then echo "unchanged: $CUR"; exit 0; fi
echo "Claude Code changed: '${LAST:-none}' -> '$CUR'. Re-running smoke test."
if "$G/tests/smoke.sh" > "$G/.release_check.log" 2>&1; then RES="PASS"; else RES="FAIL"; fi
printf '%s\n' "$CUR" > "$STATE"
SUMMARY=$(tail -1 "$G/.release_check.log")
MSG="Guardrails release check: Claude Code is now '$CUR' (was '${LAST:-none}'). Smoke test: $RES ($SUMMARY)."
echo "$MSG"
"$PY" - "$G/config.json" "$MSG" <<'EOF'
import json, sys, urllib.request
cfg = json.load(open(sys.argv[1])); url = cfg.get("alert_webhook"); msg = sys.argv[2]
if not url: sys.exit(0)
body = json.dumps({"text": msg, "content": msg}).encode()
try:
    urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}), timeout=5).read()
except Exception as e:
    print(f"webhook post failed: {e}")
EOF
[ "$RES" = "PASS" ]
