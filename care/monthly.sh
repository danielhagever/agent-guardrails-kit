#!/bin/sh
# Monthly Care report: summarise the audit log and post it to the alert webhook.
#
#   guardrails/care/monthly.sh [YYYY-MM]        (default: the current month)
#
# Writes guardrails/reports/<month>.md and, when config.json has alert_webhook,
# POSTs the same text there (Slack and Discord accept the body). Meant for a
# monthly cron on any machine that holds the audit log, or by hand.
set -e
G=$(cd "$(dirname "$0")/.." && pwd)
PY=$("$G/hooks/_python.sh")
MONTH=${1:-$(date +%Y-%m)}
LOG=$("$PY" -c "import json,os;c=json.load(open('$G/config.json'));p=c.get('audit_log','.claude/guardrails-audit.jsonl');print(p if os.path.isabs(p) else os.path.join('$G',p))")
mkdir -p "$G/reports"
OUT="$G/reports/$MONTH.md"
"$PY" "$G/gates/report.py" "$LOG" "$MONTH" > "$OUT"
echo "wrote $OUT"
"$PY" - "$G/config.json" "$OUT" <<'EOF'
import json, sys, urllib.request
cfg = json.load(open(sys.argv[1])); url = cfg.get("alert_webhook")
text = open(sys.argv[2], encoding="utf-8").read()
if not url:
    print("no alert_webhook in config.json; report not posted"); sys.exit(0)
body = json.dumps({"text": text[:3900], "content": text[:1900]}).encode()
req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=5).read(); print("posted to webhook")
except Exception as e:
    print(f"webhook post failed: {e}"); sys.exit(1)
EOF
