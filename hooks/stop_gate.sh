#!/bin/sh
# Stop hook. Order matters:
#
# 1) stop_hook_active is read FIRST and permissively. The risk is asymmetric:
#    mistaking true for false costs an infinite loop, mistaking false for
#    true costs one skipped gate. So anything that plausibly means "already
#    continuing" allows the stop, and an unreadable payload does too.
#    CLAUDE_CODE_STOP_HOOK_BLOCK_CAP raises the runtime's own block cap if a
#    gate should be allowed to block more than once deliberately.
#
# 2) The content gate runs and only its single JSON verdict line is read.
#    A gate that CRASHES is not a gate that FAILED: reporting a syntax error
#    as a missing deliverable sends the model after the wrong problem.
DIR=$(dirname "$0")
PY=$("$DIR/_python.sh") || exit 2
INPUT=$(cat)

ACTIVE=$(printf '%s' "$INPUT" | $PY -c "
import sys, json
try:
    v = json.load(sys.stdin).get('stop_hook_active', False)
except Exception:
    print('true'); raise SystemExit          # unreadable -> never risk looping
print('true' if v is True or str(v).strip().lower() in ('true','1','yes') else 'false')
" 2>/dev/null)
[ "$ACTIVE" != "false" ] && exit 0

LINE=$("$DIR/_run.sh" check_deliverable.py 2>/dev/null)
GATE_RC=$?
VERDICT=$(printf '%s' "$LINE" | $PY -c "import sys,json;print(json.load(sys.stdin).get('verdict',''))" 2>/dev/null)
REASON=$(printf '%s' "$LINE" | $PY -c "import sys,json;print(json.load(sys.stdin).get('reason',''))" 2>/dev/null)

if [ -z "$VERDICT" ]; then
  echo "Deliverable gate could not run (exit $GATE_RC, no verdict emitted). This is a broken gate, not a failed check; fix the gate script." >&2
  exit 2
fi
[ "$VERDICT" = "pass" ] && exit 0
echo "Deliverable gate failed: $REASON" >&2
exit 2
