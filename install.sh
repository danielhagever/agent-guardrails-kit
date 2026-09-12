#!/bin/sh
# Install the kit into another repository.
#
#   ./install.sh /path/to/repo [protected-path ...]
#
# Copies hooks/, gates/ and a rewritten config.json into <repo>/guardrails/,
# with allowed_tree set to the repo root and every protected path you name
# (relative to the repo root) protected. Prints the settings.json block to add.
# Refuses to overwrite an existing guardrails/ directory.
set -e
KIT=$(cd "$(dirname "$0")" && pwd)
REPO=$1
[ -n "$REPO" ] || { echo "usage: $0 /path/to/repo [protected-path ...]" >&2; exit 2; }
[ -d "$REPO" ] || { echo "not a directory: $REPO" >&2; exit 2; }
shift
DEST="$REPO/guardrails"
[ -e "$DEST" ] && { echo "refusing: $DEST already exists" >&2; exit 2; }

mkdir -p "$DEST/tests" "$DEST/scratch"
cp -R "$KIT/hooks" "$KIT/gates" "$KIT/care" "$KIT/ci" "$KIT/templates" "$KIT/docs" "$KIT/redteam" "$DEST/"
rm -rf "$DEST/gates/__pycache__"
cp "$KIT/tests/smoke.sh" "$DEST/tests/smoke.sh"
chmod +x "$DEST/hooks/"*.sh "$DEST/tests/smoke.sh" "$DEST/gates/report.py" "$DEST/gates/exposure_report.py" "$DEST/care/"*.sh

PY=$("$KIT/hooks/_python.sh")
KIT="$KIT" DEST="$DEST" "$PY" - "$@" <<'EOF'
import json, os, sys
kit = os.environ["KIT"]; dest = os.environ["DEST"]
cfg = json.load(open(os.path.join(kit, "config.json")))
paths = sys.argv[1:] or [".env", "secrets"]
cfg["allowed_tree"] = ".."
cfg["protected_paths"] = [os.path.join("..", p) for p in paths]
# Anything that looks like a credential store is a secret, not merely protected:
# every verb is denied on it, reads included, because reading is the attack.
secretish = [p for p in paths if any(k in p.lower() for k in (".env", "secret", "credential", ".pem", "key", ".npmrc", "kubeconfig"))]
cfg["secret_paths"] = [os.path.join("..", p) for p in secretish]
cfg["audit_log"] = "guardrails-audit.jsonl"
cfg["deliverable"]["path"] = "scratch/deliverable.md"
cfg["_comment"] = ("Policy for this repository. Paths are relative to the guardrails/ directory, "
                   "so '../.env' is .env at the repo root. Edit protected_paths and deny_patterns; "
                   "run guardrails/tests/smoke.sh after every change.")
json.dump(cfg, open(os.path.join(dest, "config.json"), "w"), indent=2, ensure_ascii=False)
print("protected:", ", ".join(paths))
EOF

# Wire the hooks for real. Printing a block to paste was the whole activation
# step, and a delivery report on a fresh install came back saying NOT WIRED:
# an installed guard that nobody switched on is worse than none, because the
# directory is there and everyone assumes it is working.
if [ "$1" = "--print-only" ] || [ "$PRINT_ONLY" = "1" ]; then
  WIRED="skipped (--print-only): add the block below yourself"
else
  REPO="$REPO" DEST="$DEST" "$PY" - <<'PYEOF'
import json, os, shutil
repo, dest = os.environ["REPO"], os.environ["DEST"]
path = os.path.join(repo, ".claude", "settings.json")
os.makedirs(os.path.dirname(path), exist_ok=True)
data = {}
if os.path.exists(path):
    shutil.copy(path, path + ".before-guardrails")
    try:
        data = json.load(open(path))
    except ValueError:
        raise SystemExit(f"{path} is not valid JSON; refusing to touch it. Add the block by hand.")
hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])
wanted = [
    ("Write|Edit|MultiEdit|NotebookEdit", "pre_write_guard.sh"),
    ("Bash", "pre_bash_guard.sh"),
    ("Read|Grep|Glob|NotebookRead", "pre_read_guard.sh"),
    ("mcp__.*", "pre_mcp_guard.sh"),
    ("*", "pre_any_guard.sh"),
]
for matcher, script in wanted:
    cmd = "$CLAUDE_PROJECT_DIR/guardrails/hooks/" + script
    if any(cmd in json.dumps(entry) for entry in pre):
        continue
    pre.append({"matcher": matcher, "hooks": [{"type": "command", "command": cmd}]})
json.dump(data, open(path, "w"), indent=2)
print(f"wired {len(wanted)} hooks into {path}")
PYEOF
  WIRED="done automatically (a backup of any previous settings.json is beside it)"
fi

cat <<EOF

Installed into $DEST
Hooks wired: $WIRED

For reference, this is what was added to $REPO/.claude/settings.json:

{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [ { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/guardrails/hooks/pre_write_guard.sh" } ] },
      { "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/guardrails/hooks/pre_bash_guard.sh" } ] },
      { "matcher": "Read|Grep|Glob|NotebookRead",
        "hooks": [ { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/guardrails/hooks/pre_read_guard.sh" } ] },
      { "matcher": "mcp__.*",
        "hooks": [ { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/guardrails/hooks/pre_mcp_guard.sh" } ] },
      { "matcher": "*",
        "hooks": [ { "type": "command", "command": "\$CLAUDE_PROJECT_DIR/guardrails/hooks/pre_any_guard.sh" } ] }
    ]
  }
}

Verify it took effect:   $DEST/care/deliver.sh "Your name"   (the report says NOT WIRED if it did not)

Then prove it:  $DEST/tests/smoke.sh
Red team:       python3 $DEST/redteam/attack.py   (every attack executed in a sandbox)
CI template:    $DEST/ci/github-guardrails.yml (or gitlab-guardrails.yml)
Cursor mirror:  copy $DEST/templates/cursor-rules.mdc to .cursor/rules/guardrails.mdc
Alerts:         set alert_webhook in $DEST/config.json (Slack or Discord incoming webhook)
Monthly report: $DEST/care/monthly.sh    Release watch: $DEST/care/release_watch.sh
Handover doc:   $DEST/care/deliver.sh "Client name"   (writes reports/delivery-<date>.md and .html)
Add guardrails-audit.jsonl to .gitignore unless you want the log committed.
EOF
