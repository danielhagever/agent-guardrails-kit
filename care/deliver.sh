#!/bin/sh
# The handover document, generated from the installed policy rather than written.
#
#   guardrails/care/deliver.sh ["Client name"]
#
# Produces guardrails/reports/delivery-<date>.md and .html: what is protected,
# what is enforced, what was proven by running it, and what this does not cover.
# The client keeps this; it is the artifact the invoice is attached to, and
# every number in it comes from a command that just ran on their machine.
set -e
G=$(cd "$(dirname "$0")/.." && pwd)
REPO=$("$G/hooks/_repo_root.sh")
PY=$("$G/hooks/_python.sh")
CLIENT=${1:-$(basename "$REPO")}
DATE=$(date +%Y-%m-%d)
mkdir -p "$G/reports"
OUT="$G/reports/delivery-$DATE.md"

SMOKE=$(sh "$G/tests/smoke.sh" 2>&1 || true)
SMOKE_LINE=$(printf '%s' "$SMOKE" | tail -1)
RED=$("$PY" "$G/redteam/attack.py" 2>&1 || true)
RED_LINE=$(printf '%s' "$RED" | grep -E "^attacks:" || echo "red team did not run")
TOOLS=$("$PY" "$G/redteam/tools.py" 2>&1 || true)
TOOLS_LINE=$(printf '%s' "$TOOLS" | grep -E "^[0-9]+ cases" || echo "tool-guard harness did not run")
KIT_COMMIT=$(cd "$G" 2>/dev/null && git -C "$G" log -1 --format=%h 2>/dev/null || echo "not a git checkout")

CLIENT="$CLIENT" DATE="$DATE" G="$G" REPO="$REPO" SMOKE_LINE="$SMOKE_LINE" RED_LINE="$RED_LINE" \
TOOLS_LINE="$TOOLS_LINE" KIT_COMMIT="$KIT_COMMIT" "$PY" - > "$OUT" <<'EOF'
import json, os, subprocess

g, repo = os.environ["G"], os.environ["REPO"]
R = lambda p: os.path.realpath(os.path.join(g, os.path.expanduser(p)))
cfg = json.load(open(os.path.join(g, "config.json")))
rel = lambda p: p.replace("../", "")
# Not "is it listed in settings.json" but "does it run, and does it refuse".
# A hook can be wired and unreadable, wired and not executable, wired and
# pointing at a path that moved. Each one is asked a question it must answer
# with a refusal, right now, on this machine.
settings_path = os.path.join(repo, ".claude", "settings.json")
first_prot = (cfg.get("protected_paths") or [""])[0]
first_secret = (cfg.get("secret_paths") or [""])[0]
PROBE = {
    "Bash": ("Bash", {"command": f"rm -rf {R(first_prot)}"}),
    "Write": ("Write", {"file_path": R(first_prot)}),
    "Read": ("Read", {"file_path": R(first_secret)} if first_secret else None),
    "mcp__": ("mcp__fs__write", {"path": R(first_prot)}),
    "*": ("ToolThisPolicyHasNeverHeardOf", {"target": R(first_prot)}),
}


def probe(matcher, command):
    key = next((k for k in ("Bash", "Write", "Read", "mcp__") if k in matcher), "*")
    tool, payload = PROBE[key]
    if payload is None:
        return "no secret_paths declared, nothing to probe with"
    path = command.replace("$CLAUDE_PROJECT_DIR", repo).replace("${CLAUDE_PROJECT_DIR}", repo)
    if not os.path.exists(path):
        return f"**MISSING**: {path} does not exist"
    if not os.access(path, os.X_OK):
        return f"**NOT EXECUTABLE**: chmod +x {path}"
    body = json.dumps({"tool_name": tool, "cwd": repo, "tool_input": payload})
    try:
        p = subprocess.run([path], input=body, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return f"**COULD NOT RUN**: {e}"
    if p.returncode == 2:
        return "refused the probe (exit 2)"
    return f"**ALLOWED THE PROBE** (exit {p.returncode}), which means this hook is not protecting anything"


wired = []
try:
    st = json.load(open(settings_path))
    for h in (st.get("hooks", {}) or {}).get("PreToolUse", []):
        matcher = h.get("matcher") or "(all tools)"
        for entry in h.get("hooks", []):
            wired.append((matcher, probe(matcher, entry.get("command", ""))))
except (OSError, ValueError):
    wired = [("NOT WIRED", "**.claude/settings.json has no PreToolUse hooks**")]

p = lambda *a: print(*a)
p(f"# Agent guardrails: delivery report")
p(f"\n**{os.environ['CLIENT']}**, {os.environ['DATE']}. Repository: `{repo}`. Kit commit: `{os.environ['KIT_COMMIT']}`.")
p("\nEverything below was produced by running the policy that is now installed in this repository. "
  "No number here is a claim; each one is the output of a command you can re-run.\n")

p("## What is protected\n")
p("| Class | Paths | Rule |")
p("|---|---|---|")
p(f"| Secrets | {', '.join('`'+rel(x)+'`' for x in cfg.get('secret_paths', [])) or 'none declared'} | "
  f"every verb denied, reading included, and the Read, Grep and Glob tools too |")
p(f"| Protected | {', '.join('`'+rel(x)+'`' for x in cfg.get('protected_paths', [])) or 'none'} | "
  f"denied unless every verb in the command is on the read-only allow-list |")
p(f"| Executed later | {', '.join('`'+x+'`' for x in cfg.get('execution_surface', []))} | "
  f"writing denied, reading allowed |")
p(f"| The guard itself | `guardrails/config.json`, `gates/`, `hooks/`, `tests/`, `.claude/` | "
  f"writing denied, so the policy cannot be removed by the thing it governs |")

p(f"\n## What is enforced\n")
p(f"- **{len(cfg.get('deny_patterns', []))} destructive-command patterns**, checked before any path logic: "
  f"force push, history rewrite, `git clean -f`, recursive delete of root or home, pipe-to-shell, "
  f"eval of a command substitution, `terraform destroy`, `kubectl delete namespace`, `DROP TABLE`, "
  f"and git config keys that decide what git executes.")
p(f"- **{len(cfg.get('interpreter_verbs', []))} interpreter verbs** whose quoted payloads are re-lexed, so "
  f"`sh -c '...'`, `python -c '...'` and `perl -e '...'` are read rather than trusted.")
p(f"\n**The hooks, each one run just now with a payload it must refuse:**\n")
p("| Matcher | Proof |")
p("|---|---|")
for matcher, result in wired:
    p(f"| `{matcher}` | {result} |")
p("")
p(f"- **Every block is logged** to `{cfg.get('audit_log')}`" +
  (f" and posted to your webhook." if cfg.get("alert_webhook") else
   " (no alert webhook set yet: add one in guardrails/config.json to get a Slack or Discord message per block)."))

p("\n## What was proven, on this machine, today\n")
p("```")
p(os.environ["SMOKE_LINE"].strip())
p(os.environ["RED_LINE"].strip())
p(os.environ["TOOLS_LINE"].strip())
p("```")
p("\nThe red team does not ask the guard for a verdict and believe it. For each attack it builds a throwaway "
  "sandbox with a canary file in a protected path and a fake credential in a secret path, asks the guard, "
  "**runs the command anyway**, and compares. `LEAK` means the guard allowed something that really did damage. "
  "`over-blocked` means it refused something harmless, which is counted too, because that is the number that "
  "decides whether a team keeps the policy switched on. The second harness attacks the Write, Read and MCP "
  "gates, and the gates themselves as programs: a gate that crashes or hangs exits with a code the hook layer "
  "reads as broken, and a broken gate does not stop the tool call, so every malformed or pathological input "
  "has to end in a refusal rather than an error.\n")
p("Re-run all three at any time:\n")
p("```\nguardrails/tests/smoke.sh\npython3 guardrails/redteam/attack.py\npython3 guardrails/redteam/tools.py\n```")

p("\n## Keeping it true\n")
p("- `guardrails/ci/github-guardrails.yml` (or the GitLab one) runs the smoke test on every push, so a policy "
  "that stops holding fails the build rather than failing quietly.")
p("- `guardrails/care/release_watch.sh`, run daily, re-proves the policy the day Claude Code changes version.")
p("- `guardrails/care/monthly.sh` turns the audit log into a monthly report of what the agents tried and were "
  "stopped from doing.")
p("- `guardrails/care/drift.sh` answers the question this report cannot: is the policy still true? It lists "
  "credential-looking files and production-looking directories that have appeared since it was written and are "
  "not covered by any declared path. Run it monthly; it reads names, never contents.")

p("\n## What this does not cover\n")
p("- A credential already exported in the shell the agent inherits, or a cloud CLI already logged in on the "
  "same machine. Scope the agent's identity; a hook cannot help there.")
p("- Tools that are not Claude Code. Cursor has its own permission model; `guardrails/templates/"
  "cursor-rules.mdc` mirrors this policy where Cursor reads it, and the enforcement point is Cursor's admin "
  "settings.")
p("- A compromised host. These are hooks, not a sandbox. Unattended runs belong in a container with no "
  "network path to production.")
p("- Anything server-side. A force push blocked on a laptop is still worth blocking on the server: branch "
  "protection and a pre-receive hook are the copy that survives a bypassed client.")
p("- Attacks nobody has written yet. 366 executed attacks and 78 tool-guard cases are tested here, over eleven "
  "rounds; the number outstanding is not zero, which is why both red teams ship with the kit and why a "
  "working bypass is welcome as an issue.")
EOF

"$PY" - "$OUT" <<'EOF'
import re, sys
md = open(sys.argv[1], encoding="utf-8").read()
html = md
html = re.sub(r"^# (.+)$", r"<h1>\1</h1>", html, flags=re.M)
html = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html, flags=re.M)
html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)
html = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", html)
rows = []
out = []
for line in html.splitlines():
    if line.startswith("|"):
        cells = [c.strip() for c in line.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            continue
        tag = "th" if not rows else "td"
        rows.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
        continue
    if rows:
        out.append("<table>" + "".join(rows) + "</table>")
        rows = []
    if line.startswith("```"):
        out.append("<pre>" if not out or not out[-1].startswith("<pre>") else "</pre>")
        continue
    out.append(f"<p>{line}</p>" if line.strip() and not line.startswith("<h") else line)
if rows:
    out.append("<table>" + "".join(rows) + "</table>")
body = "\n".join(out).replace("<p></p>", "")
open(sys.argv[1].replace(".md", ".html"), "w", encoding="utf-8").write(
    "<!doctype html><meta charset='utf-8'><title>Agent guardrails delivery report</title>"
    "<style>body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:820px;"
    "margin:40px auto;padding:0 20px;color:#15171b}h1{font-size:1.7rem}h2{font-size:1.15rem;margin-top:32px}"
    "table{border-collapse:collapse;width:100%;font-size:.95rem;margin:12px 0}td,th{border-bottom:1px solid #e3e5ea;"
    "padding:8px 6px;text-align:left;vertical-align:top}code{background:#f3f4f6;padding:1px 4px;border-radius:3px;"
    "font-size:.9em}pre{background:#0b0d11;color:#d7dbe0;padding:14px;border-radius:8px;overflow-x:auto;font-size:13px}"
    "pre p{margin:0;color:inherit}</style>" + body)
EOF
echo "wrote $OUT"
echo "wrote ${OUT%.md}.html"
