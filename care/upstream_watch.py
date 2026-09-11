#!/usr/bin/env python3
"""Upstream watch: what changed in Claude Code that a guardrail owner must know.

    python3 care/upstream_watch.py [--state DIR] [--all]

Reads the latest published version from the npm registry and the public
CHANGELOG, and for every version newer than the last one it saw, writes
<state>/upstream-<version>.md with only the lines that touch hooks, permission
rules, sandboxing, settings or MCP. Prints a one-line summary per version.

Why: hook and permission semantics change between releases, sometimes as
bypass fixes (2.1.268 fixed deny rules that did not apply on symlinked paths
or next to `eval`). A Care client should hear about that from you the same
week, with the smoke test re-run, not from an incident.

Posts the summary to alert_webhook in config.json when one is set.
No dependencies beyond the standard library.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

NPM = "https://registry.npmjs.org/@anthropic-ai/claude-code/latest"
CHANGELOG = "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md"
RELEVANT = re.compile(r"\b(hook|hooks|PreToolUse|PostToolUse|Stop hook|permission|deny|allow rule|ask rule|"
                      r"sandbox|settings\.json|managed setting|bypass|MCP|symlink|--dangerously|allowedTools|"
                      r"disallowedTools|Bash tool|Read or Edit|trust)\b", re.I)
HERE = os.path.dirname(os.path.abspath(__file__))


def get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "agent-guardrails-kit"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def vkey(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v))


def sections(md):
    """{version: [bullet lines]} from the CHANGELOG, newest first."""
    out, cur = {}, None
    for line in md.splitlines():
        m = re.match(r"^##\s+v?(\d+\.\d+\.\d+)", line)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur and line.strip().startswith(("-", "*")):
            out[cur].append(line.strip().lstrip("-* ").strip())
    return out


def post(text):
    cfg_path = os.path.join(HERE, "..", "config.json")
    try:
        url = json.load(open(cfg_path)).get("alert_webhook")
    except Exception:  # noqa: BLE001
        url = None
    if not url:
        return
    body = json.dumps({"text": text[:3900], "content": text[:1900]}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}), timeout=5).read()
    except Exception as e:  # noqa: BLE001
        print(f"webhook post failed: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=os.path.join(HERE, "..", "reports"))
    ap.add_argument("--all", action="store_true", help="report the latest version even if already seen")
    a = ap.parse_args()
    os.makedirs(a.state, exist_ok=True)
    seen_file = os.path.join(a.state, ".upstream_last_version")
    last = open(seen_file).read().strip() if os.path.exists(seen_file) else ""

    try:
        latest = json.loads(get(NPM)).get("version", "")
        md = get(CHANGELOG)
    except Exception as e:  # noqa: BLE001
        print(f"upstream fetch failed: {e}")
        return 1
    secs = sections(md)
    if not latest:
        print("npm returned no version")
        return 1
    if not last or a.all:
        # First run (or --all): baseline on the latest release only. Reporting
        # the whole history would post hundreds of versions into a client's
        # Slack the day the watch is installed.
        new = [latest] if latest in secs else []
    else:
        new = [v for v in secs if vkey(last) < vkey(v) <= vkey(latest)]
    if not new:
        print(f"no new Claude Code versions since {last or 'first run'} (latest {latest})")
        return 0
    summaries = []
    for v in sorted(new, key=vkey):
        lines = [ln for ln in secs.get(v, []) if RELEVANT.search(ln)]
        path = os.path.join(a.state, f"upstream-{v}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Claude Code {v}: guardrail-relevant changes\n\n")
            f.write(f"Source: {CHANGELOG}\n\n")
            if lines:
                f.write("\n".join(f"- {ln}" for ln in lines) + "\n\n")
                f.write("Action: re-run `tests/smoke.sh` (or the full suite) and review whether any deny pattern "
                        "or protected path depended on the behaviour that changed.\n")
            else:
                f.write("Nothing in this release touches hooks, permission rules, sandboxing, settings or MCP.\n")
        summaries.append(f"{v}: {len(lines)} guardrail-relevant line{'s' if len(lines) != 1 else ''} -> {path}")
    with open(seen_file, "w") as f:
        f.write(max(new, key=vkey))
    text = "Claude Code upstream watch\n" + "\n".join(summaries)
    print(text)
    post(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
