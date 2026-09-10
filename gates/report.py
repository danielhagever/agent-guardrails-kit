#!/usr/bin/env python3
"""Monthly report from the guardrails audit log.

Usage: python3 gates/report.py [path/to/guardrails-audit.jsonl] [YYYY-MM]

Prints Markdown: how many agent actions the guards blocked, by reason, by
tool, by day, with the ten most recent blocked commands. This is the page a
CTO forwards; it turns an invisible control into a visible monthly number.
"""
import collections
import json
import os
import sys

LAB = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(LAB, ".claude", "guardrails-audit.jsonl")
month = sys.argv[2] if len(sys.argv) > 2 else None

rows = []
try:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if month and not str(r.get("ts", "")).startswith(month):
                continue
            rows.append(r)
except FileNotFoundError:
    print(f"no audit log at {path}")
    sys.exit(0)

label = month or "all time"
print(f"# Guardrails report ({label})\n")
print(f"**{len(rows)} blocked** agent actions.\n")
if not rows:
    sys.exit(0)

by = lambda k: collections.Counter(str(r.get(k, "")) for r in rows)  # noqa: E731
print("## By reason\n")
for reason, n in by("reason").most_common():
    print(f"- {n} x {reason}")
print("\n## By tool\n")
for tool, n in by("tool").most_common():
    print(f"- {n} x {tool or 'unknown'}")
print("\n## By day\n")
for day, n in sorted(collections.Counter(str(r.get("ts", ""))[:10] for r in rows).items()):
    print(f"- {day}: {n}")
print("\n## Most recent blocked actions\n")
for r in rows[-10:][::-1]:
    print(f"- `{r.get('ts','')}` {r.get('tool','')}: `{r.get('what','')[:120]}`")
