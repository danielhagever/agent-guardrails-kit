#!/usr/bin/env python3
"""PreToolUse guard for MCP tools.

The Bash and Write hooks cover the tools Claude Code ships with. An MCP server
is a different set of hands on the same filesystem: a filesystem server, a
database tool, a deploy helper. Their arguments are free-form JSON, so the only
honest thing to do is walk every string in the payload, and refuse when one of
them resolves inside a protected or secret path.

Nothing else is judged here. What an MCP tool is allowed to do in general is a
question for the allow-list in .claude/settings.json; this gate only makes sure
the paths this policy protects are protected from that direction too.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (abs_pattern, clean_uri, in_any_protected,  # noqa: E402
                  load_config, pattern_reaches, read_hook_input, resolve,
                  verdict, within)

cfg = load_config()
data = read_hook_input()
tool = data.get("tool_name", "") or "an MCP tool"
cwd = data.get("cwd") or os.getcwd()
SECRETS = cfg.get("_secret_abs", [])

READ_ONLY_HINTS = ("read", "get", "list", "search", "query", "fetch", "describe", "show")


def strings(node, out, depth=0):
    if depth > 6:
        return
    if isinstance(node, dict):
        for v in node.values():
            strings(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            strings(v, out, depth + 1)
    elif isinstance(node, str) and node.strip():
        out.append(node.strip())


candidates = []
strings(data.get("tool_input", {}), candidates)

for raw in candidates:
    if len(raw) > 4096:
        continue
    raw = clean_uri(raw)
    stem = raw.split("*")[0].split("?")[0]
    if not stem or stem.startswith("-"):
        continue
    rp = resolve(stem, cwd)
    if any(within(rp, s) or within(s, rp) for s in SECRETS):
        verdict("deny", f"{tool} was given a path inside a secret ({raw[:60]}); "
                        f"secrets are denied to every tool, MCP servers included")
    pat_abs = abs_pattern(raw, cwd)
    if any(ch in raw for ch in "*?[") and any(pattern_reaches(pat_abs, s) for s in SECRETS):
        verdict("deny", f"{tool} uses a pattern that can match a secret path ({raw[:60]})")
    if in_any_protected(rp, cfg):
        # A read-shaped tool name is not proof, so protected paths are denied to
        # MCP tools outright: this gate cannot tell a reader from a writer, and
        # guessing in the permissive direction is how a guard becomes decoration.
        verdict("deny", f"{tool} was given a path inside the protected tree ({raw[:60]}); "
                        f"MCP tools are not covered by the Bash allow-list, so this is denied")

verdict("allow", "no protected path in this MCP call")
