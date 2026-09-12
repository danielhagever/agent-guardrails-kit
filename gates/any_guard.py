#!/usr/bin/env python3
"""PreToolUse guard for every OTHER tool: the ones that do not exist yet.

The four gates beside this one name the tools they cover: Bash, the writing
tools, the reading tools, MCP. That list is an allow-list of tool NAMES, and
an allow-list of names fails open the day the name changes. When Claude Code
ships a tool that edits files under a name nobody here predicted, the matcher
does not fire, no gate runs, and the settings file still looks complete. That
is the same failure the kit exists to prevent, one level up.

So this gate matches everything, returns immediately for the tools that have
their own gate, and for anything else walks every string in the payload and
refuses when one of them resolves inside a guarded path. It cannot know what
the tool does, which is the point: a tool this policy has never heard of does
not get to touch the paths the policy protects.

Policy lives in config.json.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (clean_uri, deadline, in_any_protected, load_config,  # noqa: E402
                  read_hook_input, resolve, shares_inode, verdict, within)

deadline(8)
cfg = load_config()
data = read_hook_input()

tool = data.get("tool_name", "") or ""
cwd = data.get("cwd") or os.getcwd()

# Tools with a gate of their own. Everything else is a stranger.
COVERED = {"bash", "write", "edit", "multiedit", "notebookedit",
           "read", "grep", "glob", "notebookread"}
if tool.lower() in COVERED or tool.startswith("mcp__"):
    verdict("allow", f"{tool} has its own gate")

# Tools that carry no filesystem path at all. Listed by name rather than
# guessed from the payload, because guessing in the permissive direction is
# how a guard becomes decoration.
NO_PATHS = {"todowrite", "exitplanmode", "killshell", "bashoutput", "websearch"}
if tool.lower() in NO_PATHS:
    verdict("allow", f"{tool} does not take a path")


def strings(node, out, depth=0):
    if depth > 8 or len(out) > 5000:
        return
    if isinstance(node, dict):
        for v in node.values():
            strings(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            strings(v, out, depth + 1)
    elif isinstance(node, str) and node.strip():
        out.append(node.strip())


found = []
strings(data.get("tool_input", {}), found)

for raw in found:
    if len(raw) > 4096:
        continue
    for candidate in {raw, clean_uri(raw)}:
        if not candidate or candidate.startswith("-"):
            continue
        rp = resolve(candidate.split("*")[0].split("?")[0], cwd)
        if not rp:
            continue
        if any(within(rp, s) or within(s, rp) for s in cfg.get("_secret_abs", [])) \
                or shares_inode(rp, cfg.get("_secret_abs", [])):
            verdict("deny", f"{tool or 'an unrecognised tool'} was given a path inside a secret "
                            f"({candidate[:60]}); secrets are denied to every tool, including the "
                            f"ones this policy has never heard of")
        if in_any_protected(rp, cfg) or shares_inode(rp, cfg["_protected_abs"]):
            verdict("deny", f"{tool or 'an unrecognised tool'} was given a path inside the "
                            f"protected tree ({candidate[:60]}). This tool has no gate of its own, "
                            f"so it cannot be told apart from a writer, and the safe answer is no")

verdict("allow", f"no guarded path in this {tool or 'tool'} call")
