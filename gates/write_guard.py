#!/usr/bin/env python3
"""PreToolUse guard for every file-writing tool.

Three bugs the first version had, all found by attacking it rather than
reading it:

1. It read only `tool_input.file_path`. NotebookEdit sends `notebook_path`
   and MultiEdit nests paths under `edits[]`, so adding NotebookEdit to the
   matcher looked like coverage while the guard silently inspected nothing.
   A guard that is wired but cannot read its input is more dangerous than a
   missing one, because the matcher list now lies to you. Paths are
   harvested from every configured key, recursively, at any depth.

2. It exited 0 when it could not find a path. A write tool whose payload
   cannot be read is exactly when to stop, not to wave through.

3. It resolved relative paths against the hook process's cwd rather than the
   session `cwd` Claude Code sends, so the same command was allowed or
   blocked depending on where the hook happened to run.

Policy lives in config.json.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (in_any_protected, load_config, read_hook_input,  # noqa: E402
                  resolve, verdict, within)

cfg = load_config()
data = read_hook_input(argv_fallback=False)

tool = data.get("tool_name", "") or "write tool"
cwd = data.get("cwd") or os.getcwd()
PATH_KEYS = set(cfg["path_keys"])


def harvest(node, out):
    """Every path-ish string anywhere in the payload, however nested."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in PATH_KEYS and isinstance(v, str) and v.strip():
                out.append(v)
            else:
                harvest(v, out)
    elif isinstance(node, list):
        for v in node:
            harvest(v, out)


paths = []
harvest(data.get("tool_input", {}), paths)

if not paths:
    verdict("deny", f"{tool} called with no readable path in tool_input "
                    f"(looked for: {', '.join(sorted(PATH_KEYS))}); "
                    f"failing closed rather than guessing")

for raw in paths:
    rp = resolve(raw, cwd)
    if in_any_protected(rp, cfg):
        verdict("deny", f"{rp} is inside the protected tree")
    if not within(rp, cfg["_allowed_tree_abs"]):
        verdict("deny", f"{rp} is outside the allowed tree "
                        f"{cfg['_allowed_tree_abs']}")

verdict("allow", f"{len(paths)} path(s) inside the allowed tree")
