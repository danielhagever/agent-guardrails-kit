#!/usr/bin/env python3
"""PreToolUse guard for the reading tools (Read, Grep, Glob, NotebookRead).

The write guard stops an agent from changing a secret. This one stops it from
ever seeing it, which is the failure that actually happened at PocketOS: the
agent did not delete a token, it READ one out of a file that had nothing to do
with its task, and then used it.

Only `secret_paths` are covered here. `protected_paths` stay readable on
purpose: a team needs `cat infra/prod/deploy.yaml` to get work done, and a
guard that blocks ordinary reading gets switched off within a week.

Policy lives in config.json.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (abs_pattern, clean_uri, deadline, load_config,  # noqa: E402
                  pattern_reaches, read_hook_input, resolve, shares_inode,
                  verdict, within)

deadline(8)
cfg = load_config()
data = read_hook_input()

tool = data.get("tool_name", "") or "read tool"
cwd = data.get("cwd") or os.getcwd()
SECRETS = cfg.get("_secret_abs", [])

if not SECRETS:
    verdict("allow", "no secret_paths declared in the policy")

PATH_KEYS = set(cfg["path_keys"]) | {"pattern", "glob", "path"}


def harvest(node, out):
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

for raw in paths:
    if not isinstance(raw, str):
        verdict("deny", f"{tool} was given a {type(raw).__name__} where a path was expected")
    raw = clean_uri(raw)
    # A glob is a request for whatever it matches. Judging only the part before
    # the first wildcard let `**/.env` through, because that part is empty.
    stem = raw.split("*")[0].split("?")[0]
    rp = resolve(stem, cwd)
    pat_abs = abs_pattern(raw, cwd)
    if shares_inode(rp, SECRETS):
        verdict("deny", f"{tool} was given a hard link to a secret file ({raw}); "
                        f"the second name reads the same bytes")
    for s in SECRETS:
        if within(rp, s) or (within(s, rp) and stem.strip("./")):
            verdict("deny", f"{tool} would read inside a secret path ({raw}); "
                            f"secrets are not readable by the agent")
        if any(ch in raw for ch in "*?[") and pattern_reaches(pat_abs, s):
            verdict("deny", f"{tool} uses a pattern that can match a secret path ({raw}); "
                            f"secrets are not readable by the agent")

verdict("allow", "no secret path in this read")
