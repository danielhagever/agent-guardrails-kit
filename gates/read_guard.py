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
from _lib import load_config, read_hook_input, resolve, verdict, within  # noqa: E402

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
    # A glob is a request for whatever it matches, so strip the wildcard part
    # and judge the directory it is rooted in; `secrets/**` must not be a way in.
    stem = raw.split("*")[0].split("?")[0]
    rp = resolve(stem, cwd)
    for s in SECRETS:
        if within(rp, s) or within(s, rp) and stem.strip("./"):
            verdict("deny", f"{tool} would read inside a secret path ({raw}); "
                            f"secrets are not readable by the agent")

verdict("allow", "no secret path in this read")
