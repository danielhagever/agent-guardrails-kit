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
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (abs_pattern, bash_verdict, clean_uri, deadline, in_any_protected,  # noqa: E402
                  load_config, pattern_reaches, read_hook_input, resolve,
                  shares_inode, verdict, within)

deadline(8)
cfg = load_config()
data = read_hook_input()
tool = data.get("tool_name", "") or "an MCP tool"
cwd = data.get("cwd") or os.getcwd()
SECRETS = cfg.get("_secret_abs", [])

READ_ONLY_HINTS = ("read", "get", "list", "search", "query", "fetch", "describe", "show")

# A tool that deletes a DIRECTORY takes everything under it. The path it names
# is then an ancestor of the guarded tree rather than inside it, which is the
# same blind spot round ten found in the Bash gate. Here there is no verb to
# read, so the tool's own name and the keys of its payload are used as a hint,
# and only in the restrictive direction: a hint can add a refusal, never remove
# one.
DESTRUCTIVE_HINT = re.compile(
    r"(delete|destroy|remove|rm|move|rename|write|replace|truncate|overwrite|unlink|purge|wipe)",
    re.I)


def looks_destructive(tool_name, payload):
    if DESTRUCTIVE_HINT.search(tool_name or ""):
        return True

    def keys(node, depth=0):
        if depth > 6:
            return []
        if isinstance(node, dict):
            out = list(node.keys())
            for v in node.values():
                out += keys(v, depth + 1)
            return out
        if isinstance(node, list):
            return [k for v in node for k in keys(v, depth + 1)]
        return []

    return any(DESTRUCTIVE_HINT.search(str(k)) for k in keys(payload))



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




COMMAND_KEYS = {"command", "cmd", "script", "shell", "run", "exec", "code", "entrypoint",
                "args", "arguments", "commandline", "command_line", "bash", "sh"}


def command_strings(node, out, key=None, depth=0):
    """Strings that are a COMMAND rather than a path.

    Two tells, and a path has neither: the key is called `command`, or the text
    contains a shell metacharacter.
    """
    if depth > 8:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            command_strings(v, out, str(k).lower(), depth + 1)
    elif isinstance(node, list):
        for v in node:
            command_strings(v, out, key, depth + 1)
    elif isinstance(node, str) and node.strip():
        if key in COMMAND_KEYS or re.search(r"[|;&><`]|\$\(", node):
            out.append(node)


candidates = []
strings(data.get("tool_input", {}), candidates)
carried = []
command_strings(data.get("tool_input", {}), carried)
for c in carried[:20]:
    why = bash_verdict(cwd, c)
    if why:
        verdict("deny", f"{tool} carries a shell command, and the Bash policy refuses it: {why}")
destructive = looks_destructive(tool, data.get("tool_input", {}))

for raw in candidates:
    if len(raw) > 4096:
        continue
    raw = clean_uri(raw)
    stem = raw.split("*")[0].split("?")[0]
    if not stem or stem.startswith("-"):
        continue
    rp = resolve(stem, cwd)
    if shares_inode(rp, SECRETS) or shares_inode(rp, cfg["_protected_abs"]):
        verdict("deny", f"{tool} was given a hard link to a guarded file ({raw[:60]}); "
                        f"a second name for the same inode is the same file")
    if any(within(rp, s) or within(s, rp) for s in SECRETS):
        verdict("deny", f"{tool} was given a path inside a secret ({raw[:60]}); "
                        f"secrets are denied to every tool, MCP servers included")
    pat_abs = abs_pattern(raw, cwd)
    if any(ch in raw for ch in "*?[") and any(pattern_reaches(pat_abs, s) for s in SECRETS):
        verdict("deny", f"{tool} uses a pattern that can match a secret path ({raw[:60]})")
    if destructive:
        for tree in cfg["_protected_abs"]:
            if rp != tree and within(tree, rp):
                verdict("deny", f"{tool} looks like it removes or overwrites what it is given, and "
                                f"{raw[:50]} contains a guarded path; the tree would go with it")
    if in_any_protected(rp, cfg):
        # A read-shaped tool name is not proof, so protected paths are denied to
        # MCP tools outright: this gate cannot tell a reader from a writer, and
        # guessing in the permissive direction is how a guard becomes decoration.
        verdict("deny", f"{tool} was given a path inside the protected tree ({raw[:60]}); "
                        f"MCP tools are not covered by the Bash allow-list, so this is denied")

verdict("allow", "no protected path in this MCP call")
