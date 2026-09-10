#!/usr/bin/env python3
"""Default-deny guard for the Bash tool over the protected tree.

The first version was a deny-list: enumerate rm/mv/rmdir and block those.
Defeating it took minutes. cp, tee, dd, sed -i, install and rsync all wrote
into the protected tree untouched; so did `sh -c "rm ..."`, `find -delete`,
`ls | xargs rm`, `P=path; rm $P/x` and `(cd protected && rm x)`. Two of the
blocks it did produce came from a quoting parse error rather than detection,
which is worse than missing them: a guard wrong in both directions cannot be
reasoned about.

So the rule is inverted. Referencing the protected tree is denied unless
every verb in the command is on a short read-only allowlist. New tools, new
spellings and shell tricks fail closed by construction, because nothing has
to be predicted in advance.

Policy (what is protected, which verbs are read-only) lives in config.json.
This file contains only the logic that applies it.
"""
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (in_any_protected, load_config, read_hook_input,  # noqa: E402
                  resolve, verdict)

cfg = load_config()
data = read_hook_input()

cmd = data.get("tool_input", {}).get("command", "")
# Claude Code sends the session cwd. Using the hook process cwd instead made
# the same relative command allowed or blocked depending on where the hook
# happened to be launched from.
session_cwd = data.get("cwd") or os.getcwd()

if not cmd.strip():
    verdict("allow", "no command")

# Commands that must never run from an agent, whatever path they touch.
# Checked first, on the raw string, so quoting tricks around the path logic
# cannot route around them. Patterns and reasons live in config.json.
for rule in cfg.get("deny_patterns", []):
    try:
        if re.search(rule["pattern"], cmd, flags=re.IGNORECASE):
            verdict("deny", f"denied by policy: {rule['reason']}")
    except (re.error, KeyError) as e:
        verdict("deny", f"malformed deny_patterns entry in config.json ({e}); failing closed")

READ_ONLY = set(cfg["read_only_verbs"])
FIND_WRITE_FLAGS = set(cfg["find_write_flags"])


def touches_protected(token, vcwd):
    t = token.strip("'\"")
    if not t or t.startswith("-"):
        return False
    return in_any_protected(resolve(t, vcwd), cfg)


# A literal absolute mention catches payloads handed to interpreters
# (sh -c "rm /abs/protected/x") and variable assignments (P=/abs/protected),
# where the protected path is inside a quoted string rather than a bare token.
touches = any(p in cmd for p in cfg["_protected_abs"])

segments = []
vcwd = session_cwd
# Split on shell separators AND subshell parens, tracking cwd across `cd`,
# because `cd somewhere && rm ../x` changes what a relative path means
# partway through the command.
for raw in re.split(r"(?:\|\||&&|[;|&()\n])+", cmd):
    seg = raw.strip()
    if not seg:
        continue
    try:
        toks = shlex.split(seg)
    except ValueError:
        verdict("deny", "unparseable quoting in the command, refusing to guess")
    if not toks:
        continue

    # strip leading VAR=value assignments; their values still count as mentions
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        if touches_protected(toks[0].split("=", 1)[1], vcwd):
            touches = True
        toks.pop(0)
    if not toks:
        continue

    verb = os.path.basename(toks[0]).lower()
    if verb == "cd":
        target = os.path.expanduser(toks[1].strip("'\"")) if len(toks) > 1 else os.path.expanduser("~")
        vcwd = target if os.path.isabs(target) else os.path.normpath(os.path.join(vcwd, target))
        continue

    segments.append((verb, toks, seg))
    for a in toks[1:]:
        if touches_protected(a, vcwd):
            touches = True
    for m in re.finditer(r"(?:>>?\||&>>?|>>?)\s*([^\s;|&()]+)", seg):
        if touches_protected(m.group(1), vcwd):
            verdict("deny", f"redirection into the protected tree: {m.group(1)}")

if not touches:
    verdict("allow", "command does not reference the protected tree")

for verb, toks, seg in segments:
    if verb == "find":
        if any(f in toks for f in FIND_WRITE_FLAGS):
            verdict("deny", f"find with an acting flag on the protected tree: {seg[:70]}")
        continue
    if verb not in READ_ONLY:
        verdict("deny", f"'{verb}' is not on the read-only allowlist and the "
                        f"command references the protected tree")

verdict("allow", "protected tree referenced, but only by read-only verbs")
