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
INTERPRETERS = set(cfg.get("interpreter_verbs", []))
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

# --------------------------------------------------------------- tokenising
# The first version split the RAW command on ;|&() and only then ran shlex on
# each piece. That splits INSIDE quotes: `python -c "import os; os.remove(p)"`
# became two fragments with unbalanced quotes and was denied for "unparseable
# quoting" rather than for the path it touches. A block produced by a parse
# accident is exactly the failure this guard exists to be free of, and the
# same flaw let `perl -e 'unlink "protected/x"'` through, because that one
# parses cleanly and the payload is a single token that resolves to nothing.
#
# So: lex the whole command once with quotes respected (punctuation_chars puts
# ; | & ( ) < > in their own tokens), then look at structure, then look INSIDE
# each quoted token, since that is where an interpreter payload lives.
PUNCT = {";", "|", "||", "&", "&&", "|&", "(", ")", "\n"}
REDIR = {">", ">>", "<", "<<", ">|", "&>", "&>>", "2>", "2>>"}


def lex(text):
    """Shell tokens with quotes respected. Raises ValueError on bad quoting."""
    lx = shlex.shlex(text, posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    return list(lx)


def slash_paths(token):
    """Path-like substrings (they contain a separator) inside a token."""
    return re.findall(r"[A-Za-z0-9_.~@%+=:,\-]*(?:/[A-Za-z0-9_.~@%+=:,\-]+)+/?", token)


def mentions_protected(token, vcwd, deep, depth=0):
    """True when this token, or anything inside it, points into a protected tree.

    `deep` is on only for interpreter verbs (sh -c, python -c, perl -e, xargs
    and friends), because that is where an executable payload can hide a BARE
    name: `python -c 'shutil.rmtree("secrets")'`. Turning it on everywhere
    blocked `git commit -m "stop touching secrets"`, which is prose, not a
    path, and a guard that blocks commit messages gets switched off by the
    team in a week. Anything containing a separator is checked for every verb.
    """
    if touches_protected(token, vcwd):
        return True
    if any(touches_protected(p, vcwd) for p in slash_paths(token)):
        return True
    # `dd of=protected/x`, `tar --file=protected/x`: the value after the first
    # `=` is a path even though the whole token never resolves to one.
    if "=" in token:
        tail = token.split("=", 1)[1]
        if tail and (touches_protected(tail, vcwd)
                     or any(touches_protected(p, vcwd) for p in slash_paths(tail))):
            return True
    if not deep or depth >= 2 or not re.search(r"[\s'\"()]", token):
        return False
    try:
        inner = lex(token)
    except ValueError:
        inner = re.findall(r"[A-Za-z0-9_.~@%+=:,\-]+", token)
    if inner == [token]:
        return False
    return any(mentions_protected(t, vcwd, True, depth + 1) for t in inner)


try:
    tokens = lex(cmd)
except ValueError as e:
    verdict("deny", f"unparseable quoting in the command, refusing to guess: {e}")

raw_segments = [[]]
for t in tokens:
    if t in PUNCT:
        raw_segments.append([])
    else:
        raw_segments[-1].append(t)

segments = []
vcwd = session_cwd
# cwd is tracked across `cd` because `cd somewhere && rm ../x` changes what a
# relative path means partway through the command.
for toks in raw_segments:
    if not toks:
        continue

    # strip leading VAR=value assignments; their values still count as mentions
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        if mentions_protected(toks[0].split("=", 1)[1], vcwd, True):
            touches = True
        toks.pop(0)
    if not toks:
        continue

    verb = os.path.basename(toks[0]).lower()
    deep = verb in INTERPRETERS
    if verb == "cd":
        target = os.path.expanduser(toks[1]) if len(toks) > 1 else os.path.expanduser("~")
        vcwd = target if os.path.isabs(target) else os.path.normpath(os.path.join(vcwd, target))
        continue

    segments.append((verb, toks, " ".join(toks)[:70]))
    for i, a in enumerate(toks[1:], start=1):
        if a in REDIR:
            if i + 1 < len(toks) and touches_protected(toks[i + 1], vcwd):
                verdict("deny", f"redirection into the protected tree: {toks[i + 1]}")
            continue
        if mentions_protected(a, vcwd, deep):
            touches = True

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
