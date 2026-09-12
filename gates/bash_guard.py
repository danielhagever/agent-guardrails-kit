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
import fnmatch
import glob as globmod
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (in_any_protected, load_config, read_hook_input,  # noqa: E402
                  resolve, verdict, within)

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


def _clean(token):
    """Strip the punctuation tools put in front of a path.

    `curl -d @secrets/x` and `tar --file=secrets/x` both hide a path behind a
    prefix, and the first version of this guard read straight past both.
    """
    t = token.strip("'\"").strip()
    for prefix in ("@", "+", ":", "~+/", "file://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t


def touches_protected(token, vcwd):
    t = _clean(token)
    if not t or t.startswith("-"):
        return False
    return in_any_protected(resolve(t, vcwd), cfg)


def touches_secret(token, vcwd):
    t = _clean(token)
    if not t or t.startswith("-"):
        return False
    r = resolve(t, vcwd)
    return any(within(r, s) for s in cfg.get("_secret_abs", []))


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


def secret_mentions(token, vcwd, deep, depth=0):
    """Same walk as mentions_protected, but for the secret list."""
    if touches_secret(token, vcwd):
        return True
    if glob_reaches(token, vcwd, cfg.get("_secret_abs", [])):
        return True
    if any(touches_secret(p, vcwd) for p in slash_paths(token)):
        return True
    if "=" in token:
        tail = token.split("=", 1)[1]
        if tail and (touches_secret(tail, vcwd) or any(touches_secret(p, vcwd) for p in slash_paths(tail))):
            return True
    if not deep or depth >= 2 or not re.search(r"[\s'\"()]", token):
        return False
    try:
        inner = lex(token)
    except ValueError:
        inner = re.findall(r"[A-Za-z0-9_.~@%+=:,\-]+", token)
    if inner == [token]:
        return False
    return any(secret_mentions(t, vcwd, True, depth + 1) for t in inner)


def brace_expand(pattern, depth=0):
    """`protec{t,x}ed/x` is two patterns. The shell knows; the guard has to too."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", pattern)
    if not m or depth > 3:
        return [pattern]
    out = []
    for part in m.group(1).split(","):
        out += brace_expand(pattern[:m.start()] + part + pattern[m.end():], depth + 1)
    return out


def _pattern_reaches(pattern_abs, target_abs):
    """True when a glob pattern could match this path, or anything under it.

    Component by component, so `<cwd>/protec*/canary.txt` reaches into
    `<cwd>/protected`, and `[p]rotected` and `protecte?` do as well.
    """
    pc = pattern_abs.split(os.sep)
    tc = target_abs.split(os.sep)
    for i in range(min(len(pc), len(tc))):
        if not fnmatch.fnmatch(tc[i], pc[i]):
            return False
    return True


def glob_reaches(token, vcwd, targets):
    """Wildcards hid the path from every check above: rm protec*/canary.txt ran.

    Two passes, because a pattern can be dangerous before it matches anything:
    what it actually expands to on disk right now, and what it could match
    given the declared paths.
    """
    t = _clean(token)
    if not t or t.startswith("-") or not re.search(r"[*?\[\]{}]", t):
        return False
    for cand in brace_expand(t):
        try:
            for hit in globmod.glob(cand, root_dir=vcwd, recursive=True):
                if any(within(resolve(hit, vcwd), p) for p in targets):
                    return True
        except (ValueError, OSError):
            pass
        cand_abs = cand if os.path.isabs(cand) else os.path.normpath(os.path.join(vcwd, cand))
        if any(_pattern_reaches(cand_abs, p) for p in targets):
            return True
    return False


def slash_paths(token):
    """Path-like substrings (they contain a separator) inside a token."""
    return re.findall(r"[A-Za-z0-9_.~@%+=:,\-]*(?:/[A-Za-z0-9_.~@%+=:,\-]+)+/?", token)


def dynamic_near_protected(token, vcwd):
    """A token the shell will rewrite at run time, next to a protected name.

    `rm "$(pwd)/protected/x"` and `rm $HOME/secrets/.env` cannot be resolved
    statically: the text we see is not the path that will be opened. When such
    a token also contains the name of something protected, the only safe answer
    is no. Static analysis that guesses here is the bug, not the caution.
    """
    if not re.search(r"\$\(|\$\{|`|\$[A-Za-z_]", token):
        return False
    names = set()
    for p in cfg["_protected_abs"] + cfg.get("_secret_abs", []):
        names.add(os.path.basename(p))
        rel = os.path.relpath(p, vcwd)
        if not rel.startswith(".."):
            names.add(rel)
    return any(n and n in token for n in names)


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
    if dynamic_near_protected(token, vcwd):
        return True
    if glob_reaches(token, vcwd, cfg["_protected_abs"]):
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
        inner = []
    # A python or node payload is not shell: `open('config.json','w')` keeps the
    # filename inside quotes that shlex never sees, because the whole payload was
    # already one shell token. Pull every quoted literal and bare word out of it.
    inner += re.findall(r"'([^']*)'|\"([^\"]*)\"", token) and [
        m for pair in re.findall(r"'([^']*)'|\"([^\"]*)\"", token) for m in pair if m]
    inner += re.findall(r"[A-Za-z0-9_.~@%+=:,\-]+", token)
    inner = [t for t in inner if t and t != token]
    if not inner:
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
        value = toks[0].split("=", 1)[1]
        # `S=secrets/.env; cat $S` hid a secret behind one letter.
        if cfg.get("_secret_abs") and secret_mentions(value, vcwd, True):
            verdict("deny", "a variable in this command points at a secret path; "
                            "secrets are denied to every verb, reads included")
        if mentions_protected(value, vcwd, True):
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
        if cfg.get("_secret_abs") and secret_mentions(a, vcwd, deep):
            verdict("deny", f"'{verb}' would touch a secret path; secrets are denied to every verb, "
                            f"reads included")
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
