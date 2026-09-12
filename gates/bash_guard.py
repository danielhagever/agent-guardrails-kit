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
import json
import os
import re
import shlex
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import (abs_pattern, clean_uri, deadline, in_any_protected,  # noqa: E402
                  load_config, pattern_reaches, read_hook_input, resolve,
                  shares_inode, verdict, within)

deadline(8)
cfg = load_config()
data = read_hook_input()

raw_input_block = data.get("tool_input")
if not isinstance(raw_input_block, dict):
    verdict("deny", "tool_input is not an object; refusing to guess what this call does")
cmd = raw_input_block.get("command", "")
if not isinstance(cmd, str):
    # A number, a list or null here used to raise, and a gate that raises exits
    # with neither 0 nor 2: the hook layer calls that broken, and a broken gate
    # does not stop the tool call. Crashing is an allow, so it has to deny.
    verdict("deny", f"the command is a {type(cmd).__name__}, not a string; refusing to guess")
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
    t = clean_uri(token).strip("'\"").strip()
    for prefix in ("@", "+", ":", "~+/"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t


def touches_protected(token, vcwd):
    t = _clean(token)
    if not t or t.startswith("-"):
        return False
    r = resolve(t, vcwd)
    return in_any_protected(r, cfg) or shares_inode(r, cfg["_protected_abs"])


def touches_secret(token, vcwd):
    t = _clean(token)
    if not t or t.startswith("-"):
        return False
    r = resolve(t, vcwd)
    return (any(within(r, s) for s in cfg.get("_secret_abs", []))
            or shares_inode(r, cfg.get("_secret_abs", [])))


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
        cand_abs = abs_pattern(cand, vcwd)
        if any(pattern_reaches(cand_abs, p) for p in targets):
            return True
        # `rm **/**/**/**/*.txt` made the guard take eight seconds on 600
        # directories, and minutes on a real repository with node_modules. A
        # gate that slow is a gate the runtime gives up on, and giving up does
        # not stop the tool call, so a pathological pattern was a bypass. The
        # static check above already answers every `**` correctly, so the walk
        # is skipped for those and time-boxed for the rest.
        if cand.count("**") > 1:
            continue
        started = time.monotonic()
        try:
            for n, hit in enumerate(globmod.iglob(cand, root_dir=vcwd, recursive=True)):
                if any(within(resolve(hit, vcwd), p) for p in targets):
                    return True
                if n > 20_000 or (n % 256 == 0 and time.monotonic() - started > 1.5):
                    break
        except (ValueError, OSError):
            pass
    return False


def script_mentions(path_token, vcwd, seen=None):
    """Read the file a command is about to execute, and judge its contents.

    `echo 'rm protected/x' > work/go.sh; sh work/go.sh` passed every check:
    the first half writes to an allowed path, the second half mentions nothing
    protected. The damage lives in the file. So when a command runs a file that
    exists in the workspace, the file is read and scanned like a command.

    npm and make keep their commands somewhere else again, so `npm run wipe`
    and `make target` are followed into package.json and the Makefile.
    """
    seen = seen or set()
    t = _clean(path_token)
    if not t or t.startswith("-"):
        return False
    p = resolve(t, vcwd)
    if p in seen or not os.path.isfile(p):
        return False
    seen.add(p)
    try:
        if os.path.getsize(p) > 256_000:
            return False
        with open(p, encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return False
    # Archives and other binaries are read here on purpose (a tar header names
    # its entries in plain text, which is how zip-slip is caught). They also
    # contain NUL bytes, and a NUL inside a path raises in os.path.realpath:
    # the gate died, and a dead gate does not stop the tool call.
    text = text.replace("\x00", " ")
    bases = [vcwd, os.path.dirname(p)]
    for line in text.splitlines():
        # a diff names its target as a/path and b/path; git apply strips those,
        # and so must this, or the file it is about to patch is invisible
        if re.match(r"^(---|\+\+\+|diff --git|rename (from|to)|Index:)", line):
            line = re.sub(r"(^|\s)[ab]/", " ", line)
        line = line.strip().lstrip("\t")
        if not line or line.startswith("#"):
            continue
        for piece in re.split(r"[;&|]+", line):
            for tok in re.findall(r"[^\s'\"]+|'[^']*'|\"[^\"]*\"", piece):
                for base in bases:
                    if mentions_protected(tok, base, True) or (
                            cfg.get("_secret_abs") and secret_mentions(tok, base, True)):
                        return True
    return False


def _scan_text(text, bases):
    for line in text.splitlines():
        line = line.strip().lstrip("\t")
        if not line or line.startswith("#"):
            continue
        for piece in re.split(r"[;&|]+", line):
            for tok in re.findall(r"[^\s'\"]+|'[^']*'|\"[^\"]*\"", piece):
                for base in bases:
                    if mentions_protected(tok, base, True) or (
                            cfg.get("_secret_abs") and secret_mentions(tok, base, True)):
                        return True
    return False


def npm_or_make_target(toks, vcwd):
    """`npm run wipe` and `make wipe` hide the command in another file.

    Only the target that was actually asked for is judged. Scanning the whole
    file blocked `make build` because some other target in the same Makefile
    mentioned a protected path, which is a false positive a team would not
    forgive.
    """
    verb = os.path.basename(toks[0]).lower()
    args = [a for a in toks[1:] if a not in ("run", "run-script")]
    if verb in ("npm", "pnpm", "yarn", "bun"):
        prefix = vcwd
        for i, a in enumerate(args):
            if a in ("--prefix", "-C") and i + 1 < len(args):
                prefix = os.path.normpath(os.path.join(vcwd, args[i + 1]))
        wanted = [a for a in args if not a.startswith("-") and a not in (prefix, os.path.basename(prefix))]
        pkg = os.path.join(prefix, "package.json")
        if not os.path.isfile(pkg):
            return False
        try:
            scripts = json.load(open(pkg, encoding="utf-8")).get("scripts", {})
        except (ValueError, OSError):
            return False
        targets = [scripts[w] for w in wanted if w in scripts] or list(scripts.values())[:0]
        return any(_scan_text(t, [prefix, vcwd]) for t in targets)
    if verb in ("make", "gmake"):
        mk, wanted = "Makefile", []
        skip = False
        for i, a in enumerate(args):
            if skip:
                skip = False
                continue
            if a == "-f" and i + 1 < len(args):
                mk = args[i + 1]
                skip = True
            elif not a.startswith("-"):
                wanted.append(a)
        path = resolve(mk, vcwd)
        if not os.path.isfile(path):
            return False
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            return False
        recipes, current = {}, None
        for line in text.splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-/]+)\s*:(?!=)", line)
            if m:
                current = m.group(1)
                recipes[current] = []
            elif current and line.startswith(("\t", "    ")):
                recipes[current].append(line.strip())
            elif not line.strip():
                current = None
        chosen = wanted or (list(recipes)[:1])
        return any(_scan_text("\n".join(recipes.get(t, [])), [os.path.dirname(path), vcwd])
                   for t in chosen)
    return False


def runs_file_contents(verb, toks):
    """Does this command EXECUTE what is in the file, or merely handle the file?

    Round three taught the guard to read the file a command runs, because
    `echo 'rm protected/x' > work/go.sh; sh work/go.sh` mentions nothing
    protected. It then read that file for EVERY verb, which is how `cat
    README.md` came to be denied in a repository whose README simply names the
    protected directory in prose. That is the false positive that gets a guard
    switched off, so the scan is now scoped to commands that actually run,
    unpack or apply what they are given.
    """
    if verb in INTERPRETERS:
        return True
    flags = [t for t in toks[1:] if t.startswith("-")]
    if verb in ("unzip", "unar", "patch"):
        return True
    if verb in ("tar", "bsdtar", "jar", "cpio", "7z", "7za"):
        # extracting reads the entry names OUT of the archive; creating one
        # only reads ordinary files, whose prose is nobody's business
        return any(re.search(r"[xi]", f) for f in flags)
    if verb == "git" and "apply" in toks[1:3]:
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



ALWAYS_RECURSIVE = {"rg", "ag", "ack", "rsync", "ditto", "cpio", "scp", "sftp",
                    "tar", "zip", "7z", "jar"}
COPY_LIKE = {"cp", "rsync", "scp", "ditto", "install", "mv", "cpio"}
EXCLUDE_FLAGS = ("--exclude", "--exclude-dir", "--ignore", "--ignore-dir")


def _exclusion_values(toks):
    """What the command already promised not to look at."""
    out = []
    for i, t in enumerate(toks):
        if t.startswith(EXCLUDE_FLAGS) and "=" in t:
            out.append(_clean(t.split("=", 1)[1]))
        elif t in EXCLUDE_FLAGS and i + 1 < len(toks):
            out.append(_clean(toks[i + 1]))
    return out


def is_exclusion_token(toks, i):
    """An `--exclude-dir=secrets` NAMES the secret in order to avoid it.

    Without this the escape hatch is unusable: the flag that makes the command
    safe was itself read as a reference to the secret path and denied, so the
    only advice the guard could give was advice it then refused.
    """
    t = toks[i]
    if t.startswith(EXCLUDE_FLAGS):
        return True
    return i > 0 and toks[i - 1] in EXCLUDE_FLAGS


def _excluded(tree, excl, vcwd):
    base = os.path.basename(tree)
    for e in excl:
        if not e:
            continue
        if e == base or resolve(e, vcwd) == tree or fnmatch.fnmatch(base, e):
            return True
    return False


def reads_tree_from_above(verb, toks, vcwd):
    """A recursive command rooted ABOVE a secret tree walks straight into it.

    Nothing in `grep -r KEY .` or `tar -cf work/all.tar .` names the secret,
    so every check in this file that looks at the paths in a command said yes.
    The command still reads the credential, because the tree it was pointed at
    contains the tree that was declared off limits. This is the round-six hole
    with the shortest command and the widest reach.
    """
    if verb not in cfg.get("recursive_readers", []) or not cfg.get("_secret_abs"):
        return None
    flags = [t for t in toks[1:] if t.startswith("-")]
    recursive = verb in ALWAYS_RECURSIVE or any(
        f.startswith("--recursive") or (re.match(r"^-[A-Za-z]+$", f) and re.search(r"[rRa]", f))
        for f in flags)
    if not recursive:
        return None
    if verb in ("tar", "jar", "7z", "cpio") and any(re.match(r"^-?[a-zA-Z]*x", f) for f in flags):
        # Extraction reads the archive, not the tree it unpacks into, so the
        # directory after -C is a destination and not a tree being walked.
        # What an archive would WRITE is judged by reading its entry names,
        # which are plain text in both tar and zip headers.
        return None
    excl = _exclusion_values(toks)
    operands = [t for i, t in enumerate(toks[1:], start=1)
                if not t.startswith("-") and not is_exclusion_token(toks, i)]
    if verb in COPY_LIKE and len(operands) > 1:
        operands = operands[:-1]          # the destination is not a source
    starts = [resolve(_clean(t), vcwd) for t in operands]
    starts = [s for s in starts if s and os.path.isdir(s)]
    if not starts and verb in ("rg", "ag", "ack"):
        starts = [resolve(".", vcwd)]     # these search the working directory by default
    for s in starts:
        for sec in cfg["_secret_abs"]:
            if sec != s and within(sec, s) and not _excluded(sec, excl, vcwd):
                return sec
    return None


def _find_selects(name, full, pats):
    for flag, pat in pats:
        target = name if flag in ("-name", "-iname") else full
        try:
            if flag == "-regex":
                if re.search(pat, full):
                    return True
            elif fnmatch.fnmatch(target.lower() if flag.startswith("-i") else target,
                                 pat.lower() if flag.startswith("-i") else pat):
                return True
        except re.error:
            return True
    return False


def _tree_has_match(tree, pats, cap=5000):
    """Would this find(1) filter select anything inside the tree?

    A declared path is often a single file (`.env`), and os.walk on a file
    yields nothing, so the tree looked empty and the filter looked harmless.
    """
    if os.path.isfile(tree):
        return _find_selects(os.path.basename(tree), tree, pats)
    seen = 0
    for root, dirs, files in os.walk(tree):
        for name in list(dirs) + files:
            seen += 1
            if seen > cap:
                return True               # too large to verify: refuse
            if _find_selects(name, os.path.join(root, name), pats):
                return True
    return False


def find_walks_into(toks, vcwd):
    """`find . -name '.env' -exec cat {} +` names nothing and reads everything.

    find is the one verb that is given a place to START rather than a path to
    act on, so the existing rule (does any token resolve into a guarded tree)
    could never see it. Judged here by where it would walk to instead.
    """
    roots = []
    for a in toks[1:]:
        if a.startswith("-"):
            break
        roots.append(a)
    if not roots:
        roots = ["."]
    pats = [(a, _clean(toks[i + 1])) for i, a in enumerate(toks)
            if a in ("-name", "-iname", "-path", "-ipath", "-wholename", "-regex")
            and i + 1 < len(toks)]
    acting = any(f in toks for f in FIND_WRITE_FLAGS)
    for r in roots:
        start = resolve(_clean(r), vcwd)
        if not start:
            continue
        for tree in cfg["_protected_abs"]:
            if tree == start or not within(tree, start):
                continue                  # only a STRICT ancestor walks into it
            is_secret = any(within(tree, sec) for sec in cfg.get("_secret_abs", []))
            hits = _tree_has_match(tree, pats) if pats else True
            if not hits:
                continue                  # the filter cannot select anything in there
            if acting or is_secret:
                return tree, acting, is_secret
    return None


def copy_lands_in_protected(verb, toks, vcwd):
    """A source tree shaped like the repository needs no ../ to climb.

    The zip-slip tests all used `../`, which the file scanner catches in the
    archive header. This one does not: work/climb/protected/canary.txt copied
    or unpacked AT THE ROOT lands on the protected file by plain arithmetic,
    and every token in the command points somewhere harmless.
    """
    if verb not in COPY_LIKE:
        return None
    operands = [t for t in toks[1:] if not t.startswith("-")]
    if len(operands) < 2:
        return None
    dest = resolve(_clean(operands[-1]), vcwd)
    if not dest:
        return None
    for src in operands[:-1]:
        s = resolve(_clean(src), vcwd)
        if not s or not os.path.isdir(s):
            continue
        try:
            names = sorted(os.listdir(s))[:500]
        except OSError:
            continue
        landings = [os.path.join(dest, n) for n in names]
        landings.append(os.path.join(dest, os.path.basename(s)))
        for land in landings:
            if in_any_protected(land, cfg):
                return land
    return None


def alias_built_mid_command(verb, toks, more_follows):
    """`ln -s $(printf 'pro%sed' tect) work/a; echo PWNED > work/a/canary.txt`

    Every path check in this file resolves symlinks, which is why aliases that
    already exist are caught. This one does not exist yet: it is created by
    the first half of the command and used by the second, so at the moment the
    guard is asked, the dangerous path resolves to nothing. On the NEXT tool
    call the link is real and the same checks catch it, so the only case that
    has to fail closed is a link whose target cannot be read now, inside a
    command that carries on afterwards.
    """
    if verb != "ln" or not more_follows:
        return False
    operands = [t for t in toks[1:] if not t.startswith("-")]
    if not operands:
        return False
    # `$` alone is enough: `ln -s $(printf '../pro%sed' tect) work/a` lexes the
    # substitution into separate tokens, so the operand the guard sees is the
    # single character `$`. Anything the shell will rewrite counts.
    return bool(re.search(r"[$`*?\[]", operands[0]))


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
live_segments = [t for t in raw_segments if t]
last_idx = len(live_segments) - 1
for idx, toks in enumerate(live_segments):

    # strip leading VAR=value assignments; their values still count as mentions
    path_dirs = []
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        name, value = toks[0].split("=", 1)
        if name == "PATH":
            # `PATH=work:$PATH rmx` runs work/rmx, and nothing in the command
            # line says so. The directories it prepends are where to look.
            path_dirs += [d for d in value.split(":") if d and "$" not in d]
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
    for d in path_dirs:
        # `PATH=work:$PATH rmx` runs work/rmx and says nothing about it.
        if script_mentions(os.path.join(d, verb), vcwd):
            verdict("deny", f"'{verb}' resolves through a PATH this command sets itself, to a file "
                            f"that references a protected or secret path")
    if verb == "cd":
        target = os.path.expanduser(toks[1]) if len(toks) > 1 else os.path.expanduser("~")
        vcwd = target if os.path.isabs(target) else os.path.normpath(os.path.join(vcwd, target))
        continue

    segments.append((verb, toks, " ".join(toks)[:70]))

    reached = reads_tree_from_above(verb, toks, vcwd)
    if reached:
        verdict("deny", f"'{verb}' would walk into {os.path.basename(reached)} from a directory "
                        f"above it; secrets are denied to every verb, reads included. Narrow the "
                        f"path, or pass --exclude-dir={os.path.basename(reached)}")
    if verb == "find":
        walk = find_walks_into(toks, vcwd)
        if walk:
            tree, acting, is_secret = walk
            verdict("deny", f"find starts above {os.path.basename(tree)} and would "
                            f"{'act on' if acting else 'select'} what is inside it; "
                            f"{'secrets are denied to every verb' if is_secret else 'that tree is protected'}")
    landed = copy_lands_in_protected(verb, toks, vcwd)
    if landed:
        verdict("deny", f"'{verb}' would put a file at {landed}, inside the protected tree, "
                        f"without naming it: the source is shaped like the repository")
    if alias_built_mid_command(verb, toks, idx < last_idx):
        verdict("deny", "this command builds a link whose target cannot be resolved yet and then "
                        "keeps going; a hard link would be a second name for a guarded file and a "
                        "symlink a second path to it, and neither exists at the moment of the check")
    # toks[0] too: `rm${IFS}protected/x` is one token, and a line continuation
    # splits `rm \\<newline> protected/x` so that the path BECOMES the verb.
    # Scanning only the arguments missed both.
    for i, a in enumerate(toks, start=0):
        if a in REDIR:
            if i + 1 < len(toks) and touches_protected(toks[i + 1], vcwd):
                verdict("deny", f"redirection into the protected tree: {toks[i + 1]}")
            continue
        if i == 0 and a == toks[0] and verb in READ_ONLY and not re.search(r"[${}]", a):
            continue
        if is_exclusion_token(toks, i):
            continue
        if cfg.get("_secret_abs") and secret_mentions(a, vcwd, deep):
            verdict("deny", f"'{verb}' would touch a secret path; secrets are denied to every verb, "
                            f"reads included")
        if mentions_protected(a, vcwd, deep):
            touches = True

if not touches:
    # Last stop: a command can reference nothing protected and still be the
    # attack, because the path is inside the file it runs.
    for verb, toks, seg in segments:
        if npm_or_make_target(toks, session_cwd):
            verdict("deny", f"'{verb}' runs a target whose command references a protected or secret path")
        if verb in ("make", "gmake", "npm", "pnpm", "yarn", "bun"):
            # already judged above, target by target. Reading the whole Makefile
            # here blocked `make build` because a different target mentioned a
            # protected path, which is exactly the false positive to avoid.
            continue
        # toks[0] is always read: `./work/z.sh` is the file being run. The rest
        # only when the verb is one that runs, unpacks or applies its arguments.
        scan = toks if runs_file_contents(verb, toks) else toks[:1]
        for tok in scan:
            if script_mentions(tok, session_cwd):
                verdict("deny", f"'{verb}' would execute {tok[:50]}, whose contents reference a "
                                f"protected or secret path")
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
