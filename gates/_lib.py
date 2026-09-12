#!/usr/bin/env python3
"""Shared contract for every gate in this lab.

A gate is a small program. Claude Code hands it JSON on stdin, it decides,
and its EXIT CODE is the decision. Everything a gate author needs to get
right is here so it cannot be got wrong twice.

THE CONTRACT
------------
Exit codes:
    0   allow / pass
    1   fail        Stop-style gates: the check did not pass
    2   deny        PreToolUse gates: block the tool call before it runs
    other           treated by the hook layer as "the gate is broken",
                    which is deliberately distinct from "the gate said no"

Output: exactly ONE line of JSON on stdout, {"verdict": ..., "reason": ...}.
Nothing else may be printed to stdout, because the hook parses that line and
only that line. Human-facing explanation goes to stderr, where Claude Code
surfaces it back to the model.

Failing closed: every helper here refuses rather than guesses. An unreadable
payload, a missing config key or a path that cannot be resolved all deny. A
guard that waves something through when confused is worse than no guard,
because the settings file then claims a protection that does not exist.

TO ADD A GATE
-------------
    from _lib import load_config, read_hook_input, verdict, within, resolve

    cfg  = load_config()
    data = read_hook_input()
    ...
    verdict("allow", "why")            # PreToolUse: deny_code defaults to 2
    verdict("fail", "why", fail_code=1)  # Stop-style

Then wire it in .claude/settings.json and add a test to tests/run_tests.sh
that proves it fires by deliberately doing the thing it must catch.
"""
import datetime
import json
import os
import re
import sys
import unicodedata

_LAST_INPUT = {}

LAB = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CONFIG_PATH = os.path.join(LAB, "config.json")

_REQUIRED_KEYS = ("allowed_tree", "protected_paths", "read_only_verbs",
                  "find_write_flags", "path_keys", "deliverable")


def die(reason, code=2):
    """Refuse with a legible reason. Used when the gate itself cannot run."""
    print(json.dumps({"verdict": "deny", "reason": reason}))
    print(f"BLOCKED: {reason}", file=sys.stderr)
    sys.exit(code)


def _deny_on_crash(exc_type, exc, tb):
    """Any unhandled error in a gate becomes a DENY, not a crash.

    Round five found one input that crashed the guard and fixed that input.
    Round six found another (a NUL byte in a file the guard reads), which
    means the class is the bug, not the instance: a gate that raises exits
    with a code the hook layer reads as "broken", and a broken gate does not
    stop the tool call. Crashing is therefore an ALLOW, and the only safe
    behaviour for a bug nobody has found yet is to refuse.
    """
    try:
        import traceback
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass
    die(f"the guard hit an unexpected error and cannot decide "
        f"({getattr(exc_type, '__name__', 'error')}: {exc}); failing closed")


sys.excepthook = _deny_on_crash


def deadline(seconds=8):
    """Refuse if the gate has not decided within `seconds`.

    The same asymmetry again: a hook that never returns is a hook the runtime
    gives up on, and giving up does not stop the tool call. A pathological
    glob over a large repository is therefore a bypass unless slowness itself
    denies. Not available on platforms without SIGALRM, where the runtime's
    own timeout is the only backstop.
    """
    try:
        import signal

        def _out_of_time(_sig, _frame):
            die(f"the guard could not decide within {seconds} seconds; failing closed")

        signal.signal(signal.SIGALRM, _out_of_time)
        signal.alarm(seconds)
    except (ImportError, AttributeError, ValueError, OSError):
        pass


def shares_inode(path, trees, cap=50_000):
    """True when this file IS a protected file under another name.

    realpath resolves symlinks and sees nothing here: a hard link is not a
    reference to a path, it is a second name for the same inode, and the file
    it names has no memory of where it was linked from. `find . -name .env
    -exec ln {} work/hl` then `cat work/hl` reads the credential through a
    path that looks like ordinary work. Only files with more than one link are
    ever scanned for, so the walk almost never happens.
    """
    if not path:
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    if not os.path.isfile(path) or getattr(st, "st_nlink", 1) < 2:
        return False
    key = (st.st_dev, st.st_ino)
    seen = 0
    for tree in trees:
        # A declared path can be a single FILE (.env is the common case), and
        # os.walk on a file yields nothing at all, so the hard link to it was
        # invisible. Found on a client-shaped install, not in the lab, where
        # every declared path happened to be a directory.
        if os.path.isfile(tree):
            try:
                s1 = os.stat(tree)
            except OSError:
                continue
            if (s1.st_dev, s1.st_ino) == key:
                return True
            continue
        for root, _dirs, files in os.walk(tree):
            for fn in files:
                seen += 1
                if seen > cap:
                    return True     # too large to verify in time: refuse
                try:
                    s2 = os.stat(os.path.join(root, fn))
                except OSError:
                    continue
                if (s2.st_dev, s2.st_ino) == key:
                    return True
    return False


def declared_paths(pattern, base):
    """Every real path a policy entry names.

    Two entries a person would reasonably write protected NOTHING, silently:
    `~/secrets` (nobody expanded the tilde, so it guarded a directory literally
    called `~`) and `infra/*/prod` (a wildcard is not a path, so it resolved to
    something that does not exist). Silence is the worst possible answer here,
    because the settings file then claims a protection that is not there.
    """
    p = os.path.expanduser(str(pattern))
    if re.search(r"[*?\[]", p):
        import glob as _glob
        root = p if os.path.isabs(p) else os.path.join(base, p)
        hits = sorted({os.path.realpath(h) for h in _glob.glob(root, recursive=True)})
        if hits:
            return hits
        print(f"guardrails: the policy entry {pattern!r} matches nothing on disk right now; "
              f"it protects a future path only", file=sys.stderr)
    return [resolve(p, base)]


def load_config():
    """Read config.json, or refuse.

    A missing or malformed policy file must never mean "no policy". It means
    the guard cannot know what to protect, which is a stop condition.
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        die(f"policy file missing: {CONFIG_PATH}")
    except json.JSONDecodeError as e:
        die(f"policy file is not valid JSON ({CONFIG_PATH}): {e}")

    missing = [k for k in _REQUIRED_KEYS if k not in cfg]
    if missing:
        die(f"policy file is missing required key(s): {', '.join(missing)}")

    cfg["_allowed_tree_abs"] = resolve(os.path.expanduser(cfg["allowed_tree"]), LAB)
    cfg["_protected_abs"] = [q for p in cfg["protected_paths"] for q in declared_paths(p, LAB)]
    # Content-is-the-asset paths: every verb is denied on these, reads included.
    cfg["_secret_abs"] = [q for p in cfg.get("secret_paths", []) for q in declared_paths(p, LAB)]
    # The guard protects itself. An agent that can rewrite config.json or delete
    # gates/bash_guard.py can turn every other rule off, so those paths join the
    # protected list unless the policy switches it off on purpose.
    if cfg.get("self_protect", True):
        # The guard's own machinery only. Protecting the whole directory looked
        # thorough and broke ordinary work: in the lab, where the kit IS the
        # project, `git status` and writes to scratch/ all became "references
        # the protected tree". A guard that blocks the day job gets removed.
        selfies = [os.path.join(LAB, n) for n in
                   ("config.json", "gates", "hooks", "tests", ".claude")]
        selfies.append(os.path.join(os.path.dirname(LAB), ".claude"))
        for s_ in selfies:
            r = os.path.realpath(s_)
            if r not in cfg["_protected_abs"]:
                cfg["_protected_abs"].append(r)
    # Files something else executes later. Resolved against the project root, so
    # an installed copy guards the repository's hooks and workflows rather than
    # the kit's own directory.
    if cfg.get("protect_execution_surface", True):
        root = cfg["_allowed_tree_abs"]
        for rel in cfg.get("execution_surface", []):
            r = resolve(rel, root)
            if r not in cfg["_protected_abs"]:
                cfg["_protected_abs"].append(r)
    # The audit log is the evidence. A client who moves it out of the guarded
    # tree (an absolute path, or ../logs/) could have it deleted by the agent it
    # is meant to record, so wherever it is, it joins the protected list.
    if cfg.get("self_protect", True) and cfg.get("audit_log"):
        log = resolve(os.path.expanduser(cfg["audit_log"]), LAB)
        if log and log not in cfg["_protected_abs"]:
            cfg["_protected_abs"].append(log)
    # Files outside the repository that decide what runs later. ~/.claude/
    # settings.json can inject an env var into every future agent shell, which
    # is round seven's whole family delivered through a file the repo rules
    # never looked at.
    if cfg.get("protect_home_surface", True):
        home = os.path.expanduser("~")
        if home and home != "~":
            for rel in cfg.get("home_execution_surface", []):
                r = os.path.realpath(os.path.join(home, rel))
                if r not in cfg["_protected_abs"]:
                    cfg["_protected_abs"].append(r)
    cfg["_protected_abs"] += [p for p in cfg["_secret_abs"] if p not in cfg["_protected_abs"]]
    if not cfg["_protected_abs"]:
        die("policy file lists no protected_paths; refusing to run a guard "
            "that protects nothing")
    return cfg


def read_hook_input(argv_fallback=True):
    """Parse the hook payload from argv[1] or stdin, or refuse.

    argv is supported because the shell wrappers pass the body through when
    they need to read it twice; stdin is the normal path.
    """
    raw = None
    if argv_fallback and len(sys.argv) > 1 and sys.argv[1].strip():
        raw = sys.argv[1]
    else:
        try:
            raw = sys.stdin.read()
        except Exception as e:
            die(f"could not read hook input from stdin: {e}")
    try:
        data = json.loads(raw)
    except Exception as e:
        die(f"hook input is not valid JSON, refusing to guess: {e}")
    if isinstance(data, dict):
        _LAST_INPUT.clear()
        _LAST_INPUT.update(data)
    return data


def resolve(path_str, base):
    """Absolute, symlink-resolved path. Relative paths resolve against base.

    Resolution happens before any comparison, which is what makes `../` and
    symlink dodges fail rather than succeed.
    """
    if not path_str:
        return ""
    # The shell expands ~ before the command ever runs, so a guard that does not
    # is comparing a string the kernel will never see. `echo x >> ~/.zshrc`
    # resolved to <repo>/~/.zshrc and missed the file it was about to change.
    if path_str.startswith("~"):
        path_str = os.path.expanduser(path_str)
    p = path_str if os.path.isabs(path_str) else os.path.join(base, path_str)
    try:
        return os.path.realpath(p)
    except (ValueError, OSError):
        # A NUL byte inside the string raises here. That mattered: the guard
        # scans the CONTENTS of files a command will run, a tar header is
        # binary, and `tar -xf anything.tar` crashed the gate. A crashed gate
        # exits with neither 0 nor 2, which the hook layer calls broken, and a
        # broken gate does not stop the tool call. So this returns nothing,
        # which matches nothing, and the caller's own checks still apply.
        return ""


def _fs_is_case_insensitive():
    """macOS and Windows open PROTECTED/x when you asked for protected/x.

    The guard compared paths byte for byte, so `rm PROTECTED/canary.txt` ran.
    Measured once against the real filesystem rather than assumed from the
    platform name, because a case-sensitive volume on a Mac is a normal thing.
    """
    probe = os.path.join(LAB, "config.json")
    try:
        return os.path.exists(probe) and os.path.exists(probe.upper())
    except OSError:
        return False


CASE_INSENSITIVE = _fs_is_case_insensitive()


def _cmp(path):
    """One spelling of a path, so two names for the same file compare equal.

    macOS stores what you typed but treats composed and decomposed Unicode as
    the same file, so a policy naming `protégé/` and a command spelling it
    `prote\u0301gé/` were the same directory to the filesystem and two
    different strings to the guard. Normalising makes them one again; for
    ASCII, which is most policies, this changes nothing.
    """
    path = unicodedata.normalize("NFC", path)
    return path.lower() if CASE_INSENSITIVE else path


def within(resolved_path, tree):
    """True when resolved_path is tree itself or sits underneath it."""
    if not resolved_path or not tree:
        return False
    a, b = _cmp(resolved_path), _cmp(tree)
    return a == b or a.startswith(b + os.sep)


def clean_uri(token):
    """Strip the wrappers a tool puts around a path before it becomes one.

    An MCP server handed `file:///repo/secrets/.env` or `work/%2e%2e/secrets/.env`
    walked past a guard that compared the raw string, because neither is a path
    until something decodes it. Both forms are decoded here, and the caller
    checks the decoded one as well as the original.
    """
    import urllib.parse
    t = token.strip()
    for scheme in ("file://localhost", "file://", "file:"):
        if t.lower().startswith(scheme):
            t = t[len(scheme):]
            break
    if "%" in t:
        try:
            t = urllib.parse.unquote(t)
        except (ValueError, UnicodeDecodeError):
            pass
    return t


def abs_pattern(raw, cwd):
    """Absolute form of a glob, with the fixed part resolved for real.

    normpath was not enough: on macOS `/var` is a symlink to `/private/var`, so
    a pattern built with normpath and a target resolved with realpath disagreed
    on the very first component, and `**/.env` was judged unable to reach a
    secret that it plainly matches. Only the part before the first wildcard can
    be resolved; the rest stays as written.
    """
    parts = raw.split(os.sep)
    wild = next((i for i, p in enumerate(parts) if any(c in p for c in "*?[")), len(parts))
    prefix = os.sep.join(parts[:wild]) or ("." if not raw.startswith(os.sep) else os.sep)
    base = resolve(prefix, cwd)
    return os.path.join(base, *parts[wild:]) if parts[wild:] else base


def pattern_reaches(pattern_abs, target_abs):
    """True when a glob pattern could match this path, or anything under it."""
    import fnmatch
    pc = pattern_abs.split(os.sep)
    tc = target_abs.split(os.sep)
    for i in range(min(len(pc), len(tc))):
        if pc[i] == "**":
            return True
        if not fnmatch.fnmatch(_cmp(tc[i]), _cmp(pc[i])):
            return False
    return True


def in_any_protected(resolved_path, cfg):
    return any(within(resolved_path, t) for t in cfg["_protected_abs"])


def _audit(v, reason):
    """Append one line per block to the audit log named in config.json.

    This is what the monthly report reads. A logging failure must never turn
    into a verdict change, so every error here goes to stderr and nothing else.
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            rel = json.load(f).get("audit_log")
        if not rel:
            return
        path = rel if os.path.isabs(rel) else os.path.join(LAB, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        ti = _LAST_INPUT.get("tool_input", {}) if isinstance(_LAST_INPUT.get("tool_input"), dict) else {}
        what = ti.get("command") or ti.get("file_path") or ti.get("notebook_path") or ti.get("path") or ""
        row = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "tool": _LAST_INPUT.get("tool_name", ""), "verdict": v, "reason": reason,
               "what": str(what)[:200], "session": _LAST_INPUT.get("session_id", "")}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        _alert(row)
    except Exception as e:  # noqa: BLE001
        print(f"audit log write failed: {e}", file=sys.stderr)


def _alert(row):
    """POST one line to the webhook named in config.json (alert_webhook).

    Slack and Discord incoming webhooks both accept this body. Three-second
    timeout, and a failure is reported on stderr only: an unreachable Slack
    must never change a verdict or slow a block by more than a moment.
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            url = json.load(f).get("alert_webhook")
        if not url:
            return
        import urllib.request
        msg = (f"Guardrails blocked {row.get('tool') or 'a tool call'}: {row.get('what') or ''}\n"
               f"Reason: {row.get('reason')}\nAt: {row.get('ts')}")
        body = json.dumps({"text": msg, "content": msg}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:  # noqa: BLE001
        print(f"alert webhook failed: {e}", file=sys.stderr)


def bash_verdict(cwd, command, timeout=6):
    """Ask the Bash gate about a command string that arrived through another tool.

    An MCP server that runs shell commands (`mcp__shell__execute`,
    `mcp__desktop-commander__execute_command`) walks past every path rule here,
    because `rm -rf infra` is not a path and was never judged as a command. The
    whole Bash rule set already exists a directory away, so the honest thing is
    to ask it rather than to re-implement a worse copy.
    """
    import subprocess
    hook = os.path.join(LAB, "hooks", "pre_bash_guard.sh")
    if not os.path.exists(hook) or not isinstance(command, str) or not command.strip():
        return None
    body = json.dumps({"tool_name": "Bash", "cwd": cwd, "tool_input": {"command": command}})
    try:
        p = subprocess.run([hook], input=body, capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return f"the Bash policy could not judge the command this tool carries ({e})"
    if p.returncode == 2:
        line = (p.stderr or "").strip().splitlines()
        return (line[0].replace("BLOCKED: ", "") if line else "denied by the Bash policy")
    return None


def verdict(v, reason, deny_code=2, fail_code=1):
    """Emit the single JSON verdict line and exit with the contracted code."""
    print(json.dumps({"verdict": v, "reason": reason}))
    if v in ("deny", "fail"):
        _audit(v, reason)
    if v in ("deny", "fail"):
        print(f"{'BLOCKED' if v == 'deny' else 'FAILED'}: {reason}", file=sys.stderr)
        sys.exit(deny_code if v == "deny" else fail_code)
    sys.exit(0)
