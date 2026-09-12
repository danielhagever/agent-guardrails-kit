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
import sys

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

    cfg["_allowed_tree_abs"] = resolve(cfg["allowed_tree"], LAB)
    cfg["_protected_abs"] = [resolve(p, LAB) for p in cfg["protected_paths"]]
    # Content-is-the-asset paths: every verb is denied on these, reads included.
    cfg["_secret_abs"] = [resolve(p, LAB) for p in cfg.get("secret_paths", [])]
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
    p = path_str if os.path.isabs(path_str) else os.path.join(base, path_str)
    return os.path.realpath(p)


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
    return path.lower() if CASE_INSENSITIVE else path


def within(resolved_path, tree):
    """True when resolved_path is tree itself or sits underneath it."""
    if not resolved_path or not tree:
        return False
    a, b = _cmp(resolved_path), _cmp(tree)
    return a == b or a.startswith(b + os.sep)


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


def verdict(v, reason, deny_code=2, fail_code=1):
    """Emit the single JSON verdict line and exit with the contracted code."""
    print(json.dumps({"verdict": v, "reason": reason}))
    if v in ("deny", "fail"):
        _audit(v, reason)
    if v in ("deny", "fail"):
        print(f"{'BLOCKED' if v == 'deny' else 'FAILED'}: {reason}", file=sys.stderr)
        sys.exit(deny_code if v == "deny" else fail_code)
    sys.exit(0)
