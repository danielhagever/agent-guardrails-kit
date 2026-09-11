#!/usr/bin/env python3
"""Agent Exposure Report: what a coding agent could do in this setup today.

Usage:
  python3 gates/exposure_report.py --settings .claude/settings.json --claudemd CLAUDE.md \
      [--repo /path/to/repo] [--company "Acme"] [--out report.md]

Reads only what you point it at. Never prints secret values: when it finds a
secret-looking string it reports the file and the pattern name, not the match.
Exit code 0 always; the score is in the report.

The score mirrors the browser grader (agent-guardrails.meshulam791.workers.dev/grade)
so a client sees the same number twice: once when they self-checked, once in
the written review.
"""
import argparse
import datetime
import json
import os
import re
import sys

SECRET_FILES = re.compile(r"(^|/)(\.env(\..*)?|.*\.pem|id_rsa|id_ed25519|.*\.p12|.*\.pfx|.*service[-_]?account.*\.json|\.netrc|\.npmrc|\.pypirc|credentials(\.json)?|kubeconfig|\.aws/credentials)$", re.I)
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "Slack token": re.compile(r"\bxox[abp]-[0-9A-Za-z-]{20,}\b"),
    "OpenAI/Anthropic-style key": re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe live key": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    "database URL with password": re.compile(r"\b(postgres|mysql|mongodb(\+srv)?|redis)://[^:/\s]+:[^@\s]+@", re.I),
}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next", "target"}
TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".sh", ".md", ".txt", ".rb", ".go", ".java", ".kt", ".cs", ".php", ".tf", ".tfvars", ".xml", ".properties", ""}


def load_json(path):
    if not path:
        return None, "not provided"
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "file not found"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"


def read_text(path):
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def scan_repo(root, max_files=20000):
    """Secret-looking files and strings, CI configs, agent config presence."""
    out = {"secret_files": [], "secret_hits": {}, "ci": [], "has_settings": False, "has_claudemd": False,
           "has_hooks_dir": False, "scanned": 0, "truncated": False}
    root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root)
        for fn in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, fn)) if rel_dir != "." else fn
            out["scanned"] += 1
            if out["scanned"] > max_files:
                out["truncated"] = True
                return out
            if SECRET_FILES.search(rel.replace(os.sep, "/")):
                out["secret_files"].append(rel)
            if rel.replace(os.sep, "/") in (".claude/settings.json", ".claude/settings.local.json"):
                out["has_settings"] = True
            if fn == "CLAUDE.md":
                out["has_claudemd"] = True
            if rel.replace(os.sep, "/").startswith((".github/workflows/", ".gitlab-ci.yml", ".circleci/")):
                out["ci"].append(rel)
            if rel.replace(os.sep, "/").startswith("guardrails/hooks"):
                out["has_hooks_dir"] = True
            ext = os.path.splitext(fn)[1].lower()
            if ext in TEXT_EXT:
                try:
                    if os.path.getsize(os.path.join(dirpath, fn)) > 2_000_000:
                        continue
                    with open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore") as f:
                        txt = f.read()
                except OSError:
                    continue
                for name, rx in SECRET_PATTERNS.items():
                    if rx.search(txt):
                        out["secret_hits"].setdefault(name, []).append(rel)
    return out


def grade(settings, settings_err, claudemd, repo, flags):
    findings = []  # (severity, title, what_an_agent_can_do_today, fix)
    score = 0
    s = settings or {}
    raw = json.dumps(settings) if settings else ""
    hooks = s.get("hooks", {}) if isinstance(s, dict) else {}
    pre = hooks.get("PreToolUse", []) if isinstance(hooks, dict) else []
    matchers = " | ".join(str(h.get("matcher", "")) for h in pre if isinstance(h, dict))
    has_bash = bool(re.search(r"\bBash\b", matchers)) or any(isinstance(h, dict) and not h.get("matcher") for h in pre)
    has_write = bool(re.search(r"Write|Edit|MultiEdit|NotebookEdit", matchers)) or any(isinstance(h, dict) and not h.get("matcher") for h in pre)
    perms = s.get("permissions", {}) if isinstance(s, dict) else {}
    deny = "\n".join(perms.get("deny", []) or [])
    allow = "\n".join(perms.get("allow", []) or [])

    if settings_err and settings_err != "not provided":
        findings.append(("gap", f"settings.json is unusable ({settings_err})",
                         "Claude Code ignores a broken settings file entirely, so every rule in it is off.",
                         "Fix the JSON first. A broken settings file is the same as no settings file."))
    if has_bash:
        score += 2
    else:
        findings.append(("gap", "No PreToolUse hook on Bash",
                         "Any shell command the agent decides to run, runs. `rm -rf`, `git push --force`, `curl ... | sh`, `terraform destroy` are all one decision away.",
                         "A PreToolUse hook on Bash that denies by default near protected paths and blocks destructive patterns (this kit's `bash_guard.py`)."))
    if has_write:
        score += 1
    else:
        findings.append(("gap", "No PreToolUse hook on Write, Edit, MultiEdit or NotebookEdit",
                         "The agent can overwrite any file the process can, including `.env`, CI configs and deploy scripts.",
                         "A write guard that reads every path key in the payload and fails closed when it cannot (this kit's `write_guard.py`)."))
    d_git = bool(re.search(r"git\s+push.*(--force|-f)|reset\s+--hard|force", deny, re.I))
    d_rm = bool(re.search(r"\brm\b", deny))
    d_pipe = bool(re.search(r"curl|wget|\|\s*(ba)?sh", deny, re.I))
    d = sum([d_git, d_rm, d_pipe])
    if d == 3:
        score += 2
    elif d > 0:
        score += 1
        findings.append(("weak", "Destructive-command deny rules are partial",
                         "Covered: " + ", ".join(x for x, ok in (("force push", d_git), ("rm", d_rm), ("pipe-to-shell", d_pipe)) if ok) + ". The others run unchallenged.",
                         "Deny force push, reset --hard, git clean -f, recursive delete on root or home, and curl|sh, then back them with a hook because deny strings are matched literally."))
    else:
        findings.append(("gap", "No deny rules for destructive commands",
                         "`git push --force origin main` and `git reset --hard` need no approval beyond the model's own judgment.",
                         "Deny rules as the floor, a fail-closed hook as the ceiling."))
    if re.search(r"Read\((\./)?\.env|\.env\*|secrets|\.pem|id_rsa", deny, re.I):
        score += 1
    else:
        findings.append(("gap" if (repo and repo["secret_files"]) or flags.get("env") else "weak",
                         "Nothing stops the agent from reading secret files",
                         ("Reachable now: " + ", ".join(repo["secret_files"][:6]) + (" and more" if repo and len(repo["secret_files"]) > 6 else "") + ". `cat .env` succeeds.") if repo and repo["secret_files"] else "`cat .env` and `cat ~/.aws/credentials` succeed if those files exist where the agent runs.",
                         "Deny Read on `.env*`, `*.pem`, `id_rsa`, the secrets folder; move production secrets out of agent-reachable paths."))
    if re.search(r"Bash\(\*\)|^Bash$", allow, re.M):
        score -= 1
        findings.append(("gap", "permissions.allow grants blanket Bash",
                         "Every shell command is pre-approved; the approval prompt that would have caught a bad one never appears.",
                         "Allow narrow patterns only (`Bash(npm test:*)`, `Bash(git status)`)."))
    if re.search(r"bypassPermissions|dangerouslySkipPermissions|skipPermissions", raw, re.I):
        score -= 2
        findings.append(("gap", "A permission-bypass flag is set",
                         "Hooks still run, but every confirmation prompt is gone. Unattended sessions run with the model's judgment only.",
                         "Remove the bypass outside throwaway sandboxes; use hooks plus an OS sandbox for unattended runs."))
    prose = len(re.findall(r"\b(never|do not|don'?t|must not|avoid)\b", claudemd or "", re.I))
    if prose and not has_bash:
        findings.append(("gap", f"CLAUDE.md carries {prose} prose rule{'s' if prose > 1 else ''} and nothing enforces them",
                         "The agent reads 'never touch production' and usually complies. Usually is the problem: PocketOS had the same sentence.",
                         "Keep the prose for intent; add a hook for each rule that matters."))
    elif claudemd and not prose:
        findings.append(("weak", "CLAUDE.md states no safety rules",
                         "Intent is not written anywhere the agent reads, so a reviewer cannot even argue the agent broke a rule.",
                         "Two lines naming protected paths and forbidden commands, mirrored by hooks."))
    if re.search(r"PostToolUse|audit|guardrails-audit", raw, re.I) or (repo and repo["has_hooks_dir"]):
        score += 1
    else:
        findings.append(("weak", "Nothing records what the agent tried and was blocked from",
                         "After an incident there is no log of agent actions to reconstruct from; before one there is no number to show anyone.",
                         "An audit line per block and a monthly summary (this kit writes both)."))
    if flags.get("prod"):
        findings.append(("gap", "Agents run where production credentials are already logged in",
                         "A hook cannot fix a token that sits in `~/.kube` or `~/.aws` on the same machine. `kubectl delete ns prod` uses the developer's own session.",
                         "Scoped identities: agents run with a limited token, never the developer's prod session."))
    else:
        score += 1
    if flags.get("ci") and not has_bash:
        findings.append(("gap", "Unattended agent runs with no Bash hook",
                         "Nobody is there to press 'no'. A wrong step runs to completion.",
                         "Hooks first, then a sandboxed runner with no network path to production."))
    elif not flags.get("ci"):
        score += 1
    if flags.get("cursor"):
        findings.append(("weak", "Cursor is in use and has its own permission model",
                         "settings.json does not cover it; a rule that holds in Claude Code can be absent in Cursor on the same repo.",
                         "Mirror the deny rules in `.cursor/rules` and Cursor Business admin policy; test both (this kit ships a rules template)."))
    else:
        score += 1
    if repo:
        if repo["secret_hits"]:
            names = ", ".join(f"{k} in {len(v)} file{'s' if len(v) > 1 else ''}" for k, v in repo["secret_hits"].items())
            findings.append(("gap", "Secret-looking strings inside tracked files",
                             f"Found: {names}. An agent that greps the repo finds them too, and PocketOS is what happens next.",
                             "Rotate them, move them to a secrets manager, add the paths to the protected list. Values were not printed here."))
        if repo["ci"] and not has_bash:
            findings.append(("weak", "CI configuration is writable by the agent",
                             f"{len(repo['ci'])} pipeline file{'s' if len(repo['ci']) > 1 else ''} ({', '.join(repo['ci'][:3])}). A one-line edit exfiltrates every CI secret on the next run.",
                             "Protect the CI directory with the write guard; require review on pipeline changes."))
    score = max(0, min(10, score))
    return score, findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--settings")
    ap.add_argument("--claudemd")
    ap.add_argument("--repo")
    ap.add_argument("--company", default="your team")
    ap.add_argument("--out")
    ap.add_argument("--env", action="store_true", help="secret files live in agent-reachable repos")
    ap.add_argument("--prod", action="store_true", help="agents run on machines holding production credentials")
    ap.add_argument("--ci", action="store_true", help="agents run unattended (CI, cron)")
    ap.add_argument("--cursor", action="store_true", help="the team also uses Cursor")
    a = ap.parse_args()

    settings, err = load_json(a.settings)
    claudemd = read_text(a.claudemd)
    repo = scan_repo(a.repo) if a.repo else None
    flags = {"env": a.env, "prod": a.prod, "ci": a.ci, "cursor": a.cursor}
    score, findings = grade(settings, err, claudemd, repo, flags)
    verdict = ("Solid. Prove it with tests in CI and keep it current." if score >= 8 else
               "Partial. The gaps below are the ones an incident report would name." if score >= 5 else
               "Exposed. Today the model is the only thing standing between an agent and production.")
    today = datetime.date.today().isoformat()
    lines = [f"# Agent exposure report: {a.company}", f"_{today}. Inputs: "
             + ", ".join(x for x in [a.settings and "settings.json", a.claudemd and "CLAUDE.md", a.repo and f"repo scan ({repo['scanned']} files{', truncated' if repo['truncated'] else ''})"] if x)
             + ". No secret values are reproduced in this document._", "",
             f"## Score: {score} / 10", "", f"**{verdict}**", ""]
    gaps = [f for f in findings if f[0] == "gap"]
    weak = [f for f in findings if f[0] == "weak"]
    if gaps:
        lines += ["## What an agent can do today", "", "| Gap | What succeeds right now | Fix |", "|---|---|---|"]
        lines += [f"| {t} | {w} | {x} |" for _, t, w, x in gaps]
        lines.append("")
    if weak:
        lines += ["## Weak spots", ""] + [f"- **{t}.** {w} Fix: {x}" for _, t, w, x in weak] + [""]
    good = []
    if settings and not err:
        s = settings
        pre = (s.get("hooks", {}) or {}).get("PreToolUse", [])
        if pre:
            good.append("PreToolUse hooks are wired: " + ", ".join(str(h.get("matcher") or "all tools") for h in pre if isinstance(h, dict)))
        if (s.get("permissions", {}) or {}).get("deny"):
            good.append(f"{len(s['permissions']['deny'])} deny rules present")
    if claudemd and re.search(r"\b(never|do not|don'?t|must not)\b", claudemd, re.I):
        good.append("CLAUDE.md states intent (prose rules exist)")
    if repo and not repo["secret_files"] and not repo["secret_hits"]:
        good.append("Repo scan found no secret files or secret-looking strings")
    if good:
        lines += ["## Already in place", ""] + [f"- {g}" for g in good] + [""]
    lines += ["## Next step", "",
              "One repo, five evenings: hooks, permission rules, a written policy, and a test suite in your CI that proves every block above is closed. You pay after the tests pass. Free kit to start from: github.com/danielhagever/agent-guardrails-kit", ""]
    text = "\n".join(lines)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {a.out} (score {score}/10, {len(gaps)} gaps, {len(weak)} weak)")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
