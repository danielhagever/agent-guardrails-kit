# agent-guardrails-kit

Fail-closed guardrails for Claude Code (and any agent that runs shell commands and edits files through hooks). Two PreToolUse hooks, one policy file, an audit log, a real-time alert on every block, a monthly report, an exposure report for the setup you have today, CI templates that prove the policy on every push, and a test suite that proves every block.

    ./tests/run_tests.sh      # 121 assertions, all green

Built after an evening of breaking my own deny-list. The story is in the [write-up](https://agent-guardrails.meshulam791.workers.dev/), the short version is below.

## What it blocks

| Layer | Rule | Examples that are denied |
|---|---|---|
| Protected paths | A command that references a protected path is denied unless every verb in it is on a short read-only allow-list | `rm`, `mv`, `cp`, `tee`, `sed -i`, `dd`, `rsync`, `find -delete`, `sh -c "rm ..."`, `P=protected; rm $P/x`, `(cd protected && rm x)`, `echo x >\| protected/x`, symlink and `../` dodges |
| File writes | Write, Edit, MultiEdit and NotebookEdit are denied inside protected paths and outside the allowed tree; every path key in the payload is inspected, including nested `edits[]` and `notebook_path` | writes into `protected/`, writes to `/tmp`, payloads with no readable path (fails closed) |
| Destructive patterns | Regexes on the raw command, checked before any path logic | `git push --force`, `git reset --hard`, `git clean -f`, `git checkout -- .`, `git branch -D`, `curl \| sh`, `rm -rf /`, `terraform destroy`, `kubectl delete namespace`, `docker system prune -a`, `DROP TABLE` |

Reads of protected files (`cat`, `grep`, `ls`, `head`) stay allowed. Unknown verbs fail closed, so tools nobody predicted are covered by construction.

Every block appends one JSON line to `.claude/guardrails-audit.jsonl` and, when `alert_webhook` in `config.json` is set, POSTs a Slack- or Discord-compatible message to it within the same call (three-second timeout; a dead webhook never changes a verdict). `python3 gates/report.py [log] [YYYY-MM]` turns a month of the log into a Markdown report: blocks by reason, by tool, by day, most recent ten.

## Exposure report: where you stand before touching anything

    python3 gates/exposure_report.py --settings .claude/settings.json --claudemd CLAUDE.md --repo . --company "Acme"

Scores the setup out of 10 (same rules as the browser grader), lists what an agent can do today with the exact command that would succeed, scans the repo for secret files and secret-looking strings (reports file and pattern, never the value), flags writable CI pipelines, and ends with the fix for each gap. Flags `--prod`, `--ci`, `--cursor`, `--env` describe how agents run at your team.

## Care: the parts that run without anyone

- `care/monthly.sh [YYYY-MM]` writes `reports/<month>.md` from the audit log and posts it to the webhook. Cron it monthly.
- `care/release_watch.sh` re-runs the smoke test the day `claude --version` changes and posts PASS or FAIL. Cron it daily.
- `ci/github-guardrails.yml` and `ci/gitlab-guardrails.yml` prove the policy on every push and weekly, and give the README a badge.
- `templates/cursor-rules.mdc` mirrors the policy where Cursor reads it, since Cursor does not run these hooks.
- `docs/CONTROL-MAPPING.md` maps each guardrail to SOC 2, ISO 27001 and NIST CSF controls, with the evidence each one produces, for the security questionnaire.
- `docs/AGENT-SAFETY-STACK.md` places hooks among the four other layers (scoped credentials, MCP allow-lists, sandboxed unattended runs, response), because PocketOS was a credentials failure first.

## Why an allow-list

The first version was a deny-list (`rm`, `mv`, `rmdir`). It was defeated in minutes by every row in the first table above, and two of the blocks it did produce came from a quoting parse error rather than detection. A guard that is wrong in both directions cannot be reasoned about. The rule is now inverted and every bypass is a permanent regression test.

Three more lessons, all found by attacking rather than reading:

- Resolve paths (`realpath`, against the session `cwd` Claude Code sends) before comparing. Otherwise `../`, symlinks and a `cd` mid-command change the answer.
- Read every path key in the tool payload. A guard that is wired but cannot read its input is more dangerous than a missing one, because the matcher list lies.
- Fail closed on confusion: unparseable quoting, missing or malformed `config.json`, a payload with no path.

## Install in another repo

    ./install.sh /path/to/your/repo .env secrets infra/prod

This copies `hooks/`, `gates/`, `care/`, `ci/`, `templates/`, `docs/` and a rewritten `config.json` into `your-repo/guardrails/`, protects the paths you list (relative to the repo root), and prints the `.claude/settings.json` block to add. Then:

    cd /path/to/your/repo && guardrails/tests/smoke.sh

Eight assertions against the installed policy. Wire the same command into CI and the protection is proven on every push, not just on the day it was installed.

## Layout

    config.json            all policy: protected paths, read-only verbs, deny patterns, audit log path, alert webhook
    hooks/                 shell wrappers Claude Code calls (pre_bash_guard.sh, pre_write_guard.sh, stop_gate.sh)
    gates/                 the logic: bash_guard.py, write_guard.py, check_deliverable.py, report.py, exposure_report.py, _lib.py
    care/                  monthly.sh, release_watch.sh
    ci/                    GitHub Actions and GitLab CI templates
    templates/             cursor-rules.mdc
    docs/                  CONTROL-MAPPING.md, AGENT-SAFETY-STACK.md, DEVELOPERS.md
    tests/run_tests.sh     the lab suite (121 assertions); tests/smoke.sh for installed copies
    .claude/settings.json  the two PreToolUse hooks

`stop_gate.sh` is an optional Stop hook that refuses to end a session until a named deliverable exists and has real content. It is tested but not wired by default.

## Contract for a gate

Exit 0 allows, 2 denies, 1 fails (Stop gates), anything else means "the gate is broken", which the hook layer treats differently from "the gate said no". Exactly one JSON line on stdout; human text on stderr. `gates/_lib.py` holds the whole contract.

## Limits

Hooks run inside Claude Code. They do nothing for a token that is already in the agent's environment, for other tools that read the same files, or for an agent with a different permission model (Cursor has its own). Treat this as one layer: scoped credentials and an OS sandbox are the others.

## Grade your current setup first

Paste your `settings.json` and `CLAUDE.md` into the [grader](https://agent-guardrails.meshulam791.workers.dev/grade). It runs in the browser, uploads nothing, and names the gaps.

MIT licence. Daniel Meshulam, Israel. I install and test-prove this for teams on Claude Code and Cursor: [agent-guardrails.meshulam791.workers.dev](https://agent-guardrails.meshulam791.workers.dev/).
