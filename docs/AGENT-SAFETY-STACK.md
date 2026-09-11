# The agent safety stack: five layers, and where this kit sits

PocketOS (April 2026) was not a hooks failure. An agent found an infrastructure token in a file, and the token could delete production and its backups. Hooks are one layer. Here are the five, in the order to install them, with what the kit covers and what you do elsewhere.

## 1. Scoped credentials (the layer that would have saved PocketOS)

- Agents run with their own identity, never the developer's logged-in prod session. No `~/.kube/config` with a prod context, no `~/.aws/credentials` with admin, no long-lived `DATABASE_URL` in the shell.
- Give the agent a token that can do the task and nothing else, and that expires. A token that can only push to a feature branch cannot rewrite `main`.
- Backups live under a different identity than the primary. If one token can delete both, you have no backup.

Kit coverage: none. This is IAM work. The exposure report flags the symptoms (secret files in reach, secret-looking strings in the repo).

## 2. Protected paths and destructive-command gates (this kit)

- Writes into `.env*`, `secrets/`, `infra/prod/`, CI pipeline files: denied.
- Commands that reference those paths: denied unless every verb is read-only. Unknown verbs fail closed.
- Force push, history rewrite, `git clean -f`, `rm -rf` on root or home, `curl | sh`, `terraform destroy`, `kubectl delete namespace`, `DROP TABLE`: denied by pattern, before any path logic.
- Every block logged and alerted; the whole policy proven by tests in CI.

Kit coverage: complete for Claude Code. Cursor gets the mirrored rules file and its admin policy.

## 3. MCP and tool allow-lists

- Every MCP server the agent can reach is a new set of hands. List them explicitly; deny the rest.
- For each server, prefer read-only capabilities unless a write is the job. A database MCP with `DROP` available is a loaded gun on the desk.
- Pin server versions; a supply-chain change in an MCP server is a change in what the agent can do.

Kit coverage: `permissions.deny` entries for `mcp__<server>__<tool>` patterns in `.claude/settings.json`; the exposure report checks for blanket allows. The allow-list itself is a per-team decision.

## 4. Sandboxed execution for unattended runs

- CI jobs, cron sessions and headless agents have nobody to press "no". Run them in a container or VM with no network path to production, an ephemeral filesystem, and the same hooks installed.
- Egress allow-list: the agent can reach the package registry and the git host, nothing else.

Kit coverage: the hooks install the same way inside the sandbox; `ci/` templates prove them there. The sandbox itself is your CI provider's or an OS feature.

## 5. Observability and response

- Audit log per block, monthly report, real-time alert (this kit).
- A named owner for "an agent tried X": who reads the alert, what they do in the first ten minutes.
- Release watch: the day the agent runtime updates, the policy is re-proven (this kit, `care/release_watch.sh`).

Kit coverage: complete, once the webhook is set.

## Order of work for a new team

1. Layer 1 for the two or three credentials that can destroy something (one afternoon of IAM).
2. Layer 2 install with the kit, proven in CI (five evenings with me, or the free kit on your own).
3. Layer 3 allow-list written down, deny the rest (one hour).
4. Layer 4 only where agents run unattended.
5. Layer 5 webhook and owner named (thirty minutes).
