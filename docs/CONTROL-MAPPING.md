# Control mapping: what the guardrails give an auditor

One page for the security questionnaire. Each row names something this kit does, the evidence it produces, and the control families it is normally cited against. This is a mapping, not a certification; your auditor decides what counts.

| Guardrail | Evidence it produces | SOC 2 (Trust Services Criteria) | ISO/IEC 27001:2022 Annex A | NIST CSF 2.0 |
|---|---|---|---|---|
| Protected paths: agents cannot write to, or run destructive verbs on, secrets and infra directories | `guardrails/config.json` (policy), `tests/smoke.sh` output in CI (proof on every push) | CC6.1 logical access, CC6.3 access removal/restriction, CC8.1 change management | A.8.3 information access restriction, A.8.32 change management | PR.AA (identity and access), PR.PS (platform security) |
| Destructive-command deny patterns (force push, history rewrite, pipe-to-shell, infra teardown) | same policy file; each pattern has a regression test | CC8.1 change management, CC7.2 anomaly monitoring | A.8.32 change management, A.8.28 secure coding | PR.PS-01 configuration management |
| Fail-closed behaviour (malformed policy, unreadable payload, unknown verb all deny) | tests in `tests/run_tests.sh` named "fails closed" | CC6.1, CC7.1 detection of configuration changes | A.8.9 configuration management | PR.PS, DE.CM |
| Audit log: one JSON line per blocked action (tool, command, reason, time, session) | `.claude/guardrails-audit.jsonl`, monthly report from `gates/report.py` | CC7.2 monitoring, CC7.3 evaluation of security events, CC4.1 monitoring activities | A.8.15 logging, A.8.16 monitoring activities | DE.CM-01, DE.AE |
| Real-time alert on every block (Slack or Discord webhook) | webhook payload; the alert test in the suite | CC7.2, CC7.3, CC7.4 incident response | A.8.16, A.5.24 incident management planning | DE.AE-06, RS.CO |
| Release watch: policy re-proven when the agent runtime changes | `care/release_watch.sh` log and alert | CC8.1 change management, CC7.1 | A.8.32, A.8.8 technical vulnerability management | ID.RA, PR.PS |
| Policy as code, reviewed through pull requests | git history of `guardrails/` | CC8.1, CC3.2 risk assessment | A.5.8 information security in project management, A.8.32 | GV.PO, PR.PS |
| CI proof and badge on every push | GitHub Actions / GitLab job history | CC7.1, CC8.1 | A.8.29 security testing in development | ID.IM, PR.PS |

What this kit does **not** give you, so nobody claims it does: secrets management (rotate and scope tokens elsewhere), network egress control (OS or container sandbox), coverage of agents that do not run Claude Code hooks (Cursor policy is mirrored in `templates/cursor-rules.mdc`, but the enforcement point is Cursor's own admin settings).

Suggested wording for a questionnaire answer: "Coding agents run under a policy-as-code guardrail layer that denies writes to and destructive commands against protected paths, blocks force-push, history rewrite and pipe-to-shell patterns, fails closed on any policy or payload error, logs every blocked action, alerts the team in real time, and is re-proven by an automated test suite in CI on every push and on every runtime release."
