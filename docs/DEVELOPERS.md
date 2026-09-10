# Developing gates

Internal reference for extending this toolkit. The war stories that explain
*why* each rule exists are in the top-level README; this file is the *how*.

## Layout

    config.json          all policy. logic never hardcodes what to protect.
    gates/_lib.py        the shared contract: config, input, verdicts, paths
    gates/*.py           one file per check, logic only
    hooks/_python.sh     interpreter resolution (python3 / python / py -3)
    hooks/_run.sh        shared runner: finds python, execs a gate
    hooks/*.sh           thin wrappers, one per hook event
    .claude/settings.json  wiring, scoped to this directory only
    tests/run_tests.sh   104 assertions

## The contract

Claude Code hands a gate JSON on stdin. Its **exit code is the decision**:

| code | meaning |
|---|---|
| 0 | allow / pass |
| 1 | fail — Stop-style gates: the check did not pass |
| 2 | deny — PreToolUse gates: block the tool call before it runs |
| other | the gate is **broken**, which is deliberately distinct from "said no" |

Print exactly **one** JSON line to stdout: `{"verdict": ..., "reason": ...}`.
Nothing else, because the hook parses that line and only that line. Human
explanation goes to stderr, where Claude Code surfaces it back to the model.

That last row matters more than it looks. A gate with a syntax error and a
gate reporting a genuine failure must not be indistinguishable, or you spend
an afternoon fixing a deliverable that was never the problem.

## Writing a new gate

```python
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import load_config, read_hook_input, verdict, resolve, within

cfg  = load_config()          # dies with a legible reason if policy is bad
data = read_hook_input()      # dies if the payload is unreadable

path = resolve(data["tool_input"]["file_path"], data.get("cwd") or os.getcwd())
if not within(path, cfg["_allowed_tree_abs"]):
    verdict("deny", f"{path} is outside the allowed tree")
verdict("allow", "fine")
```

Then wire it in `.claude/settings.json` and **add a test that proves it
fires by deliberately doing the thing it must catch**. A gate with no
failing-case test is decoration.

## Rules that are not negotiable

**Fail closed.** Every refusal path in `_lib` denies rather than guesses:
unreadable payload, missing config key, empty `protected_paths`. A guard that
waves things through when confused is worse than no guard, because the
settings file then advertises a protection that does not exist.

**Resolve before comparing.** Always `resolve()` a path before testing
containment. Comparing raw strings is how `../` and symlinks walk straight
past a guard.

**Honour the session cwd.** Claude Code sends `cwd` in the payload. Use it,
not the hook process's own working directory, or the same relative command
will be allowed or blocked depending on where the hook happened to launch.

**Read every payload shape.** `Write` sends `file_path`, `NotebookEdit`
sends `notebook_path`, `MultiEdit` nests under `edits[]`. `config.json`
lists the keys and `harvest()` walks the payload recursively. Adding a tool
to a matcher without teaching the guard to read it produces a guard that is
wired and blind, which is the most dangerous state available.

**Allowlist, never deny-list.** For anything destructive, enumerate what is
*safe* and refuse the rest. Enumerating what is dangerous is a game you lose
the first time someone types `tee`.

## Changing policy

Edit `config.json`. Nothing else. Verified: swapping `protected_paths` from
`["protected"]` to `["deliverable"]` inverts which deletions are blocked,
with no code change.

| key | effect |
|---|---|
| `allowed_tree` | writes outside this are denied |
| `protected_paths` | never writable, read-only access still allowed |
| `read_only_verbs` | the Bash allowlist |
| `find_write_flags` | flags that make `find` an acting command |
| `path_keys` | payload keys the write guard harvests |
| `deliverable.*` | target file, required sections, content floors |

## Running the tests

    ./tests/run_tests.sh          # 104 assertions, exits non-zero on failure

The suite is idempotent: it restores the deliverable at the end and can run
repeatedly. It includes a sandbox that removes `python3` from `PATH` to prove
the interpreter resolver works on a Windows/Git Bash-style box.

**Mutation-test after changing a guard.** Break it on purpose and confirm the
suite notices. Measured on the current suite:

| neutered | failures |
|---|---|
| `_lib.py` — `die()` made a no-op | 52 |
| `gates/bash_guard.py` — all denials become allows | 23 |
| `gates/write_guard.py` — all denials become allows | 10 |
| `hooks/stop_gate.sh` — verdict allowlist widened | 9 |
| `hooks/_python.sh` — always claims `python3` | 6 |
| `tests/run_tests.sh` — restore traps removed | 2 |
| `gates/check_deliverable.py` — checks disabled | 4 |

If a change drops one of those counts, coverage for that path just got thinner.

**Mutate the logic, not the verdict names.** Renaming `verdict("fail")` to
`verdict("allow")` inside the content gate scores zero, and that is not a
coverage hole: `stop_gate.sh` accepts only the literal verdict `pass`, so the
wrapper catches the rename. A mutation that the next layer blocks measures
defence in depth, not the gate. To test the gate, disable what it *checks*.

The same trap has a second face: a mutation can be semantically equivalent.
Deleting the `^` from `re.match(r"^#{1,6}...")` scores zero because `re.match`
is already anchored, so nothing changed. The regression it was standing in for
is `re.match` becoming `re.search`, which lets `As discussed above # Findings`
count as a section heading. That scored zero too, until a test was written for
it. A zero always needs one of three explanations: the next layer caught it,
the mutation changed nothing, or the coverage is missing. Only the third is a
bug, and you cannot tell which you have without looking.
