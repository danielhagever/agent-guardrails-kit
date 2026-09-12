#!/bin/sh
# Has the repository grown a secret the policy does not know about?
#
#   guardrails/care/drift.sh            (exit 1 if something is uncovered)
#
# A policy is correct on the day it is written. Then somebody adds
# config/master.key, a .pem, a service-account JSON, a new infra directory,
# and the settings file still says the repository is protected. This is the
# check that keeps the delivery report true a month later: it lists files that
# LOOK like credentials and are not inside any declared secret path, and
# directories that look like production and are not protected. It prints names
# and reasons, never contents.
#
# Cron it monthly beside care/monthly.sh, or run it in CI.
set -e
G=$(cd "$(dirname "$0")/.." && pwd)
# Installed, the kit lives at <repo>/guardrails. Run from the kit's own
# checkout there is no <repo> above it, and walking the parent means walking
# the whole home directory, which is how this printed fifteen findings about
# the user's Bluetooth cache the first time it ran.
REPO=$("$G/hooks/_repo_root.sh")
PY=$("$G/hooks/_python.sh")
G="$G" REPO="$REPO" "$PY" - "$@" <<'EOF'
import json, os, re, sys

g, repo = os.environ["G"], os.environ["REPO"]
sys.path.insert(0, os.path.join(g, "gates"))
from exposure_report import SECRET_FILES            # one list of patterns, not two
import _lib

cfg = json.load(open(os.path.join(g, "config.json")))
covered = [_lib.resolve(os.path.expanduser(p), g)
           for p in cfg.get("secret_paths", []) + cfg.get("protected_paths", [])]
PROD_DIRS = re.compile(r"(^|/)(infra|deploy|terraform|k8s|kubernetes|helm|ansible|charts)"
                       r"(/|$)|(^|/)(prod|production)(/|$)", re.I)
SKIP = {".git", "node_modules", "dist", "build", "__pycache__", "guardrails",
        ".next", "target", "vendor", "site-packages", "Library", "DerivedData"}
KEEP_DOT = {".aws", ".ssh", ".config", ".github", ".circleci", ".gcp", ".azure"}


def skip_dir(name):
    if name in SKIP or name.startswith(".venv") or name.startswith("venv"):
        return True
    return name.startswith(".") and name not in KEEP_DOT

loose_secrets, loose_prod, seen = [], [], 0
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if not skip_dir(d)]
    for name in files:
        seen += 1
        if seen > 40000:
            break
        full = os.path.realpath(os.path.join(root, name))
        rel = os.path.relpath(full, repo)
        if not SECRET_FILES.search(rel.replace(os.sep, "/")):
            continue
        if any(_lib.within(full, c) for c in covered):
            continue
        loose_secrets.append(rel)
    for d in list(dirs):
        full = os.path.realpath(os.path.join(root, d))
        rel = os.path.relpath(full, repo)
        if PROD_DIRS.search(rel.replace(os.sep, "/")) and not any(
                _lib.within(full, c) or _lib.within(c, full) for c in covered):
            loose_prod.append(rel)

print(f"Policy drift check for {repo}")
print(f"  declared: {len(cfg.get('secret_paths', []))} secret path(s), "
      f"{len(cfg.get('protected_paths', []))} protected path(s)")
if not loose_secrets and not loose_prod:
    print("  nothing uncovered: every credential-looking file and production-looking "
          "directory is inside a declared path.")
    raise SystemExit(0)
if loose_secrets:
    print(f"\n  {len(loose_secrets)} credential-looking file(s) NOT covered by secret_paths:")
    for r in sorted(set(loose_secrets))[:40]:
        print(f"    {r}")
    print("    -> add these to secret_paths in guardrails/config.json "
          "(every verb denied, reading included)")
if loose_prod:
    print(f"\n  {len(set(loose_prod))} production-looking director(ies) NOT covered:")
    for r in sorted(set(loose_prod))[:20]:
        print(f"    {r}")
    print("    -> add to protected_paths if an agent has no business writing there")
print("\n  Contents were never read; this is a name check.")
raise SystemExit(1)
EOF
