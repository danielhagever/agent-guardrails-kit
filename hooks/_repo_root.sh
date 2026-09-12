#!/bin/sh
# Print the repository this policy protects.
#
# Installed, the kit lives at <repo>/guardrails and the answer is the parent.
# Run from its own checkout there is no repository above it, and taking the
# parent anyway means taking the user's home directory: the smoke test then
# reported four false failures, and the drift check reported fifteen findings
# about a Bluetooth cache. One answer, in one place, for every script.
G=$(cd "$(dirname "$0")/.." && pwd)
if [ "$(basename "$G")" = "guardrails" ] && { [ -d "$G/../.git" ] || [ -f "$G/../.claude/settings.json" ]; }; then
  (cd "$G/.." && pwd)
else
  printf '%s' "$G"
fi
