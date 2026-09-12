#!/bin/sh
# PreToolUse: every tool. Returns at once for the ones with their own gate.
INPUT=$(cat)
exec "$(dirname "$0")/_run.sh" any_guard.py "$INPUT"
