#!/bin/sh
# PreToolUse: Bash
INPUT=$(cat)
exec "$(dirname "$0")/_run.sh" bash_guard.py "$INPUT"
