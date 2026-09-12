#!/bin/sh
# PreToolUse: Read|Grep|Glob|NotebookRead
INPUT=$(cat)
exec "$(dirname "$0")/_run.sh" read_guard.py "$INPUT"
