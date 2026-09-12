#!/bin/sh
# PreToolUse: mcp__.*
INPUT=$(cat)
exec "$(dirname "$0")/_run.sh" mcp_guard.py "$INPUT"
