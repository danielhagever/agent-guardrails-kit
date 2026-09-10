#!/bin/sh
# Shared runner for every gate. One place that knows how to find a python,
# so the resolver logic is not copy-pasted into each hook and cannot drift.
#
# Usage:  exec "$(dirname "$0")/_run.sh" <gate-file.py> [args...]
#
# Exit codes pass through untouched from the gate, because the hook layer
# distinguishes 0 / 1 / 2 / other and collapsing them would erase the
# difference between "denied" and "the gate is broken".
DIR=$(dirname "$0")
GATE="$1"; shift
PY=$("$DIR/_python.sh") || exit 2
exec $PY "$DIR/../gates/$GATE" "$@"
