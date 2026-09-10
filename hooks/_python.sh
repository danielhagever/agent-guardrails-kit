#!/bin/sh
# Print the interpreter to use. macOS has python3; Git Bash on Windows
# commonly has only `python` or the `py` launcher, so a hardcoded python3
# is a hook that silently never runs on the client's actual machine.
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; exit 0; fi
done
if command -v py >/dev/null 2>&1; then printf 'py -3'; exit 0; fi
echo "no python interpreter found (tried python3, python, py -3)" >&2
exit 127
