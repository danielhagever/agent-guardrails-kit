#!/bin/sh
# Print the interpreter to use. macOS has python3; Git Bash on Windows
# commonly has only `python` or the `py` launcher, so a hardcoded python3
# is a hook that silently never runs on the client's actual machine.
#
# The version matters as much as the name. `python` is still Python 2 on some
# older Linux images, and the gates need Python 3.9 or newer (3.9 is what
# /usr/bin/python3 is on macOS without Homebrew). Taking the first name on PATH
# without asking its version gave a gate that crashed, and a gate that crashes
# denies, so the agent could not run `ls *.md`.
#
# Asking costs a Python start-up on every tool call (about 16ms), so a name
# whose real file already says its version (Homebrew, pyenv and uv resolve to
# python3.12 and the like) is trusted without asking. /usr/bin/python3 on a Mac
# is a shim with no version in its name, so that one is still asked.
ok() { "$@" -S -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; }
named() {
  p=$(command -v "$1" 2>/dev/null) || return 1
  r=$(realpath "$p" 2>/dev/null) || return 1
  case "${r##*/}" in python3.9|python3.1[0-9]) return 0 ;; esac
  return 1
}
for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
  if command -v "$c" >/dev/null 2>&1 && { named "$c" || ok "$c"; }; then printf '%s' "$c"; exit 0; fi
done
if command -v py >/dev/null 2>&1 && ok py -3; then printf 'py -3'; exit 0; fi
echo "no Python 3.9+ interpreter found (tried python3, python3.9 to 3.14, python, py -3)" >&2
exit 127
