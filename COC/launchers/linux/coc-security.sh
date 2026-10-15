#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3 is unavailable. Use the manual runbooks; do not install packages on a suspect host.' >&2
    exit 1
fi
exec python3 "$SCRIPT_DIR/coc_security.py" "$@"
