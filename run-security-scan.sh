#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ -d "$root/.scan-tools/bin" ]; then
    export PATH="$root/.scan-tools/bin:$PATH"
fi
if [ -x "$root/.venv/bin/python" ]; then
    python="$root/.venv/bin/python"
else
    python=python3
fi
if ! "$python" -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
    echo 'Python 3.9+ is required. Install with: brew install python' >&2
    exit 3
fi
export PYTHONPATH="$root${PYTHONPATH:+:$PYTHONPATH}"
if [ "${1:-}" = "--ui" ]; then
    shift
    exec "$python" -m secscan ui "$@"
fi
exec "$python" -m secscan scan "$@"
