#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi
if ! .venv/bin/python -c 'import scapy, sys; assert scapy.__version__ == "2.8.0"; __import__("compression.zstd" if sys.version_info >= (3, 14) else "backports.zstd")' >/dev/null 2>&1; then
    .venv/bin/python -m pip install -r requirements.txt
fi
exec .venv/bin/python -m wifi_watcher "$@"
