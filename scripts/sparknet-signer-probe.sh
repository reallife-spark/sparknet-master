#!/usr/bin/env bash
# Probe the isolated signer's capabilities without signing anything.
#
# This script exists for the SO_PEERCRED caller allowlist: the Python client is
# launched as `python -`, so the signer identifies the trusted script through
# the bounded ancestor walk, not through a Python command line.
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  cat <<'USAGE'
usage: sparknet-signer-probe.sh

Sends the read-only `capabilities` request to the isolated signer and prints the
JSON response. It never signs or appends to the ledger. The signer's caller
allowlist identifies this script through the bounded ancestor walk.
USAGE
  exit 0
fi

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

SOCKET="${SPARKNET_SIGNER_SOCKET:-${SPARKNET_STATE_DIR:?missing}/signer/signer.sock}"
PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

SOCKET_PATH="$SOCKET" "$PY" - <<'PYEOF'
import json
import os
import socket
import sys
from pathlib import Path

path = Path(os.environ["SOCKET_PATH"])
if not path.exists():
    sys.exit(f"signer socket not found: {path}")
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.settimeout(10.0)
try:
    connection.connect(str(path))
    connection.sendall(b'{"op":"capabilities"}\n')
    payload = connection.recv(65536)
finally:
    connection.close()
print(payload.decode("utf-8").strip())
PYEOF
