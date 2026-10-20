#!/usr/bin/env bash
# MASTER-SIDE: sign a registry entry THROUGH the isolated signer's unix socket.
#
# sparknet-registry-sign.sh signs directly with the operational key, loading it
# into the calling process. That is convenient for tests and for a host that has
# no signer running, and it is deliberately bypassed in production: it never
# touches the socket, so the signer never records the signature in the ledger.
# This script is the production path. It hands the entry to the signer over its
# 0600 unix socket, so the key never enters this process and every signature lands
# as a `signature_issued` block in the Master's hash-chained ledger.
#
# The entry is passed as-is (minus any `signature_b64`); the signer rebuilds the
# canonical envelope itself. Ed25519 is deterministic, so re-signing an unchanged
# entry reproduces the identical signature while still appending a ledger block.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

ENTRY=""
SOCKET=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-sign-socket.sh --entry <entry.json> [--socket <path>] [--out <entry.json>]

Signs one registry entry through the isolated signer's unix socket. The entry must
be a single authorizations[] object (fingerprint, identity, capabilities,
issued_at, expires_at, revoked); any existing signature_b64 is dropped and rebuilt.
With --out the signed entry is written there; otherwise it is printed to stdout.
The signer also appends a signature_issued block to the ledger.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --entry)  ENTRY="$2"; shift 2 ;;
    --socket) SOCKET="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$ENTRY" ] || { echo "--entry required" >&2; usage; exit 1; }
[ -f "$ENTRY" ] || { echo "entry not found: $ENTRY" >&2; exit 1; }
[ -n "$SOCKET" ] || SOCKET="${SPARKNET_STATE_DIR:?missing}/signer/signer.sock"

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

ENTRY_PATH="$ENTRY" SOCKET_PATH="$SOCKET" OUT_PATH="$OUT" "$PY" - <<'PYEOF'
import json
import os
import socket
import sys
from pathlib import Path

entry_path = Path(os.environ["ENTRY_PATH"])
socket_path = Path(os.environ["SOCKET_PATH"])
out_path = os.environ.get("OUT_PATH", "")

if not socket_path.exists():
    sys.exit(f"signer socket not found: {socket_path} (is sparknet-master-signer running?)")

entry = json.loads(entry_path.read_text())
if not isinstance(entry, dict):
    sys.exit("entry must be a JSON object")
entry.pop("signature_b64", None)


def call(payload):
    """One request, one connection. The signer serves one line and closes."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(30.0)
    try:
        connection.connect(str(socket_path))
        connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        line = b""
        while b"\n" not in line:
            chunk = connection.recv(4096)
            if not chunk:
                break
            line += chunk
    finally:
        connection.close()
    return json.loads(line.split(b"\n", 1)[0].decode("utf-8"))


root = call({"op": "root-id"})
if not root.get("ok"):
    sys.exit(f"signer refused root-id: {root.get('error')}")

response = call({"op": "sign-registry-entry", "root_id": root["root_id"], "entry": entry})
if not response.get("ok"):
    sys.exit(f"signer refused to sign: {response.get('error')}")

signed = response["entry"]
text = json.dumps(signed, indent=2) + "\n"
if out_path:
    Path(out_path).write_text(text)
    print(f"signed {entry_path} -> {out_path} (ledger block {response.get('ledger_block', '')[:16]}...)", file=sys.stderr)
else:
    sys.stdout.write(text)
PYEOF
