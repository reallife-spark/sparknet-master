#!/usr/bin/env bash
# Sign a guard approval THROUGH the isolated signer's unix socket.
#
# sparknet-approval-issue.sh signs directly with the operational key, loading it
# into the calling process. That is convenient for tests and for a host that has
# no signer running, and it is deliberately bypassed in production: it never
# touches the socket, so the signer never records the approval in the ledger.
# This script is the production path. It hands the envelope to the signer over
# its 0600 unix socket, so the key never enters this process and every issued
# approval lands as a `signature_issued` block in the Master's hash-chained
# ledger.
#
# The envelope is passed as-is (minus any signature_b64); the signer rebuilds
# the canonical bytes itself, from the one rule in shared/sparknet-authz.py.
# Ed25519 is deterministic, so re-signing an unchanged envelope reproduces the
# identical signature while still appending a ledger block.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

APPROVAL=""
SOCKET=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-approval-sign-socket.sh --approval <approval.json> [--socket <path>] [--out <approval.json>]

Signs one guard approval through the isolated signer's unix socket. The file is
either an approval envelope or the {"approval": ..., "signature_b64": ...}
artifact sparknet-approval-issue.sh writes; any existing signature_b64 is
dropped and rebuilt. With --out the signed artifact is written there; otherwise
it is printed to stdout. The signer also appends a signature_issued block to
the ledger.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --approval) APPROVAL="$2"; shift 2 ;;
    --socket) SOCKET="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$APPROVAL" ] || { echo "--approval required" >&2; exit 1; }
[ -f "$APPROVAL" ] || { echo "approval not found: $APPROVAL" >&2; exit 1; }
[ -n "$SOCKET" ] || SOCKET="${SPARKNET_STATE_DIR:?missing}/signer/signer.sock"

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

APPROVAL_PATH="$APPROVAL" SOCKET_PATH="$SOCKET" OUT_PATH="$OUT" "$PY" - <<'PYEOF'
import json
import os
import socket
import sys
from pathlib import Path

approval_path = Path(os.environ["APPROVAL_PATH"])
socket_path = Path(os.environ["SOCKET_PATH"])
out_path = os.environ.get("OUT_PATH", "")

if not socket_path.exists():
    sys.exit(f"signer socket not found: {socket_path} (is sparknet-master-signer running?)")

document = json.loads(approval_path.read_text())
if not isinstance(document, dict):
    sys.exit("the approval file must be a JSON object")
approval = document.get("approval") if isinstance(document.get("approval"), dict) else document
approval = {k: v for k, v in approval.items() if k != "signature_b64"}


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

response = call({"op": "sign-guard-approval", "root_id": root["root_id"], "approval": approval})
if not response.get("ok"):
    sys.exit(f"signer refused to sign: {response.get('error')}")

# The signature travels beside the envelope, never inside it: the canonical rule
# covers exactly the envelope's fields, and an extra field inside it would be
# unsigned authority-shaped data the peer is right to refuse.
signed = dict(response["approval"])
signed.pop("signature_b64", None)
signature_b64 = str(response.get("signature_b64") or "")
if not signature_b64:
    sys.exit("the signer returned no signature")
artifact = {"approval": signed, "signature_b64": signature_b64}
text = json.dumps(artifact, indent=2) + "\n"
if out_path:
    Path(out_path).write_text(text)
    print(
        f"signed {approval_path} -> {out_path} (ledger block {response.get('ledger_block', '')[:16]}...)",
        file=sys.stderr,
    )
else:
    sys.stdout.write(text)
PYEOF
