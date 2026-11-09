#!/usr/bin/env bash
# MASTER-SIDE: sign an identity into a registry entry using the operational key.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

IDENTITY=""
CAPS="telemetry"
NODE_PUBKEY=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-sign.sh --identity <identity.json> [--capabilities c1,c2] [--node-pubkey <file-or-b64>] [--out <entry.json>]

Signs the identity file with the Master's operational key (from $SPARKNET_STATE_DIR/keys/operational.ed25519)
and writes a registry entry JSON to stdout or --out.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2 ;;
    --capabilities) CAPS="$2"; shift 2 ;;
    --node-pubkey) NODE_PUBKEY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$IDENTITY" ] || { echo "--identity required" >&2; usage; exit 1; }
[ -f "$IDENTITY" ] || { echo "identity not found: $IDENTITY" >&2; exit 1; }

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OP_PRIV="$STATE_DIR/keys/operational.ed25519"
[ -f "$OP_PRIV" ] || { echo "operational key missing at $OP_PRIV" >&2; exit 1; }

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

IDENTITY_PATH="$IDENTITY" NODE_PUBKEY_VALUE="$NODE_PUBKEY" OP_PRIV_PATH="$OP_PRIV" \
CAPS_RAW="$CAPS" OUT_PATH="$OUT" FABRIC_ROOT="$FABRIC_ROOT" "$PY" - <<'PYEOF'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

fabric_root = os.environ["FABRIC_ROOT"]
sys.path.insert(0, f"{fabric_root}/shared")
from sparknet_loader import load_shared
authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[f"{fabric_root}/shared"])

identity = json.loads(Path(os.environ["IDENTITY_PATH"]).read_text())
raw_pub = os.environ.get("NODE_PUBKEY_VALUE", "").strip()
node_pubkey = Path(raw_pub).read_text().strip() if raw_pub and Path(raw_pub).is_file() else (raw_pub or None)
node_pubkey = node_pubkey or identity.get("node_pubkey_b64")
private = authz.private_key_from_b64(Path(os.environ["OP_PRIV_PATH"]).read_text().strip())
caps = [value.strip() for value in os.environ.get("CAPS_RAW", "").split(",") if value.strip()]
entry = authz.sign_authorization(
    identity, private, caps, ttl_days=365, now=datetime.now(timezone.utc), node_pubkey_b64=node_pubkey
)
text = json.dumps(entry, indent=2, sort_keys=False) + "\n"
out = os.environ.get("OUT_PATH", "")
if out:
    Path(out).write_text(text)
else:
    sys.stdout.write(text)
PYEOF
