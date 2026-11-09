#!/usr/bin/env bash
# Verify a registry against the operational public key in state dir.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

REG=""
usage() {
  cat <<'USAGE'
usage: sparknet-registry-verify.sh --registry <registry.json>

Verifies the document shape, duplicate identities, every entry signature under
the master key the document names, and that the document names this node's
operational public key from $SPARKNET_STATE_DIR/keys/operational.pub.b64.
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done
[ -n "$REG" ] || { echo "--registry required" >&2; usage; exit 1; }
[ -f "$REG" ] || { echo "registry not found: $REG" >&2; exit 1; }

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OP_PUB="$STATE_DIR/keys/operational.pub.b64"
[ -f "$OP_PUB" ] || { echo "pub missing at $OP_PUB" >&2; exit 1; }

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

REG_PATH="$REG" OP_PUB_PATH="$OP_PUB" FABRIC_ROOT="$FABRIC_ROOT" "$PY" - <<'PYEOF'
import importlib.util
import json
import os
import sys
from pathlib import Path

fabric_root = os.environ["FABRIC_ROOT"]
sys.path.insert(0, fabric_root)
spec = importlib.util.spec_from_file_location("authz", f"{fabric_root}/shared/sparknet-authz.py")
authz = importlib.util.module_from_spec(spec)
sys.modules["authz"] = authz
spec.loader.exec_module(authz)

reg = json.loads(Path(os.environ["REG_PATH"]).read_text())
expected_pub = Path(os.environ["OP_PUB_PATH"]).read_text().strip()
if reg.get("master_public_key_b64") != expected_pub:
    sys.exit("FAIL: registry master_public_key_b64 does not name this operational key")
master_pub = authz.public_key_from_b64(expected_pub)
entries = reg.get("authorizations")
if not isinstance(entries, list):
    sys.exit("FAIL: registry has no authorizations list")

seen_ids, seen_fps = set(), set()
for index, entry in enumerate(entries):
    if not isinstance(entry, dict):
        sys.exit(f"FAIL {index}: entry is not an object")
    node_id = (entry.get("identity") or {}).get("node_id", "")
    if not node_id or node_id in seen_ids:
        sys.exit(f"FAIL {index}: duplicate or empty node_id")
    seen_ids.add(node_id)
    fp = entry.get("fingerprint", "")
    if not fp or fp in seen_fps:
        sys.exit(f"FAIL {index}: duplicate or empty fingerprint")
    seen_fps.add(fp)
    try:
        computed = authz.fingerprint(entry.get("identity") or {})
        caps = entry.get("capabilities") or []
        if fp != computed:
            raise ValueError("fingerprint does not match identity")
        if any(c not in authz.KNOWN_CAPABILITIES for c in caps):
            raise ValueError("unknown capability")
        if not caps and not entry.get("revoked"):
            raise ValueError("an authorizing entry grants no capability")
        if entry.get("revoked") and caps:
            raise ValueError("a revoked entry must grant no capability")
        message = authz.authorization_message(entry)
        if not authz.verify_signature(master_pub, str(entry.get("signature_b64") or ""), message):
            raise ValueError("signature does not verify")
    except Exception as exc:
        sys.exit(f"FAIL {index}: {node_id}: {exc}")
print(f"OK: {len(entries)} entries")
PYEOF
