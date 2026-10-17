#!/usr/bin/env bash
# Sign a revoked authorization for an identity.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

IDENTITY=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-revoke.sh --identity <identity.json> [--out <entry.json>]

Signs a REVOKED authorization for an identity. The entry grants nothing, so
there is no capability list to set: --capabilities used to be accepted here and
silently ignored, which is worse than not offering it.
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done
[ -n "$IDENTITY" ] || { echo "--identity required" >&2; exit 1; }
[ -f "$IDENTITY" ] || { echo "identity not found: $IDENTITY" >&2; exit 1; }

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OP_PRIV="$STATE_DIR/keys/operational.ed25519"
[ -f "$OP_PRIV" ] || { echo "operational key missing" >&2; exit 1; }

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"
tmp=$(mktemp)
cat > "$tmp.py" <<PYEOF
import sys, json
sys.path.insert(0, '${FABRIC_ROOT}')
import importlib.util
spec = importlib.util.spec_from_file_location('authz', '${FABRIC_ROOT}/shared/sparknet-authz.py')
authz = importlib.util.module_from_spec(spec)
sys.modules['authz'] = authz
spec.loader.exec_module(authz)
from pathlib import Path
from datetime import datetime, timezone

identity = json.loads(Path('${IDENTITY}').read_text())
priv_b64 = Path('${OP_PRIV}').read_text().strip()
priv = authz.private_key_from_b64(priv_b64)
cap = []
now = datetime.now(timezone.utc)
entry = authz.sign_authorization(identity, priv, cap, ttl_days=365, now=now)
entry['revoked'] = True
print(json.dumps(entry, indent=2))
PYEOF
"$PY" "$tmp.py" > "$tmp.out"
rm -f "$tmp.py"
if [ -n "$OUT" ]; then cp "$tmp.out" "$OUT"; else cat "$tmp.out"; fi
rm -f "$tmp.out"
