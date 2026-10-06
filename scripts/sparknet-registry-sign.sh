#!/usr/bin/env bash
# MASTER-SIDE: sign an identity into a registry entry using the operational key.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

IDENTITY=""
CAPS="telemetry,guard-read"
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-sign.sh --identity <identity.json> [--capabilities c1,c2] [--out <entry.json>]

Signs the identity file with the Master's operational key (from $SPARKNET_STATE_DIR/keys/operational.ed25519)
and writes a registry entry JSON to stdout or --out.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --identity) IDENTITY="$2"; shift 2 ;;
    --capabilities) CAPS="$2"; shift 2 ;;
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

# build capabilities array
IFS=',' read -r -a cap_arr <<< "$CAPS"
cap_list=""
for c in "${cap_arr[@]}"; do
  c_trimmed=$(echo "$c" | tr -d '[:space:]')
  [ -n "$c_trimmed" ] && cap_list+="\"$c_trimmed\","
done
cap_list="[${cap_list%,}]"

# sign via authz
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
cap = json.loads('${cap_list}')
now = datetime.now(timezone.utc)
entry = authz.sign_authorization(identity, priv, cap, ttl_days=365, now=now)
print(json.dumps(entry, indent=2, sort_keys=False))
PYEOF
"$PY" "$tmp.py" > "$tmp.out"
rm -f "$tmp.py"
if [ -n "$OUT" ]; then
  cp "$tmp.out" "$OUT"
else
  cat "$tmp.out"
fi
rm -f "$tmp.out"
