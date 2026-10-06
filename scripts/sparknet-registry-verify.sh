#!/usr/bin/env bash
# Verify a registry against the operational public key in state dir.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

REG=""
usage() {
  cat <<'USAGE'
usage: sparknet-registry-verify.sh --registry <registry.json>

Verifies all authorization entries against $SPARKNET_STATE_DIR/keys/operational.pub.b64.
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

reg = json.loads(Path('${REG}').read_text())
pub_b64 = Path('${OP_PUB}').read_text().strip()
pub = authz.public_key_from_b64(pub_b64)
now = datetime.now(timezone.utc)
for i, entry in enumerate(reg.get('authorizations', [])):
    ident = entry.get('identity', {})
    caps = entry.get('capabilities', [])
    decision = authz.evaluate(ident, {'authorizations': [entry]}, pub, now=now)
    if not decision.allowed:
        print(f'FAIL {i}: {decision.reason}')
        sys.exit(1)
    if set(decision.capabilities) != set(caps):
        print(f'CAPS {i}: mismatch')
        sys.exit(2)
print(f'OK: {len(reg.get("authorizations", []))} entries')
PYEOF
"$PY" "$tmp.py"
rc=$?
rm -f "$tmp.py"
exit $rc
