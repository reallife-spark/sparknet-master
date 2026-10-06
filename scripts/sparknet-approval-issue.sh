#!/usr/bin/env bash
# Issue a signed approval payload per guard-protocol (minimal).
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

TARGET=""
CONTENT=""
OUT=""
NONCE_FILE="${SPARKNET_STATE_DIR:-/tmp}/approval_nonces.json"

usage() {
  cat <<'USAGE'
usage: sparknet-approval-issue.sh --target <path> --content <file> [--out <payload.json>]
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --content) CONTENT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done
[ -n "$TARGET" ] || { echo "--target required" >&2; exit 1; }
[ -f "$CONTENT" ] || { echo "--content required" >&2; exit 1; }

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OP_PRIV="$STATE_DIR/keys/operational.ed25519"
[ -f "$OP_PRIV" ] || { echo "priv missing" >&2; exit 1; }

mkdir -p "$(dirname "$NONCE_FILE")"
[ -f "$NONCE_FILE" ] || echo '{}' > "$NONCE_FILE"

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"
tmp=$(mktemp)
cat > "$tmp.py" <<PYEOF
import sys, json, os, base64, hashlib
sys.path.insert(0, '${FABRIC_ROOT}')
import importlib.util
spec = importlib.util.spec_from_file_location('authz','${FABRIC_ROOT}/shared/sparknet-authz.py')
authz = importlib.util.module_from_spec(spec)
sys.modules['authz']=authz
spec.loader.exec_module(authz)
from pathlib import Path
from datetime import datetime, timezone

content = Path('${CONTENT}').read_bytes()
# simple nonce: sha256 of content+time
import secrets
nonce = secrets.token_hex(16)
nf = Path('${NONCE_FILE}')
nonces = json.loads(nf.read_text())
if nonce in nonces:
    raise SystemExit('nonce collision')
nonces[nonce] = {'target':'${TARGET}','ts':datetime.now(timezone.utc).isoformat()}
nf.write_text(json.dumps(nonces, indent=2))

payload = {
  'target': '${TARGET}',
  'content_digest': hashlib.sha256(content).hexdigest(),
  'nonce': nonce,
  'issued_at': datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
}
# sign canonical-ish bytes
msg = json.dumps(payload, sort_keys=True).encode()
priv = authz.private_key_from_b64(Path('${OP_PRIV}').read_text().strip())
sig = authz.sign_bytes(priv, msg)
# sign_bytes may return bytes or str depending on impl; normalize
if isinstance(sig, str):
  sig_bytes = sig.encode('ascii')
else:
  sig_bytes = sig
payload['signature_b64'] = base64.b64encode(sig_bytes).decode()
print(json.dumps(payload, indent=2))
PYEOF
"$PY" "$tmp.py" > "$tmp.out"
rc=$?
rm -f "$tmp.py"
[ $rc -ne 0 ] && { rm -f "$tmp.out"; exit $rc; }
if [ -n "$OUT" ]; then cp "$tmp.out" "$OUT"; else cat "$tmp.out"; fi
rm -f "$tmp.out"
