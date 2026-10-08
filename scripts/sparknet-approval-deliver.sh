#!/usr/bin/env bash
# Stub deliver: POST to peer's 9090 (just records intent, does not actually POST unless --url given).
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

FINGERPRINT=""
PAYLOAD=""
URL=""
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-approval-deliver.sh --fingerprint <fp> [--payload <payload.json>] [--url http://10.100.0.x:9090/...] [--out <rec.json>]
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --fingerprint) FINGERPRINT="$2"; shift 2 ;;
    --payload) PAYLOAD="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done
[ -n "$FINGERPRINT" ] || { echo "--fingerprint required" >&2; exit 1; }

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"
tmp=$(mktemp)
cat > "$tmp.py" <<PYEOF
import sys, json, os
from datetime import datetime, timezone

rec = {
  'fingerprint': '${FINGERPRINT}',
  'delivered_at': datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
  'delivered': False,
  'url': '${URL}' or None,
}
# if payload exists, just attach size
try:
  if '${PAYLOAD}':
    p = json.load(open('${PAYLOAD}'))
    rec['payload_digest'] = p.get('content_digest')
except Exception:
  pass
print(json.dumps(rec, indent=2))
PYEOF
"$PY" "$tmp.py" > "$tmp.out"
rm -f "$tmp.py"
if [ -n "$OUT" ]; then cp "$tmp.out" "$OUT"; else cat "$tmp.out"; fi
rm -f "$tmp.out"
