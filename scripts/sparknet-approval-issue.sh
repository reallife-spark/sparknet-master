#!/usr/bin/env bash
# Issue a signed guard approval: the Master mints the envelope, signs it with
# the operational key, and records the nonce so the same nonce is never issued
# twice.
#
# The envelope is the one the peer verifies (contracts/guard-approval.json), and
# the canonical bytes come from shared/sparknet-authz.py::guard_approval_message
# — the same rule the peer's guard verifies with. A local copy of that rule is
# how the two sides drifted apart in the first place: the Master used to sign
# {target, content_digest}, the signer used {peer_fingerprint, target_path,
# action} and the peer verified {file_path, content_b64, content_sha256}, so no
# approval the Master could produce was one a peer would accept.
#
# This is the offline path: it loads the operational key into this process,
# which is convenient for tests and for a host with no signer running. The
# production path is sparknet-approval-sign-socket.sh, which hands the envelope
# to the isolated signer so the key never enters a calling process and every
# issued approval lands in the Master's hash-chained ledger.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

TARGET=""
CONTENT=""
PEER_FINGERPRINT=""
IDENTITY=""
TTL_SECONDS="60"
REQUEST_ID=""
NONCE=""
OUT=""
OPERATOR_OS=""

usage() {
  cat <<'USAGE'
usage: sparknet-approval-issue.sh --target <path> --content <file> \
         (--peer-fingerprint <fp> | --identity <identity.json>) \
         [--ttl-seconds N] [--request-id ID] [--nonce HEX] [--out <approval.json>]
         [--operator-os <canonical-json>]

Issues one signed guard approval for a single protected file on a single peer.

  --target           the peer's protected path (must be in the peer's
                     manifests/critical-manifest.json protected_paths)
  --content          file whose bytes become the new content of that path
  --peer-fingerprint the peer the approval is addressed to (sha256 of the
                     peer's canonical identity)
  --identity         an identity manifest to derive that fingerprint from
  --ttl-seconds      validity window; the peer's policy allows 60 (default)
  --request-id       correlates plan -> permission -> execute
  --nonce            single-use value; the Master refuses to issue it twice
  --out              where to write the signed approval; stdout otherwise
  --operator-os      canonical JSON of the OS identity of the human behind this
                     approval ({"uid":0,"euid":0,"username":"root","groups":[],
                     "is_root":true}); omit it to attest nobody. It is signed into
                     the envelope, and the peer guard refuses a privileged apply
                     whose attestation is absent or is_root:false — see
                     contracts/guard-approval.json approval.operator_os.

The result is {"approval": {...}, "signature_b64": "..."} — the envelope and
the signature over its canonical bytes, ready for sparknet-approval-deliver.sh.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --content) CONTENT="$2"; shift 2 ;;
    --peer-fingerprint) PEER_FINGERPRINT="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --ttl-seconds) TTL_SECONDS="$2"; shift 2 ;;
    --request-id) REQUEST_ID="$2"; shift 2 ;;
    --nonce) NONCE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --operator-os) OPERATOR_OS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$TARGET" ] || { echo "--target required" >&2; exit 1; }
[ -f "$CONTENT" ] || { echo "--content required (a file)" >&2; exit 1; }
if [ -z "$PEER_FINGERPRINT" ] && [ -z "$IDENTITY" ]; then
  echo "--peer-fingerprint or --identity required" >&2
  exit 1
fi
if [ -n "$IDENTITY" ] && [ ! -f "$IDENTITY" ]; then
  echo "identity not found: $IDENTITY" >&2
  exit 1
fi

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OP_PRIV="$STATE_DIR/keys/operational.ed25519"
[ -f "$OP_PRIV" ] || { echo "operational key missing at $OP_PRIV" >&2; exit 1; }
NONCE_FILE="$STATE_DIR/approval_nonces.json"

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

TARGET_PATH="$TARGET" \
CONTENT_PATH="$CONTENT" \
PEER_FINGERPRINT="$PEER_FINGERPRINT" \
IDENTITY_PATH="$IDENTITY" \
TTL_SECONDS="$TTL_SECONDS" \
REQUEST_ID="$REQUEST_ID" \
NONCE="$NONCE" \
OP_PRIV="$OP_PRIV" \
NONCE_FILE="$NONCE_FILE" \
FABRIC_ROOT="$FABRIC_ROOT" \
OUT_PATH="$OUT" \
OPERATOR_OS="$OPERATOR_OS" \
"$PY" - <<'PYEOF'
import base64
import hashlib
import json
import os
import secrets
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

FABRIC_ROOT = Path(os.environ["FABRIC_ROOT"])
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[FABRIC_ROOT / "shared"])

target = os.environ["TARGET_PATH"]
content_path = Path(os.environ["CONTENT_PATH"])
peer_fingerprint = os.environ["PEER_FINGERPRINT"].strip()
identity_path = os.environ.get("IDENTITY_PATH", "").strip()
ttl = int(os.environ.get("TTL_SECONDS") or "60")
request_id = os.environ.get("REQUEST_ID", "").strip()
nonce = os.environ.get("NONCE", "").strip()
op_priv = Path(os.environ["OP_PRIV"])
nonce_file = Path(os.environ["NONCE_FILE"])
out_path = os.environ.get("OUT_PATH", "").strip()
operator_os_raw = os.environ.get("OPERATOR_OS", "").strip()

if identity_path:
    peer_fingerprint = authz.fingerprint(json.loads(Path(identity_path).read_text()))
if not peer_fingerprint:
    sys.exit("a peer fingerprint is required: pass --peer-fingerprint or --identity")

content = content_path.read_bytes()
now = datetime.now(timezone.utc)
nonce = nonce or secrets.token_hex(16)
request_id = request_id or uuid.uuid4().hex

approval = {
    "peer_fingerprint": peer_fingerprint,
    "file_path": target,
    "content_b64": base64.b64encode(content).decode(),
    "content_sha256": hashlib.sha256(content).hexdigest(),
    "issued_at": now.isoformat().replace("+00:00", "Z"),
    "expires_at": (now + timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z"),
    "nonce": nonce,
    # Round-tripped through the shared codec rather than passed through: the
    # guard decodes strictly, so a malformed attestation must be refused here at
    # issue time, where an operator can fix it, and not at the peer.
    "operator_os": authz.encode_operator_os(authz.decode_operator_os(operator_os_raw)),
    "request_id": request_id,
}

# The canonical bytes are the rule the peer verifies with — not a local copy.
# Validate and sign *before* spending the nonce: a malformed request must not
# burn a value that can never be issued again.
message = authz.guard_approval_message(approval)
private_key = authz.private_key_from_b64(op_priv.read_text().strip())
signature = authz.sign_bytes(private_key, message)

# The Master refuses to issue the same nonce twice. A nonce the peer has
# already seen is dead on arrival there, so re-issuing one would mint an
# approval that can never be used — and the record of issued nonces is what
# makes "never twice" a fact rather than an intention.
nonce_file.parent.mkdir(parents=True, exist_ok=True)
tracked: dict = {}
if nonce_file.is_file():
    try:
        tracked = json.loads(nonce_file.read_text())
    except json.JSONDecodeError:
        tracked = {}
if nonce in tracked:
    sys.exit(
        f"refusing to issue nonce {nonce} again: it was already issued at "
        f"{tracked[nonce].get('issued_at') if isinstance(tracked.get(nonce), dict) else 'an earlier run'}"
    )
tracked[nonce] = {
    "target": target,
    "peer_fingerprint": peer_fingerprint,
    "issued_at": now.isoformat().replace("+00:00", "Z"),
}
tmp = nonce_file.with_name(nonce_file.name + ".tmp")
tmp.write_text(json.dumps(tracked, indent=2, sort_keys=True) + "\n")
os.replace(tmp, nonce_file)

artifact = {"approval": approval, "signature_b64": signature}

text = json.dumps(artifact, indent=2) + "\n"
if out_path:
    Path(out_path).write_text(text)
    print(
        f"issued approval for {peer_fingerprint[:16]}... ({target}, nonce {nonce}) -> {out_path}",
        file=sys.stderr,
    )
else:
    sys.stdout.write(text)
PYEOF
