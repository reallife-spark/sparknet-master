#!/usr/bin/env bash
# Publish a signed registry as a distribution publication.
#
# A registry alone is not distributable: its entries carry no freshness, so an
# attacker who can write to the channel could replay an older one in which a
# peer was not yet revoked. A *publication* wraps the registry with a monotonic
# sequence and a publication time, and the Master signs a digest of the registry
# together with those two fields. The peer installs a publication, never a bare
# registry, and refuses a sequence it has already seen.
#
# The signature is produced by shared/sparknet-authz.py::registry_publication_message
# — the same rule the peer verifies with — either through the isolated signer
# (`--socket`, production) or with the operational key in this process
# (`--offline`, tests and hosts with no signer running).
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

REGISTRY=""
OUT=""
SEQUENCE=""
PUBLISHED_AT=""
SOCKET=""
OFFLINE="0"

usage() {
  cat <<'USAGE'
usage: sparknet-registry-publish.sh --registry <registry.json> [--out <dir>] \
         [--sequence N] [--published-at ISO8601] [--socket <signer.sock>] [--offline]

Builds one signed registry publication and writes it to <dir>/current.json.

  --registry      the signed registry document (contracts/registry-schema.json)
  --out           the publication directory (default: $SPARKNET_STATE_DIR/registry)
  --sequence      publication counter; must exceed the last one (default: last + 1)
  --published-at  ISO-8601 UTC timestamp (default: now; tests pin it)
  --socket        sign through the isolated signer's unix socket
                  (default: $SPARKNET_STATE_DIR/signer/signer.sock when it exists)
  --offline       sign with the operational key in this process instead

The registry is checked against contracts/registry-schema.json before anything is
signed, and its master_public_key_b64 must name this Master's operational key: a
registry signed by somebody else must not be republished as if it were ours.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --sequence) SEQUENCE="$2"; shift 2 ;;
    --published-at) PUBLISHED_AT="$2"; shift 2 ;;
    --socket) SOCKET="$2"; shift 2 ;;
    --offline) OFFLINE="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$REGISTRY" ] || { echo "--registry required" >&2; usage; exit 1; }
[ -f "$REGISTRY" ] || { echo "registry not found: $REGISTRY" >&2; exit 1; }

STATE_DIR="${SPARKNET_STATE_DIR:?missing}"
OUT="${OUT:-$STATE_DIR/registry}"
SEQUENCE_FILE="$STATE_DIR/registry-sequence.json"
OP_PUB="$STATE_DIR/keys/operational.pub.b64"

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

# Refuse to publish a document no peer would accept. The checker is the same one
# the contract test runs; publishing an invalid registry would only move the
# failure to a node whose operator cannot fix it.
"$PY" "$FABRIC_ROOT/shared/sparknet-registry-schema.py" --registry "$REGISTRY" >/dev/null || {
  echo "refusing to publish: $REGISTRY does not conform to contracts/registry-schema.json" >&2
  exit 1
}

if [ "$OFFLINE" != "1" ] && [ -z "$SOCKET" ]; then
  SOCKET="$STATE_DIR/signer/signer.sock"
  [ -S "$SOCKET" ] || { echo "signer socket not found: $SOCKET (use --offline to sign in-process)" >&2; exit 1; }
fi
if [ "$OFFLINE" = "1" ] && [ -n "$SOCKET" ]; then
  echo "--offline and --socket are mutually exclusive" >&2
  exit 1
fi

REGISTRY_PATH="$REGISTRY" \
OUT_DIR="$OUT" \
SEQUENCE="$SEQUENCE" \
PUBLISHED_AT="$PUBLISHED_AT" \
SOCKET_PATH="$SOCKET" \
SEQUENCE_FILE="$SEQUENCE_FILE" \
OP_PUB="$OP_PUB" \
OP_PRIV="$STATE_DIR/keys/operational.ed25519" \
FABRIC_ROOT="$FABRIC_ROOT" \
"$PY" - <<'PYEOF'
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

FABRIC_ROOT = Path(os.environ["FABRIC_ROOT"])
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[FABRIC_ROOT / "shared"])

registry_path = Path(os.environ["REGISTRY_PATH"])
out_dir = Path(os.environ["OUT_DIR"])
sequence_arg = os.environ.get("SEQUENCE", "").strip()
published_at = os.environ.get("PUBLISHED_AT", "").strip()
socket_path = os.environ.get("SOCKET_PATH", "").strip()
sequence_file = Path(os.environ["SEQUENCE_FILE"])
op_pub = Path(os.environ["OP_PUB"])
op_priv = Path(os.environ["OP_PRIV"])

registry = json.loads(registry_path.read_text())
if not isinstance(registry, dict):
    sys.exit(f"{registry_path} is not a registry document")

# The registry must be *ours*. Republishing another fabric's document (or one
# whose entries were signed elsewhere) would mint a Master signature over data
# this Master never authorised.
if op_pub.is_file():
    ours = op_pub.read_text().strip()
    claimed = str(registry.get("master_public_key_b64") or "")
    if claimed != ours:
        sys.exit(
            f"refusing to publish: the registry names master key {claimed[:16]}... "
            f"but this Master's operational key is {ours[:16]}..."
        )

last = 0
if sequence_file.is_file():
    try:
        last = int(json.loads(sequence_file.read_text()).get("sequence") or 0)
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        sys.exit(f"cannot read the last sequence from {sequence_file}")

if sequence_arg:
    try:
        sequence = int(sequence_arg)
    except ValueError:
        sys.exit(f"--sequence must be an integer, got {sequence_arg!r}")
else:
    sequence = last + 1
if sequence <= last:
    sys.exit(
        f"refusing to publish sequence {sequence}: {last} is already published. "
        f"A lower or equal sequence is a rollback, which a peer refuses."
    )

if not published_at:
    published_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

unsigned = {
    "sequence": sequence,
    "published_at": published_at,
    "registry": registry,
    "registry_sha256": authz.registry_digest(registry),
}
try:
    message = authz.registry_publication_message(unsigned)
except authz.AuthzError as exc:
    sys.exit(f"refusing to publish a malformed publication: {exc}")


def call_signer(payload: dict) -> dict:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(30.0)
    try:
        connection.connect(socket_path)
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


if socket_path:
    root = call_signer({"op": "root-id"})
    if not root.get("ok"):
        sys.exit(f"signer refused root-id: {root.get('error')}")
    response = call_signer(
        {
            "op": "sign-registry-publication",
            "root_id": root["root_id"],
            "publication": {
                "sequence": sequence,
                "published_at": published_at,
                "registry": registry,
            },
        }
    )
    if not response.get("ok"):
        sys.exit(f"signer refused to sign: {response.get('error')}")
    publication = response["publication"]
    signature = response["signature_b64"]
    ledger_block = response.get("ledger_block")
    # The signer recomputes the digest; if it disagrees with ours, one of the
    # two canonicalised a different document and neither signature is usable.
    if publication.get("registry_sha256") != unsigned["registry_sha256"]:
        sys.exit("signer and publisher disagree about the registry digest; refusing to emit")
else:
    private_key = authz.private_key_from_b64(op_priv.read_text().strip())
    signature = authz.sign_bytes(private_key, message)
    publication = unsigned
    ledger_block = None

artifact = {**publication, "signature_b64": signature}

# Check the artifact with the *receiver's* rule before writing it: the same
# function the guard and the offline client run. A publication this Master emits
# but a peer refuses is a distribution failure discovered at the worst possible
# place, so the check happens here, where the error names this script.
install = load_shared("sparknet-registry-install.py", "sparknet_registry_install", dirs=[FABRIC_ROOT / "shared"])
schema = load_shared("sparknet-registry-schema.py", "sparknet_registry_schema", dirs=[FABRIC_ROOT / "shared"])
try:
    install.verify_publication(
        artifact,
        authz.public_key_from_b64(publication["registry"]["master_public_key_b64"]),
        authz,
        schema,
    )
except install.InstallError as exc:
    sys.exit(f"internal: a peer would refuse this publication [{exc.code}]: {exc.detail}")

out_dir.mkdir(parents=True, exist_ok=True)
out_file = out_dir / "current.json"
tmp = out_file.with_name(out_file.name + ".tmp")
tmp.write_text(json.dumps(artifact, indent=2) + "\n")
os.replace(tmp, out_file)

sequence_file.parent.mkdir(parents=True, exist_ok=True)
tmp = sequence_file.with_name(sequence_file.name + ".tmp")
tmp.write_text(
    json.dumps(
        {
            "sequence": sequence,
            "published_at": published_at,
            "registry_sha256": unsigned["registry_sha256"],
            "deprecated": "The current publication's own sequence is authoritative; this file exists so a later publish cannot reuse a number.",
        },
        indent=2,
    )
    + "\n"
)
os.replace(tmp, sequence_file)

entries = len(registry.get("authorizations") or [])
print(
    f"published sequence {sequence} ({entries} entries, sha256 {unsigned['registry_sha256'][:16]}...) "
    f"-> {out_file}",
    file=sys.stderr,
)
if ledger_block:
    print(f"  ledger block {str(ledger_block)[:16]}...", file=sys.stderr)
PYEOF
