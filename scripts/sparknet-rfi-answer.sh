#!/usr/bin/env bash
# Compose, sign and deliver one RFI answer into a peer's 01_Inbox.
#
# This is the Master-side half of the request-for-information channel
# (contracts/rfi-schema.json). A peer asks for information; the Master gathers an
# answer, signs it with the operational key, and pushes it to POST /api/v1/rfi on
# the peer's guard (port 9090, the guard's existing overlay listener). The answer
# is self-authenticating: its signature covers a projection that includes the
# destination item_name and the content's digest, so no transport wrapper and no
# second signature are needed. The peer installs it through
# shared/sparknet-rfi-install.py — the one acceptance rule.
#
# Delivery is a push because the Master already dials peers on 9090 for guard
# approvals and registry publications, and because the answer's own signature is
# what the peer checks, not the transport.
#
# A request arrives two ways. With --request <artifact>, the composer consumes the
# file the 8090 peer intake queued: it re-verifies shape/freshness, takes the
# request_id and destination peer *from the request*, and enforces its `scope`
# against the categories the answer declares via --sources. Without --request, the
# operator path still takes --request-id/--peer directly — needed when a request
# arrived out of band or no listener is running. Attribution is the intake's (the
# overlay), not a signature: see RFI_REQUEST_DESIGN.md.
#
# WHAT THIS SCRIPT DOES NOT DO, and why:
#
#   * It does not *gather* the answer. Gathering is upstream (the fabric's semantic
#     store, port 4223, is spec-only). The content is read from --content or
#     --empty; --sources is the upstream's declaration of which vault categories
#     it drew on, and in --request mode the composer refuses any source outside
#     the request's scope. Scope narrows; the answer cannot widen it.
#   * It cannot re-attest the request's sender. The overlay did that when the
#     intake received it; the queued artifact is 0600 in a 0700 directory. The
#     composer re-checks the request's shape and freshness, not its provenance.
#
# The signature is produced by shared/sparknet-authz.py::sign_rfi_answer — the same
# rule the peer verifies with — either through the isolated signer (--socket,
# production) or with the operational key in this process (--offline, tests and
# hosts with no signer running).
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

REQUEST_ID=""
REQUEST_FILE=""
PEER=""
URL=""
ITEM_NAME=""
CONTENT=""
SOURCE_CATEGORIES=""
EMPTY="0"
REGISTRY=""
SOCKET=""
OFFLINE="0"
ANSWERED_AT=""
TIMEOUT="10"
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-rfi-answer.sh --request <artifact> --item-name <name> \
          (--content <file|-> [--sources <category,...>] | --empty) \
          [--url <url>] [--registry <registry.json>] \
          [--socket <signer.sock>] [--offline] [--answered-at ISO8601] \
          [--timeout SECONDS] [--out <record.json>]

       sparknet-rfi-answer.sh --request-id <id> --peer <fingerprint> \
          --item-name <name> (--content <file|-> | --empty) \[same options]

Composes one signed RFI answer and pushes it to the peer's POST /api/v1/rfi.

  --request     a verified request artifact queued by the 8090 intake; the peer
                and request_id come from it, and its scope constrains --sources
  --request-id  the request this answers (operator path); the answer echoes it, and
                it is what makes a re-delivered answer a duplicate, not new data
  --peer        the destination peer's fingerprint (operator path); the answer is
                bound to it, so one minted for a node cannot install elsewhere
  --item-name   the destination filename under the peer's 01_Inbox/ (a single
                safe component; it is inside the signature, so the peer cannot be
                made to write elsewhere)
  --content     the answer payload: a file path, or '-' for stdin
  --sources     comma-separated vault categories the content was drawn from. With
                --request, a non-empty answer must declare them and every one must
                be inside the request's scope; an empty answer declares none.
  --empty       compose an empty answer ("nothing found" is a legitimate answer)
  --url         the exact endpoint; overrides the registry lookup. The operator
                path requires --peer (or --request, which supplies it). This is how
                a test reaches a loopback guard.
  --registry    where to resolve --peer to an overlay address
                (default: $VAULT_PATH/manifests/node-authorizations.json). A
                bare registry or a publication wrapping one both work.
  --socket      sign through the isolated signer's unix socket
                (default: $SPARKNET_STATE_DIR/signer/signer.sock when it exists)
  --offline     sign with the operational key in this process instead
  --answered-at ISO-8601 UTC timestamp (default: now; --offline only, tests pin it)
  --timeout     seconds for the delivery POST (default 10)
  --out         where to write the delivery record; stdout otherwise

The peer is looked up in the registry and must be present and not revoked: an
answer carries requested material into a node's inbox, and a revoked node has no
privileges to receive it. A peer that refuses or is unreachable is recorded and
the exit status is non-zero, so a re-delivery pass tries again.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --request) REQUEST_FILE="$2"; shift 2 ;;
    --request-id) REQUEST_ID="$2"; shift 2 ;;
    --peer) PEER="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --item-name) ITEM_NAME="$2"; shift 2 ;;
    --content) CONTENT="$2"; shift 2 ;;
    --sources) SOURCE_CATEGORIES="$2"; shift 2 ;;
    --empty) EMPTY="1"; shift ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --socket) SOCKET="$2"; shift 2 ;;
    --offline) OFFLINE="1"; shift ;;
    --answered-at) ANSWERED_AT="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -n "$REQUEST_FILE" ]; then
  [ -f "$REQUEST_FILE" ] || { echo "request artifact not found: $REQUEST_FILE" >&2; exit 1; }
  [ -z "$PEER" ] || { echo "--request takes the peer from the artifact; drop --peer" >&2; exit 1; }
  [ -z "$REQUEST_ID" ] || { echo "--request takes the id from the artifact; drop --request-id" >&2; exit 1; }
else
  [ -n "$REQUEST_ID" ] || { echo "--request-id required" >&2; usage; exit 1; }
  [ -n "$PEER" ] || { echo "--peer required (the destination fingerprint)" >&2; usage; exit 1; }
fi
[ -n "$ITEM_NAME" ] || { echo "--item-name required" >&2; usage; exit 1; }
if [ "$OFFLINE" = "1" ] && [ -n "$SOCKET" ]; then
  echo "--offline and --socket are mutually exclusive" >&2
  exit 1
fi

# Exactly one content source. Reading stdin happens here, before the Python
# heredoc, because the heredoc is the interpreter's own stdin.
CONTENT_SOURCES=0
[ -n "$CONTENT" ] && CONTENT_SOURCES=$((CONTENT_SOURCES + 1))
[ "$EMPTY" = "1" ] && CONTENT_SOURCES=$((CONTENT_SOURCES + 1))
if [ "$CONTENT_SOURCES" -ne 1 ]; then
  echo "exactly one of --content <file|-> or --empty is required" >&2
  exit 1
fi

TMP_CONTENT=""
# The if-form, not `[ -n "$TMP" ] && rm`: a false `&&` list returns 1, and an EXIT
# trap's status becomes the script's, which would turn a clean delivery into a
# non-zero exit whenever the content came from a file rather than stdin.
cleanup() { if [ -n "$TMP_CONTENT" ]; then rm -f "$TMP_CONTENT"; fi; }
trap cleanup EXIT

CONTENT_FILE=""
if [ "$EMPTY" = "1" ]; then
  CONTENT_FILE=""
elif [ "$CONTENT" = "-" ]; then
  TMP_CONTENT="$(mktemp)"
  cat > "$TMP_CONTENT"
  CONTENT_FILE="$TMP_CONTENT"
else
  [ -f "$CONTENT" ] || { echo "content file not found: $CONTENT" >&2; exit 1; }
  CONTENT_FILE="$CONTENT"
fi

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

if [ "$OFFLINE" != "1" ] && [ -z "$SOCKET" ]; then
  SOCKET="$SPARKNET_STATE_DIR/signer/signer.sock"
  [ -S "$SOCKET" ] || { echo "signer socket not found: $SOCKET (use --offline to sign in-process)" >&2; exit 1; }
fi

REQUEST_ID="$REQUEST_ID" \
REQUEST_FILE="$REQUEST_FILE" \
PEER="$PEER" \
SOURCES="$SOURCE_CATEGORIES" \
URL="$URL" \
ITEM_NAME="$ITEM_NAME" \
CONTENT_FILE="$CONTENT_FILE" \
CONTENT_EMPTY="$EMPTY" \
REGISTRY="$REGISTRY" \
SOCKET_PATH="$SOCKET" \
ANSWERED_AT="$ANSWERED_AT" \
TIMEOUT="$TIMEOUT" \
OUT_PATH="$OUT" \
STATE_DIR="$SPARKNET_STATE_DIR" \
VAULT_PATH="$VAULT_PATH" \
FABRIC_ROOT="$FABRIC_ROOT" \
"$PY" - <<'PYEOF'
import base64
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FABRIC_ROOT = Path(os.environ["FABRIC_ROOT"])
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[FABRIC_ROOT / "shared"])

request_id = os.environ["REQUEST_ID"]
request_file = os.environ.get("REQUEST_FILE", "").strip()
peer = os.environ["PEER"]
sources_arg = os.environ.get("SOURCES", "")
url_override = os.environ.get("URL", "").strip()
item_name = os.environ["ITEM_NAME"]
content_file = os.environ.get("CONTENT_FILE", "").strip()
content_empty = os.environ.get("CONTENT_EMPTY") == "1"
registry_arg = os.environ.get("REGISTRY", "").strip()
socket_path = os.environ.get("SOCKET_PATH", "").strip()
answered_at = os.environ.get("ANSWERED_AT", "").strip()
timeout = float(os.environ.get("TIMEOUT") or "10")
out_path = os.environ.get("OUT_PATH", "").strip()
state_dir = Path(os.environ["STATE_DIR"])
vault_path = Path(os.environ["VAULT_PATH"])

GUARD_PORT = 9090
GUARD_ROUTE = "/api/v1/rfi"

# --- the payload -------------------------------------------------------------

if content_empty:
    content = b""
elif content_file:
    try:
        content = Path(content_file).read_bytes()
    except OSError as exc:
        sys.exit(f"cannot read the answer content {content_file}: {exc}")
else:
    sys.exit("no answer content: pass --content <file|-> or --empty")

# --- the request artifact (70C) ----------------------------------------------

request_doc = None
scope = []
question = ""
if request_file:
    try:
        request_doc = json.loads(Path(request_file).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read the request artifact {request_file}: {exc}")
    if not isinstance(request_doc, dict):
        sys.exit("the request artifact is not a JSON object")
    # Attribution was the intake's job (the overlay source). Re-checking with the
    # artifact's own fingerprint validates shape, freshness and the nonce format;
    # it cannot re-attest the sender, and does not pretend to.
    ok, reason = authz.verify_rfi_request(
        request_doc,
        expected_fingerprint=str(request_doc.get("peer_fingerprint", "")),
        now=datetime.now(timezone.utc),
    )
    if not ok:
        sys.exit(f"refusing an invalid request artifact [{reason}]")
    peer = request_doc["peer_fingerprint"]
    request_id = request_doc["request_id"]
    question = request_doc["question"]
    scope = list(request_doc["scope"])

sources = sorted({s.strip() for s in sources_arg.split(",") if s.strip()})
if request_doc is not None:
    if content and not sources:
        sys.exit("a non-empty answer to --request must declare --sources (the categories it drew on)")
    if content_empty and sources:
        sys.exit("an empty answer drew on nothing; drop --sources")
    outside = [s for s in sources if s not in scope]
    if outside:
        sys.exit(f"scope narrows: {outside} is outside the request's scope {scope}; refusing to widen it")
elif content_empty and sources:
    sys.exit("an empty answer drew on nothing; drop --sources")

# --- resolve the destination -------------------------------------------------


def _authorizations(doc):
    """A bare registry or a publication wrapping one -> its authorizations[]."""
    if not isinstance(doc, dict):
        return None
    registry = doc.get("registry") if isinstance(doc.get("registry"), dict) else doc
    entries = registry.get("authorizations")
    return entries if isinstance(entries, list) else None


url = url_override
if not url:
    registry_path = Path(registry_arg) if registry_arg else vault_path / "manifests" / "node-authorizations.json"
    if not registry_path.is_file():
        sys.exit(f"no registry to resolve --peer against: {registry_path} (pass --registry or --url)")
    try:
        entries = _authorizations(json.loads(registry_path.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read the registry {registry_path}: {exc}")
    if entries is None:
        sys.exit(f"{registry_path} carries no authorizations[] list")
    match = [e for e in entries if isinstance(e, dict) and e.get("fingerprint") == peer]
    if not match:
        sys.exit(f"the registry names no peer with fingerprint {peer[:16]}...")
    entry = match[0]
    if entry.get("revoked"):
        sys.exit(f"refusing to answer a revoked peer ({peer[:16]}...): it holds no privileges")
    address = str(entry.get("overlay_ipv4") or "").split("/", 1)[0].strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        sys.exit(f"the registry entry for {peer[:16]}... carries no usable overlay_ipv4")
    url = f"http://{address}:{GUARD_PORT}{GUARD_ROUTE}"


# --- sign --------------------------------------------------------------------


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
    pubkey = call_signer({"op": "public-key"})
    if not pubkey.get("ok"):
        sys.exit(f"signer refused public-key: {pubkey.get('error')}")
    master_public_key = authz.public_key_from_b64(pubkey["public_key_b64"])
    response = call_signer(
        {
            "op": "sign-rfi-answer",
            "root_id": root["root_id"],
            "answer": {
                "content_b64": base64.b64encode(content).decode("ascii"),
                "item_name": item_name,
                "peer_fingerprint": peer,
                "request_id": request_id,
            },
        }
    )
    if not response.get("ok"):
        sys.exit(f"signer refused to sign the answer: {response.get('error')}")
    artifact = response["answer"]
    ledger_block = response.get("ledger_block")
else:
    op_priv = state_dir / "keys" / "operational.ed25519"
    op_pub = state_dir / "keys" / "operational.pub.b64"
    if not op_priv.is_file():
        sys.exit(f"no operational key at {op_priv} (use --socket, or provision the key)")
    private_key = authz.private_key_from_b64(op_priv.read_text().strip())
    if op_pub.is_file():
        master_public_key = authz.public_key_from_b64(op_pub.read_text().strip())
    else:
        master_public_key = private_key.public_key()
    moment = None
    if answered_at:
        try:
            moment = datetime.fromisoformat(answered_at.replace("Z", "+00:00"))
        except ValueError:
            sys.exit(f"--answered-at must be ISO-8601, got {answered_at!r}")
    artifact = authz.sign_rfi_answer(
        content=content,
        item_name=item_name,
        peer_fingerprint=peer,
        request_id=request_id,
        master_private_key=private_key,
        now=moment,
    )
    ledger_block = None

# --- check it with the receiver's rule before delivering ---------------------
#
# verify_rfi_answer is the peer's own check. Passing now=the artifact's own
# answered_at makes this a *structural* check (signature, digest, peer binding,
# item-name safety) rather than a freshness one: whether the answer is still
# inside its window when it arrives is the peer's decision against the peer's
# clock, not the composer's. A compose a peer would refuse is caught here, where
# the error names this script, instead of at the destination.
self_now = datetime.fromisoformat(str(artifact["answered_at"]).replace("Z", "+00:00"))
ok, reason, _ = authz.verify_rfi_answer(
    artifact,
    master_public_key=master_public_key,
    peer_fingerprint=peer,
    now=self_now,
    installed_request_ids=(),
)
if not ok:
    sys.exit(f"internal: a peer would refuse this answer [{reason}]; refusing to deliver")

# --- deliver -----------------------------------------------------------------

record = {
    "request_id": request_id,
    "peer_fingerprint": peer,
    "item_name": item_name,
    "sources": sources,
    "content_sha256": artifact["content_sha256"],
    "url": url,
    "delivered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "delivered": False,
    "status": None,
    "response": None,
    "error": None,
}
if request_doc is not None:
    record["question"] = question
    record["scope"] = scope
if ledger_block:
    record["ledger_block"] = ledger_block

body = json.dumps(artifact).encode("utf-8")
request = urllib.request.Request(
    url, data=body, headers={"Content-Type": "application/json"}, method="POST"
)
exit_code = 0
try:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        record["status"] = response.status
        record["response"] = response.read().decode("utf-8", "replace")
        record["delivered"] = response.status == 200
        if not record["delivered"]:
            exit_code = 1
except urllib.error.HTTPError as exc:
    record["status"] = exc.code
    record["response"] = exc.read().decode("utf-8", "replace")
    record["error"] = f"the peer refused the answer (HTTP {exc.code})"
    exit_code = 1
except (urllib.error.URLError, OSError) as exc:
    record["error"] = f"could not reach the peer: {exc}"
    exit_code = 1

document = {
    "request_id": request_id,
    "peer_fingerprint": peer,
    "item_name": item_name,
    "content_sha256": artifact["content_sha256"],
    "url": url,
    "delivery": record,
    "ok": exit_code == 0,
}
text = json.dumps(document, indent=2) + "\n"
if out_path:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(text)
    print(f"{peer[:16]}...: {record.get('error') or record['status']}", file=sys.stderr)
else:
    sys.stdout.write(text)
raise SystemExit(exit_code)
PYEOF
