#!/usr/bin/env bash
# Deliver a signed guard approval to the peer it was issued for.
#
# The peer listens on its own overlay address, port 9090 (the guard port in
# contracts/ports.json), and accepts one route: POST /api/v1/critical-file/patch
# with {"payload": <base64 canonical bytes>, "signature": <base64>}. The
# canonical bytes are produced by shared/sparknet-authz.py::guard_approval_message
# — the same rule the peer verifies with.
#
# The peer's address is resolved from the signed registry: the fingerprint names
# the peer, and the registry entry names its overlay address. An explicit --url
# overrides that, and with neither the script refuses rather than guessing.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

FINGERPRINT=""
APPROVAL=""
PAYLOAD=""
SIGNATURE=""
REGISTRY=""
URL=""
OUT=""
TIMEOUT="10"

usage() {
  cat <<'USAGE'
usage: sparknet-approval-deliver.sh --fingerprint <fp> (--approval <approval.json> | --payload <payload.json> --signature <b64>) \
         [--registry <registry.json>] [--url <url>] [--timeout SECONDS] [--out <record.json>]

Delivers one signed guard approval to the peer named by --fingerprint.

  --fingerprint  the peer the approval is addressed to
  --approval     the file sparknet-approval-issue.sh wrote
  --payload      a bare approval envelope (without the signature)
  --signature    its base64 signature, when --payload is used
  --registry     the signed registry to resolve the peer's overlay address from
                 (default: manifests/node-authorizations.json, when it exists)
  --url          the exact endpoint to POST to; overrides the registry lookup
  --timeout      seconds to wait for the peer (default 10)
  --out          where to write the delivery record; stdout otherwise

The record says whether the peer accepted the approval, and the peer's own
answer verbatim. A refusal by the peer is a delivery that happened and was
refused — the record says so, and the exit status is non-zero.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --fingerprint) FINGERPRINT="$2"; shift 2 ;;
    --approval) APPROVAL="$2"; shift 2 ;;
    --payload) PAYLOAD="$2"; shift 2 ;;
    --signature) SIGNATURE="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$FINGERPRINT" ] || { echo "--fingerprint required" >&2; exit 1; }
if [ -z "$APPROVAL" ] && { [ -z "$PAYLOAD" ] || [ -z "$SIGNATURE" ]; }; then
  echo "--approval (or --payload plus --signature) required" >&2
  exit 1
fi
if [ -n "$APPROVAL" ] && [ ! -f "$APPROVAL" ]; then
  echo "approval not found: $APPROVAL" >&2
  exit 1
fi

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

FINGERPRINT="$FINGERPRINT" \
APPROVAL="$APPROVAL" \
PAYLOAD="$PAYLOAD" \
SIGNATURE="$SIGNATURE" \
REGISTRY="${REGISTRY:-$ROLE_ROOT/manifests/node-authorizations.json}" \
URL="$URL" \
TIMEOUT="$TIMEOUT" \
FABRIC_ROOT="$FABRIC_ROOT" \
OUT_PATH="$OUT" \
"$PY" - <<'PYEOF'
import base64
import json
import os
import sys
import http.client
import urllib.error
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
from datetime import datetime, timezone
from pathlib import Path

FABRIC_ROOT = Path(os.environ["FABRIC_ROOT"])
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[FABRIC_ROOT / "shared"])

fingerprint = os.environ["FINGERPRINT"].strip()
approval_path = os.environ.get("APPROVAL", "").strip()
payload_path = os.environ.get("PAYLOAD", "").strip()
signature = os.environ.get("SIGNATURE", "").strip()
registry_path = os.environ.get("REGISTRY", "").strip()
url = os.environ.get("URL", "").strip()
timeout = float(os.environ.get("TIMEOUT") or "10")
out_path = os.environ.get("OUT_PATH", "").strip()

GUARD_PORT = 9090
GUARD_ROUTE = "/api/v1/critical-file/patch"

# --- the envelope ------------------------------------------------------------
if approval_path:
    try:
        artifact = json.loads(Path(approval_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read the approval {approval_path}: {exc}")
    if not isinstance(artifact, dict):
        sys.exit(f"{approval_path} is not an approval artifact")
    approval = artifact.get("approval")
    signature = str(artifact.get("signature_b64") or signature)
else:
    try:
        approval = json.loads(Path(payload_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read the payload {payload_path}: {exc}")

if not isinstance(approval, dict):
    sys.exit("the approval envelope must be an object")
if not signature:
    sys.exit("no signature: an unsigned approval is not an approval")

# The envelope must address the peer we are about to deliver to. Delivering one
# peer's approval to another would be exactly the mistake the peer refuses to
# make — but it must be refused here too, before anything is sent.
addressed = str(approval.get("peer_fingerprint") or "")
if addressed != fingerprint:
    sys.exit(
        f"the approval addresses {addressed or 'no peer'} but --fingerprint names {fingerprint}"
    )

try:
    canonical = authz.guard_approval_message(approval)
except authz.AuthzError as exc:
    sys.exit(f"refusing to deliver a malformed approval: {exc}")

# --- where to deliver --------------------------------------------------------
if not url:
    registry_file = Path(registry_path)
    if not registry_file.is_file():
        sys.exit(
            f"cannot resolve the peer's address: no --url and no registry at {registry_file}. "
            f"Publish the signed registry (make registry-publish) or pass --url."
        )
    try:
        registry = json.loads(registry_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"cannot read the registry {registry_file}: {exc}")
    entries = registry.get("authorizations") if isinstance(registry, dict) else None
    if not isinstance(entries, list):
        sys.exit(f"{registry_file} has no authorizations[] list")
    entry = next(
        (e for e in entries if isinstance(e, dict) and e.get("fingerprint") == fingerprint),
        None,
    )
    if entry is None:
        sys.exit(f"the registry {registry_file} names no peer with fingerprint {fingerprint}")
    address = str(entry.get("overlay_ipv4") or "")
    if not address:
        sys.exit(f"the registry entry for {fingerprint} carries no overlay_ipv4")
    # The identity records the address with its prefix length; a URL wants the
    # bare address, and "10.100.0.9/32:9090" is not a host.
    address = address.split("/", 1)[0].strip()
    try:
        import ipaddress

        address = str(ipaddress.ip_address(address))
    except ValueError:
        sys.exit(f"the registry entry for {fingerprint} carries an unusable overlay_ipv4: {address}")
    url = f"http://{address}:{GUARD_PORT}{GUARD_ROUTE}"

packet = {
    "payload": base64.b64encode(canonical).decode(),
    "signature": signature,
}
request = urllib.request.Request(
    url,
    data=json.dumps(packet).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

record = {
    "fingerprint": fingerprint,
    "url": url,
    "request_id": approval.get("request_id"),
    "nonce": approval.get("nonce"),
    "file_path": approval.get("file_path"),
    "delivered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "delivered": False,
    "status": None,
    "response": None,
    "error": None,
}
exit_code = 0
try:
    with _opener.open(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", "replace")
        record["status"] = response.status
        record["response"] = body
        record["delivered"] = True
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", "replace")
    record["status"] = exc.code
    record["response"] = body
    record["error"] = f"the peer refused the approval (HTTP {exc.code})"
    exit_code = 1
except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
    record["error"] = f"could not reach the peer: {exc}"
    exit_code = 1

text = json.dumps(record, indent=2) + "\n"
if out_path:
    Path(out_path).write_text(text)
    print(f"delivered to {url}: {record.get('error') or record['status']}", file=sys.stderr)
else:
    sys.stdout.write(text)
raise SystemExit(exit_code)
PYEOF
