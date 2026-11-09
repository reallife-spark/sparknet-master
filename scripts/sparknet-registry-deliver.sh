#!/usr/bin/env bash
# Deliver a signed registry publication to the peers it describes.
#
# The peer listens on its own overlay address, port 9090 (the guard port in
# contracts/ports.json), and accepts POST /api/v1/registry with the publication
# artifact as the body. The artifact is self-authenticating: its signature is
# over a projection that includes the sequence, so no transport wrapper and no
# second signature are needed.
#
# Delivery is a push because the Master already dials peers on 9090 for guard
# approvals, and because a peer whose entry has just been revoked must still
# *receive* that revocation: the route is deliberately not gated on the peer's
# own capability.
#
# The peer's address comes from the publication's own registry (fingerprint ->
# overlay_ipv4). An explicit --url overrides it for a single peer, which is how
# the end-to-end test reaches a loopback guard.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

PUBLICATION=""
PEER=""
URL=""
TIMEOUT="10"
OUT=""

usage() {
  cat <<'USAGE'
usage: sparknet-registry-deliver.sh --publication <publication.json> \
         [--peer <fingerprint>] [--url <url>] [--timeout SECONDS] [--out <record.json>]

Pushes one signed registry publication to every peer in its registry, or to the
one peer named by --peer.

  --publication  what sparknet-registry-publish.sh wrote
  --peer         deliver to one fingerprint instead of every entry
  --url          the exact endpoint for a single peer (requires --peer);
                 overrides the registry lookup
  --timeout      seconds per peer (default 10)
  --out          where to write the delivery record; stdout otherwise

Revoked entries are delivered to as well as live ones. That is the point of the
channel: the node being revoked has to learn about it. A peer that refuses or is
unreachable is recorded, and the exit status is non-zero so the re-delivery pass
tries again.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --publication) PUBLICATION="$2"; shift 2 ;;
    --peer) PEER="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

[ -n "$PUBLICATION" ] || { echo "--publication required" >&2; usage; exit 1; }
[ -f "$PUBLICATION" ] || { echo "publication not found: $PUBLICATION" >&2; exit 1; }
if [ -n "$URL" ] && [ -z "$PEER" ]; then
  echo "--url names one endpoint, so it requires --peer" >&2
  exit 1
fi

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

PUBLICATION_PATH="$PUBLICATION" \
PEER="$PEER" \
URL="$URL" \
TIMEOUT="$TIMEOUT" \
FABRIC_ROOT="$FABRIC_ROOT" \
OUT_PATH="$OUT" \
"$PY" - <<'PYEOF'
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FABRIC_ROOT = Path(os.environ["FABRIC_ROOT"])
sys.path.insert(0, str(FABRIC_ROOT / "shared"))
from sparknet_loader import load_shared  # noqa: E402 - import after the loader path shim

authz = load_shared("sparknet-authz.py", "sparknet_authz", dirs=[FABRIC_ROOT / "shared"])

publication_path = Path(os.environ["PUBLICATION_PATH"])
peer_filter = os.environ.get("PEER", "").strip()
url_override = os.environ.get("URL", "").strip()
timeout = float(os.environ.get("TIMEOUT") or "10")
out_path = os.environ.get("OUT_PATH", "").strip()

GUARD_PORT = 9090
GUARD_ROUTE = "/api/v1/registry"

try:
    artifact = json.loads(publication_path.read_text())
except (OSError, json.JSONDecodeError) as exc:
    sys.exit(f"cannot read the publication {publication_path}: {exc}")
if not isinstance(artifact, dict):
    sys.exit(f"{publication_path} is not a publication artifact")

# Refuse to push something the peer will refuse. A partial or unsigned artifact
# is a delivery that cannot work, and finding out here names this command.
publication = {k: v for k, v in artifact.items() if k != "signature_b64"}
if set(artifact) != set(authz.REGISTRY_PUBLICATION_FIELDS) | {"signature_b64"}:
    sys.exit(
        f"{publication_path} is not a publication: expected "
        f"{sorted(set(authz.REGISTRY_PUBLICATION_FIELDS) | {'signature_b64'})}, "
        f"found {sorted(artifact)}"
    )
try:
    authz.registry_publication_message(publication)
except authz.AuthzError as exc:
    sys.exit(f"refusing to deliver a malformed publication: {exc}")
signature = str(artifact.get("signature_b64") or "")
if not signature:
    sys.exit("refusing to deliver an unsigned publication")

registry = artifact["registry"]
entries = registry.get("authorizations") if isinstance(registry, dict) else None
if not isinstance(entries, list):
    sys.exit(f"{publication_path} carries no registry authorizations[] list")

# The Master sits at the overlay anchor (contracts/overlay.json), which is
# reserved and never assignable to a peer. If the registry carries an entry for
# the Master itself, there is no guard to hand it to: POSTing to the anchor
# address cannot succeed, and treating it as a delivery failure would leave the
# re-delivery unit red on every tick forever.
try:
    anchor_ip = str(json.loads((FABRIC_ROOT / "contracts" / "overlay.json").read_text())["master_anchor_ipv4"])
except (OSError, json.JSONDecodeError, KeyError, TypeError):
    anchor_ip = ""

if peer_filter:
    targets = [e for e in entries if isinstance(e, dict) and e.get("fingerprint") == peer_filter]
    if not targets:
        sys.exit(f"the publication's registry names no peer with fingerprint {peer_filter}")
else:
    targets = [e for e in entries if isinstance(e, dict)]

records = []
exit_code = 0
for entry in targets:
    fingerprint = str(entry.get("fingerprint") or "")
    if url_override:
        url = url_override
    else:
        address = str(entry.get("overlay_ipv4") or "")
        if not address:
            records.append(
                {
                    "fingerprint": fingerprint,
                    "url": None,
                    "delivered": False,
                    "error": "the registry entry carries no overlay_ipv4",
                }
            )
            exit_code = 1
            continue
        # Identity files record the address with its prefix length; a URL wants
        # the bare address, and "10.100.0.9/32:9090" is not a host.
        address = address.split("/", 1)[0].strip()
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            records.append(
                {
                    "fingerprint": fingerprint,
                    "url": None,
                    "delivered": False,
                    "error": f"unusable overlay_ipv4: {address}",
                }
            )
            exit_code = 1
            continue
        if anchor_ip and address == anchor_ip:
            print(
                f"skipping {fingerprint[:16]}...: {address} is the master anchor, not a peer",
                file=sys.stderr,
            )
            records.append(
                {
                    "fingerprint": fingerprint,
                    "url": None,
                    "delivered": False,
                    "skipped": "master_anchor",
                    "error": None,
                }
            )
            continue
        url = f"http://{address}:{GUARD_PORT}{GUARD_ROUTE}"

    record = {
        "fingerprint": fingerprint,
        "url": url,
        "sequence": artifact["sequence"],
        "registry_sha256": artifact["registry_sha256"],
        "delivered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "delivered": False,
        "status": None,
        "response": None,
        "error": None,
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(artifact).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    # A proxy or a 302 would let a third party answer "200" without the guard
    # ever installing the publication.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", "replace")
            record["status"] = response.status
            record["response"] = body
            try:
                result = json.loads(body)
            except json.JSONDecodeError:
                result = {}
            if result.get("status") not in {"REGISTRY_INSTALLED", "REGISTRY_ALREADY_INSTALLED"}:
                record["error"] = "peer did not confirm registry installation"
                exit_code = 1
            else:
                record["delivered"] = True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        record["status"] = exc.code
        record["response"] = body
        record["error"] = f"the peer refused the publication (HTTP {exc.code})"
        exit_code = 1
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
        record["error"] = f"could not reach the peer: {exc}"
        exit_code = 1
    records.append(record)

document = {
    "publication": str(publication_path),
    "sequence": artifact["sequence"],
    "registry_sha256": artifact["registry_sha256"],
    "delivered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "peers": records,
    "ok": exit_code == 0,
}
text = json.dumps(document, indent=2) + "\n"
if out_path:
    Path(out_path).write_text(text)
    for record in records:
        print(
            f"{record['fingerprint'][:16]}...: {record.get('error') or record['status']}",
            file=sys.stderr,
        )
else:
    sys.stdout.write(text)
raise SystemExit(exit_code)
PYEOF
