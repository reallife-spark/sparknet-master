#!/usr/bin/env bash
# MASTER-SIDE: co-sign and install the formed cluster trust root on this node.
#
# The master-node half of the election. It runs the same shared member
# ceremony as a peer — bid, vote, co-sign — because a node that has not cast
# one of the votes has no business installing the result of them, and
# then installs what formed: --identity flips to role master (if this node won)
# and the signed root lands in --root-doc (cluster-trust-root.json).
#
# --expect-master is required and must name the candidate this node voted for.
# shared/sparknet-election.py refuses to co-sign a root naming anyone else, so
# a lying exchange cannot turn two honest votes and one refusal into a master.
# Normative: contracts/consensus-protocol.md.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

URL="${SPARKNET_ELECTION_URL:-http://127.0.0.1:4210}"
EXPECT=""
IDENTITY="$ROLE_ROOT/manifests/master-identity.json"
ROOT_DOC="$ROLE_ROOT/manifests/cluster-trust-root.json"
KEY_DIR="${SPARKNET_KEY_DIR:-$SPARKNET_STATE_DIR/keys}"
WAIT="${SPARKNET_ELECTION_WAIT:-30}"

usage() {
  cat <<USAGE
usage: sparknet-election-approve.sh --expect-master <node-id> [--url <url>]
                                    [--identity <file>] [--root-doc <file>]
                                    [--key-dir <dir>] [--wait-seconds <n>]

Runs the member ceremony (bid -> vote -> co-sign) and installs the formed
cluster trust root: --identity role flips to master when this node is the one
the root names; the signed root is written into --root-doc.

  --expect-master  the candidate this node voted for; required, never guessed
  --url            \$SPARKNET_ELECTION_URL or http://127.0.0.1:4210
  --identity       $ROLE_ROOT/manifests/master-identity.json
  --root-doc       $ROLE_ROOT/manifests/cluster-trust-root.json
  --key-dir        \$SPARKNET_KEY_DIR or \$SPARKNET_STATE_DIR/keys
  --wait-seconds   \$SPARKNET_ELECTION_WAIT or 30
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --expect-master|--expect) EXPECT="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --root-doc) ROOT_DOC="$2"; shift 2 ;;
    --key-dir) KEY_DIR="$2"; shift 2 ;;
    --wait-seconds) WAIT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$EXPECT" ]; then
  # Never defaulted: "who did you vote for" is the question the check exists
  # to ask, and a script that answered it itself would answer it with the root.
  echo "--expect-master is required (the candidate this node voted for)" >&2
  usage >&2
  exit 1
fi

[ -f "$IDENTITY" ] || { echo "identity not found: $IDENTITY" >&2; exit 1; }

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"
ELECTION="$FABRIC_ROOT/shared/sparknet-election.py"
[ -f "$ELECTION" ] || { echo "election implementation not found: $ELECTION" >&2; exit 1; }

if [ ! -f "$KEY_DIR/cluster.ed25519" ]; then
  echo "no cluster key at $KEY_DIR/cluster.ed25519 — create one first:" >&2
  echo "  $PY $ELECTION keygen --key-dir $KEY_DIR" >&2
  echo "(sparknet-master-keygen.sh mints cluster/operational/identity together)" >&2
  exit 1
fi

exec "$PY" "$ELECTION" --shared-dir "$FABRIC_ROOT/shared" member \
  --url "$URL" \
  --candidate "$EXPECT" \
  --identity "$IDENTITY" \
  --root-doc "$ROOT_DOC" \
  --key-dir "$KEY_DIR" \
  --wait-seconds "$WAIT"
