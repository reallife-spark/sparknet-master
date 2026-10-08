#!/usr/bin/env bash
# Generate this node's Ed25519 keypairs into $SPARKNET_STATE_DIR/keys (0600).
#
# THREE keys, not one, and the distinction is the security model rather than a
# detail:
#
#   cluster      signs a cluster trust root only. Every member has one.
#   operational  signs registry entries and approvals. Only the elected Master's
#                node has one, and only inside the isolated signer (Step 17).
#   identity     signs this node's own authorization envelope.
#
# If one key did all three jobs, every node's key would be a key that could sign a
# registry entry, and every node would be a Master-in-waiting. The cluster key is
# deliberately weak alone: it helps form a root, and forming a root needs every
# member — 2 of 2 in a pair, 3 of 3 in the full cluster.
#
# This script contains no cryptography. Key generation lives in
# ../../shared/sparknet-authz.py and is invoked here, so there is exactly one
# implementation of "how does a node get a key" in the fabric.
#
# Why it does not delegate to the peer's scripts, since that was the original
# intent and looks like an oversight otherwise:
#   - peer-node/scripts/sparknet-env.sh hardcodes SPARKNET_ROLE="peer" and its own
#     vault root, so sourcing it here would resolve this role to the peer's vault —
#     the exact silent misdirection AGENTS.md warns about.
#   - peer-node/scripts/sparknet-keygen.sh emits one ed25519-<role> seed. This role
#     needs three *named* keys with different signing scopes, which is a different
#     shape, not a different name.
# Refactoring the peer's deployment scripts is a peer-role change; Step 16 of the
# build plan records this as the unsatisfiable half of that DoD rather than
# pretending it was met.
#
# It also cannot make this node master. Generating an operational key does not
# confer authority: election needs every member's signature on a cluster
# trust root, and nothing here can produce one alone.
set -euo pipefail

# --help BEFORE the environment is sourced and before anything derives a key:
# without this guard, `keygen --help` ran the whole script — on a machine with
# no keys yet it would have GENERATED them while answering a help request.
case "${1:-}" in
  -h|--help)
    cat <<'USAGE'
sparknet-master-keygen.sh — generate this node's three Ed25519 keypairs

Usage:
  scripts/sparknet-master-keygen.sh          create missing keys (idempotent)
  scripts/sparknet-master-keygen.sh --help    print this text and exit

Keys land in $SPARKNET_STATE_DIR/keys (mode 0600, outside the vault):
  cluster      signs a cluster trust root (every member has one)
  operational  signs registry entries (elected Master's signer only)
  identity     signs this node's own authorization envelope

Existing keys are left alone; generation delegates to
shared/sparknet-authz.py so there is one implementation of key creation.
Generating an operational key confers no authority — election needs every
member's signature on a cluster trust root.
USAGE
    exit 0 ;;
esac

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null

# sparknet-master-env.sh guarantees this, and deliberately resolves it *outside*
# the vault: the admin surface bind-mounts this tree read-only into an LLM
# container, so a key under it would be readable from there. See that script for
# why the peer's "<vault>/.state" default is not copied here.
STATE_DIR="${SPARKNET_STATE_DIR:?sparknet-master-env.sh did not resolve SPARKNET_STATE_DIR}"
KEY_DIR="$STATE_DIR/keys"
AUTHZ="${SPARKNET_AUTHZ:-$FABRIC_ROOT/shared/sparknet-authz.py}"

[ -f "$AUTHZ" ] || {
  echo "keygen: shared/sparknet-authz.py not found at $AUTHZ" >&2
  echo "        set SPARKNET_AUTHZ or SPARKNET_FABRIC_ROOT." >&2
  exit 1
}

PY="${PY:-$FABRIC_ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

# find_spec rather than a bare `import cryptography`: this only needs to know the
# module is installed, and importing it to find that out both loads the library
# for nothing and puts the word "cryptography" into this script as if it used it.
if ! "$PY" -c 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec("cryptography") else 1)' 2>/dev/null; then
  echo "keygen: 'cryptography' is required. Run 'make devtools' at the fabric root." >&2
  exit 1
fi

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

# One invocation per key, both halves from it. Calling generate-keypair twice would
# mint two unrelated keypairs and write a public half that does not match its
# private one — a key that loads fine and then fails every verification.
for name in cluster operational identity; do
  priv="$KEY_DIR/$name.ed25519"
  pub="$KEY_DIR/$name.pub.b64"
  if [ -f "$priv" ]; then
    printf '%-24s exists, left alone\n' "$name.ed25519"
    continue
  fi
  pair="$KEY_DIR/.$name.pair"
  "$PY" "$AUTHZ" generate-keypair > "$pair" || exit 1
  [ "$(wc -l < "$pair")" -eq 2 ] || {
    echo "keygen: expected two lines from generate-keypair, got $(wc -l < "$pair")" >&2
    exit 1
  }
  # Private half to a 0600 file via a umask-scoped subshell: create the file with
  # the right mode before any key material exists, rather than writing it wide and
  # chmod-ing afterwards.
  ( umask 077; sed -n 1p "$pair" > "$priv" ) || exit 1
  sed -n 2p "$pair" > "$pub.tmp"
  mv "$pub.tmp" "$pub"
  chmod 0644 "$pub"
  rm -f "$pair"
done

echo
echo "keys:   $KEY_DIR  (private 0600, public 0644, never committed)"
echo "public: *.pub.b64 — safe to publish; cluster_pubkey_b64 goes into the trust root"
echo
echo "Generating an operational key does not make this node master."
echo "Election requires every member's signature on a cluster trust root."
