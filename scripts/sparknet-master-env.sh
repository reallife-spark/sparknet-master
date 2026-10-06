#!/usr/bin/env bash
# Resolve this role's paths and prove they point at THIS vault.
#
# Thin by design: every fact here is derived, none is stored. The peer's
# sparknet-env.sh is not copied or re-implemented — if this file needed logic the
# peer already has, it would resolve the peer's script by path and call it instead.
set -euo pipefail

ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_ROOT="${SPARKNET_FABRIC_ROOT:-$(dirname "$ROLE_ROOT")}"

if [ -f "$ROLE_ROOT/.env" ]; then
  set -a; . "$ROLE_ROOT/.env"; set +a
fi

: "${VAULT_PATH:=$ROLE_ROOT}"
: "${SPARKNET_PEER_NODE:=$FABRIC_ROOT/peer-node}"

# The state dir is deliberately OUTSIDE $ROLE_ROOT. This used to default to
# "<role>/.state", which put the Master's private keys inside the vault — and the
# admin surface bind-mounts the vault read-only into an LLM-driven container
# (configs/admin-surface/docker-compose.admin.yml: `../..:/workspace/sparknet:ro`).
# That made the Step 18 guarantee "no key material reachable from the admin
# surface" false the moment Step 1 generated a key, while every test still
# passed: they read the compose file's *text*, and the key was reachable through
# the mount rather than mentioned in it.
#
# Docker cannot exclude a subdirectory from a bind mount, so the only way to keep
# the key out is to not put it under the mount. XDG is the honest answer: state
# belongs in the user's state directory, not in a knowledge vault. The peer's
# default is still "<vault>/.state" and deliberately so — no admin surface mounts
# it, and moving it would break the peer's bundle portability for no gain.
if [ -z "${SPARKNET_STATE_DIR:-}" ]; then
  if [ -n "${XDG_STATE_HOME:-}" ]; then
    SPARKNET_STATE_DIR="$XDG_STATE_HOME/sparknet/master-node"
  elif [ -n "${HOME:-}" ]; then
    SPARKNET_STATE_DIR="$HOME/.local/state/sparknet/master-node"
  else
    echo "sparknet-master-env: neither SPARKNET_STATE_DIR, XDG_STATE_HOME nor HOME is set." >&2
    echo "  Refusing to guess a home for the Master signing key. Set SPARKNET_STATE_DIR" >&2
    echo "  to an absolute path on a filesystem that is not the vault." >&2
    exit 1
  fi
fi

export VAULT_PATH ROLE_ROOT FABRIC_ROOT SPARKNET_PEER_NODE SPARKNET_STATE_DIR

printf 'role:        %s\n' "master-node"
printf 'role root:   %s\n' "$ROLE_ROOT"
printf 'fabric root: %s\n' "$FABRIC_ROOT"
printf 'vault path:  %s\n' "$VAULT_PATH"
printf 'peer node:   %s\n' "$SPARKNET_PEER_NODE"
printf 'state dir:   %s\n' "$SPARKNET_STATE_DIR"
