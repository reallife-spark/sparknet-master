#!/usr/bin/env bash
# Render (never enable) the 4203 queue unit for this Master.
#
# The listener queues a verified request and cannot sign. Approval is the
# separate `make share-ratify-approve SHARE_ID=...` path, which reaches the
# isolated signer socket. This unit is deliberately staged: 4203 is a
# three-node leg and the two-node pair does not need it.
set -euo pipefail
ROLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./sparknet-master-env.sh
. "$ROLE_ROOT/scripts/sparknet-master-env.sh" >/dev/null
FABRIC_ROOT="${FABRIC_ROOT:-$(cd "$ROLE_ROOT/.." && pwd)}"
STATE_DIR="${SPARKNET_STATE_DIR:?missing SPARKNET_STATE_DIR}"
KEY_DIR="${SPARKNET_SHARE_TRUSTED_KEY_DIR:-$STATE_DIR/share-keys}"
PY="${SPARKNET_PYTHON:-$FABRIC_ROOT/.venv/bin/python}"
SERVICE_USER="${SPARKNET_SERVICE_USER:-raxxar}"
OUT=""
if [ "${1:-}" = "--out" ]; then OUT="${2:?--out needs a path}"; fi
UNIT="$(cat <<UNIT
[Unit]
Description=Sparknet share ratification queue (4203, human approval required)
After=network-online.target sparknet-master-wireguard-anchor.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
EnvironmentFile=-$ROLE_ROOT/.env
ExecStart=$PY $ROLE_ROOT/services/sparknet-share-ratify.py --serve --bind 10.100.0.1 --port 4203 --state $STATE_DIR/share-ratify/queue.json --registry $ROLE_ROOT/manifests/node-authorizations.json --trusted-key-dir $KEY_DIR
Restart=on-failure
RestartSec=10
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
)"
if [ -n "$OUT" ]; then
  printf '%s\n' "$UNIT" > "$OUT"
else
  printf '%s\n' "$UNIT"
fi
