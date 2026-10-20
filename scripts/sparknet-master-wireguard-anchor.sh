#!/usr/bin/env bash
# Bring up the Master's WireGuard overlay (10.100.0.1) and pin its config.
#
# A Master is a peer that won an election: it runs the same overlay, as
# 10.100.0.1/24 with one [Peer] stanza per authorized node. The bring-up itself
# is the peer's sparknet-wg-bringup.sh, resolved by path — this role keeps one
# implementation and never a copy, exactly as it loads the peer's services.
#
# Inputs come from the deployed state dir, rendered out of band:
#   $SPARKNET_STATE_DIR/wireguard/<iface>.conf      Address + MTU
#   $SPARKNET_STATE_DIR/wireguard/<iface>.setconf   pure config (peers), optional
#
# It also places the conventional /etc/wireguard/<iface>.conf (0600 root), the
# path tooling and an operator expect and the path the protected-path manifest
# names, and pins both copies with chattr +i.
#
# Runs as root. Deliberately no teardown path: stopping the overlay is the
# KillSwitch's job, never a plain systemctl stop.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./sparknet-master-env.sh
source "$SCRIPT_DIR/sparknet-master-env.sh" >/dev/null

log() { printf '[%s] [master-wg-anchor] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "the anchor unit must run as root (euid 0); current euid=$(id -u)"
command -v chattr >/dev/null 2>&1 || die "chattr(1) not found (e2fsprogs) — cannot pin the overlay config"

IFACE="${SPARKNET_WG_INTERFACE-}"
[[ -n "$IFACE" ]] || die "SPARKNET_WG_INTERFACE is not set — refusing to guess the overlay interface (the deployment env file must name it, e.g. wg1)"
CONF_DIR="${SPARKNET_WG_RENDER_DIR:-$SPARKNET_STATE_DIR/wireguard}"
CONF="$CONF_DIR/$IFACE.conf"
SETCONF="$CONF_DIR/$IFACE.setconf"
ETC_CONF="/etc/wireguard/$IFACE.conf"
[[ -f "$CONF" ]] || die "master overlay config missing: $CONF (render it with 'make wg-render-master')"

PEER_NODE="${SPARKNET_PEER_NODE:-$(dirname "$(dirname "$SCRIPT_DIR")")/peer-node}"
BRINGUP="$PEER_NODE/scripts/sparknet-wg-bringup.sh"
[[ -x "$BRINGUP" ]] || die "peer bring-up helper not found: $BRINGUP"

# If anything below fails after the unlock, re-pin whatever exists before we
# exit, so a mid-sequence failure never leaves the live overlay config writable.
# shellcheck disable=SC2329  # reached indirectly, via `trap repin_on_exit EXIT`
repin_on_exit() {
  local rc=$?
  if (( rc != 0 )); then
    for f in "$CONF" "$ETC_CONF"; do
      [[ -f "$f" ]] && chattr +i "$f" 2>/dev/null || true
    done
    log "master anchor failed (rc=$rc); re-pinned any existing config before exit"
  fi
  return "$rc"
}
trap repin_on_exit EXIT

# The config is pinned between boots; unlock it so the pin can be re-applied.
chattr -i "$CONF" 2>/dev/null || true
if [[ -f "$ETC_CONF" ]]; then
  chattr -i "$ETC_CONF" 2>/dev/null || true
fi

# Place the conventional /etc/wireguard/<iface>.conf (0600 root) alongside the
# authoritative state-dir config. It holds the private key, so it is 0600.
install -d -m 0755 /etc/wireguard
install -m 0600 "$CONF" "$ETC_CONF"
log "placed $ETC_CONF (mode 0600)"

log "master anchor on $IFACE (config $CONF)"
if [[ -f "$SETCONF" ]]; then
  "$BRINGUP" --iface "$IFACE" --conf "$CONF" --setconf "$SETCONF"
else
  "$BRINGUP" --iface "$IFACE" --conf "$CONF"
fi

# The /24 overlay address makes the kernel install the overlay route itself, so
# the Master needs no explicit route — unlike a peer's /32, which does.
chattr +i "$CONF"
chattr +i "$ETC_CONF"
log "pinned $CONF and $ETC_CONF with chattr +i"
log "master overlay up. The Master can still revoke any peer from its side."
exit 0
