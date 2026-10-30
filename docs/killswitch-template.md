---
title: Cluster KillSwitch — implementation and preserved draft
updated: 2026-10-25
status: partially-built
---

# Cluster KillSwitch — implementation and preserved draft

The working control is
[`../services/sparknet-killswitch.py`](../services/sparknet-killswitch.py),
invoked through [`../scripts/sparknet-killswitch.sh`](../scripts/sparknet-killswitch.sh)
or `make -C master-node killswitch`. The fenced draft at the bottom is the
earliest sketch, kept only as provenance; it is not executed.

> [!warning] **Built; dry-run exercised, destructive run not yet performed.**
> The implementation and its fake-runner tests are complete (Step 8). On
> 2026-10-26 the current code was deployed to the Master (`agx32`, host
> `blue-team`) and its dry-run was exercised through both the wrapper and
> `make -C master-node killswitch`; `wg1`, the signer/anchor/firewall/ledger
> units and the admin container were unchanged and no emergency chains appeared.
> The live destructive run — real `systemctl`, `docker`, `ip` and `iptables` on a
> host with an overlay — is **not** verified. Step 8's live DoD is
> `DoD: confirm: user`.

## Scope, and the two switches that are easy to confuse

| | Peer node containment | Cluster KillSwitch (this) |
|---|---|---|
| Lives in | `peer-node/scripts/sparknet-node-containment.sh` | the Master, `master-node/` |
| Scope | this node's own anchor and local services | every Master-side control plane, plus the overlay |
| Runs as | root, on the peer | root, on the Master |
| A peer can run it | yes — it is the peer's own | **no** — there is no peer copy or Make target |
| Default | acts on an explicit invocation | **dry-run**; `--force` changes state |

The peer's switch tears down *its own* WireGuard anchor and stops its own
services. The cluster KillSwitch is Master-side: it stops the Master's control
planes, removes the overlay transport, and installs an emergency drop policy.
It does not SSH to peers. A peer left running locally can no longer receive a
signed instruction, so it is inert for guarded actions — the isolation a
revocation produces, applied to the whole fabric at once.

## What the implementation does

Both modes require `EUID 0`; `--help` is the only action that does not. The
overlay interface is read from `SPARKNET_WG_INTERFACE` and never guessed.

`--force` runs this ordered sequence. Failures do not short-circuit: the report
collects them so a missing signer unit cannot prevent the overlay from coming
down. An optional target that reports itself absent is recorded as `absent`,
not as a containment failure; any other non-zero exit is a real failure and the
run exits non-zero.

1. `systemctl disable --now` each control unit:
   `sparknet-master-signer.service`, `sparknet-peer-intake.service`,
   `sparknet-reflex-broker.service`, `sparknet-registry-deliver.timer`,
   `sparknet-registry-deliver.service`.
2. `systemctl disable --now sparknet-master-wireguard-anchor.service` so a
   reboot cannot silently restore the authority path.
3. `docker update --restart=no sparknet-admin-webui`, then
   `docker stop sparknet-admin-webui` — stop the LLM-driven admin surface and
   remove its restart policy.
4. `ip link del <interface>` — remove the overlay.
5. Remove any earlier `SPARKNET_EMERG_IN/OUT/FWD` jumps, then create the three
   private iptables chains and insert one jump from `INPUT`, `OUTPUT` and
   `FORWARD`.

The host ruleset is deliberately **not** flushed. The chains add explicit drops
and leave the built-in policies and Docker's rules intact: input/output on the
overlay interface, non-loopback TCP to the Master control ports (`8081, 8088,
8090, 4203, 4210, 4220–4224, 9090`), UDP `51820`, and all forwarded traffic. An
operator's SSH session survives. The deployed Masters run the legacy iptables
toolchain (the fabric's firewall is iptables); `nft` is not installed there, so
the implementation does not depend on it.

## Recovery

Recovery is a deliberate operator action, not an inverse flag:

1. Remove the jumps: `iptables -D INPUT -j SPARKNET_EMERG_IN`,
   `iptables -D OUTPUT -j SPARKNET_EMERG_OUT`,
   `iptables -D FORWARD -j SPARKNET_EMERG_FWD`; then `iptables -F` and `-X`
   each of `SPARKNET_EMERG_IN`, `SPARKNET_EMERG_OUT`, `SPARKNET_EMERG_FWD`.
2. Bring the overlay back first:
   `systemctl enable --now sparknet-master-wireguard-anchor.service`; verify
   `ip link show wg1` and a peer handshake before starting anything that binds
   `10.100.0.1`.
3. Restore the admin container exactly as it was:
   `docker update --restart=unless-stopped sparknet-admin-webui` and
   `docker start sparknet-admin-webui`; verify `Up (healthy)` on
   `10.100.0.1:8088`.
4. Re-enable **only** the control units that were enabled/active in the
   baseline. Typically `sparknet-registry-deliver.timer` and
   `sparknet-registry-deliver.service`, then `sparknet-master-signer.service`.
   Re-enable `sparknet-peer-intake.service` or
   `sparknet-reflex-broker.service` only if the baseline shows them active; both
   are staged/not-enabled by default.
5. Verify the signed registry, ledger chain and peer `authz-verify`, and the
   admin HTTP endpoint before declaring recovery.

The KillSwitch never restarts a unit on failure; a partial run stays contained
until an operator performs the steps above.

`docs/master-control-plane.md` and `master-node/AGENTS.md` carry the same
scope. `master-node/tests/test_killswitch.py` proves the sequence, the absent
vs. failure distinction, the no-flush policy, and that the peer has no
`killswitch` target.

## Preserved earliest draft

Kept for provenance. It logs five steps and performs none of them; its
`sparknet-env.sh` path is pre-split and its `EUID`/`UID` are the same value
printed twice. Do not run it.

```bash
#!/usr/bin/env bash
# KillSwitch (root-restricted) - minimal viable implementation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$(cd "${SCRIPT_DIR}/../scripts" && pwd)/sparknet-env.sh"

DRY_RUN=0
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--force]"
      echo "KillSwitch: halts schedulers, tears down wg0, stops control planes, enforces nftables drop (ROOT-GATED)"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

log() {
  local level="$1"
  shift
  printf "[%s] [%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*"
}

log "INFO" "sparknet-killswitch starting"
log "INFO" "EUID=$(id -u), UID=$(id -u), USER=${USER:-$(id -un)}"

# Root-gating check
if [[ "$(id -u)" -ne 0 ]]; then
  log "ERROR" "KillSwitch requires root privileges (EUID=0). Current EUID=$(id -u)"
  log "ERROR" "Root-gated as per design - requires signed approvals"
  exit 1
fi

log "INFO" "ROOT-GATED check: PASSED"
log "INFO" "Staged teardown (template):"
log "INFO" "  1. Halt Sparknet schedulers/agents"
log "INFO" "  2. Tear down wg0 (WireGuard Master Anchor)"
log "INFO" "  3. Stop control planes (orchestrator/agents)"
log "INFO" "  4. Enforce emergency nftables drop policy"
log "INFO" "  5. Lock critical paths state"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "INFO" "DRY-RUN: No actual teardown performed"
  log "INFO" "sparknet-killswitch completed (DRY-RUN)"
  exit 0
fi

if [[ "${FORCE}" -ne 1 ]]; then
  log "WARN" "Use --force to execute actual teardown (template mode)"
  log "INFO" "sparknet-killswitch completed (template mode, no action)"
  exit 0
fi

log "INFO" "Executing teardown (template mode)"
log "INFO" "sparknet-killswitch completed"
exit 0
```
