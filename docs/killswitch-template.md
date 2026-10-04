---
title: Cluster KillSwitch — preserved template
updated: 2026-10-04
status: preserved-not-wired
---

# Cluster KillSwitch — preserved template

> **This is not the KillSwitch.** It is the earliest draft of it, kept here so
> Step 8 of [`../plans/MASTER_BUILD_PLAN.md`](../plans/MASTER_BUILD_PLAN.md) has
> a concrete starting point instead of writing from nothing.
>
> It is a **fenced code block, not a file on disk.** That is deliberate: the
> master role carries no executable surface, and a `.sh` that can be run is a
> claim the role cannot honour yet. See
> [`../../peer-node/AGENTS.md`](../../peer-node/AGENTS.md) for why a peer must not
> be able to invoke this at all.

## Scope, and the two switches that are easy to confuse

| | Peer node containment | Cluster KillSwitch (this) |
|---|---|---|
| Lives in | `peer-node/scripts/sparknet-node-containment.sh` | the Master (Step 8) |
| Scope | this node's own anchor | every control plane in the fabric |
| Runs as | root, on the peer | root, on the Master |
| A peer can run it | yes — it is the peer's own | **never** |

The peer's switch tears down *its own* WireGuard anchor and stops its own
services. It cannot touch a sibling. The cluster KillSwitch is a Master-side
action: it halts the fabric's control planes and drops policy across the whole
deployment.

## What the draft did, and what it did not

The draft below is honest about its own state, which is the main reason it is
worth keeping:

- It **root-gates** correctly — `EUID 0` or it exits. That part is right and
  should survive into Step 8 unchanged.
- It **logs a five-step teardown and then does nothing.** Every step is a
  `log "INFO"` line. There is no `systemctl stop`, no `wg-quick down`, no
  `nft` rule. `--force` is accepted and still only logs.
- It was therefore **safe to ship and useless in practice**: it looked like a
  containment control while containing nothing. Step 8 must close that gap, and
  its DoD requires the real actions.

Two defects to fix rather than inherit:

1. **It sourced `../scripts/sparknet-env.sh`**, a pre-split path. The environment
   is now `scripts/sparknet-env-init.sh` plus `.env`.
2. **`$(id -u)` is printed twice** in the same log line, labelled `EUID=` and
   `UID=`. Cosmetic, but it is the kind of thing that makes a reader doubt the
   root-gate is real.

## Preserved draft

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

## Step 8 DoD, unchanged

`EUID 0`; halts the fabric control planes and drops nftables policy; documented as
cluster-wide and explicitly distinct from the peer node-containment switch; and
not invocable by a peer at all. The draft satisfies only the first, and satisfies
the third only by existing — which is why it is a document and not a script.
