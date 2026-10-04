---
title: sparknet master-node Build Plan
updated: 2026-10-04
current: 1
---

# sparknet master-node — Build Plan

> Single source of truth for turning this role from specification into
> implementation. The `current:` cursor marks the step being worked. Write this
> file back **immediately** on every advance; append the matching transition
> line to `log.md`.
>
> **No `scripts/`, `services/` or `systemd/` directory exists yet, by design.**
> Step 3 is where that stops being true. Steps 1 and 2 are deliberately
> knowledge-and-contract work that needs no code.

## Status Legend

- `[ ]` not started / in progress
- `[x]` complete — DoD verified
- **DoD** — the check that proves the step is done; `DoD: confirm: user` when a human must confirm
- `current: N` — step being worked now; `current: done` — terminal

## What already exists

| Piece | Where | State |
|---|---|---|
| Signed canonical form, fingerprint, verify, sign | `../shared/sparknet-authz.py` | **implemented and tested** |
| Overlay, capability, identity, port, guard contracts | `../contracts/` | **implemented and tested** |
| Peer guard that verifies and applies | `../peer-node/services/sparknet-guard-d.py` | **implemented and tested** |
| Peer anchor, render, keygen, install | `../peer-node/scripts/` | **implemented and tested** |
| Master `[Peer]` stanza template | `configs/wireguard/master-peer.template` | documentation only |

The Master role's *crypto* is done. What is missing is everything around it:
key lifecycle, registry authorship, the overlay listener, approval issuance,
containment and scheduling.

## Step 1 — Keypair and registry substrate

- [ ] **Step 1** — Establish a real Master keypair and the registry it signs.
      - **DoD**: (1) a Master Ed25519 keypair exists at
        `$SPARKNET_STATE_DIR/keys` at mode 0600 and is **not** tracked by git;
        (2) `manifests/master-identity.json` describes the Master at
        `10.100.0.1` with `role: master`; (3) `contracts/identity-schema.json`
        records the new public key and drops the "bootstrap only" caveat;
        (4) `make contract-test` still green; (5) a signed test entry verifies
        against the new key.
      - **Status**: pending
      - **Note**: this replaces the discarded bootstrap key. Until it lands, the
        Master cannot sign anything and no peer can be authorized.

## Step 2 — Registry schema and the spec/impl boundary

- [ ] **Step 2** — Write `docs/registry-protocol.md` (it does not exist yet),
      then turn it into a checkable schema and
      make the "specified, not built" status machine-detectable.
      - **DoD**: (1) `manifests/registry.schema.json` exists and validates the
        current `../peer-node/manifests/node-authorizations.json`;
        (2) `tests/test_master_spec.py` asserts this subvault declares itself
        unbuilt, so the status cannot silently rot into a false claim;
        (3) every page in `docs/` that describes an unbuilt component carries an
        explicit unbuilt marker.
      - **Status**: pending

## Step 3 — Signing and registry CLI

- [ ] **Step 3** — Give this role its own executable surface. **This is where
      `scripts/` and `services/` come into existence.**
      - **DoD**: (1) `scripts/` and `services/` exist with their own
        `sparknet-env.sh` resolving `SPARKNET_ROLE=master`;
        (2) `make keys` generates the Master WireGuard + Ed25519 pair;
        (3) `make authz-sign IDENTITY=<peer identity>` produces a signed
        registry entry; (4) `make registry-verify` checks the whole registry;
        (5) `make revoke FINGERPRINT=<fp>` signs `revoked: true`;
        (6) peer suite still green.
      - **Status**: pending

## Step 4 — Master-side overlay listener

- [ ] **Step 4** — Render and maintain the Master's `wg0` with one stanza per
      authorized peer.
      - **DoD**: (1) `make wg-render-master` generates `wg0.conf` with one
        `[Peer]` per registry entry, each `AllowedIPs` limited to that peer's own
        `/32`; (2) entries with `revoked: true` are excluded; (3) an unsigned or
        expired entry is excluded; (4) re-render is idempotent; (5) a test
        proves no stanza can carry a mask wider than one `/32`.
      - **Status**: pending
      - **Safety**: the Master must never accept an `AllowedIPs` wider than the
        peer's own address, or that peer could source-spoof a sibling.

## Step 5 — Guard approval issuer

- [ ] **Step 5** — Make `guard-apply` grantable in practice.
      - **DoD**: (1) `make approval-issue TARGET=<path> CONTENT=<file>` produces
        a signed approval payload per `../contracts/guard-protocol.md`;
        (2) `make approval-deliver FINGERPRINT=<fp>` POSTs it to that peer's
        `10.100.0.x:9090`; (3) the Master tracks issued nonces and refuses to
        issue the same nonce twice; (4) an integration test signs on this side
        and applies on a peer stub, proving the two agree.
      - **Status**: pending
      - **Note**: until this exists, `guard-apply` is defined and enforced but
        ungrantable. This is the highest-value step in the plan.

## Step 6 — Registry distribution channel

- [ ] **Step 6** — Give peers a way to receive a signed registry.
      - **DoD**: (1) a documented distribution channel exists (the design
        decision is recorded in `docs/registry-protocol.md`);
        (2) `make registry-publish` emits it; (3) a peer-side target documents
        how to consume and verify it; (4) a tampered registry fails closed on
        the peer; (5) revocation propagates within the documented window.
      - **Status**: pending — and the channel itself is currently
        **unspecified**; `contracts/identity-schema.json` marks
        `distribution: UNSPECIFIED` on purpose. Choosing it is part of this step.

## Step 7 — Instant-push listener (8090)

- [ ] **Step 7** — Bind `10.100.0.1:8090` and POST ACL changes to peers.
      - **DoD**: (1) the listener binds `10.100.0.1` only, never a wildcard;
        (2) it refuses off-overlay sources; (3) an ACL change reaches a peer
        within the documented window; (4) tests cover the refusal paths.
      - **Status**: pending
      - **Blocked by**: Step 4 (needs to know which peers exist).

## Step 8 — Cluster KillSwitch

- [ ] **Step 8** — Implement the Master-wide containment action.
      - **DoD**: (1) root-gated (`EUID 0`); (2) halts the fabric control planes
        and drops nftables policy; (3) documented as cluster-wide and
        explicitly distinct from the peer node-containment switch;
        (4) it cannot be invoked by a peer at all.
      - **Status**: pending
      - **Starting point**: `docs/killswitch-template.md` preserves the earliest
        draft. It root-gates correctly but its five teardown steps are log lines
        only — `--force` still does nothing — so it must not be mistaken for a
        working control.
      - **Note**: resolves the contradiction found during the split, where
        `../peer-node/docs/wireguard.md` documented the KillSwitch as Master-side
        while the repository shipped a peer-side script. The peer script is now
        `../peer-node/scripts/sparknet-node-containment.sh`, scoped to one node,
        and says in its own header that it is *not* this.

## Step 9 — Nocturnal pooling scheduler

- [ ] **Step 9** — Idle detection and the pooled-memory batch scheduler.
      - **DoD**: (1) idle detection across SSH sessions, WireGuard byte
        counters and `nvidia-smi`; (2) the scheduler establishes the pooled
        fabric only when all nodes report idle; (3) it commits artifacts back to
        vaults; (4) any non-idle signal aborts the transition.
      - **Status**: pending
      - **Note**: highest-risk step. It is the only one that autonomously moves
        data between nodes, so it needs the strictest human-oversight gate and
        should not start before Steps 5 and 8 exist.

## Sequencing note

Steps 1–4 are prerequisites for a peer to be genuinely useful: a real keypair, a
signed registry, and a master-side overlay that actually accepts the peer.
Step 5 is what makes the guard meaningful. Steps 8 and 9 are containment and
autonomy — valuable, but building them before 1–5 would mean automating a
control plane that has no real authority behind it.

## Next

Add steps here as work is identified. New roadmap work after `current: done`
becomes a new step, not a reuse of this plan.