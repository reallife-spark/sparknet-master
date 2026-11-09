---
title: Master control plane
type: specification
role: master
status: partially-built
updated: 2026-10-25
---

# Master control plane

> [!warning] Some of this page is not built — each unbuilt part is marked
> This role **has** `scripts/`, `services/` and `systemd/` (Steps 15–18). The
> components below describe what the Master **must** do; the table marks the
> ones that do it today. The work order is
> [`../plans/MASTER_BUILD_PLAN.md`](../plans/MASTER_BUILD_PLAN.md).
>
> The signed canonical form in [`../../shared/sparknet-authz.py`](../../shared/sparknet-authz.py)
> is implemented and is what the Master signs with.

## What the Master owns

The Master is the fabric's only source of authority. Concretely it holds four
things:

1. **The Ed25519 private key.** Possession is the whole trust model. Everything
   the Master can grant, revoke or authorize derives from it, and a peer without
   it can verify but never grant.
2. **The overlay root.** `10.100.0.1`, with one `[Peer]` stanza per authorized
   node, each restricted to that node's own `/32`.
3. **The registry.** `manifests/node-authorizations.json` — the signed record of
   who exists, what they may do, and whether they are revoked.
4. **The cluster KillSwitch.** Fabric-wide containment, from the Master, root on
   the Master.

## Responsibilities — the Master as infrastructure administrator

The user has directed that the Master also **administers** the fabric's
infrastructure: git, file sharing, NAT and the vector embeddings database.
"Administers" is a role responsibility, not an existence claim — all four are
`implementation_state: implemented` for all four as of 2026-10-31 in `contracts/ports.json` (`4220`–`4223`;
`bound_by: master`, `overlay_only`, bound to `10.100.0.1`). The scoping is
[`../plans/MASTER_ADMIN_PLAN.md`](../plans/MASTER_ADMIN_PLAN.md).

Nothing on that list listens yet. A port flips to `provisioned` only with real
scaffolding and a `runtime_why` measurement, and the four services are, like
the signer and the admin surface, **structural non-adjacency**: an
infrastructure service may not load, invoke or proxy to the signing key.

## Components

| Component | Purpose | State | Build plan step |
|---|---|---|---|
| Key lifecycle | generate, rotate, and above all *not lose* the private key | built | 1 |
| Registry schema | machine-checkable shape for the signed record | built (Step 2) | 2 |
| Signing CLI | `authz-sign`, `registry-verify`, `revoke` | built | 3 |
| Overlay listener | master `wg0`, one stanza per authorized peer | built | 4 |
| Approval issuer | signs and delivers `guard-apply` payloads | **built (Step 5)** — canonical approval, signer-socket signature, delivery, and application on the peer guard in the test path | 5 |
| Registry distribution | how a signed registry reaches a peer | **built (Step 6)** — a signed `publication` pushed Master→peer guard on 9090, monotonic `sequence` | 6 |
| Peer intake (`8090`) | peer→Master telemetry evidence and RFI requests | **built (fabric Steps 69C, 70B)** — `services/sparknet-peer-intake.py`, overlay-only, attributed by the registry. Telemetry is `telemetry`-gated and recorded; an RFI request needs only a registered, non-revoked peer and is queued for the composer, never answered here. Both act on nothing. The old instant-push purpose was superseded by Step 6's 9090 registry push and is retired; the unit is staged, not enabled | 7 → fabric 69C |
| Cluster KillSwitch | fabric-wide containment | **built (Step 8); live run unverified** — `services/sparknet-killswitch.py` root-gates, defaults to dry-run, stops the control units and admin container, removes the overlay, and installs the `SPARKNET_EMERG_*` iptables chains without flushing the host ruleset. Fake-runner tests pass; the destructive run on a real Master is `DoD: confirm: user` | 8 |
| Nocturnal batch scheduler | idle evidence + a time-boxed batch lease | **9A adopted, 9B built (2026-10-25), 9C built (2026-10-26)** — `plans/NOCTURNAL_BATCH_DESIGN.md` replaces literal pooled memory with whole-node jobs on idle nodes; `shared/sparknet-idle.py` collects session/GPU evidence into telemetry `metrics.idle`; `services/sparknet-wg-observer.py` supplies authoritative WireGuard deltas from a root snapshot; `services/sparknet-scheduler.py` implements `plan`/`arm`/`status`/`abort`, three-sample gating, the 02:00–05:00 window and two-step confirmation. Assignments are `[]` until 9D; no dispatch occurs | 9 |
| Share ratification | ratify a peer's time-boxed share | **built / not enabled on the pair** — `services/sparknet-share-ratify.py` has a signed 4203 listener and human queue; no unit is enabled | 10 |
| Evidence/review repository | make share events reviewable | **not built** — the hash-chained ledger verifies, but no share events feed a repository and there is no retention policy or clone-and-compare path | 11 |
| Review agents and trust decisions | produce findings and signed trust transitions | **not built** — no review service or finding producer; 70G only *surfaces* a retained flag, never decides | 12 |
| Git / file share / NAT / vector DB (`4220`–`4223`) | infrastructure administration | **all four built/live 2026-10-31**; `4220`/`4221` are read-only, `4222` is status/dry-run, `4223` is signed query-only | `MASTER_ADMIN_PLAN.md` |

## The signing path

```
peer identity (canonical JSON)
        │
        ▼
   fingerprint          SHA-256 of the canonical bytes
        │
        ▼
  Master signs          Ed25519 over {fingerprint, identity, capabilities,
        │               overlay_ipv4, issued_at, expires_at, revoked}
        ▼
  registry entry        distributed to the peer
        │
        ▼
  peer verifies         signature, then revocation, then expiry, then capability
```

Two properties make this safe rather than merely clever:

- **`capabilities` and `overlay_ipv4` are inside the signed envelope.** Signing
  only the identity would leave them mutable by anyone who can edit the registry
  file — which would let an attacker escalate a peer to `guard-apply` without the
  Master ever approving it.
- **`revoked` is inside the envelope too.** So only the Master can flip it. An
  attacker with registry write access can revoke a node (a safe denial) but
  cannot reinstate one, which would need a fresh signature.

## Revocation

Revocation is a Master-side action on the Master's own `wg0`:

```bash
wg set wg0 peer <PEER_PUBLIC_KEY> remove
systemctl reload wg-quick@wg0
```

The peer's local `wg0.conf` is untouched and stays `chattr +i`. The peer
therefore cannot self-reinstate, and the Master cannot corrupt the peer's
configuration. The link dies on the next packet.

A revoked peer's experience: it keeps serving its own vault, but its guard
refuses to bind and refuses to apply, because it can no longer receive a valid
signature. Its egress is pinned to the Master, which it can no longer reach.
It is **isolated, not warned** — that is the intended posture.

Revocation is meaningless without distribution (step 6): revoking the tunnel
while a peer still holds a validly-signed, unexpired registry entry would leave
it believing it is still authorized for `guard-apply` for offline operations.
Revocation must be a signed fact, not just a routing event.

## What the Master must never do

- **Never adopt the peer egress rule.** A peer pins `wlan0` to `10.100.0.1`
  only; on the Master that would blackhole the fabric. The rule itself is in
  [`../../contracts/overlay.json`](../../contracts/overlay.json); the Master's
  own egress posture is only bounded here — `docs/network-posture.md` is still
  not written.
- **Never issue an `AllowedIPs` mask wider than one `/32`** on a peer stanza,
  or that peer could source-spoof a sibling.
- **Never let the private key leave the machine**, and never commit it.
- **Never ship an empty-because-broken registry silently.** The registry is
  empty today on purpose (fail-closed, nobody has privileges). Distinguishing
  "no peers yet" from "I cannot load my registry" must remain visible.
- **Never sign a nonce twice.** Replay defence depends on the Master being the
  sole issuer and tracking what it issued.

## Related

What exists today:

- [`../plans/MASTER_BUILD_PLAN.md`](../plans/MASTER_BUILD_PLAN.md) — the work
  order, including the registry, KillSwitch and egress steps
- [`../plans/MASTER_ADMIN_PLAN.md`](../plans/MASTER_ADMIN_PLAN.md) — the
  infrastructure-administrator scope (git, file share, NAT, vector DB),
  all spec-only
- [`../../contracts/identity-schema.json`](../../contracts/identity-schema.json) —
  canonical form and the signed envelope
- [`../../contracts/guard-protocol.md`](../../contracts/guard-protocol.md) — the
  approval conversation, and why the Master side of it is the isolated signer
  (Step 17) rather than another service
- [`../../contracts/guard-approval.json`](../../contracts/guard-approval.json) —
  the approval envelope as a machine-readable contract: the eight fields, the
  canonical bytes, the transport
- [`../../contracts/ports.json`](../../contracts/ports.json) — which role listens
  where, and which of those listeners are still declared-but-unimplemented.
  `implementation_state` travels with the contract; `runtime` is measured per host

## What actually runs here

Build plan Steps 15–16 made this role executable. `make validate` proves each
line of it.

| Path | Runs | Verified by |
|---|---|---|
| `services/sparknet-parity.py` | loads `peer-node/services/*` by path | `make parity`, `tests/test_master_parity.py` |
| `services/sparknet-ledger.py` | verifies the Master's hash chain | `make ledger` |
| `scripts/sparknet-master-env.sh` | resolves vault + peer paths | `make env-show` |
| `scripts/sparknet-master-keygen.sh` | writes 3 Ed25519 keys to `$SPARKNET_STATE_DIR/keys`, 0600 | `make keygen`, `make keys-check` |
| `scripts/sparknet-approval-issue.sh` | mints a canonical guard approval and spends its nonce | `make approval-issue`, `tests/test_approval.py` |
| `scripts/sparknet-approval-sign-socket.sh` | signs an approval **through the signer socket**, recording a ledger block | `make approval-sign-socket`, `tests/test_signer_isolation.py` |
| `scripts/sparknet-approval-deliver.sh` | POSTs the approval to the peer it names | `make approval-deliver`, `tests/test_approval.py` |
| `systemd/*.service` | parity check and chain verification at boot | `make units`, `make units-check` |

The parity loader is the load-bearing one. It is what makes "a Master is a peer"
true in the code rather than only in prose, and it **fails loudly** instead of
falling back to a private copy: a second copy of `sparknet-guard-d.py` would
verify signatures correctly on one node and fail on the other, which is the
worst failure shape available here.

The ledger can verify but not append. Appending needs the operational key, and
the operational key belongs to the isolated signer (Step 17) — an unsigned append
would let anyone with write access rewrite the history a hash chain exists to
protect, so the honest state is verify-only. Key custody is described in
[`../security/key-management.md`](../security/key-management.md).

**Not written yet**, and named here so their absence is visible rather than
implied: `docs/network-posture.md`. (`docs/registry-protocol.md` exists since
Step 2.) Do not read this page as covering the missing one in the meantime.

[`killswitch-template.md`](killswitch-template.md) documents the working
KillSwitch and preserves the earliest draft below it. The working control is
`services/sparknet-killswitch.py`; the draft is provenance and is not executed.