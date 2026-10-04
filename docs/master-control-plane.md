---
title: Master control plane
type: specification
role: master
status: unbuilt
updated: 2026-10-04
---

# Master control plane

> [!warning] Specification only — nothing on this page is implemented
> This role has no `scripts/`, `services/` or `systemd/` directory. The
> components below describe what the Master **must** do, not what it does.
> The work order is [`../plans/MASTER_BUILD_PLAN.md`](../plans/MASTER_BUILD_PLAN.md).
>
> The one thing that *is* implemented is the signed canonical form in
> `../../../shared/sparknet-authz.py`, which this role will sign with.

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

## Components

| Component | Purpose | Build plan step |
|---|---|---|
| Key lifecycle | generate, rotate, and above all *not lose* the private key | 1 |
| Registry schema | machine-checkable shape for the signed record | 2 |
| Signing CLI | `authz-sign`, `registry-verify`, `revoke` | 3 |
| Overlay listener | master `wg0`, one stanza per authorized peer | 4 |
| Approval issuer | signs and delivers `guard-apply` payloads | 5 |
| Registry distribution | how a signed registry reaches a peer | 6 |
| Instant push (`8090`) | ACL changes POSTed to peers | 7 |
| Cluster KillSwitch | fabric-wide containment | 8 |
| Pooling scheduler | idle detection, pooled-memory batches | 9 |

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
  own egress posture is still to be specced (Step 3 of the build plan).
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
- [`../../contracts/identity-schema.json`](../../contracts/identity-schema.json) —
  canonical form and the signed envelope
- [`../../contracts/guard-protocol.md`](../../contracts/guard-protocol.md) — the
  approval conversation, and why the Master side of it does not exist yet
- [`../../contracts/ports.json`](../../contracts/ports.json) — which role listens
  where, and which of those listeners are still declared-but-unimplemented

**Not written yet**, and named here so their absence is visible rather than
implied: `docs/registry-protocol.md`, `docs/network-posture.md`. Each is the
subject of a numbered step in the build plan; do not read this page as covering
them in the meantime.

[`killswitch-template.md`](killswitch-template.md) exists, but read its header
first: it is the preserved earliest draft of the cluster KillSwitch, it logs its
teardown steps instead of performing them, and it is a document rather than a
script precisely so nothing can invoke it.