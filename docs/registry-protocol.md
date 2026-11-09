---
title: Registry protocol
type: specification
role: master
status: partially-built
updated: 2026-10-23
---

# Registry protocol

> [!info] The shape and the channel are both contracted and built
> A registry's *shape* is stated once, in
> [`../../contracts/registry-schema.json`](../../contracts/registry-schema.json).
> The *distribution channel* is stated in
> [`../../contracts/registry-publication.json`](../../contracts/registry-publication.json):
> the Master signs a **publication** (the registry plus a monotonic sequence)
> and **pushes** it to each peer's guard on 9090 (`POST /api/v1/registry`).
> Peers install a publication, never a bare registry, and refuse a sequence
> they have already seen. The push replaced the earlier pull/listener design;
> see [Distribution channel](#distribution-channel).

This document describes the registry format the Master emits and peers consume.
It was written before the CLI existed so the contract could not drift; the CLI
that arrived in Step 3 now emits and verifies it, and Step 2 turned the shape
into a checkable schema.

## The canonical shape

One file states it: [`../../contracts/registry-schema.json`](../../contracts/registry-schema.json).
The Master reaches it through a symlink
([`../manifests/registry.schema.json`](../manifests/registry.schema.json)) —
not a copy, because two copies of a shape would drift and the copies would win
the argument by being read more often. The example document a peer ships is
[`../../peer-node/manifests/node-authorizations.json`](../../peer-node/manifests/node-authorizations.json).

The document:

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | the shape's version. `1.0` — not `1.0.0` |
| `master_public_key_b64` | yes | the operational public key every entry is signed under |
| `description` | no | free text; never read by code |
| `authorizations` | yes | the entries, one per authorized node |

Each entry in `authorizations`:

| Field | Required | Meaning |
|---|---|---|
| `fingerprint` | yes | SHA-256 of the canonical identity bytes; the lookup key |
| `identity` | yes | the node's identity: `node_id`, `role`, `wireguard_public_key_b64`, `overlay_ipv4`, `requested_capabilities` |
| `capabilities` | yes | what the node may do, a subset of the closed vocabulary |
| `overlay_ipv4` | yes | the node's overlay address (bare IPv4, no prefix) |
| `issued_at` | yes | ISO-8601 |
| `expires_at` | yes | ISO-8601; an expired entry grants nothing |
| `revoked` | no | only the Master may set it, and it is inside the signed envelope |
| `signature_b64` | yes | Ed25519 over `{fingerprint, identity, capabilities, overlay_ipv4, issued_at, expires_at, revoked}` |

Two names in that table were the whole problem when this step was reopened:
there is **no `role` field on the document** (the role lives inside each
identity), and the signature field is **`signature_b64`**, not `signature` —
the one implementation, [`../../shared/sparknet-authz.py`](../../shared/sparknet-authz.py),
emits and verifies that name and has never read another.

## Checking a registry

```bash
# the shape and the signatures, against the contract
shared/sparknet-registry-schema.py --registry <path>

# the shape only
shared/sparknet-registry-schema.py --registry <path> --no-verify-signatures
```

Exit codes: `0` conforms, `1` does not, `2` usage or I/O error. The checker
refuses a schema keyword it does not implement rather than ignoring it — a rule
nobody enforces is a rule that quietly stops being true. It is standard library
only on purpose: the fabric's runtime dependency allow-list is `cryptography`
alone, so a validator needing `jsonschema` would pass here and fail on a node.

The Master's own verifier is the same implementation from the other side:

```bash
make -C master-node registry-verify REGISTRY=<path>
```

`master-node/tests/test_registry_schema.py` pins all of it: the shipped
registry conforms, a registry the implementation mints conforms, and the three
ways the draft schema was wrong are refused.

## Distribution channel

The channel is a **push**, and the artifact is a **publication**, because a
registry on its own cannot be distributed safely: its entries carry no
freshness, so anyone who can write to the channel could replay an older
registry in which a now-revoked node is still authorised. The sequence turns
that replay into a refusal.

### The publication

The Master wraps the signed registry in five fields and signs three of them:

| Field | In the signature? | Meaning |
|---|---|---|
| `sequence` | yes | monotonic counter; a peer refuses a lower sequence, and an equal one only if its digest differs |
| `published_at` | yes | when this publication was made (ISO-8601 UTC) |
| `registry_sha256` | yes | SHA-256 of the canonical registry bytes |
| `registry` | via the digest | the signed registry document |
| `signature_b64` | — | Ed25519 over `{published_at, registry_sha256, sequence}` |

The rule is implemented once, in
[`../../shared/sparknet-authz.py`](../../shared/sparknet-authz.py)
(`registry_publication_message`, `registry_digest`, `verify_registry_publication`),
and used by the signer, the publisher and the peer. The sequence is *inside*
the signature so it cannot be lowered (a rollback) or raised (stranding a peer
ahead of the Master) without the Master key.

### Who talks to whom

1. `make -C master-node registry-publish REGISTRY=… OUT=…` validates the
   registry against the contract, refuses a document whose
   `master_public_key_b64` is not this Master's operational key, signs through
   the isolated signer (or `--offline`), and writes `<OUT>/current.json`.
2. `make -C master-node registry-deliver PUBLICATION=…` resolves each peer's
   address from the publication's own registry and POSTs the artifact to
   `http://<overlay>:9090/api/v1/registry`. It delivers to revoked entries too:
   the node being revoked must receive the document that revokes it.
3. The peer's guard verifies and installs it (below). It answers
   `REGISTRY_INSTALLED`, `REGISTRY_ALREADY_INSTALLED` for the steady-state
   re-push, or one of the refusal codes in the contract.

The deliverer skips an entry whose address is the overlay anchor
(`contracts/overlay.json`): that is the Master itself, and there is no guard
there to receive its own publication.

`sparknet-registry-deliver.timer` re-pushes every **60 s**. That interval is
the documented revocation window: a peer whose first push failed is converged
on the next tick. A peer whose guard is down keeps its last verified registry —
an entry's `expires_at`, enforced locally, bounds how long stale authority can
last.

### What the peer accepts

The acceptance order is the contract's, and each step is a refusal with a code
the operator can act on:

| Check | Refusal |
|---|---|
| the artifact is exactly the five fields with consistent types and digest | `400 malformed_publication` |
| the signature verifies under `manifests/keys/master-ed25519.pub.b64` | `403 bad_signature` |
| the registry names the same Master key the peer pinned | `403 wrong_master_key` |
| the document satisfies `contracts/registry-schema.json`, entries included | `400 invalid_registry` |
| `sequence` is not lower, and an equal one carries the same digest | `409 stale_publication` |
| a pinned key exists at all | `503 no_master_key` |

The peer never trusts the key an incoming registry *names*; it only checks that
the claim agrees with its pin. A peer with a valid signature but no pinned key
refuses everything.

Installing is two atomic writes: the registry first, then
`manifests/registry-installation.json` (the sequence record). A crash between
them leaves an older record, so re-delivering the same publication is accepted
— convergence, not a deadlock. Re-delivering the publication whose sequence
*and* digest are already installed answers `REGISTRY_ALREADY_INSTALLED` and
writes nothing: the 60 s re-delivery pass must be a no-op, or the delivery unit
would fail on every tick. Equality alone does not buy that: an equal sequence
carrying a different registry is a fork, not a replay, and is refused as
`stale_publication` — as is any lower sequence.

Registry installation is a write to the peer's own vault, so it needs neither
`--apply-enabled` nor euid 0. That flag arms writes to protected `/etc` paths.
The guard route is deliberately **not** gated on the peer's `guard-apply`
capability, for the same reason delivery reaches revoked entries: a revocation
the revoked node cannot hear is not a revocation.

The acceptance rule lives once, in
[`../../shared/sparknet-registry-install.py`](../../shared/sparknet-registry-install.py),
because there are two receive paths: the guard's live route and the offline
`make -C peer-node registry-fetch PUBLICATION=…` (a node with no daemon, or an
operator previewing with `DRY_RUN=1`). `make -C peer-node registry-status`
shows the installed sequence and the capabilities the entry confers.

### What the channel is not

- **Not a pull surface.** There is no `GET` route; a peer cannot ask for a
  registry, and the Master does not listen on a registry port. The old Step 7
  8090 pull listener is retired; fabric Step 69C re-scoped 8090 into the
  peer→Master intake listener (telemetry evidence), which is a different
  direction and carries no registry traffic.
- **Not an authorisation.** Installing a registry grants nothing by itself: the
  capabilities are the ones the Master signed into the entry, and `evaluate`
  still enforces expiry and revocation.
- **Not a substitute for the signer.** Delivering an already-signed artifact
  needs no key; only publishing does.

## What is built, and what is not

| Piece | State | Step |
|---|---|---|
| the shape | contracted, checked, tested | 2 (this document) |
| signing, verifying, publishing | built — `scripts/sparknet-registry-{sign,verify,publish,revoke}.sh` | 3 |
| the distribution channel | built — publish → push → guard install; `master-node/tests/test_registry_dist.py` drives the real guard | 6 |
| tamper fails closed *on the peer* | proven end to end — a modified registry, a foreign signature and a foreign key are all refused by the peer's own guard | 6 |
| revocation propagation | proven end to end; the window is the 60 s re-delivery interval, and a successful push is immediate | 6 |

The shipped registry is **empty on purpose**: a committed entry grants its
capabilities to whoever holds the matching identity, so a fresh deployment
carries none. Empty is fail-closed, and the difference between "no peers yet"
and "I cannot load my registry" must stay visible.
