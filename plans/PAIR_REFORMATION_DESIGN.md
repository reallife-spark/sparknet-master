# Re-formation reference design — informed by NVIDIA PAIR's membership model

Status: **policy B adopted — partly.** The chain being built in
`shared/sparknet-consensus.py` and the signer is the Q2 half of this design:
`previous_root_id` in the signed root fields makes a re-formation a chain, a
pure verifier can refuse a root that does not descend from the root in force,
and `verify_chain(roots)` lets an offline peer pull and verify the whole
lineage over the existing share path. The Q1 half — the *reduced*-membership
root (majority to reduce) — is **not** adopted: unanimity stays n of n, and the
unsatisfiable-reduced-root case remains a named gap in
`contracts/consensus-protocol.md`. Anything Q2-related that this note proposes
but the implementation does not yet do is a spec item for the pull path's mode
of exposure, not a contract change.

Reference: PAIR (`services/nvpair-cluster-manager/` `spec.md`, Apache-2.0).
PAIR's cluster-manager keeps a roster of members and manages admission and
removal with three properties sparknet lacks:

1. **Monotonic admission epochs** — the roster carries a strictly increasing
   epoch; every membership change advances it, so two rosters are ordered by
   their epochs *without* a global clock.
2. **Endorsement chains** — each change is endorsed by the members that were
   authorised at the *previous* epoch, so the epoch history is a chain, not a
   set, and a younger roster provably descends from an older one.
3. **Removal proofs that survive restart** — when a node is removed, the
   evidence of its removal is durable and offline-verifiable; the removed node
   must produce it *before* it can act again ("proof before re-pin").

The translation is **not** a copy. PAIR's unilateral removal is replaced by
sparknet's 1-signature revoke; PAIR's many-to-many fan-out is replaced by the
n-of-n root; PAIR's central cluster-manager is replaced by the roster that the
trust root itself carries. What transfers is the *three properties*, which are
the ones §Re-formation lacks.

## The two open questions, restated

- **Q1 — the unsatisfiable reduced root.** With unanimity held at n of n even
  after a member is lost, a full cluster losing one member leaves two survivors
  who cannot form a new root, and a pair leaves one. Re-formation is needed
  precisely when it is impossible. **Still open** — the Q2 work below does not
  touch it.
- **Q2 — how a re-formed root reaches a peer.** The old root is locally
  indistinguishable from the new one (`verify_root` is pure over a single
  root), and broadcasting over a channel the superseded Master controls is how
  a rolled-back Master suppresses the news of its own replacement. **Closed by
  policy B**: `previous_root_id` puts the ordering inside the root itself, so a
  pure verifier holding the new root refuses the old one offline, and the news
  is pulled, not broadcast.

## Proposed answer to Q1: admission epochs + removal proof, mapped

PAIR's monotonic epoch and removal-proof discipline give sparknet a way to
form a *reduced* root without betraying the no-self-elevation premise. The key
insight: **unanimity must hold at the epoch where a node joins or is named —
it does not need to hold at every later epoch for the roster to shrink.** That
is exactly what PAIR's "endorsed by the previous epoch's members" means.

Design:

- The trust root carries an **epoch** (derived from a monotonic counter, not a
  wall clock; the existing `nonce` is the seed). Every root — original or
  re-formed — records the epoch of the root it descends from.
- A **reduced root** (n−1 members, or 2 in a pair that lost none) is formed by
  the survivors signing a new root whose **endorsement chain** includes:
  - the survivors' signatures, *and*
  - the removal proof for the dropped member: the node's `revoked` entry as
    signed by the previous operational key, or a survivor-signed statement that
    the member is unreachable-and-departed carried in the registry.
  `verify_root(new, previous)` then checks the chain: the new root must
  descend from `previous` by removing *exactly* the members whose removal is
  evidenced in it. This mirrors PAIR's `proof-before-de-pin`: the lingering
  member cannot act under the old root because the removal proof lives in the
  chain *before* the new epoch.
- The **escaped hole closes**: a lone survivor forms a membership of one, which
  is *not a cluster* — so instead of a root, the survivor holds only the
  removal proof (a tombstone) and must re-witness a new member before any root
  exists. That respects the existing statement: a cluster cannot survive below
  its minimum of two, *by design or by omission*.

Which policy option this implements: **B, with the collusion guard supplied by
the chain.** A Byzantine majority cannot reach a *newly-added* authority
without unanimity at the epoch that adds it, which is the guard option B asked
for. A majority can only *shrink*, which is the exactly the denial-path
unilateral revocation already allows.

## Proposed answer to Q2: pull-don't-broadcast, chain-ordered

PAIR's roster fixpoint is reached by members **re-scanning** the cluster until
their view converges — membership changes are *pulled*, not pushed. Sparknet
already has a pull-shaped channel: the peer↔peer share handoff (runbook Phase
8) and the registry redistribution are pulled by the peer. So:

- A new root reaches a peer through the peer's **next pull** from *any member
  of the new root* (a node the new root names, verified by the
  `previous_root_id` chain — the ordering half of this design, adopted).
- The superseded Master does not need to be told and cannot suppress the news,
  because it is not the channel: a peer that pulls from a new-root member
  always sees the newer epoch, and a peer that has not pulled simply keeps the
  old root — the same lease-not-broadcast constraint, now satisfied by ordering
  rather than by channel monopoly.
- `check-not-reverted` (signer) keys on `root_id` and is now monotonic: adopt a
  root whose `previous_root_id` names the ledger's root in force, refuse
  anything else without `--accept-requalification`. That is the
  strictly-newer admission PAIR uses, made local.

## What this deliberately does not do

- **No fourth membership.** The chain proves descent; it does not change the
  2..3 bound in `cluster_trust_root.members`.
- **No authority widening.** A re-formed root still requires unanimity among
  the members of the *new* root, and a node removed by re-formation cannot
  re-form its way back in on its own (the removed member's cluster key is not in
  the new endorsement set).
- **No reduced-membership root.** The chain (Q2) is built; the reduced-root
  *document* (Q1) is not. It stays a named gap in `consensus-protocol.md`, and
  no live pair exists to exercise a drop. The operator still must pick A/B/C
  for the threshold before the reduced path can be specified.

## Suggested decision path

1. Operator picks A / B / C (unanimity unchanged / majority-to-reduce / join
   first). The design above is the concrete shape of **B**; pick A to leave
   §Re-formation unchanged, pick C to require a join ceremony.
2. **Done (2026-10-09), as the chain half only.** The Q2 orderings are now in
   the code and the contracts: `previous_root_id` in the signed root fields,
   `unchained_root` refusal on the trust path, `verify_chain(roots)`, the
   monotonic `check_not_reverted`, and policy-B text in
   `consensus-protocol.md` / `identity-schema.json` /
   `capabilities.json` / `ports.json`. Q1 (majority-to-reduce) remains a policy
   choice the operator has not made, so the reduced-root document is still not
   written.
3. Wire the pull path (Q2) into the existing share handoff rather than a new
   port. **Adopted**: re-formation news pulls over 4220 git-repo / 4201
   share-intake, with the mode of exposure (how far a peer may fall behind)
   recorded as the one open spec item.

Provenance: PAIR reviewed 2026-10-08, `services/nvpair-cluster-manager`
`spec.md` (admission epochs, endorsement chains, removal proofs) and
`services/nvpair-node-scanner` README (roster re-scan convergence). Mapping to
sparknet's unanimity is deliberate: PAIR's unilateral removal and central
manager are the parts this design discards.