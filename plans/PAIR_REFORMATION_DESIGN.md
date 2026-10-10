# Re-formation reference design — informed by NVIDIA PAIR's membership model

Status: **policy B adopted — fully built (fabric `PLAN.md` Step 21, schema
1.2).** Both halves are now in `shared/sparknet-consensus.py`,
`shared/sparknet-election.py` and the signer. The Q2 half — the orderings:
`previous_root_id` and `epoch` in the signed root fields, the `unchained_root`
refusal on the trust path, `verify_chain(roots)` for an offline peer, and the
monotonic `check_not_reverted` — was built in Step 16. The Q1 half — the
*reduced*-membership root (majority to reduce) — was the open policy choice;
the operator chose **option B full**, and it is now built: a chained root with a
strict-subset membership, each dropped member evidenced by a removal proof, with
the collusion guard this design's "chain" supplies. The same-material change is
recorded in `contracts/consensus-protocol.md` (§Re-formation) and
`contracts/identity-schema.json` (`cluster_trust_root.reformation`). Live deploy
of a re-formation to agx64/agx32 remains `DoD: confirm: user`.

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
  precisely when it is impossible. **Resolved and built (Step 21)**: option B
  full — the threshold moves *down to the survivors* for a reduction, and the
  drop is evidenced by a removal proof; see below.
- **Q2 — how a re-formed root reaches a peer.** The old root is locally
  indistinguishable from the new one (`verify_root` is pure over a single
  root), and broadcasting over a channel the superseded Master controls is how
  a rolled-back Master suppresses the news of its own replacement. **Closed by
  policy B**: `previous_root_id` and `epoch` put the ordering inside the root
  itself, so a pure verifier holding the new root refuses the old one offline,
  and the news is pulled, not broadcast.

## Answer to Q1: admission epoch + removal proof, adopted and built

PAIR's monotonic epoch and removal-proof discipline give sparknet a way to
form a *reduced* root without betraying the no-self-elevation premise. The key
insight: **unanimity must hold at the epoch where a node joins or is named —
it does not need to hold at every later epoch for the roster to shrink.** That
is exactly what PAIR's "endorsed by the previous epoch's members" means. This
was adopted by operator decision on 2026-10-10 as **option B full** and the
build is in Step 21.

As built:

- The trust root carries a signed **`epoch`** (a non-negative integer, not a
  wall clock): `0` for a genesis root, `parent.epoch + 1` for a chained one.
  The trust path checks it, so a stale root cannot be replayed as a fresh
  generation.
- A **reduced root** (a strict subset of the parent's members) is formed by the
  survivors signing a chained new root and shipping one **removal proof** per
  dropped member alongside it — carried outside the signed bytes, each proof
  independently signed:
  - a **`revocation`** proof signed by the *parent* root's elected Master with
    its **operational** key (the contract's existing 1-signature revoke, made
    durable), or
  - an **`attested`** proof signed by **every survivor** with its **cluster**
    key (majority-to-reduce, the survivors consulting).
  `verify_root(child, trust=parent)` then checks that the child's dropped set
  — parent membership minus child membership — is *exactly* the set the proofs
  evidence, and that each proof names the parent. This mirrors PAIR's
  `proof-before-de-pin`: the lingering member cannot act under the old root
  because the removal proof lives in the chain *before* the new epoch.
- The **escaped hole closes**: a lone survivor forms a membership of one, which
  is *not a cluster* — so instead of a root, the survivor holds only the
  removal proof (a tombstone) and must re-witness a new member before any root
  exists. That respects the existing statement: a cluster cannot survive below
  its minimum of two, *by design or by omission*.

Which policy option this implements: **B, with the collusion guard supplied by
the survivors' signatures.** A Byzantine majority cannot reach a *newly-added*
authority without unanimity at the epoch that adds it, which is the guard option
B asked for. A majority can only *shrink*, and even then every survivor must
sign the drop (or the parent Master must revoke) — the removal is not
unilateral for a majority, only the 1-signature revoke path already allowed.

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
  2..3 bound in `cluster_trust_root.members`. A chained root that *adds* a
  member is still refused (`unchained_root`): adding is the join ceremony.
- **No authority widening.** A re-formed root still requires unanimity among
  the members of the *new* root, and a node removed by re-formation cannot
  re-form its way back in on its own (the removed member's cluster key is not in
  the new endorsement set, and its removal is a signed fact in the chain).
- **No silent eviction.** A reduction is refused unless its dropped set is
  exactly the set its removal proofs evidence, so a colluding majority cannot
  vanish an honest node without leaving evidence a pure verifier can check.

## Suggested decision path

1. Operator picks A / B / C (unanimity unchanged / majority-to-reduce / join
   first). The design above is the concrete shape of **B**; pick A to leave
   §Re-formation unchanged, pick C to require a join ceremony. **Chosen:** the
   operator selected **B full** on 2026-10-10, and it is built (Step 21).
2. **Done (2026-10-09) as the chain half; completed (2026-10-10) as the reduced
   half.** The Q2 orderings are in the code and the contracts:
   `previous_root_id` and `epoch` in the signed root fields, `unchained_root`
   refusal on the trust path, `verify_chain(roots)`, the monotonic
   `check_not_reverted`. The Q1 reduced path is now built too:
   `shared/sparknet-consensus.py` gains the 1.2 schema, the `epoch` check and
   the removal-proof verification, and the reduced-root document is written into
   `consensus-protocol.md` / `identity-schema.json` / `capabilities.json` /
   `ports.json`.
3. Wire the pull path (Q2) into the existing share handoff rather than a new
   port. **Adopted**: re-formation news pulls over 4220 git-repo / 4201
   share-intake, with the mode of exposure (how far a peer may fall behind)
   recorded as the one open spec item. Live deploy of a re-formation to
   agx64/agx32 is `DoD: confirm: user`.

Provenance: PAIR reviewed 2026-10-08, `services/nvpair-cluster-manager`
`spec.md` (admission epochs, endorsement chains, removal proofs) and
`services/nvpair-node-scanner` README (roster re-scan convergence). Mapping to
sparknet's unanimity is deliberate: PAIR's unilateral removal and central
manager are the parts this design discards.