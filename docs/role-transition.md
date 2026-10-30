---
title: Role transition: peer -> master (election)
type: specification
role: master
status: built
updated: 2026-10-22
---

# Role transition: peer -> master (election)

> [!info] Built, and proven live on real hosts
> The consensus arc (Steps 13–14) is implemented in
> [`../../shared/sparknet-consensus.py`](../../shared/sparknet-consensus.py) and
> was proven live on 2026-10-07: agx64 and agx32 co-formed a 2/2 trust root
> naming agx64 Master over the deployed transport (the Step 57 pair later
> reversed this: agx32 Master / agx64 peer), and the signer that followed
> signed a live registry entry a still-peer verified. The **replace-Master
> re-formation** leg is documented in
> [`../../contracts/deployment-runbook.md`](../../contracts/deployment-runbook.md)
> and was deliberately left unexecuted.

The built flow (Steps 13–14) has no pre-existing master to approve a request —
with an empty registry there is nobody to grant anything. A node becomes
Master by **winning a unanimous member election** — 2 of 2 in a pair, 3 of 3 in
the full cluster — not by being approved.

Authoritative spec: `contracts/consensus-protocol.md` (§Election, §Exchange,
§The cluster trust root, §Re-formation) and the operational procedure in
`contracts/deployment-runbook.md`.

In one sentence: every member casts one signed vote each for one candidate; if
all votes are from distinct members and all name that candidate, the candidate's
operational keypair is bound as `master_pubkey` in a root co-signed by every
cluster key; the candidate's identity flips exactly the four fields (role, role
note, operational-key held + root id, trust_root) and every other member stays a
peer with no root document — no loss of cluster keys, ledger chain, capabilities
or signed notes.

Wiring: `make -C peer-node election-request` and
`make -C master-node election-approve EXPECT=<node>` are the same shared
`member` ceremony under two names; the roles differ in what they hold, not in
how they agree. Local proof: [`../../scripts/sparknet-rehearsal.sh`](../../scripts/sparknet-rehearsal.sh)
(fabric Step 12). Real nodes: `contracts/deployment-runbook.md` Phase 5.