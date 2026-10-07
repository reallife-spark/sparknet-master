# Role transition: peer -> master (election)

The built flow (Step 11) has no pre-existing master to approve a request —
with an empty registry there is nobody to grant anything. A node becomes
Master by **winning a unanimous three-member election**, not by being approved.

Authoritative spec: `contracts/consensus-protocol.md` (§Election, §Exchange,
§The cluster trust root, §Re-formation) and the operational procedure in
`contracts/deployment-runbook.md`.

In one sentence: three members cast one signed vote each for one candidate; if
all three are distinct and all name that candidate, the candidate's operational
keypair is bound as `master_pubkey` in a root co-signed by all three cluster
keys; the candidate's identity flips exactly the four fields (role, role note,
operational-key held + root id, trust_root) and the two losers stay peers with
no root document — no loss of cluster keys, ledger chain, capabilities or
signed notes.

Wiring: `make -C peer-node election-request` and
`make -C master-node election-approve EXPECT=<node>` are the same shared
`member` ceremony under two names; the roles differ in what they hold, not in
how they agree. Local proof: `scripts/sparknet-rehearsal.sh` (Step 12). Real
nodes: `contracts/deployment-runbook.md` Phase 5.