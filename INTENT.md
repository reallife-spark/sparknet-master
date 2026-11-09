---
title: sparknet master-node — INTENT
role: master
template: true
intent: design-contract
updated: 2026-10-31
---

# sparknet master-node — INTENT

How the Master role is meant to work and what must remain true on every
deployment. `PLAN.md` is the work order; `MISSION.md` is why the role exists;
`AGENTS.md` is the operating charter.

## A Master is a peer that won an election

There is no separate Master species. Every member runs the same peer services;
one additionally holds the operational key and signs. A node becomes Master
because a unanimous signed cluster trust root named it — not because a file,
directory or prompt says so. That is why this role loads the peer's services by
path and why its identity manifest stays `role: peer` until the ceremony.
## Invariants

1. **Authority is key possession.** The vocabulary governs what a peer may do;
   the key governs what the Master can authorise. A peer with every capability
   but no key can never grant, revoke or escalate.
2. **Three keys, three jobs.** The cluster key forms a trust root, the identity
   key signs the node's envelope, the operational key signs registry entries and
   approvals. One key doing all three makes every node a Master-in-waiting.
3. **The operational key lives in one process.** Only the isolated signer loads
   it; it exposes a unix socket, signs only canonical typed operations under a
   valid trust root, and shares no namespace with the peer services.
4. **Isolation is structural, not policy.** The admin surface reads
   configuration as input; filesystem and namespace boundaries separate it from
   the key. A permission rule is not the control.
5. **Registry authority is signature, not file presence.** An entry counts only
   when its signature verifies under the trust root and it is well-formed,
   unexpired and unrevoked.
6. **Revocation is immediate.** A revoked peer becomes inert without its
   cooperation: the Master stops signing for it and removes it from its overlay.
7. **Knowledge and authority stay separate.** The Master may send a signed,
   scoped RFI answer, a share ratification, a registry publication or an
   approval. Only the RFI answer may carry knowledge, and it lands in
   `01_Inbox/` as data. Telemetry, admin requests and registry entries are never
   knowledge. See `../contracts/knowledge-flow.md`.
8. **One copy of the peer's services.** Load `../peer-node/services/` by path.
   A copy would drift and produce signatures that verify on one node and fail on
   another.
9. **Specification is not implementation.** Tested code is not a deployed
   service. Live claims are dated and host-specific; unbuilt components are
   marked unbuilt.
10. **The Master does not run a user's node.** It supplies authority and scoped
    knowledge; it does not choose a prompt, run a model or write a vault.

## First deployment

1. `make env-init` writes `.env` and the numbered skeleton; `make user-init`
   creates the user key once.
2. `make keygen` creates the cluster, operational and identity keys at 0600;
   the election forms a signed root naming this node.
3. `make signer-unit` stages the signer; only the election may enable it.
4. `make validate`, `make parity`, `make ledger` and `make keys-check` prove the
   surface, parity, empty ledger and key hygiene. The registry starts empty and
   fail-closed.

A fresh Master with no election is a peer with a vote, not authority.

## AI operating model

- Read `CONTEXT.md`, `AGENTS.md`, `MISSION.md`, `INTENT.md`, `MEMORY.md` and
  today's session file before acting; read `00_System/alpha-admin.md` for the
  write, signing and secret discipline.
- Read the ledger as evidence, not a summary. No agent signs:
  `cluster-admin`, `evidence-reviewer` and `registry-keeper` compose requests
  for an operator and cannot reach the key.
- Answer an RFI only within its scope and from the allow-listed fabric corpus;
  prefer "nothing found" to invention.
- Never claim live signer, election, overlay or admin-surface behaviour here.

## Blank-slate rule

A production Master starts with empty categories, its identity pages, the
governance set and its role code. It does not inherit another Master's root id,
host names, sessions or live claims. Deployment state belongs in `manifests/`,
`PLAN.md`, `MEMORY.md`, `log.md` and `02_Daily/`.
## Change intent

New work gets a plan step, not a rewrite. Change `INTENT.md` only when the
design contract changes; a cross-role change is one commit. If it contradicts
`AGENTS.md` or `../contracts/`, those win and this page is wrong.
