---
title: sparknet master-node — INTENT
role: master
template: true
intent: design-contract
updated: 2026-10-29
---

# sparknet master-node — INTENT

This page states how the Master role is meant to work and what must remain true
on every deployment. It is not a plan, a runbook or a status page.
`plans/MASTER_BUILD_PLAN.md` is the work order; `MISSION.md` is why the role
exists and declares its machine-readable build status; `AGENTS.md` is the
operating charter.

## A Master is a peer that won an election

There is no separate Master species. Every member of a cluster runs the same
peer services and holds the same capability vocabulary. One member additionally
holds the operational key and signs. A node becomes Master because the members
ran the election ceremony and a unanimous signed cluster trust root named it —
not because a file on disk says so.

That is why this role loads the peer's services by path instead of carrying its
own copies, and why `manifests/master-identity.json` keeps `role: peer` until the
ceremony makes it otherwise.

## Invariants

1. **Authority is key possession.** The capability vocabulary governs what a
   peer may do; the operational key governs what the Master can authorise. A
   peer holding every capability without that key can never grant, revoke or
   escalate.
2. **Three keys, three jobs.** The cluster key helps form a trust root, the
   identity key signs the node's own authorization envelope, and the operational
   key signs registry entries and approvals. They are distinct on purpose; one
   key doing all three would make every node a Master-in-waiting.
3. **The operational key lives in one process.** Only the isolated signer loads
   it. The signer exposes a unix socket, not a TCP port, signs only canonical
   bytes authorised by a valid trust root, and shares no volume or network
   namespace with the peer services.
4. **Isolation is structural, not policy.** The admin surface is an LLM
   application that reads configuration as input. It is separated from the key by
   filesystem and namespace boundaries; a permission rule is not the control.
5. **Registry authority is signature, not file presence.** An entry is
   authoritative only when its signature verifies under the trust root and the
   entry is well-formed, unexpired and unrevoked. Writing a file does not put a
   node in the registry.
6. **Revocation is immediate.** A revoked peer becomes inert without its
   cooperation: the Master stops signing for it and removes it from its own
   overlay.
7. **One copy of the peer's services.** The Master loads `../peer-node/services/`
   by path. A second copy would drift and produce signatures that verify on one
   node and fail on another.
8. **Specification is not implementation.** Tested code is not a deployed
   service. Live claims are dated and host-specific; unbuilt components are
   marked unbuilt.

## First deployment

A fresh Master is expected to run from its first boot:

1. `make env-init` writes the role `.env` and numbered vault skeleton.
2. `make user-init` creates the user key and fills `00_System/user.md` once.
3. `make keygen` creates the cluster, operational and identity keys in the state
   directory at 0600.
4. The election ceremony forms a signed cluster trust root naming this node.
5. `make signer-unit` stages the signer unit; only the election may enable it.
6. `make validate`, `make parity`, `make ledger` and `make keys-check` prove the
   role surface, peer-service resolution, empty ledger and key hygiene.
7. The registry starts empty and fail-closed. No peer holds privileges until the
   Master signs a grant.

A fresh Master with no election is a peer with a vote, not an authority. Nothing
in this vault may claim otherwise.

## AI operating model

- Read `AGENTS.md`, `MISSION.md`, `INTENT.md`, `MEMORY.md` and today's session
  file before acting.
- Read `00_System/alpha-admin.md` for the write, signing and secret-handling
  discipline.
- Read the ledger as evidence, not a summary of evidence.
- No agent signs. `cluster-admin`, `evidence-reviewer` and `registry-keeper`
  compose signature requests for an operator; they do not hold or reach the key.
- Never claim live signer, election, overlay or admin-surface behaviour from a
  development host. Those are target-host checks.

## Blank-slate rule

A production Master starts with empty vault categories, its identity pages, the
governance set and its role code. It does not inherit another Master's root id,
host names, sessions or live claims. Deployment-specific state belongs in
`manifests/`, `plans/`, `MEMORY.md`, `log.md` and `02_Daily/`, not in
`INTENT.md`. `MISSION.md` keeps the machine-readable build status the tests
require; narrative status lives in `plans/MASTER_BUILD_PLAN.md`.

## What this page is not

It is not a runbook, not a deployment record and not a status page. If a
statement here contradicts `AGENTS.md` or `../contracts/`, those win and this page
is wrong.
