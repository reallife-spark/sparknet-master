---
title: sparknet master-node — MISSION
role: master
template: true
status: partially-built
updated: 2026-10-31
---

# sparknet master-node — MISSION

The **elected signing role**. A Master is a peer that won an election and holds
the one operational key able to authorise privileged action. It supplies
authority, the registry, scoped fabric knowledge and evidence to the peers; it
does not run a peer's model, choose a user's work or edit a user's vault.

`INTENT.md` is the design contract; `AGENTS.md` is the operating charter and
wins if the two ever disagree. `MEMORY.md` holds the current build and live
state; `PLAN.md` is the work order.

## Scope

- **In scope**: the operational key and its isolated signer, registry
  authorship and revocation, typed guard approvals, share ratification, scoped
  RFI answers, the cluster KillSwitch, evidence and telemetry intake, the
  admin surface, and the shared infrastructure the operator delegated (git,
  file share, NAT, vector store — each only to the state its contract names).
- **Out of scope**: serving a peer's local vault or inference, choosing a
  peer's prompts, writing a peer's vault, or treating telemetry as authority.
- **Out of scope**: a general query oracle. An RFI answer is limited to the
  requesting peer's scope and the allow-listed fabric corpus.

## Success

This vault should answer, fluently and with citations:

1. What can the Master do that no peer can, and by what mechanism?
2. How does a new node get registered, and what must be true first?
3. How is a node revoked, and what does the revoked node experience?
4. What is the Master forbidden to do to itself?
5. Which key signs what, what may cross to a peer, and what is proven live?

The role succeeds when a peer's only path to a privileged action runs through
the Master, revocation works without the peer's cooperation, and scoped
knowledge reaches a peer without becoming authority. Key custody is the product.

## Non-goals

Running user chat, pushing personal pages into a corpus, or treating a file,
flag or peer's vault as auto-remediable.

## Constraints

- **No secrets in the vault.** The operational key belongs in
  `$SPARKNET_STATE_DIR/keys` at mode 0600, referenced only by path.
- **Specification is not implementation.** Tested code is not a deployed
  service; live claims are dated and host-specific.
- **One copy of the peer's services; structural isolation.** Load them by path;
  the signer is separated by filesystem and namespace, not a permission rule.
- Knowledge and authority never share a channel; see
  `../contracts/knowledge-flow.md`.
