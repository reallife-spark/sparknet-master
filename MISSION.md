---
title: sparknet master-node — MISSION
status: partially-built
updated: 2026-10-29
---

# sparknet master-node — MISSION

The **Master role** of the sparknet fabric: the node that holds signing
authority over the overlay.

## Status

**Built, and proven live — with named gaps.** Build plan Steps 15–18 landed: this
role has `scripts/`, `services/` and `systemd/`, loads the peer's services by
path, keeps a hash-chained ledger, generates its own keys into the state
directory, has an isolated signer for the operational key, and declares an admin
surface and `MASTERSPIKE` knowledge manifest. Steps 2 and 5 followed on
2026-10-22: the registry has a single stated shape, and `guard-apply` is now
grantable — the approval envelope is one rule in `../shared/sparknet-authz.py`,
signed by the isolated signer and accepted by the peer's own guard. Step 6
followed on 2026-10-23: the registry now travels as a signed **publication** the
Master pushes to each peer's guard on 9090, so distribution and revocation
propagation are built rather than specified.

The election→signer→registry arc was **proven live on real hosts on
2026-10-07**: agx64 and agx32 co-formed a 2/2 cluster trust root, the signer ran
as `sparknet-master-signer.service` on agx64, signed a live registry entry a
still-peer verified, survived a real reboot, and demonstrated a live
revoke→peer-inert→re-authorize cycle. The overlay anchor came up unattended on a
real reboot of each host on 2026-10-19.

**Not yet running**, each a numbered step rather than an omission:

| Missing | Step | Consequence |
|---|---|---|
| nocturnal live arming | `9` | the scheduler, idle detector and WG observer are built and tested; arming a lease on a real fleet remains operator-confirmed (`DoD: confirm: user`), and the observer service/timer are staged, not enabled |
| share ratification, evidence repository, review agents | `10`–`12` | the code is complete 2026-10-29: registry-checked + signer-signed ratification, ledger-hashed evidence committed to git, and signed reversible trust transitions recorded in the ledger. The live 4203 listener, peer round trips and telemetry consumption remain `DoD: confirm: user` |
| admin services (`4220`–`4223`) | `MASTER_ADMIN_PLAN.md` | git, file share, NAT and the vector DB are contracted `spec-only` |
| the two destructive legs | — | rollback and a replace-Master re-formation are documented and deliberately unexecuted (`../../contracts/deployment-runbook.md`) |

> `8090` is no longer missing: its instant-push purpose was superseded by Step 6's
> 9090 registry push and retired, and fabric Step 69C re-scoped it into the
> peer→Master **intake** listener (telemetry evidence), implemented and staged (not
> enabled). See `plans/MASTER_BUILD_PLAN.md` Step 7.

`guard-apply` left this list on 2026-10-22 (build plan Step 5): the Master
mints a canonical approval, the isolated signer signs it, the Master delivers
it to the peer it names, and the peer's own guard accepts it — proven by a test
that signs on this side and applies on the peer's guard daemon, loaded by
path. What that does **not** claim: no approval has been delivered on a real
overlay, and the protected-file *write* needs euid 0 and `chattr` on a target
node, so the exercised path ends at the peer's dry-run verification.

On **this** development host none of the fabric runs: there is no cluster, no
wireguard kernel module, nothing bound. The live claims above are dated claims
about real hosts; what is verifiable here is the code, the tests, and the
boundaries. Two claims in this file are load-bearing and tested: the signer is
**deployed only by election** (it ran live on agx64 on 2026-10-07; it is not a
service a role install may enable), and the admin surface carries no signing
capability. `make validate` checks both.

`make validate` checks the boundary claims in this file; `make parity` proves the
peer-service resolution; `make keys-check` proves no key material is in the vault.

## Scope

- **In scope**: everything needed for a node to hold the Master role — the
  Ed25519 signing key and its lifecycle, authoring and revoking the node
  registry, maintaining the overlay at `10.100.0.1` with one stanza per
  authorized peer, issuing signed guard approvals, the cluster KillSwitch, the
  peer-intake listener (telemetry evidence, `8090`), the idle-detection
  nocturnal batch scheduler (a time-boxed lease over whole-node jobs, never a
  literal memory pool), and the **infrastructure administration** the user delegated to the
  Master: the fabric's git, file sharing, NAT and vector embeddings database
  (all contracted `spec-only`, `4220`–`4223`; scoped in
  `plans/MASTER_ADMIN_PLAN.md`).
- **Out of scope**: the peer role (see `../peer-node/`) — serving a local vault,
  local inference, the peer-side guard daemon, the peer egress restriction, and
  node-local containment. Cross-role contracts live in `../contracts/`.
- **Out of scope**: the shared authorization implementation, which already
  exists once in `../shared/sparknet-authz.py`.

## Success

This vault should answer, fluently and with citations:

1. What can the Master do that no peer can, and by what mechanism?
2. How does a new node get registered, and what must be true first?
3. How is a node revoked, and what does the revoked node experience?
4. What is the Master forbidden to do to itself?
5. What is specified but not yet built, and in what order should it be built?
6. Which key signs what, and why are there three?
7. Why does the operational key live in a separate process from the admin surface?
8. What does the Master administer, and what does "administers" not yet mean?

## Success for the role itself

The Master is successful when a peer's only path to any privileged action runs
through it, and when revoking that peer takes effect immediately without the
peer's cooperation. Key custody is the whole product: everything else is
downstream of never losing that key and never letting it leave.

## Constraints

- Content language, citation rules and domain conventions are stated in
  `AGENTS.md` — that file wins over this page.
- **No secrets in the vault.** The Master private key belongs in
  `$SPARKNET_STATE_DIR/keys` at mode 0600, referenced only by path.
- **Specification is not implementation.** Now that this role *has* code, the
  risk runs the other way: a page describing the signer or the election as working
  when it is specified-only. Mark every unbuilt component as such, and do not
  describe tested code as deployed.
- **One copy of the peer's services.** Load them by path
  (`services/sparknet-parity.py`). A copy here would drift from the peer's, and
  the drift would surface as signatures that verify on one node and fail on
  another.
- **Structural isolation, not policy.** The signer is separated by filesystem and
  namespace, not by a permission file. The governed surface here is an LLM
  application that reads configuration as input.
- Live network and kernel behaviour is not verifiable on the development host;
  claims about it must be marked unverified rather than asserted.