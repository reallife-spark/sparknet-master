# sparknet master-node — MISSION

The **Master role** of the Sparknet fabric: the node that holds signing
authority over the overlay.

## Status

**Running, partially.** Build plan Steps 15–18 landed: this role has `scripts/`,
`services/` and `systemd/`, loads the peer's services by path, keeps a
hash-chained ledger, generates its own keys into the state directory, has an
isolated signer for the operational key, and declares an admin surface and
`MASTERSPIKE` knowledge manifest.

**Not yet running**, each a numbered step rather than an omission:

| Missing | Step | Consequence |
|---|---|---|
| election | 14 (impl) | the trust-root schema exists; no node has voted, so no node is Master |
| overlay anchoring | 3 | `10.100.0.1` is documented, not bound |
| admin page deployed | 18 | the surface is declared, configured, and deployed on the live Master at `10.100.0.1:8088` (relocated from 8080, fabric Step 55); on the dev host nothing binds it |
| registry distribution | 1–4 | peers read an operator-placed registry; nothing pushes one |

So this role can currently generate keys, prove parity, verify a chain, and sign
against a *fixture* trust root. It cannot yet grant anything a peer would accept,
because no real root exists to grant under. `plans/MASTER_BUILD_PLAN.md` is the
work order for the rest.

Two claims in this file are load-bearing and tested: the signer is
**implemented and unit-tested, never deployed**, and the admin surface carries no
signing capability. `make validate` checks both.

`make validate` checks the boundary claims in this file; `make parity` proves the
peer-service resolution; `make keys-check` proves no key material is in the vault.

## Scope

- **In scope**: everything needed for a node to hold the Master role — the
  Ed25519 signing key and its lifecycle, authoring and revoking the node
  registry, maintaining the overlay at `10.100.0.1` with one stanza per
  authorized peer, issuing signed guard approvals, the cluster KillSwitch, the
  instant-push listener, the idle-detection scheduler for nocturnal memory
  pooling, and the **infrastructure administration** the user delegated to the
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