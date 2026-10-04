# sparknet master-node — MISSION

The **Master role** of the Sparknet fabric: the node that holds signing
authority over the overlay.

## Status

Specification and backlog. Nothing here runs yet. This is deliberate — see
`plans/MASTER_BUILD_PLAN.md`, which is the work order that turns this role into
an implementation.

## Scope

- **In scope**: everything needed for a node to hold the Master role — the
  Ed25519 signing key and its lifecycle, authoring and revoking the node
  registry, maintaining the overlay at `10.100.0.1` with one stanza per
  authorized peer, issuing signed guard approvals, the cluster KillSwitch, the
  instant-push listener, and the idle-detection scheduler for nocturnal memory
  pooling.
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
- **Specification is not implementation.** Pages here must not read as though
  the role already functions. Mark every unbuilt component as such.
- Live network and kernel behaviour is not verifiable on the development host;
  claims about it must be marked unverified rather than asserted.