# sparknet master-node — Session Memory

> Standing state only. Read at session start; **replace, never append**.
> The plan and its cursor live in `plans/MASTER_BUILD_PLAN.md` — this file
> mirrors it, it does not own it. Per-session detail belongs in
> `sessions/YYYY-MM-DD.md`.

Updated: 2026-10-05

## Standing State

- **Plan cursor**: `plans/MASTER_BUILD_PLAN.md` `current: 2`. Phase 0 (13–18) and
  honest verification (19) are complete; **Step 1 (keypair/registry substrate) is
  complete**. Steps 2–12 remain unbuilt — registry distribution, `10.100.0.1:8090`,
  grantable `guard-apply`, the KillSwitch, the batch scheduler, the sharing regime.
- **`$SPARKNET_STATE_DIR` is outside the vault.** `$XDG_STATE_HOME/sparknet/master-node`
  or `~/.local/state/...`. Moving it was structural, not cosmetic: the admin surface
  bind-mounts the vault read-only into an LLM container, so the old default
  `<role>/.state` put the signing key inside the mount and it was readable from that
  surface. Docker cannot exclude a subdir from a bind mount. Keys were migrated
  without rotation. `make keys-check` fails if overridden back inwards. The peer
  keeps `<vault>/.state` deliberately — no such mount.
- **Vault**: this directory (`master-node/`), categories: concepts, entities,
  skills, references, synthesis, journal.
- **Config**: `.env` (`VAULT_PATH`); staged writes: false.
- **Fabric root**: parent directory, holding `contracts/` and `shared/`.
  Override with `SPARKNET_FABRIC_ROOT`.
- **Blockers**: none technically; what is missing is a named step, not a fault.
  **Election is not built** — `shared/sparknet-consensus.py` verifies a trust root
  but produces none, so nothing yet makes a node Master. The signer therefore has
  no root to bind to in practice, and refuses to start. A three-node cluster also
  **cannot survive the loss of a member**; see the open question recorded in
  `contracts/consensus-protocol.md`. The admin page is **declared, and now
  deployed on the live Master at `10.100.0.1:8088`** (relocated from 8080, fabric
  Step 55); on this development host nothing binds it (`DoD: confirm: user`).

## Key Standing Facts

- **This role has an executable surface** (Steps 15–17): `scripts/`, `services/`,
  `systemd/`, `manifests/`, `blockchain/`, `security/`. `make -C master-node
  validate` checks all of it. It runs the peer's services **by path** — a copy
  under `master-node/` fails the build on purpose.
- **The admin surface carries no signing authority** (Step 18). `sign` sits in
  `explicitly_not_granted`, the opencode terminal config denies the state dir and
  `signer.sock`, and port 8088 is contracted `provisioned` /
  `not-verifiable-here`. This is the boundary that lets an LLM-driven
  multi-user surface exist at all, and it is asserted by tests rather than by
  prose. Admin agents are role-scoped in `master-node/.opencode/agents/` — never
  mirrored into the peer or the root agent set.
- **The signer exists and is unit-tested; it has never run deployed.**
  `services/sparknet-signer.py` is the only process that holds the operational
  key. It is stricter than the plan asked: it never signs caller-supplied bytes at
  all, deriving canonical form from typed fields. Its unit is deliberately excluded
  from `make units` — installing a role and enabling a key-holding process are
  different acts, and the second belongs to the election (`make signer-unit`
  stages it without enabling it).
- **A node is a peer until it is elected.** `manifests/node-identity.json` says
  `role: peer` and carries no claim to authority; the trust root confers that.
- The Master holds the only Ed25519 private key in the fabric. It never leaves
  this machine and is never committed. A peer holding the same capability
  vocabulary without that key can verify but never grant.
- **Stale roots are detected by the ledger, not by root validity.** A superseded
  root verifies perfectly on its own — right node, right key, three real member
  signatures — so every signature records the `root_id` it was issued under, and
  starting against a different root requires `--accept-requalification`. A plain
  restart under the *same* root is not a revert and is not refused.
- The shipped `master-ed25519.pub.b64` is a **bootstrap** key whose private
  half was discarded — it cannot sign. Step 1 of the build plan replaces it.
- The peer egress rule (wlan pinned to `10.100.0.1`) must never be adopted on
  the Master. It would blackhole the fabric. See `docs/network-posture.md`.
- `../shared/sparknet-authz.py` is the single implementation of the signed
  canonical form. This role signs with it; peers verify with it. Never copy it.
- `guard-apply` cannot be granted to any peer until Step 4 (approval issuer)
  exists — the capability is defined and enforced, but nothing can issue it.
- The peer's live WireGuard, nftables, `chattr +i` and systemd behaviour is
  unverified on the development host; do not claim otherwise.
- **`opencode agent list` must be read from a file, never a pipe.** It emits
  ~12 MB for this role and a pipe truncates it to ~1 MB, silently dropping the
  role's own agents — which sort last, so the test blames the agent file for a
  harness fault. This cost real debugging time; the Step 18 DoD says so.
- **`tally()` verifies every vote before counting it, and says what it dropped.**
  It did not, and the gap was that a forged third ballot could manufacture
  unanimity — one `node_id` field away. It was untested because nothing had ever
  forged a vote. Unverifiable votes are dropped *and reported* in `rejected`;
  silently ignoring them would let an election tolerate forgery it cannot see.
- **A superseded trust root still verifies on its own.** No nonce can make it stop:
  nothing inside a root says it was replaced, and `verify_root` cannot order two
  roots. Supersession is enforced where history lives — the ledger's `root_id`,
  and `check_not_reverted` refusing a different root without
  `--accept-requalification`. A peer must *learn* a re-formed root before the old
  Master stops being recognised by it, and **how it learns is undecided**. Do not
  let a doc claim otherwise; the contract and `identity-schema.json` were corrected
  and both open questions are priced in `../contracts/consensus-protocol.md`.
- **A bundle does not ship the fabric-level `tests/`.** An extracted node cannot run
  `test_contracts.py`, so it cannot check contract drift for itself. Parity is
  proved at the build host before bundling, not inside the bundle.
- **`contracts/ports.json` is uncommitted.** A mutation used
  `git checkout contracts/ports.json` to undo itself and reverted the whole
  two-axis `implementation_state`/`runtime` rework plus 5 ports. The contract
  tests caught it and the file was restored from the last verified bundle
  (`dist/sparknet-master-worktree-20261005-170914.tar.gz`). Restore **uncommitted
  contracts from a bundle**, never from HEAD.
- **The Master administers the fabric's git, file share, NAT and vector
  embeddings DB** (user-directed). This is a role *responsibility*, not a
  claim of existence: `contracts/ports.json` lists them `4220`–`4223`,
  `spec-only`, `bound_by: master`, `overlay_only`, bound to `10.100.0.1`.
  Scoped in `plans/MASTER_ADMIN_PLAN.md`; no daemon, no code, and no
  adjacency to the signer — same structural rule as the admin surface.