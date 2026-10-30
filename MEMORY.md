# sparknet master-node — Session Memory

> Standing state only. Read at session start; **replace, never append**.
> The plan and its cursor live in `plans/MASTER_BUILD_PLAN.md` — this file
> mirrors it, it does not own it. Per-session detail belongs in
> `sessions/YYYY-MM-DD.md`.

Updated: 2026-10-29

## Standing State

- **Plan cursor**: `plans/MASTER_BUILD_PLAN.md` `current: 10`. Phase 0 (13–18),
  honest verification (19), Steps 1–9 and 20–21 are complete. **Steps 10–12 were
  reopened 2026-10-29**: their scaffolds are not wired end to end. The KillSwitch
  (8) is implemented (iptables chains; neither Master has nft), fake-runner
  tested, dry-run verified, and live containment+recovery verified on the
  deployed Master (`agx32`/`blue-team`, 2026-10-28). Step 9's premise was
  **re-decided 2026-10-25**: `plans/NOCTURNAL_BATCH_DESIGN.md` replaces literal
  pooled memory with a time-boxed batch lease over independent whole-node jobs.
  **9D completed 2026-10-28**: scheduler dispatch is wired to the peer
  cluster-job ingress loopback with result recording; live arming remains
  operator-confirmed. Step 10's `services/sparknet-share-ratify.py` implements
  the acceptance/ratification logic and asks the isolated signer for a canonical
  signed envelope; no 4203 listener is deployed. Step 11's
  `services/sparknet-evidence-capture.py` writes, hashes, records via the signer
  and commits to `evidence-repo/`; `verify_repo` checks a clone against the
  ledger. Step 12's `services/sparknet-review-agents.py` reviews evidence and
  signs reversible `trust_level_changed` events; trust stays a belief, not a
  registry field. The live listener, peer round trips and telemetry consumption
  remain `DoD: confirm: user`. Do not read implementation or design as live proof.
- **Step 7 (8090) was re-scoped and closed by fabric Step 69C (2026-10-25)**:
  the instant-push purpose was superseded by Step 6's 9090 push and retired (the
  `sparknet-registry-listener.py` stub and the text-inspection
  `test_listener_8090.py` are deleted), and 8090 is now the peer→Master
  **intake** listener — `services/sparknet-peer-intake.py` (renamed from
  `sparknet-telemetry-intake.py` at fabric Step 70B) +
  `systemd/sparknet-peer-intake.service` (staged, not enabled), overlay-only,
  registry-attributed. Telemetry is `telemetry`-gated and recorded; RFI requests
  need only a registered, non-revoked peer and are queued for the composer,
  never answered here. Evidence-not-authority, tested by `test_peer_intake.py`
  over a real socket.
- **Step 20 is deployed live**, not a remaining leg: the signer answers a silent
  client with a timeout, serves a second concurrent client, and serialises key
  use, deployed 2026-10-09 under root `65d9ce25…`. **Step 21 is complete**:
  console code landed 2026-10-12; live legs verified the same day; the admin
  surface bound `10.100.0.1:8088` on 2026-10-19 and answered HTTP 200 from the
  peer. A human browser check is an operator observation, not unbuilt code.
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
  **The election is built and was proven live on real hosts on 2026-10-07** —
  agx64 and agx32 co-formed a 2/2 trust root and the signer ran as
  `sparknet-master-signer.service` on agx64; the signer was unit-tested before
  that and is deployed only where an election put it. A three-node cluster still
  **cannot survive the loss of a member**; see the open question recorded in
  `contracts/consensus-protocol.md`. The admin page is **declared, and now
  deployed on the live Master at `10.100.0.1:8088`** (relocated from 8080, fabric
  Step 55); on this development host nothing binds it — that is a host limitation,
  not an open implementation leg.

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
- **The signer is the only process that holds the operational key, and it ran
  live on 2026-10-07** — `sparknet-master-signer.service` on agx64, in the live
  pair, after the election that named agx64 Master. It was unit-tested before
  that, and it is deployed only where an election put it.
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
- **The guard-approval envelope is stated once**, in
  `../shared/sparknet-authz.py::guard_approval_message` and
  `../contracts/guard-approval.json`: eight fields, compact sorted JSON,
  missing *and* extra fields refused. Both the signer and the peer's guard call
  it; `../tests/test_contracts.py` fails the build on a second copy. Before
  Step 5 three shapes were live at once (issuer, signer, guard), each
  internally consistent and none acceptable to the others — "the two sides
  agree" was an inference from reading both files, and it was false.
- **An approval is bound to one peer and carries no capability.**
  `peer_fingerprint` is the peer's canonical-identity hash; the peer refuses an
  approval addressed to anybody else (`wrong_peer`). `guard-apply` comes from
  the peer's own signed registry entry, never from the approval, so an approval
  can never grant the authority it is checked against.
- **Issuing spends a nonce.** `make approval-issue` tracks nonces in
  `$SPARKNET_STATE_DIR/approval_nonces.json` and refuses a repeat;
  `make approval-sign-socket` is the production path (through the isolated
  signer, leaving a ledger block); `make approval-deliver` resolves the peer's
  overlay address from the signed registry and POSTs to
  `10.100.0.x:9090/api/v1/critical-file/patch`. The exercised path ends at the
  peer's `--dry-run` verification: the protected-file *write* needs euid 0 and
  `chattr`, so it is a target-node item, not a claim made here.
- **A registry reaches a peer as a signed *publication*, pushed to its guard.**
  `make registry-publish` wraps the registry with a monotonic `sequence` and a
  `published_at`, signs that projection plus the registry digest, and writes
  `<out>/current.json`; `make registry-deliver` POSTs it to each peer's
  `9090/api/v1/registry`. The sequence is inside the signature, so an old
  un-revoked registry cannot be replayed (`409 stale_publication`), and the
  route is not gated on the peer's `guard-apply` — a revocation must reach the
  node it revokes. The acceptance rule lives once, in
  `../shared/sparknet-registry-install.py`, because the live guard and the
  offline `registry-fetch` path must agree; the publisher checks its own output
  with that same rule. `sparknet-registry-deliver.timer` re-pushes every 60 s
  (the documented window). Proven end to end in `tests/test_registry_dist.py`
  against the peer's own guard daemon. **`revoked` is inside the signed
  envelope**: `sign_authorization(..., revoked=True)` is how revocation is
  signed — flipping the field after signing yields an entry no peer accepts
  (the old revoke script did exactly that).
- **A registry's shape is stated once**, in `../contracts/registry-schema.json`;
  `master-node/manifests/registry.schema.json` is a **symlink** to it, never a
  copy, and `../shared/sparknet-registry-schema.py` checks documents against it
  (standard library only — the runtime allow-list is `cryptography` alone).
- The peer's live WireGuard, iptables, `chattr +i` and systemd behaviour is
  unverified on the development host; do not claim otherwise. The deployed
  fleet uses iptables (`SPARKNET-FW-*`), not nftables.
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