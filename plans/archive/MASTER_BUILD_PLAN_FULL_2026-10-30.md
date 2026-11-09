---
title: sparknet master-node Build Plan
updated: 2026-10-29
current: 10
---

# sparknet master-node — Build Plan

> Single source of truth for turning this role from specification into
> implementation. The `current:` cursor marks the step being worked. Write this
> file back **immediately** on every advance; append the matching transition
> line to `log.md`.
>
> **As of Step 3 these directories exist** (`scripts/`, `services/`,
> `systemd/` — built Steps 3–4 and 15–18; the isolated signer runs live on
> agx64). Steps 1–9 and 13–21 are closed; **Steps 10–12 are open** — their
> 2026-10-28 scaffolds were marked implemented but are not wired end to end. The
> cursor sits at Step 10. Step 7 (8090) was **re-scoped and closed by fabric Step 69C** — the
> instant-push purpose was superseded by Step 6's 9090 push, and 8090 is now the
> peer→Master intake listener; see Step 7's status.
>
> **Status correction 2026-11-03:** Step 9 was reopened — 9A–9D exist but 9E–9G
> do not, so this archive no longer treats Steps 1–9 as closed. The active
> `../PLAN.md` is canonical and its cursor is 9.

## Status Legend

- `[ ]` not started / in progress
- `[x]` complete — DoD verified
- **DoD** — the check that proves the step is done; `DoD: confirm: user` when a human must confirm
- `current: N` — step being worked now; `current: done` — terminal

## What already exists

| Piece | Where | State |
|---|---|---|
| Signed canonical form, fingerprint, verify, sign | `../shared/sparknet-authz.py` | **implemented and tested** |
| Overlay, capability, identity, port, guard contracts | `../contracts/` | **implemented and tested** |
| Peer guard that verifies and applies | `../peer-node/services/sparknet-guard-d.py` | **implemented and tested** |
| Peer anchor, render, keygen, install | `../peer-node/scripts/` | **implemented and tested** |
| Master `[Peer]` stanza template | `configs/wireguard/master-peer.template` | documentation only |

The Master role's *crypto* is done. What is missing is everything around it:
key lifecycle, registry authorship, the overlay listener, approval issuance,
containment and scheduling.

## Step 1 — Keypair and registry substrate

- [x] **Step 1** — Establish a real Master keypair and the registry it signs.
      - **DoD**: (1) a Master Ed25519 keypair exists at
        `$SPARKNET_STATE_DIR/keys` at mode 0600 and is **not** tracked by git;
        (2) `manifests/master-identity.json` describes the Master at
        `10.100.0.1` — **with `role: peer`, not `role: master`**; see the
        contradiction below; (3) `contracts/identity-schema.json` stops claiming a
        tracked master public key is what peers verify against, and stops calling
        the shipped key anything but a placeholder; (4) `make contract-test` still
        green; (5) a signed test entry verifies against the new key.
      - **Status: complete 2026-10-05.** `make keygen` generates cluster,
        operational and identity pairs into `$SPARKNET_STATE_DIR/keys` at 0600 under
        a 0700 directory, gitignored and untracked; each public half is asserted to
        be the one derived from its private half, and the three to be distinct.
        `manifests/master-identity.json` describes the role at `10.100.0.1`,
        `role: peer`. `contracts/identity-schema.json`'s `master_public_key` is now
        `tracked: false` with a `published_to` pointing at the elected trust root
        rather than a file. 24 tests in `tests/test_step1_keypair.py`.
      - **A contradiction in this step's own DoD, resolved and recorded.** (2) asked
        for `role: master` here. **Step 13 removed that model** — a Master is a peer
        that won a unanimous election, and
        `tests/test_contracts.py::test_a_node_declares_itself_peer_until_it_is_elected`
        exists to fail any deployment site asserting authority it was not granted.
        The cross-role test was right and the DoD was stale, so the manifest says
        `peer` and names `role_implemented_by: master-node` for the scope instead.
        Written into the manifest and into this step so the next reader does not
        "fix" it back.
      - **The other contradiction: `keys-check` and a real keypair cannot both be
        had.** (1) asks for a keypair in `$SPARKNET_STATE_DIR/keys`; the guard
        `keys-check` scanned the whole vault for key-shaped files; and
        `$SPARKNET_STATE_DIR` defaults to `<role>/.state`, *inside* the vault.
        Generating the keypair the DoD requires therefore **failed** the check the
        same DoD requires. The guard is now two questions asked separately —
        is anything key-shaped *tracked* (asked of git, because a key deleted from
        disk but still in history is the failure that matters), and are the private
        halves that may live in the state dir actually *0600 under a 0700 directory*
        (because "may exist" is not "is protected"). The old form passed by ignoring
        precisely the files it existed to police.
      - **What this step still does not do.** It produces a key, not authority.
        Nothing here makes the node Master: no trust root names this key, the signer
        will not start without one, and `test_a_signed_entry_verifies_against_this_
        nodes_own_key` proves only that the keypair loads and signs — plus that it
        fails closed against a different key. Election is Step 14's protocol plus a
        real three-node run.
      - **Note**: this replaces the discarded bootstrap key. Until it lands, the
        Master cannot sign anything and no peer can be authorized.

## Step 2 — Registry schema and the spec/impl boundary

- [x] **Step 2** — Write `docs/registry-protocol.md` (it does not exist yet),
      then turn it into a checkable schema and
      make the "specified, not built" status machine-detectable.
      - **DoD**: (1) `manifests/registry.schema.json` exists and validates the
        current `../peer-node/manifests/node-authorizations.json`;
        (2) `tests/test_master_spec.py` asserts this subvault declares itself
        unbuilt, so the status cannot silently rot into a false claim;
        (3) every page in `docs/` that describes an unbuilt component carries an
        explicit unbuilt marker.
      - **Status**: reopened 2026-10-06 — DoD (1) is not merely unverified, it
        is **false in three independent ways**, found by trying to verify it:
        (a) the schema requires `role: "registry"` and `schema_version:
        "1.0.0"`, while the shipped `../peer-node/manifests/node-authorizations.json`
        carries neither `role` at all nor `schema_version: "1.0"` — and the peer's
        own `peer-node/tests/test_authz.py::test_registry_in_vault_is_valid_and_
        signed_by_that_key` *pins* `"1.0"`, so the two roles disagree about the
        document's shape; (b) the schema's entry `required` names `signature`,
        but `shared/sparknet-authz.py` emits and verifies `signature_b64`, so no
        real entry would validate; (c) nothing anywhere loads the file — no test,
        no script, no make target — so it validates nothing regardless. The
        `../peer-node/scripts/sparknet-registry-fetch.sh` stub meanwhile emits the
        *master's* `1.0.0` shape, so even the peer is internally inconsistent.
        Resolving which shape is canonical is a contract decision
        (`contracts/identity-schema.json` specifies only path, author, reader and
        `empty_by_default`, never the field set) and is deliberately not guessed
        here.
      - **DoD (2) is obsolete by design**: Step 15 replaced
        `test_role_has_no_executable_surface` with tests asserting the opposite,
        and the docstring of `test_master_spec.py` predicted the inversion.
      - **DoD (3)**: `docs/registry-protocol.md` carries the marker, but the
        marker is now stale in the other direction — it reads "specified, not
        built (Step 2)" while the Step 3/5/6 CLI exists, signs, verifies and
        publishes. Corrected in `docs/registry-protocol.md` with this step.
      - **Status: complete 2026-10-22.** The canonical shape was **decided from
        the implementation, not guessed**: it is what `../shared/sparknet-authz.py`
        signs and evaluates — document `{schema_version "1.0",
        master_public_key_b64, description?, authorizations[]}`, entry
        `{fingerprint, identity, capabilities, overlay_ipv4, issued_at,
        expires_at, revoked?, signature_b64}`. The contract now states it once,
        in `../contracts/registry-schema.json`, and
        `master-node/manifests/registry.schema.json` is a **symlink** to it (the
        contracts README forbids a second copy; the ledger schema's copy is the
        one precedent that predates that rule).
      - **DoD (1)**: satisfied by `../shared/sparknet-registry-schema.py`, a
        **standard-library-only** checker — the fabric's runtime dependency
        allow-list is `cryptography` alone, so a validator needing `jsonschema`
        would pass here and fail on a node. It checks the shipped registry, the
        entries the implementation itself mints, and refuses the draft's three
        mistakes (`role`, `1.0.0`, `signature`). `tests/test_registry_schema.py`
        pins all of it.
      - **DoD (2)**: asserted in the direction that is still true. The role
        **declares** its build state (`MISSION.md`, `status:` frontmatter) and
        the declaration must agree with the tree and with the plan's open steps,
        so it cannot rot into a false claim in either direction — asserting
        "unbuilt" would assert a lie.
      - **DoD (3)**: every page in `docs/` now declares a `status:` from a
        closed vocabulary, and any page that is not `built` carries a callout
        marker. Two pages were carrying stale claims in *both* directions and
        were corrected: `docs/master-control-plane.md` said the role "has no
        `scripts/`, `services/` or `systemd/` directory" (false since Steps
        15–16), and `docs/killswitch-template.md` said the role "carries no
        executable surface" (Steps 15–16 built the surface; Step 8 was then
        still a scaffold and was implemented on 2026-10-25).
      - **Cursor**: Step 2 is closed; the cursor advanced to Step 5
        (`guard-apply` grantable in practice), which closed the same day. Step 6
        (registry distribution channel) closed on 2026-10-23; the cursor sits
        at Step 7.


## Step 3 — Signing and registry CLI

- [x] **Step 3** — Give this role its own executable surface. **This is where
      `scripts/` and `services/` come into existence.**
      - **DoD**: (1) `scripts/` and `services/` exist with their own
        `sparknet-env.sh` resolving `SPARKNET_ROLE=master`;
        (2) `make keys` generates the Master's signing keys;
        (3) `make authz-sign IDENTITY=<peer identity>` produces a signed
        registry entry; (4) `make registry-verify` checks the whole registry;
        (5) `make revoke` signs `revoked: true` for an identity;
        (6) peer suite still green.
      - **Status**: complete 2026-10-05; measured green 2026-10-06. `make keys`,
        `authz-sign`, `registry-verify` and `revoke` are each exercised inside
        `make test-all` by `tests/test_registry_cli.py`,
        `tests/test_registry_cli_step3.py`, `tests/test_wg_render.py` and
        `tests/test_step1_keypair.py`.
      - **Two DoD items amended rather than quietly dropped.** The original (2)
        asked for a "WireGuard + Ed25519 pair"; `make keys` deliberately produces
        the **three named Ed25519 keys** (cluster, operational, identity) and no
        WireGuard private key at all — the renderer writes `PrivateKey = # set at
        runtime` on purpose, because a key baked into a rendered config is a key
        in the vault. That is Step 1/16's model and the DoD predates it. The
        original (5) named `FINGERPRINT=<fp>`; the target takes `IDENTITY=<path>`
        and derives the fingerprint. The behaviour it wanted — a signed
        revocation — exists and is proven by the revoked-stanza case in
        `tests/test_wg_render.py`. Both amendments are recorded here so the next
        reader sees what changed and why.

## Step 4 — Master-side overlay listener

- [x] **Step 4** — Render and maintain the Master's `wg0` with one stanza per
      authorized peer.
      - **DoD**: (1) `make wg-render-master` generates `wg0.conf` with one
        `[Peer]` per registry entry, each `AllowedIPs` limited to that peer's own
        `/32`; (2) entries with `revoked: true` are excluded; (3) an unsigned or
        expired entry is excluded; (4) re-render is idempotent; (5) a test
        proves no stanza can carry a mask wider than one `/32`.
      - **Status**: complete; measured 2026-10-06 with three tests added for the
        DoD items that had no test behind them: `test_no_stanza_can_carry_a_mask_
        wider_than_one_32`, `test_an_entry_that_does_not_verify_is_never_rendered`
        and `test_an_expired_entry_is_never_rendered`. Each was proven to fail by
        mutation — deleting the renderer's mask check makes the first fail (it
        rendered `AllowedIPs = 10.100.0.0/32`, i.e. a network address as a peer),
        and ignoring `authz.evaluate`'s verdict makes the other two fail. The
        pre-existing tests cover revoked-excluded, idempotent-re-render and
        one-stanza-per-entry.
      - **Safety**: the Master must never accept an `AllowedIPs` wider than the
        peer's own address, or that peer could source-spoof a sibling.

## Step 5 — Guard approval issuer

- [x] **Step 5** — Make `guard-apply` grantable in practice.
      - **DoD**: (1) `make approval-issue TARGET=<path> CONTENT=<file>` produces
        a signed approval payload per `../contracts/guard-protocol.md`;
        (2) `make approval-deliver FINGERPRINT=<fp>` POSTs it to that peer's
        `10.100.0.x:9090`; (3) the Master tracks issued nonces and refuses to
        issue the same nonce twice; (4) an integration test signs on this side
        and applies on a peer stub, proving the two agree.
      - **Status**: complete 2026-10-22 — measured green (`make ci`,
        `make test-all`, both role bundles rebuilt and verified).
      - **What the step found, which the plan did not anticipate.** The step was
        reopened as "half built, half missing", but the half that existed was
        built against a shape **no peer accepted**. Three implementations of "an
        approval" were live at once: the Master's issuer signed
        `{target, content_digest}`, the isolated signer signed
        `{peer_fingerprint, guard_protocol_version, target_path, action,
        expires_at}`, and the peer's guard verified
        `{file_path, content_b64, content_sha256, issued_at, expires_at, nonce,
        request_id}`. Each was internally consistent, each passed its own
        tests, and no approval the Master could mint was one a peer would
        accept. "Half built" was generous: the two halves had never met.
      - **The fix is structural, not a patch.** The projection now lives once, in
        `../shared/sparknet-authz.py::guard_approval_message`: exactly eight
        fields — `peer_fingerprint`, `file_path`, `content_b64`, `content_sha256`,
        `issued_at`, `expires_at`, `nonce`, `request_id` — serialised as compact
        sorted JSON and strict in **both** directions. A missing field is
        refused, and so is an *extra* one: the signature covers exactly the
        projection, so anything outside it is unsigned, and an unsigned field in
        an envelope that carries authority is how a second, unchecked channel
        into the guard would appear. The signer and the guard both call it, and
        `../tests/test_contracts.py` fails the build if a second copy of the
        field list appears in either role. The contract is
        `../contracts/guard-approval.json` (machine-readable) beside the
        narrative `../contracts/guard-protocol.md`.
      - **Two holes closed while the shape was being fixed.** (1) *Peer
        binding*: the envelope names the peer it is for, and the peer refuses an
        approval addressed to anybody else. Before, an approval minted for peer A
        was a valid approval peer B could apply, as long as it protected the
        same path — the signature said nothing about who it was for. (2) *The
        capability is not in the payload*: the peer reads `guard-apply` from its
        own signed registry entry, so an approval can never grant the authority
        it is checked against.
      - **DoD (1) and (3)**: `make approval-issue` mints the canonical envelope
        and spends the nonce (`$SPARKNET_STATE_DIR/approval_nonces.json`); a
        second issue with the same nonce is refused. The production path is
        `make approval-sign-socket`, which signs **through the isolated
        signer's socket** and leaves a `signature_issued` ledger block; the
        issue script signs directly with the operational key and is for hosts
        with no running signer.
      - **DoD (2)**: `make approval-deliver` resolves the peer's overlay
        address from the signed registry — the fingerprint names the peer, the
        registry entry names its address — and POSTs to
        `http://10.100.0.x:9090/api/v1/critical-file/patch`. `--url` overrides
        it. It refuses an approval that addresses a different peer *before*
        anything is sent, and writes a record that quotes the peer's own answer.
      - **DoD (4)**: `tests/test_approval.py` signs here and applies there — the
        peer's **own** guard daemon, loaded by path, on loopback, against a
        temporary vault whose registry entry grants `guard-apply`. The peer
        verifies the signature, checks the peer binding, recomputes the content
        digest, finds the path protected, finds the capability in its own
        registry and answers `PATCH_VERIFIED_DRY_RUN`; the audit ledger records
        the decision. The negative legs are there too: an approval addressed to
        another peer is refused (`wrong_peer`), and a peer whose registry entry
        does not grant `guard-apply` stays inert.
      - **DoD (4) amended, not quietly dropped**: the peer stub runs
        `--dry-run`, so the *write* of a protected file is not exercised — that
        needs euid 0 and `chattr` on a target node, and the peer's own suite
        records the same limit. What the test proves is that the two sides
        **agree**: the Master's bytes are the peer's bytes, and the peer
        accepts the Master's signature while refusing everything else. The
        write leg is a target-node checklist item, not a claim made here.
      - **Cross-role**: `contracts/` + `shared/` + both roles in one commit,
        then `make contract-test`.

## Step 6 — Registry distribution channel

- [x] **Step 6** — Give peers a way to receive a signed registry.
      - **DoD**: (1) a documented distribution channel exists (the design
        decision is recorded in `docs/registry-protocol.md`);
        (2) `make registry-publish` emits it; (3) a peer-side target documents
        how to consume and verify it; (4) a tampered registry fails closed on
        the peer; (5) revocation propagates within the documented window.
      - **Decision (2026-10-23)**: **the Master pushes to each peer's guard on
        9090** (`POST /api/v1/registry`). Rejected: a peer pull from a new
        Master listener on 8091 (new port, unsigned GET, and a per-peer key
        resolver the shared HTTP module does not have), and the fabric git repo
        (spec-only). Push reuses the path Step 5 proved, adds no port, and — the
        decisive point — can deliver a revocation *to the peer it revokes*,
        which a route gated on that peer's capability could not.
      - **DoD verified**:
        (1) the channel is stated in
        `../../contracts/registry-publication.json` (machine-checkable) and
        `docs/registry-protocol.md` (narrative), with the alternatives and why
        they were rejected; the "unspecified" notes in `registry-schema.json`
        and `identity-schema.json` are replaced.
        (2) `make registry-publish` emits a five-field publication (registry,
        `registry_sha256`, monotonic `sequence`, `published_at`, `signature_b64`
        beside the envelope) after validating the document and refusing one that
        names a foreign Master key. The signature comes from the isolated signer
        (`sign-registry-publication`) or `--offline`; the script then checks its
        own output with `shared/sparknet-registry-install.py::verify_publication`
        — the receiver's rule, not the emitter's own assumption.
        (3) `make -C peer-node registry-fetch PUBLICATION=…` (and
        `registry-status`) documents the operator path; the live path is the
        guard's `POST /api/v1/registry`. Both call the same acceptance rule.
        (4) `tests/test_registry_dist.py` drives the peer's **own guard daemon**
        (loaded by path) and proves three tamper shapes refused without an
        install: a document edited under its digest (`400
        malformed_publication`), a consistent envelope signed by a foreign key
        (`403 bad_signature`), and a registry naming a foreign Master key (`403
        wrong_master_key`). Further tests prove the replay refusal, the
        timer's idempotent re-push, and the master-anchor skip.
        (5) the same suite publishes an authorising registry, delivers it, sees
        the capability take effect, then publishes a revoked registry, delivers
        it, and sees `evaluate` deny with `REASON_REVOKED`. The window is the
        installed `sparknet-registry-deliver.timer` (60 s) and the contract
        states it; a successful push is immediate.
      - **Install order** is registry first, sequence record second, so a crash
        between the writes makes the publication idempotent rather than
        permanently refusable. A *lower* sequence is a rollback (`409
        stale_publication`); an equal sequence is accepted as a no-op
        (`REGISTRY_ALREADY_INSTALLED`) only when its digest matches, which is
        what keeps the 60 s re-delivery a green unit, and refused when it does
        not, because an equal sequence with different content is a fork.
        Registry installation needs neither `--apply-enabled` nor euid 0: it
        writes the peer's own vault, not a protected `/etc` path.
      - **Enabling change**: `sign_authorization` gained `revoked=`, because
        `revoked` is inside the signed envelope and the old revoke script
        flipped it *after* signing, producing an entry no peer would accept. The
        schema now allows an empty `capabilities` list only on a revoked entry —
        the document that carries a revocation must be installable.

## Step 7 — 8090: instant-push listener, re-scoped to peer intake

- [x] **Step 7** — Bind `10.100.0.1:8090`. Originally "POST ACL changes to peers";
      **re-scoped and closed by fabric Step 69C** (2026-10-25).
      - **DoD**: (1) the listener binds `10.100.0.1` only, never a wildcard;
        (2) it refuses off-overlay sources; (3) ~~an ACL change reaches a peer
        within the documented window~~ — superseded, see Status; (4) tests cover
        the refusal paths against a real socket, not by reading source text.
      - **Status: closed by re-scope, 2026-10-25.** The instant-push *purpose* was
        superseded in direction by Step 6, which pushes the signed registry
        Master→peer on 9090 — a Master-side ACL-push listener was never needed, and
        the 7-line `sparknet-registry-listener.py` stub (which printed and exited)
        is **deleted**, along with `tests/test_listener_8090.py` (the text-inspection
        test this step's own Status flagged as unable to fail). Fabric Step 69C
        re-scoped 8090 into the Master's **peer→Master intake listener**
        (`services/sparknet-peer-intake.py` — renamed at fabric Step 70B when the RFI
        request route joined it; `systemd/sparknet-peer-intake.service`,
        staged not enabled): it binds `10.100.0.1` only and refuses a non-overlay bind
        (DoD 1), attributes every request by the WireGuard-authenticated source via
        the signed registry and refuses an unregistered / revoked / `telemetry`-ungranted
        source before reading the body (DoD 2, strengthened), and
        `master-node/tests/test_peer_intake.py` binds a real `ThreadingHTTPServer`
        and POSTs real bodies to cover each refusal (DoD 4 — the fake test is gone).
        DoD 3 (ACL push) is retired with the purpose; `contracts/ports.json` records
        8090 as `master-peer-intake` / `implemented`, and Step 68C's RFI request route
        will join this same listener rather than found a second one. See
        `../../MASTER_OBSERVABILITY_DESIGN.md`.
      - **Was blocked by**: Step 4 (which peers exist) — now moot; attribution reads
        the same registry Step 4's overlay does.

## Step 8 — Cluster KillSwitch

- [x] **Step 8** — Implement the Master-wide containment action.
      - **DoD**: (1) root-gated (`EUID 0`); (2) halts the fabric control planes
        and drops firewall policy (iptables on the deployed Masters); (3) documented as cluster-wide and
        explicitly distinct from the peer node-containment switch;
        (4) it cannot be invoked by a peer at all.
      - **Status**: built 2026-10-25, deployed/dry-run verified 2026-10-26, live
        containment+recovery verified 2026-10-28 on `agx32`/`blue-team`.
        `services/sparknet-killswitch.py` root-gates both modes, defaults to
        dry-run, requires `--force` to change state, disables control units plus
        overlay anchor, removes admin restart policy and stops it, deletes
        overlay interface, and installs `SPARKNET_EMERG_*` iptables chains
        (explicit drops; no host ruleset flush). `scripts/sparknet-killswitch.sh`
        is a root wrapper with explicit `SPARKNET_WG_INTERFACE` and `--force`
        passthrough. `tests/test_killswitch.py` has 14 fake-runner tests.
      - **Note**: resolves the contradiction found during the split, where
        `../peer-node/docs/wireguard.md` documented the KillSwitch as Master-side
        while the repository shipped a peer-side script. The peer script is now
        `../peer-node/scripts/sparknet-node-containment.sh`, scoped to one node,
        and says in its own header that it is *not* this.

## Step 9 — Nocturnal batch scheduler

- [ ] **Step 9** — Idle detection and the time-boxed nocturnal batch scheduler.
      **Status corrected 2026-11-03: open.** The former `[x]` was premature:
      9A–9C are implemented, 9D's task ingress exists, but 9E–9G are not built.
      The active plan now carries the reopened step.
      - **DoD**: (1) idle detection on every node covers interactive SSH
        sessions, WireGuard byte deltas and GPU activity (`nvidia-smi` where
        available, `tegrastats` on the deployed AGX fleet), and treats a missing,
        stale or unreadable signal as busy; (2) three consecutive all-idle
        samples are required, after which the scheduler creates a time-boxed
        **batch lease**, never a pooled-memory fabric, and any non-idle/stale
        signal aborts arming or drains an armed window; (3) only
        operator-supplied, signed, whole-node cluster jobs bounded by budget and
        expiry may run, with no new port, capability or remote-shell path; (4)
        results are signed, committed under each vault's
        `01_Inbox/nocturnal/<lease_id>/<job_id>/`, record incomplete coverage,
        and are never auto-promoted; (5) default is dry-run, arming requires a
        two-step operator confirmation, and live deployment is
        `DoD: confirm: user`.
      - **Status**: **9A adopted, 9B implemented 2026-10-25; 9C implemented 2026-10-26; 9D completed 2026-10-28** —
        `plans/NOCTURNAL_BATCH_DESIGN.md` records measured fleet constraints.
        `shared/sparknet-idle.py`, `services/sparknet-wg-observer.py`, and
        `services/sparknet-scheduler.py` (plan/arm/status/abort + dispatch wiring)
        implemented; tests pass. Dispatch wired to peer cluster-job ingress loopback
        with construction/placement stubs and result recording under
        `01_Inbox/nocturnal/`. No port/capability added; `--execute-enabled`
        remains off by default.
      - **Note**: highest-risk step. It is the only one that moves work between
        nodes on its own, so it needs the strictest human-oversight gate. Do not
        start dispatch integration before Step 8's live leg and cluster-job task
        ingress exist.

## Step 10 — Share ratification service

- [ ] **Step 10** — The authority side of the inter-node sharing regime. A peer
      raises a share; the Master ratifies it within 2 h or the peers isolate.
      - **DoD**: (1) a Master-side endpoint accepts a share request, verifies the
        requesting peer's grant against the signed registry, and issues a
        ratification signed with the Master key; (2) ratification is
        time-boxed — a request not ratified within 2 h of acceptance is refused,
        so the peer's local clock and the Master's agree on the deadline;
        (3) refusals are reasons a peer can act on, not bare errors;
        (4) a ratified share is **authorised with its flag retained for audit**,
        so approval never erases the fact that unapproved data crossed nodes;
        (5) the service cannot be reached by anything that is not a registry peer.
      - **Status**: **code complete 2026-10-29; live listener open.**
        `services/sparknet-share-ratify.py` accepts a share, verifies the grant
        with `authz.verify_grant` against the signed registry, enforces the 2 h
        clock, and asks the isolated signer (`sign-share-ratification`) for a
        canonical signed ratification or refusal; the signer records
        `share_ratified`. Tests: `test_share_ratify.py` (8) plus the signer op
        tests. The 4203 listener, live peer round trip and source gate remain
        `DoD: confirm: user`.
      - **Note**: the peer side of this clock is built in `../peer-node/PLAN.md`
        Step 8 and enforces it locally, so a share can never outlive its window
        just because the Master was unreachable. This step is what lets a share
        *survive* ratification, not what stops it expiring.

## Step 11 — Evidence capture and the review repository

- [ ] **Step 11** — Everything accessed or shared between nodes becomes
      reviewable evidence, held in a git repository this role hosts.
      - **DoD**: (1) every share event — grant, access, transfer, isolation,
        ratification — appends to the hash-chained ledger before it is committed
        to the review repository, so the chain is verifiable independently of
        git; (2) the repository records who, what, when, which grant, which node
        pair and which share type, in a form a reviewer can read without
        running sparknet; (3) retention is explicit and stated, because an
        evidence store that grows without a policy is a liability rather than a
        control; (4) a cloned copy of the repository reproduces the ledger's
        chain, or the discrepancy is detectable.
      - **Status**: **code complete 2026-10-29; live deployment open.**
        `services/sparknet-evidence-capture.py` validates an event, writes it,
        records its digest via the signer's `record-share-evidence`
        (`share_evidence` ledger block), then commits it to `evidence-repo`.
        `verify_repo` compares a clone's files with the ledger's hashes.
        Tests: `test_evidence_and_review.py` plus the signer op tests. The
        share-event callers (the peer share regime) and a real on-node
        ledger/repository run remain `DoD: confirm: user`.

## Step 12 — Review agents and trust decisions

- [ ] **Step 12** — The Master's agents do the review the share regime promises,
        and decide what a flagged node's trust level becomes.
      - **DoD**: (1) review agents consume the evidence repository and produce a
        finding per flagged share without altering the evidence; (2) trust levels
        move only through a signed Master event — `authenticated`,
        `unauthenticated`, `flagged` — recorded in the ledger with a reason; the
        registry stays the permission document and carries no trust field,
        because a level is a belief and must never act as a grant; (3) a decision
        to restore trust is reversible and its reversal does not delete the
        record of the flag; (4) in a two-node mesh the Master is **not**
        applicable: the peers are symmetric and verify shared information
        against the existing knowledge base instead, and the Master does not
        interpose.
      - **Status**: **code complete 2026-10-29; live delivery open.**
        `services/sparknet-review-agents.py` reviews every evidence event
        without altering it and emits a reversible, flag-preserving transition
        signed by the isolated signer (`sign-trust-transition`, a
        `trust_level_changed` ledger event). The registry is not written; live
        peer/telemetry consumption remains `DoD: confirm: user`.

## Step 13 — Consensus protocol and the cluster trust root

- [x] **Step 13** — The Master is elected, not fixed. Nothing above can be built
      until the fabric agrees on who may hold the signing key.
      - **DoD**: (1) `contracts/consensus-protocol.md` states membership, election,
        the 3-of-3 unanimity rule, the cluster trust root's canonical form, and
        re-formation on master change, in the normative voice of
        `guard-protocol.md`; (2) `contracts/identity-schema.json` gains a
        `cluster_trust_root` block that **replaces** the single-key root: three
        member cluster keys co-sign the root, and the root names the elected
        master's operational public key; (3) `contracts/capabilities.json` gains
        `cluster-vote` for peers, keeping the Master's authority as key
        possession rather than a granted capability; (4) `contracts/ports.json`
        declares the election port and states it is `spec-only` until built;
        (5) `contracts/guard-protocol.md`'s *The asymmetry* section is rewritten:
        asymmetry is now a **role state**, not a structural property of the
        codebase, and a test asserts the page no longer claims a peer can never
        produce an approval as a timeless fact; (6) `make contract-test` and
        `make validate` green.
      - **Why unanimity and not a majority**: a 2-of-3 majority lets one
        compromised node paired with any other install a hostile master. With
        3-of-3 a single bad node can *deny* an election but can never *win* one.
        That asymmetry is the whole reason for the threshold, and it is the
        deliberate price of a liveness cost: one offline node blocks the
        election, and re-formation is the documented escape.
      - **Replace vs revoke asymmetry**: replacing the master requires unanimity;
        revoking a node stays unilateral. A revoked node is inert either way, so
        unilateral revocation is a safe denial, while replacement changes who
        holds authority and must not be unilateral. This is the same reasoning
        already recorded in `capabilities.json`'s `escalation_note`.
      - **Not threshold cryptography**: three ordinary Ed25519 signatures over
        identical canonical bytes. The elected master's operational key is
        single-key; unanimity protects *who may hold it*, not each signature.
      - **Status: complete 2026-10-05.** Added `contracts/consensus-protocol.md`;
        `identity-schema.json` gained `cluster_trust_root` (three members, two
        keys, acceptance rules, unanimity, replace-vs-revoke table, re-formation);
        `capabilities.json` gained `cluster-vote` as a say and not a grant;
        `ports.json` declares 4210 `cluster-election` as `spec-only`. The
        `guard-protocol.md` asymmetry section is rewritten as a role state and
        cross-references this protocol. Ten contract tests added.

## Step 14 — One consensus implementation, shared

- [x] **Step 14** — All three nodes must reach the same decision, so the decision
        procedure is one implementation loaded by path, never copied per node.
      - **DoD**: (1) `shared/sparknet-consensus.py` implements canonical root
        bytes, propose/vote/tally, unanimity and root verification, importing
        `sparknet-authz.py` rather than reimplementing Ed25519 — and a test fails
        if it imports anything but `sparknet-authz` for crypto; (2) unanimity
        requires three votes that are three **distinct** members, so one node
        voting three times cannot elect itself, and a test proves it; (3) votes
        carry an injected clock and an injected clock is required, so no test
        sleeps for a real window; (4) a root is rejected unless all three named
        members signed it and the master's public key is the one it names;
        (5) re-formation produces a root that invalidates the previous one, and
        the old key is refused; (6) the file is listed in
        `shared/sparknet-bundle.sh` so a bundle carries it.
      - **Status: complete 2026-10-05.** `shared/sparknet-consensus.py` implements
        canonical root bytes, sign/verify vote, `tally`, `attach_root_signatures`
        and `verify_root`, and `registry_signer_is_authorised` joins consensus to
        the existing authorization scheme. `public_key_from_b64` was added to
        `sparknet-authz.py` rather than duplicating key parsing. 24 tests in
        `tests/test_consensus.py`, all on real keys and real signatures.
      - **Four bugs found by writing the tests, not by reading the code**:
        `_load_authz` used `sys.modules.setdefault` and then executed a second,
        unregistered module — `sparknet-authz.py` already registers first, and its
        `@dataclass` fails confusingly otherwise; the module docstring contained
        the literal `datetime.now()` and tripped its own wall-clock test; the
        fixture used `wireguard_public_key` where the contract says
        `wireguard_pubkey`; and `REASON_REPLAY` was used but never declared.
      - **Mutations proven to fail**: setting `UNANIMITY = 2` fails
        `test_two_of_three_is_not_enough`; removing the per-member signature
        verification fails three tests including
        `test_a_root_signed_by_strangers_is_rejected`; removing the nonce-supersede
        check fails `test_replaying_a_root_is_refused`; collapsing a member's three
        votes to one fails `test_one_member_voting_three_times_has_cast_one_vote`.
      - **A note on how the first attempt to prove the strangers test was invalid**:
        two mutation attempts silently did nothing, because the replacement string
        did not match the source and the run then tested unmodified code and
        reported success. A green mutation run is not evidence the mutation
        happened; the mutant has to be confirmed present in the file first.

## Step 15 — Invert the unbuilt-role boundary, on purpose

- [x] **Step 15** — This role gains an executable surface. Every assertion that
        it has none must be inverted **in the same commit that adds code**.
      - **DoD**: (1) `master-node/tests/test_master_spec.py::test_role_has_no_executable_surface`
        and `::test_pages_still_declare_the_role_unbuilt` are replaced by tests
        that assert the role now *has* a surface and that its pages describe what
        works; (2) `master-node/Makefile`'s `validate` target no longer fails when
        `scripts/` or `services/` exists, and instead asserts each present
        directory is wired into a unit; (3) `AGENTS.md`, `MISSION.md`,
        `docs/master-control-plane.md` and the root `AGENTS.md` stop claiming
        "specified, not built" and say what works instead;
        (4) **`test_private_key_is_never_in_the_vault` is not weakened, skipped or
        deleted** — it is the anchor the whole step stands on;
        (5) `test_master_template_is_documentation_only` still passes, so no live
        `wg0.conf` enters the vault.
      - **Status**: complete 2026-10-05.
      - **Note**: the module docstring of `test_master_spec.py` predicted this
        migration and named the discipline. Honouring it means the inversion is a
        deliberate act with the prose updated alongside, not a side effect of
        files landing.
      - **Result**: (1) replaced by `test_the_role_has_an_executable_surface`,
        `test_pages_do_not_still_claim_the_role_is_unbuilt` and
        `test_claiming_pages_name_something_real` — the last one requires the pages
        to positively describe the surface, so merely deleting the stale sentence
        would not pass. (2) `validate` now runs `units-check`, `keys-check`,
        `parity` and `ledger` and fails if any of them fail.
        `test_every_executable_directory_is_wired_to_something` requires every file
        in `scripts/`, `services/` and `systemd/` to be referenced by a unit or a
        make target, so nothing can sit inert. (3) all four pages plus the root
        `AGENTS.md`, `Makefile` and `index.md`. (4) and (5) untouched and passing.
      - **Also inverted**: `scripts/sparknet-bundle.sh` verified a master bundle by
        asserting it had *no* code — the sharpest form of the same false claim,
        since it would have reported a stripped bundle as correct.

## Step 16 — Master node parity with a peer

- [x] **Step 16** — A master is a peer that won an election. It runs the same node
        code, loaded from one place, so there is provably one implementation.
      - **DoD**: (1) `master-node/services/` loads peer services by path, using
        the pattern already proven in production at
        `peer-node/services/sparknet-guard-d.py:293` (`_load_authz_module`), and a
        test asserts the master's copy of the peer's service resolves to the same
        file the peer uses — no duplicate implementation; (2) `master-node/`
        gains `manifests/` (node identity, cluster trust root, registry),
        `blockchain/ledger.json` and a `security/` key-management page;
        (3) `master-node/scripts/` are thin and delegate to the one implementation;
        (4) `master-node/systemd/` wires the election timer and the signer;
        (5) `make bundle ROLE=master` produces a bundle that runs.
      - **Status**: complete 2026-10-05, with items 3 and 4 amended below before
        the work started rather than after.
      - **Amendment to (3) — delegation was impossible, not merely inconvenient.**
        The peer scripts are role-specific. `peer-node/scripts/sparknet-env.sh`
        hardcodes `SPARKNET_ROLE="peer"` and resolves to the peer's own vault root,
        so sourcing it here would point this role at the peer's vault: precisely
        the silent misdirection every `.env` exclusion in the bundler exists to
        prevent. `sparknet-keygen.sh` emits a single `ed25519-<role>` seed, whereas
        this role needs three *named* keys with different signing scopes. The
        achievable form of "thin" is to delegate to `shared/sparknet-authz.py`,
        which is role-agnostic. The scripts say so in their headers, and
        `test_keygen_header_says_why_it_cannot_delegate_to_the_peer` keeps the
        non-delegation from being read as an oversight later.
      - **Amendment to (4) — the signer unit is Step 17, and shipping it here would
        have been worse than omitting it.** A unit whose `ExecStart` names a service
        that does not exist yet is exactly what `units-check` and the wiring test
        were written to catch: a file that looks like functionality and is not. The
        same applies to an election timer that would vote for nobody while port
        `4210` remains `spec-only`. Both land with their implementation.
      - **Result**: (1) `services/sparknet-parity.py` with a hard allowlist and a
        loud failure; the absence of a fallback to a local copy is the point, and
        `test_parity_fails_loudly_instead_of_using_a_local_copy` covers it.
        (2) `manifests/node-identity.json` declares `role: peer` because a node is
        a peer until elected — the fabric-level assertion that replaced
        `test_each_role_declares_its_own_role_value`, which had encoded the old
        "Master is a separate species" model. `blockchain/ledger.json` verifies and
        does not append, because appending needs the signer.
        (3) keygen delegates to `authz generate-keypair` and contains no
        cryptography; `test_scripts_contain_no_cryptography_of_their_own` inspects
        code lines only, since the header discusses this in prose.
        (4) `sparknet-master-parity.service` and `sparknet-master-ledger.service`
        only. (5) a master bundle now ships `peer-node/` too, because parity
        resolves it by path, and `sparknet-bundle.sh` proves the resolution landed
        *inside the extracted bundle* rather than on the build host.
      - **Bug this step found in itself**: the keygen originally invoked
        `generate-keypair` twice per key — once for the private half, once for the
        public — producing two unrelated keypairs. Both halves loaded, both were the
        right length, and no signature would ever verify.
        `test_keygen_writes_three_keys_that_load_and_sign` requires each public half
        to correspond to its private half, and mutation M7 confirms it fails when
        the two-invocation form is restored.

## Step 17 — The isolated signer

- [x] **Step 17** — The one thing this role must never do is let an LLM-driven web
        surface reach a key that authorizes the fabric.
      - **DoD**: (1) `master-node/services/sparknet-signer.py` signs and does
        nothing else: it holds the operational key, exposes only a unix socket,
        and accepts only canonical bytes already co-signed by the cluster root;
        (2) it refuses to sign anything not named by a valid root, and a test
        proves a forged or stale root is rejected; (3) the key is never readable
        by the peer-functionality surface — no shared volume, and a test asserts
        the signer is not reachable from the bridge, agent ports or the Open
        WebUI network; (4) signing requests are recorded in the ledger, and the
        signer's own capability set contains no capability other than signing;
        (5) **DoD: confirm: user** for (3)'s deployed containment — the unit test
        proves the topology, not that a real deployment held.
      - **Status**: implemented and unit-tested. DoD (3)'s *deployed* containment
        is still unconfirmed and is what gates enabling the unit on a real host —
        see below.
      - **Result**: (1) `services/sparknet-signer.py` signs and does nothing else.
        It is **stricter than the DoD asks**: the wording was "accepts only
        canonical bytes already co-signed by the cluster root", and the
        implementation never signs caller-supplied bytes at all, because the moment
        a signer will sign arbitrary bytes, every upstream canonicalisation bug
        becomes a key-compromise bug. Canonical form is derived from typed fields
        by the one implementation in `shared/`.
        (2) A root must be valid, must name this node, and must name *this key* —
        without that last check any node could start a signer whose signatures all
        satisfied `verify_root`. **36 tests** cover the refusals.
        (3) Unix socket only, mode 0600, path confined to `$SPARKNET_STATE_DIR`. The
        scheme check runs against the raw argument string, not a `Path`, because
        `Path("tcp://h:p")` collapses to `tcp:/h:p` and would miss exactly the
        input the check exists to catch.
        (4) Every signature appends a `signature_issued` block to
        `blockchain/ledger.json` tagged with the `root_id` it was issued under. The
        signer's capability set is exactly `{"sign"}`.
        (5) `systemd/sparknet-master-signer.service` is the only unit whose
        `ExecStart` names the signer, and it is deliberately **not** in the
        `make units` set: installing a role and enabling a process that holds the
        Master key are different acts, and the second belongs to the election.
        `make signer-unit` stages it without enabling it.
      - **The stale-root problem, and what the ledger is for**: a superseded root is
        the hardest case in the file, because *on its own it is valid* — it names
        this node, it names this key, all three members signed it. "Is this root
        well-formed" therefore cannot detect that the cluster has since
        re-formed. The ledger is what remembers: every signature records its
        `root_id`, so a ledger naming a different root means this process is being
        pointed at a superseded one, and starting is refused unless the operator
        passes `--accept-requalification`. Adopting a *newer* root needs the same
        flag, which is correct — that is the moment worth being deliberate about.
        A plain restart under the *same* root is not refused, and
        `test_restarting_under_the_same_root_is_not_a_revert` pins that boundary,
        because a blunt staleness check that refused it would make the signer
        impossible to restart.
      - **A defect this step found in the signer itself**: the fixture
        discovered that a registry entry can be filed under a fingerprint that is
        not the hash of its identity. `authz.evaluate` rejects that as
        `unknown_fingerprint`, so signing it would mint a perfectly valid
        signature over an authorization *no peer would ever accept* — the operator
        sees `ok` and the grant silently does nothing. The signer now refuses it
        before signing. Found because the test fixture was honest enough to fail.
      - **Mutations M8–M12 all caught**: dropping the fingerprint check, dropping
        the ledger staleness memory, making `--accept-requalification`
        unconditional, dropping the key/root binding, and emptying
        `check_socket_path` each break a named test. M10's first attempt was a
        no-op — the mutation text did not match the branch — which is recorded here
        because a "surviving" mutation that never applied is the easiest kind of
        false all-clear to accept.
      - **Also fixed here**: `manifests/node-identity.json` had drifted to
        `wireguard_pubkey_b64` while the contract, the peer manifest, `authz` and
        the docs all said `wireguard_public_key_b64`. Because `fingerprint()`
        ignores fields outside `IDENTITY_FIELDS`, this raised nothing and warned
        nothing — the identity simply hashed differently from the contract, and
        the node would have been unreachable for reasons resembling a network
        fault. `test_the_identity_manifest_uses_the_contract_field_names` now
        pins it.
      - **Why this is a separate process and not a permission rule**: Open WebUI
        is multi-user and LLM-driven. A prompt injection there reaching the
        signing key would invert the fabric's central thesis, because the key
        grants everything the peer roles deliberately withhold. Isolation is
        structural; a deny rule is a policy statement that the thing it governs
        may later ignore.

## Step 18 — Admin agents, MASTERSPIKE and the admin surface

- [x] **Step 18** — The master's reason to exist is administration, so its agents,
        its manifest and its UI are admin-shaped rather than peer-shaped.
      - **DoD**: (1) `master-node/.opencode/agents/` defines admin-geared agents
        (cluster administration, registry keeping, evidence review) and a test
        asserts they resolve through `opencode agent list` read via a file, never
        a pipe; (2) `master-node/MASTERSPIKE-manifest.json` follows the three
        layer llm-wiki shape from `.opencode/skills/llm-wiki/SKILL.md` — raw,
        wiki, schema — with every layer oriented to administration, and a test
        asserts all three layers are present and non-empty; (3) Open WebUI and an
        opencode terminal are reachable as an admin page over the overlay, and the
        admin agent config carries **no** signing capability, asserted by a test;
        (4) the vendored wiki suite resolves `master-node/` as its own vault, and
        `make wiki-preflight` passes for this role.
      - **Status**: complete.
      - **Result**: three admin-geared agents (`cluster-admin`,
        `registry-keeper`, `evidence-reviewer`) resolve through `opencode agent
        list`; `MASTERSPIKE-manifest.json` carries administration-oriented raw /
        wiki / schema layers; `manifests/admin-surface.json` declares the granted
        and `explicitly_not_granted` capabilities with `sign` among the latter;
        `configs/admin-surface/` holds the overlay-bound Open WebUI compose file
        and the opencode terminal config; port 8088 (relocated from 8080, fabric
        Step 55) is contracted as
        `provisioned` / `not-verifiable-here`; `make wiki-preflight` resolves
        `master-node/`. 12 tests in `master-node/tests/test_admin_surface.py`.
      - **DoD: confirm: user** for (3) only — whether an operator can actually
        reach the page. Open WebUI is not installed here and no overlay interface
        exists, so nothing binds `10.100.0.1:8088`. The declaration is verified;
        the reachability is not, and is recorded as `provisioned` rather than
        `implemented` precisely because config without a listener is not a page.
      - **Note**: the admin surface is where the injection risk lives, which is
        why Step 17 exists and why (3) asserts the absence of a signing
        capability here rather than trusting it.
      - **Note**: the first attempt to verify (1) read `opencode agent list`
        through a pipe, which truncated ~12 MB to ~1 MB and dropped this role's
        own agents — the test blamed the agents for the harness's fault. It now
        writes the listing to a file, and the DoD says so on purpose.

## Step 19 — Verify honestly, and record what could not be checked

- [x] **Step 19** — The claims this role makes must be the claims it can support.
      - **DoD**: (1) `make test-all` green at the parent, including this role;
        (2) `make contract-test` green; (3) `make lint` clean; (4) an in-process
        three-node simulation elects, refuses a two-vote attempt, and re-forms on
        a master change, all with injected clocks and no sleeps;
        (5) every unverifiable claim is marked `DoD: confirm: user` rather than
        silently passed, and this page lists what was **not** verified and why.
      - **Status: complete 2026-10-05.** DoD (1) 617 tests green — 355 fabric,
        185 peer, 77 master, 1 skip — plus `make lint`, `make validate` and
        `make contract-test`. DoD (4) is `tests/test_election_simulation.py`, 15
        tests on real Ed25519 keys: a three-node unanimous election, five distinct
        forgery and equivocation refusals, re-formation with the superseded root
        refused, and an AST check that nothing in the file calls `sleep`.
      - **A real gap the simulation found, in the contract rather than the code.**
        `tally()` deduplicated votes by `node_id` and never called `verify_vote()`.
        A vote is a network packet, so *anyone* could forge a third vote naming a
        member who had not voted and manufacture unanimity outright — the one thing
        this fabric exists to prevent. It was untested because no test had ever
        forged anything. `tally` now verifies every signature before counting it,
        drops unverifiable votes, and reports them in `rejected` rather than
        ignoring them: an election must tolerate forgery without being able to hide
        it. Mutations M21 (verification removed), M22 (rejections unrecorded) and
        M23 (verification moved after counting) all fail the suite.
      - **A second gap: a superseded root still verifies on its own.** The contract
        claimed "a new nonce means the old master_pubkey stops being recognised".
        It does not. `verify_root` sees one root and the one already held and cannot
        order two roots; the old root says nothing about being replaced. Supersession
        is enforced where history lives — the ledger's `root_id` records, and
        `sparknet-signer.check_not_reverted` refusing a different root without
        `--accept-requalification` — while a peer must *learn* the new root before
        the old Master stops being recognised by it. `consensus-protocol.md` and
        `identity-schema.json` were corrected, and the open question is recorded:
        a superseded Master must not be able to suppress the news of its own
        replacement, which is the textbook argument for a lease rather than a
        broadcast.
      - **Not verified here, and claimed nowhere.** Listed rather than passed:
        - *Live admin page reachability* — `DoD: confirm: user` (Step 18). Nothing
          binds `10.100.0.1:8088` (relocated from 8080, fabric Step 55); Open WebUI
          is not installed and no overlay
          interface exists on this host.
        - *Deployed signer containment* — `DoD: confirm: user` (Step 17). The unit
          is staged and excluded from `make units` on purpose. Topology is proven;
          that a real deployment held is not.
        - *Election in a live cluster* — `DoD: confirm: user`. The simulation is
          in-process. No votes have crossed the overlay, no trust root has been
          formed by three separate machines, and no node has run under one.
        - *A re-formed root reaching a peer* — open, see above. Not a missing test;
          an undecided protocol.
        - *n=3 survival of a member loss* — undecided by design. Three options are
          priced in `consensus-protocol.md`; picking one is a policy call.
        - *WireGuard, `chattr +i`, systemd on this host* — no `wg`, `wg-quick`
          or `nvidia-smi` on this dev machine, and one peer only. The deployed
          fleet uses iptables, not nftables.
        - *Steps 1–12* — after the 2026-10-06 audit this is no longer a blanket
          claim. **Built and measured: Steps 1, 3 and 4** (keypair,
          signing/registry CLI, master overlay renderer). **Steps 2, 5, 6 and 7
          closed later**, on evidence: the registry schema (2026-10-22), the
          guard approval issuer (2026-10-22), the registry distribution channel
          (2026-10-23), and 8090 re-scoped to peer intake (fabric Step 69C,
          2026-10-25). **Still specified, not built: Steps 9–12** — the
          nocturnal batch scheduler and share-ratification service are 2-line
          scaffolds, and Steps 11–12 (evidence/review repository and review
          agents) have no service. Step 8's KillSwitch is implemented, but its
          destructive live leg is `DoD: confirm: user`. The checkboxes on Steps
          8–12 were returned to `[ ]` on 2026-10-25; their `Status:` lines had
          said "reopened" since 2026-10-06.
          **Completed since this list was written: Steps 20 and 21** (signer
          liveness, deployed 2026-10-09; admin console, live on
          `10.100.0.1:8088`). Nothing in this page implies otherwise.
      - **Where the cursor goes.** Phase 0 (13–18) and honest verification (19) are
        done; Steps 1–7 are closed (Step 7 by re-scope); Steps 20–21 are complete.
        The 2026-10-06 audit reopened Steps 2 and 5–12 on evidence; 2, 5, 6, 7,
        8 and 9 have since closed, so the **next genuinely open step is Step 10**.
        Steps 10–12 were reopened 2026-10-29 because their scaffolds are not
        wired end to end. Election itself lives in the fabric plan (root
        `PLAN.md` Step 11), not here — this role consumes it.

## Step 20 — Signer liveness: client timeouts and a non-blocking accept loop

- [x] **Step 20** — Signer liveness: a client read timeout and a non-blocking
      accept loop. The original defect was real: `_serve_one` blocked in `recv`
      with **no read timeout**, so a client that connected and never sent a
      complete line held the accept loop forever and every later signing request
      queued behind it. `listen(8)` hid the symptom until it did not.
      - **DoD**: (1) a per-client read timeout that answers
        `{"ok": false, "error": "timeout"}` and closes, so a silent client
        costs bounded time instead of the whole signer; (2) a second concurrent
        client is served while the first is still connected and silent —
        proved by a test that opens a hung connection, then a real one, and
        gets an answer on the second; (3) the single-key-holder invariant
        survives the concurrency (the operational key is used under a lock, or
        requests are serialised — chosen and justified in the step, not
        implied); (4) `make test-all` and `make lint` green, and the signer's
        existing signature/containment tests unchanged in behaviour.
      - **Status: complete 2026-10-09.** The signer now answers a silent client
        with the timeout error, serves a second concurrent client, and serialises
        key use under a lock; the tests cover both the hung-client path and
        concurrent signing. The hardened signer was **deployed live** on the pair
        on 2026-10-09 (root `65d9ce25…`, a silent client timed out, a second
        concurrent request was served). Code landed in `bc518d6`; the live
        deployment is recorded in `../../PLAN.md` Step 20's status. The old
        `DoD: confirm: user` deployment leg is therefore satisfied, not waived.

## Step 21 — Master admin console: supervise every node's WebUI

- [x] **Step 21** — The Master's admin surface becomes the one place an
      administrator signs in and supervises the whole fabric's Open WebUI users,
      privileges and activity: a console that composes signed `admin-request`s
      (the new `admin-supervise` capability, fabric Step 29 Phase 2), shows a
      live feed of signups and successful logins from every node, and can list
      users, change roles, approve pending signups, and inspect a user's
      Knowledge, models and chats — each action performed by the *peer's* own
      agent against the peer's own WebUI, never a direct write.
      Design: `../ADMIN_FEDERATION_DESIGN.md` (fabric root).
      - **DoD**: (1) the console reads each node's event spool through the
        bridge `/admin/*` route, carrying a signature the peer verifies under
        `admin-supervise` before any WebUI call; (2) approval/role change/KB read
        are expressible and audited; (3) the admin surface binds
        `10.100.0.1:8088` per `../contracts/ports.json` (Step 18's open leg);
      (4) KDE Connect pages the operator on signup/login; (5) no peer exposes
        a human admin (service account only).
      - **Status: complete 2026-10-19.** Console landed as code 2026-10-12
        (fabric Step 29 Phases 3–4).
        `master-node/services/sparknet-admin-console.py` composes a signed
        `admin-request`, signs it over the isolated signer's socket, and
        dispatches to a peer's `/admin/*` route; `list_events` reads the peer's
        own auth-event spool for the feed, and `feed --ping` pages KDE devices.
        Wired as `make console`; `master-node/tests/test_admin_console.py`
        covers compose/sign/dispatch/resolve/feed/notify. **Live legs verified
        2026-10-12** (fabric Step 29 Phase 5, cluster2 `.131`/`.133`): a real
        pending signup, the signed `approve`/`role` legs over the overlay (200,
        `pending→user`, `user`↔`admin`), the live `events`/`feed` read of the
        peer's spool, a KDE push the operator confirmed on both devices, no human
        admin on a peer (service account only) — with one console defect fixed
        (the CLI prepended the target node as the first entity field, breaking
        every `user_id` action). **DoD (3) closed 2026-10-19**: the admin surface
        is bound at `10.100.0.1:8088` (relocated from 8080, fabric Step 55) and
        returned `HTTP 200` from the peer; the remaining human browser check is an
        operator observation, not an unimplemented leg.

## Sequencing note

**Steps 13 and 14 gate everything below them.** Steps 1–4 assume a Master that
exists and holds a key. Under the election model there is no such Master until
Step 13 contracts the root and Step 14 implements agreement, so building Step 3's
signing CLI first would produce a signer for a master nobody elected. Treat 13–14
as Phase 0: their DoDs must pass before Step 1's keypair work means anything, and
Step 1's keypair becomes one of **three** cluster keys rather than the single
root.

Steps 1–4 then remain prerequisites for a peer to be genuinely useful: real
cluster keys, a signed registry, and a master-side overlay that accepts the peer.
Step 5 is what makes the guard meaningful. Steps 8 and 9 are containment and
autonomy. Steps 15–19 are the boundary inversion, parity, signer isolation and
admin surface.

The ordering constraint that matters most is **Step 15 before Step 16**: the
boundary is inverted in the same commit that adds the first real code, never
earlier, or the role claims to be unbuilt while running.

Steps 10–12 exist because of the inter-node sharing regime in
`../peer-node/PLAN.md` Step 8, which grants a share **optimistically** and
requires ratification within 2 h. That is a deliberate choice: the peers
enforce the deadline themselves so a share cannot outlive its window because the
Master was down, and the Master ratifies to let a share *survive* rather than to
stop it expiring. Steps 10–12 therefore sit after the registry exists, and are
best built after the peer's share plumbing — building the review half first would
mean reviewing evidence no peer produces yet.

## Next

Add steps here as work is identified. New roadmap work after `current: done`
becomes a new step, not a reuse of this plan.

**Audit trail for the 2026-10-06 reopening.** Every checkbox in Steps 1–12 was
flipped to `[x]` in one commit (`32f3e79`) while each step's `Status:` still read
`pending` — the boxes and the statuses disagreed for every one of them, and only
Steps 13–19 had ever received a written status. This audit set each status from
what is actually in the tree (test runs, line counts, greps, mutation runs) and
returned the boxes to `[ ]` where the DoD does not hold. The rule this plan now
follows is the one its own charter states: `[x]` only after the DoD is verified,
and the status line says *how* it was verified.

**Audit trail for the 2026-10-25 reconciliation.** A full plan audit found the
reopening had never reached the checkboxes: Steps 8–12 still carried `[x]` while
their own `Status:` lines said "reopened 2026-10-06 and not built." They are
`[ ]` again. In the other direction, Steps 20 and 21 were still `[ ]` although
Step 20 was deployed live on 2026-10-09 and Step 21's console was bound on
`10.100.0.1:8088` on 2026-10-19; both are `[x]`, with the evidence above. The
cursor is **8**, the first genuinely unbuilt step. No work was completed by this
reconciliation — only the record was made true.
