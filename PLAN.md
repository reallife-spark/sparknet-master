---
title: sparknet master-node Plan
updated: 2026-11-10
current: 28
---

# sparknet master-node — Active Plan

> Single source of truth for Master work. The `current:` cursor names the step
> being worked. Write this file back **immediately** on every advance and append
> the transition line to `00_System/log.md`. Completed steps 1–9, 13–21 are in
> `plans/archive/MASTER_BUILD_PLAN_FULL_2026-10-30.md`; `plans/MASTER_BUILD_PLAN.md`
> is a symlink to this file for old links.

## Status Legend

- `[ ]` not started / in progress
- `[x]` complete — DoD verified
- `[~]` closed by operator scope decision — explicitly not DoD-verified
- **DoD** — the check that proves the step is done; `DoD: confirm: user` when a
  human must confirm
- `current: N` — step being worked; `current: done` — terminal

## Closed steps

| Step | Scope | Evidence |
|---|---|---|
| 1–8 | key/registry, schema, CLI, overlay, approvals, distribution, intake, KillSwitch | archived plan and `log.md` |
| 10 | share ratification closed by operator scope decision 2026-11-04 — two-node `peer_pair`; 4203 staged for a future third node | this step |
| 13–21 | consensus, shared election, role inversion, parity, signer, admin surface, honest verification, signer liveness, console | archived plan and `log.md` |

## Step 9 — Nocturnal batch scheduler (reopened 2026-11-03)

- [ ] **Step 9** — Keep the nocturnal lease a time-boxed batch window over
  independent idle nodes, never a pooled-memory fabric.
  - [x] **9A–9C** — The batch-lease design, the idle-evidence collector and the
    root WireGuard observer, and the `plan`/`arm`/`status`/`abort` lease state
    machine are implemented and tested.
  - [x] **9D — task ingress.** The peer bridge carries loopback
    `/v1/cluster/submit`, `/v1/cluster/status/<id>` and
    `/v1/cluster/result/<id>` with execution disabled by default. 9G adds the
    signed dispatcher, placement and reduce; the ingress itself is unchanged.
  - [x] **9E — artifact commits.** `contracts/nocturnal-artifact-schema.json`
    and `shared/sparknet-nocturnal.py` define, validate, sign and write signed
    participant results and manifests under
    `01_Inbox/nocturnal/<lease_id>/<job_id>/`, with coverage, a state-dir git
    repository and no automatic promotion.
  - [x] **9F — optional timer.** `sparknet-nocturnal-probe.service`/`.timer`
    runs `scheduler status --notify` and has no path to `plan` or `arm`.
  - [ ] **9G — live deploy.** The signed dispatcher, placement, peer execution,
    reduce and artifact path are implemented and locally tested. A two-node
    live window on agx64/agx32 with an operator present is still
    `DoD: confirm: user`; the scheduler only permits 02:00–05:00 local.
  - **DoD**: 9E writes and commits signed artifacts with explicit coverage and
    no auto-promotion; 9F cannot arm; 9G is the live two-node window.
  - **Status 2026-11-04:** 9E/9F and the 9G code path are implemented and
    covered by `tests/test_nocturnal.py`, `tests/test_cluster.py`, the bridge
    cluster tests and the scheduler dispatch tests. Preflight is live: the root
    WireGuard observer timer is enabled and writing `/mnt/log/sparknet-wg.json`,
    and the peer telemetry pusher succeeded. 9G remains the live operator window;
    it cannot run outside 02:00–05:00 local and the current nodes are busy.
  - **Deferred 2026-11-06:** 9G is parked until after Step 26. Do not arm or
    run the nocturnal window during the role inversion; the Master host and
    scheduler state move.

## Step 10 — Share ratification service

- [~] **Step 10 — CLOSED BY SCOPE (not DoD-verified).** The share-ratification
  service is code-complete, tested and staged, but the current fabric is a
  two-node `peer_pair`, where governance is symmetric and no Master ratification
  is required. A live 4203 round trip needs a third host and a three-entry
  registry. On 2026-11-04 the operator chose the two-node posture; the 4203
  queue stays built, disabled and inactive for a future third node. This is a
  scope retirement, not a claim that the live leg ran.
  - **DoD**: signed accept/refuse envelopes, deadline and flag-retained fields,
    duplicate/expired/unknown-grant refusals, tests through the real signer, a
    staged `4203` listener. The live third-node leg is retained for a future
    three-node deployment.
  - **Status**: code complete 2026-10-29; multi-key listener and durable human
    queue added 2026-10-31. Tested; no unit enabled on the pair. Closed by
    operator scope decision 2026-11-04.

## Step 11 — Evidence capture and review repository

- [x] **Step 11 — complete and live-verified on agx32 2026-11-04.** Validate one
  share-evidence event, write it under `evidence-repo/events/`, record its digest
  in the signed ledger and commit it.
  - **DoD**: hashed event, signer-recorded ledger block, git commit, `verify_repo`
    against the ledger, missing/unrecorded file discrepancy; tests green.
  - **Status**: the live `share.transfer` event was captured, its SHA-256
    `8723c220…` recorded as ledger block `c4ea7399…`, committed to the evidence
    repository, and `verify_repo` returned `ok: true` with one recorded file.

## Step 12 — Review agents and trust decisions

- [x] **Step 12 — complete and live-verified on agx32 2026-11-04.** Produce a
  finding for each evidence event without modifying the evidence, and emit a
  reversible signed trust belief. Never write a registry or a grant.
  - **DoD**: signed `trust_level_changed` with `reversible`/`flag_preserved`,
    invalid levels refused, evidence read-only, tests green.
  - **Status**: one finding was produced for the live evidence event; a signed
    `authenticated` transition and its `flagged` reversal were recorded for a
    test node id, both with `reversible: true` and `flag_preserved: true`; no
    registry or grant was written.

## Step 22 — Scoped knowledge responder and AI context

- [x] **Step 22** — Make the Master supply scoped fabric knowledge to a user's
  peer without becoming a general oracle:
  - [x] **22A — Context.** Generate `CONTEXT.md` and load it in the Master's
    OpenCode terminal and admin surface; never expose the peer context as the
    Master's.
  - [x] **22B — Responder.** Consume queued RFI requests, search only the
    allow-listed fabric corpus, enforce the request's `scope`, return an empty
    answer when nothing matches, sign through the isolated signer and deliver
    through the existing RFI answer transport.
  - [x] **22C — Knowledge intake.** Record the answer/response in the ledger and
    telemetry as evidence; never treat it as authority or as a peer's vault read.
  - **DoD**: an end-to-end loopback test (peer request → `8090` intake → queue →
    responder → signed answer → peer guard → `01_Inbox/`), scope/empty/revoked
    refusals, `make context-check`, `make render`, `make contract-test`,
    `make test-all`; live units and cross-node delivery are
    `DoD: confirm: user`.
  - **Status: complete and live-verified on agx32 2026-10-31.** 8090 intake and the responder run; a real peer RFI was answered and installed; the admin console `feed`/`users` paths work; registry sequence 2 was re-signed and delivered. Master tests and bundle verify pass.

## Step 23 — Qdrant Master store, uplift intake and distillation

- [x] **Step 23** — Run the Master's Qdrant-backed 4223 store, receive consented
  uplift on 8091, and operate the same-family distillation scaffold.
  - [x] **23A — 4223.** `services/sparknet-vector-serve.py` loads
    `scripts/sparknet-vector.py`; only `sparknet-fabric` and
    `sparknet-shared` are served. Local tests pass.
  - [x] **23B — Uplift intake.** `services/sparknet-uplift-intake.py` verifies
    overlay source, node signature, `model-uplift`, freshness and nonce, then
    stores inventory, traces, snapshots and KV manifests. It holds no key.
  - [x] **23C — Distillation.** `services/sparknet-distill.py` builds a
    consented, redacted dataset, refuses a failed doctor, evaluates a candidate
    and can sign a `distillation_run` through the isolated signer.
  - [x] **23D — Live.** Qdrant `v1.20.0` on agx32; registry sequence 7 grants
    `model-uplift` and delivered 200; 8091 intake mirroring 41 inventory
    records; four agx64 snapshots uploaded and one restored (40 points); a real
    Qwen2.5-7B→Qwen2.5-1.5B LoRA run was signed (`run-20261101T101033Z-…`) and
    its model card published. Raw vLLM KV capture completed as root 81H on
    2026-11-01 (299 blocks, 627 MB, pushed and digest-verified).
  - **DoD**: master suite green; live legs `DoD: confirm: user`.

## Step 24 — Master memory control and read-through

- [x] **Step 24 — complete and live-verified on agx32 2026-11-04.** Let the Master govern fleet memory without a mirror:
  - [x] **24A — Capability and actions.** `memory-supervise` is a sensitive
    Master-issued capability; `memory_status`, `memory_policy_set`,
    `memory_read` and `memory_purge` are signed admin actions with fields inside
    the canonical projection.
  - [x] **24B — Peer execution.** The bridge verifies the signature, the target
    and `memory-supervise`, then forwards to the local Python gateway; the
    content is transient and the peer audits it.
  - [x] **24C — Console posture.** The Master console carries a read-only Memory
    menu and the admin console composes the memory verbs; no content mirror is
    stored.
  - [x] **24D — Project memory.** The shared `06_Projects` lifecycle and memory
    bundle commands work in the Master role vault; reports are signed by the
    operator, not the Master AI.
  - **DoD**: `make test-master`, `make test-admin-supervise`,
    `make contract-test`, `make context-check`, `make bundle-verify ROLE=master`;
    live `memory_status` and an on-demand content read are
    `DoD: confirm: user`.
  - **Status: complete 2026-11-04.** The peer memory sidecar is live on agx64, and the Master's signed `memory_status` and `memory-read` actions returned live records through the peer gateway. The root `memory-supervise` capability is in registry sequence 8; no mirror is stored. The cursor stays at Step 9 because 9G is the remaining open step.

## Step 25 — Master admin-only WebUI and OpenCode engine

- [x] **Step 25** — Recreate the Master admin surface as admin-only, retire the
  old cluster2 user surface, and give the administrator a working engine.
  - [x] `admin-surface/docker-compose.admin.yml` is host-network, Open WebUI
    `v0.13.0`, `ENABLE_SIGNUP=false`, one `admin@sparknet.local` account from a
    deploy-time password at 0600.
  - [x] The engine runs as `sparknet-opencode-engine@master` with
    `--single-vault /srv/sparknet/knowledge/master-admin`; the role vault is
    never mounted.
  - [x] The old cluster2 `sparknet-webui` on `8181` was exported and retired;
    its one user chat was imported into the peer account and its volume was
    removed after the backup.
  - [x] Live admin chat returned `webui-master-ok` on agx32; the Master
    `/api/v1/users/` list has exactly one admin.
  - **DoD**: admin-only WebUI, live engine round trip, no user surface on the
    Master; browser click-through `DoD: confirm: user`.

## Step 26 — Master role inversion: agx64 Master

- [x] **Step 26** — Move the elected Master role from `agx32` to `agx64` by a
  chained re-formation, not a fresh election.
  - [x] **26A — Freeze and backup.** Park 9G; stop the signer and Master
    services; archive and verify the ledger, evidence repo, registry, trust
    root, `master-admin` vault, admin WebUI volume, Master Qdrant,
    `/srv/sparknet/uplift`, `/srv/sparknet/distill`, share-ratify and scheduler
    state; record the old root id, ledger head and registry sequence.
  - [x] **26B — Identity and roster.** Point `master-node/manifests/master-identity.json`
    and `master-node/manifests/node-identity.json` at `sparknet-node-0001` /
    `10.100.0.1/32`; keep `role: peer` in the committed templates; generate the
    new operational key on `agx64`; build the new roster with new fingerprints
    and existing cluster pubkeys; copy the held old root to `agx64`.
  - [x] **26C — Re-formation.** Run the exchange with `--trust <old-root>`;
    `agx64` approves `EXPECT=sparknet-node-0001`; `agx32` requests
    `CANDIDATE=sparknet-node-0001`; verify 2/2 signatures, lineage, epoch,
    master id and new operational key; keep the old signer disabled.
  - [x] **26D — Move Master services.** Restore ledger/evidence/registry/root/
    admin vault/admin WebUI/Master Qdrant/uplift/distill on `agx64`; do not
    copy the old operational key or signer socket; start signer, ledger,
    parity, admin console/surface, 8090/8091, 4220–4223, 4203, scheduler and
    firewall units; set `SPARKNET_NODE_ID=sparknet-node-0001`.
  - [x] **26E — Registry and grants.** Sign the higher-sequence registry for the
    new identities with the existing capability sets; deliver to `agx32`;
    re-issue grants and tokens; point admin federation at `agx32`; rotate
    secrets; update goSpark control-plane placement.
  - [x] **26F — Model and verification.** Move the teacher runtime config and
    compose to `master-node/`, update the catalog/role placement/admin model
    filter, keep the teacher weights on `agx64`, and benchmark; run the Master
    suite and every gate; remove old Master services/keys from `agx32` after
    verification.
  - **DoD**: new root verifies and chains; signer on `agx64` returns the new
    root id; old signer is disabled; registry verifies on both; admin 8088,
    8090, 8091 and 4220–4223 are healthy on `agx64`; ledger/evidence/admin vault
    parity holds; teacher runs on `agx64`; `make test-master`,
    `make contract-test`, `make context-check`, `make bundle-verify ROLE=master`
    and `make ci` pass; live legs are `DoD: confirm: user`.
  - **Status 2026-11-06:** Master live on `agx64`. Root `c77a3446…`, registry
    sequence 9, signer/ledger/parity, admin 8088, console 8098, intake
    8090/8091, 4220–4223, share 4201/4202, engine 4204, Qdrant 6333. Admin
    federation `users` and `memory_status` returned 200; teacher benchmark
    21.88 tok/s, 21.21 GiB, 100%; old `agx32` Master data/units/keys removed;
    goSpark control on `agx64`, agent on `agx32`. Step complete; loopback token
    rotation remains under root 88G.

## Step 27 — Master-side Gemini blueprint surfaces

- [~] **Step 27 — CLOSED BY STEP 89 SUPERSESSION (scope).** The Master half of
  the sovereign-cluster blueprint was delivered by Step 89A/E/H; this step is
  not a second implementation.
  - [x] **27A — Contracts and envelopes.** Step 89A/B adopted the event, ABAC,
    collaboration, exec, self-improvement, package, lake and distillation
    contracts, canonical forms and vectors.
  - [x] **27B — Orchestrator and ABAC.** Step 89C/D: signed event routing,
    named agents, ABAC narrowing, denial audit and no authority on a knowledge
    channel.
  - [~] **27C — Lake and collaboration.** Consented, signed per-department lake
    intake and the live collaboration broker are delivered. Retention is
    recorded as `retention_days` metadata; no automatic deletion job was
    adopted. Deletion/expiry is retired from this step; a future need is new
    work.
  - [~] **27D — Distillation and packages.** Operator-triggered distillation,
    evaluation, signed run/model card, model-runtime lease/promote/rollback,
    package index and signed distribution are delivered. The “online trace-tap
    scheduler” is the uplift trace intake plus the signed schedule record, not
    an autonomous training scheduler; student deployment uses model-runtime
    promotion, not live weight hot-swap. Those stronger forms are retired from
    this step; a future need is new work.
  - [x] **27E — Dashboard and verification.** Step 89E/F and the console
    surfaces expose nodes, queue, KB, users/approvals, lake, distill, events,
    ABAC and collaboration; writes remain signed admin requests.
  - **Status 2026-11-09 — closed by supersession.** Evidence: the Step 89
    channel matrix, `tests/test_event*.py`, `test_agent_bus.py`,
    `test_orchestrator.py`, `test_abac.py`, `test_collab.py`, `test_exec*.py`,
    `test_self_improve.py`, `test_package*.py`, `test_data_lake.py`,
    `master-node/tests/test_step89_admin.py`, and the console tests. No direct
    peer vault/DB write was introduced.

## Step 28 — Understand-Anything + issue intake (master half)

- [ ] **Step 28** — Add the Master half of the Step 91 integration. Opened ahead
  of the queued Step 27 by operator direction on 2026-11-09; Step 27 remains
  queued and is not cancelled.
  - [x] **28A — Skills and tracker.** Load the nine `/understand*` skills, the
    Matt Pocock engineering family and `setup-matt-pocock-skills`; run the
    setup with the local markdown tracker and write `docs/agents/*`,
    `GLOSSARY.md`, `docs/adr/` and `.scratch/issues/`.
  - [x] **28B — Issue intake.** Extend `services/sparknet-peer-intake.py` with
    `POST /api/v1/issues`; verify the signature, overlay fingerprint, expiry,
    nonce and `issue-report` capability; re-check redaction; upsert by
    `(node_id, issue_id)`.
  - [x] **28C — Store and triage.** Append to `/mnt/log/sparknet-issues.jsonl`
    and keep a local triage state; add `GET /api/issues` and the Issues tab.
    Fabric 93B completes the writer: append-only
    `<state-dir>/issues/triage.jsonl`, derived `triage.json`, and
    `scripts/sparknet-issue-triage.py`.
  - [x] **28D — Console.** The shared Understand and Issues tabs render for the
    Master role with the master config.
  - **DoD**: `make -C master-node test`, `make contract-test`,
    `make context-check`, `make role-skills-check` and
    `make bundle-verify ROLE=master` are green; signed acceptance, capability
    refusal, replay refusal, digest mismatch and redaction refusal are covered
    by tests; live peer delivery is `DoD: confirm: user`.

  - **Status 2026-11-09 — Master half implemented.** The Master catalog no
    longer shadows the 80-skill base suite (1614 role-local), the local tracker
    and docs are in place, `POST /api/v1/issues` verifies the signature,
    overlay fingerprint, capability, digest, expiry and replay and appends to
    the issue store, and the console exposes the issues read-only. Fabric 93B
    adds the append-only triage writer and derived view. `make ci`,
    `make -C master-node test` and `make bundle-verify ROLE=master` are green.
    Live peer delivery is `DoD: confirm: user`.

## Next

`current:` moves one step at a time, and only after the DoD is verified.
Peer work stays in `../peer-node/PLAN.md`; fabric work in `../PLAN.md`.
