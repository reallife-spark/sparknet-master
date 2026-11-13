# master-node log — append-only transition trail

One line per plan transition, newest at the bottom. History before the numbered
layout lives in git history; this is the running record from `00_System/log.md`
forward. The root `log.md` is a symlink to this file.

- [2026-10-06] LAYOUT master vault moved to the numbered PARA layout: legacy
  category dirs became symlinks into `00_System`–`07_Archives`;
  `02_Daily/2026-10-05.md` holds the session note that used to live at
  `sessions/`.
- [2026-10-08] MEMORY master `02_Daily/` cleared by operator decision — this
  development's sessions live exclusively in the fabric root's `sessions/` (the
  master build timeline was folded into `../sessions/2026-10-05.md` before
  removal). Role `02_Daily/` stays empty until the master's own main is opened
  and used. The role also gains its own `.opencode/agents/chat.md` (read-only
  chat over this vault), mirroring the fabric root's config.
- [2026-10-22] Plan cursor 2 -> 5 — **Step 2 closed** (registry schema and the
  spec/impl boundary). The canonical registry shape was decided from the
  implementation (`../shared/sparknet-authz.py`), not guessed: it is stated once
  in `../contracts/registry-schema.json`, and
  `master-node/manifests/registry.schema.json` is a symlink to it. The checker
  `../shared/sparknet-registry-schema.py` is standard-library only (the runtime
  allow-list is `cryptography` alone) and refuses a schema keyword it does not
  implement. DoD (2) is asserted in its honest direction: the role *declares*
  its build state (`MISSION.md`) and the declaration must agree with the tree
  and the plan's open steps. Every `docs/` page now declares a `status:` from a
  closed vocabulary, and two pages carrying stale claims in both directions were
  corrected. Cross-role: `contracts/` + both roles in one commit.
- [2026-10-22] Plan cursor 5 -> 6 — **Step 5 closed** (`guard-apply` grantable
  in practice). The step found a defect the plan did not anticipate: three
  "approval" shapes were live at once — the issuer signed `{target,
  content_digest}`, the signer signed `{peer_fingerprint,
  guard_protocol_version, target_path, action, expires_at}`, and the peer's
  guard verified `{file_path, content_b64, content_sha256, issued_at,
  expires_at, nonce, request_id}`. Each side passed its own tests; no approval
  the Master could mint was one a peer would accept. The projection now lives
  once, in `../shared/sparknet-authz.py::guard_approval_message` (eight fields,
  compact sorted JSON, extra fields refused), stated as a contract in
  `../contracts/guard-approval.json`, with `../tests/test_contracts.py` failing
  the build if a second copy appears in either role. Two holes closed while
  fixing the shape: the envelope names the peer (`peer_fingerprint`, so an
  approval for peer A is refused by peer B) and carries no capabilities (the
  peer reads `guard-apply` from its own signed registry entry). DoD (4) is a
  real integration test — the peer's own guard daemon, loaded by path, accepts
  a Master-signed approval and answers `PATCH_VERIFIED_DRY_RUN`, with
  `wrong_peer` and missing-capability negatives; the protected-file *write*
  needs euid 0 + `chattr` and is a target-node item, stated as such rather than
  claimed. Cross-role: `contracts/` + `shared/` + both roles in one commit.
- [2026-10-25] Plan cursor 7 -> 20 — **Step 7 closed by re-scope** (fabric Step
  69C). 8090's instant-push purpose was superseded in direction by Step 6 (the
  signed registry is pushed Master→peer on 9090, so a Master-side ACL-push
  listener was never needed) and is retired. Fabric Step 69C re-scoped 8090 into
  the Master's peer→Master **intake** listener: `services/sparknet-telemetry-intake.py`
  + `systemd/sparknet-telemetry-intake.service` (staged via `make
  telemetry-intake-unit`, not enabled — a peer-facing socket on the authority-plane
  node is an operator decision), overlay-only, binding `10.100.0.1` and refusing a
  wildcard, attributing each `POST /api/v1/telemetry` by the WireGuard-authenticated
  source via the signed registry (refusing unregistered / revoked / `telemetry`-ungranted
  before the body is read), verifying with `authz.verify_telemetry_report`, recording
  evidence to `/mnt/log/sparknet-telemetry.jsonl`, and carrying no authority. The
  7-line `sparknet-registry-listener.py` stub and `test_listener_8090.py` — the
  text-inspection test this step's own Status flagged as "cannot fail for the failure
  the DoD names" — are **deleted**; `test_telemetry_intake.py` (15 tests) binds a real
  `ThreadingHTTPServer`. `contracts/ports.json` now records 8090 as
  `master-peer-intake` / `implemented`. Cross-role: fabric Step 69C, with the master
  docs (`docs/master-control-plane.md`, `MISSION.md`, `docs/registry-protocol.md`,
  `USER_MANUAL.md`, this plan, `MEMORY.md`) reconciled in the same pass. Step 68C's
  RFI request route will join this same listener rather than found a second one.
- [2026-10-25] STEP 8 implementation complete (live destructive run unverified). `services/sparknet-killswitch.py` root-gates both modes, defaults to dry-run, requires `--force`, disables the five control units plus the overlay anchor, removes the admin container restart policy and stops it, deletes the overlay interface, and installs `inet sparknet_emergency` (input/output/forward drops; no `flush ruleset`, no host policy change). Optional absent targets are recorded without hiding real failures. `scripts/sparknet-killswitch.sh` keeps help before the root gate; `make killswitch FORCE=1` is the destructive path. 13 fake-runner tests in `tests/test_killswitch.py`; docs (`docs/killswitch-template.md` now `partially-built`, control-plane table, `systemd/README.md`, `AGENTS.md`, `MEMORY.md`, `MISSION.md`, `USER_MANUAL.md`) and the plan status reconciled. The live run is `DoD: confirm: user`, so Step 8 stays `[ ]` and the cursor stays 8.
- [2026-10-25] STEP 8 backend correction: both Masters report no `nft`, so the KillSwitch moved to iptables. Three private chains (`SPARKNET_EMERG_IN/OUT/FWD`) with explicit overlay/control-port/forward drops and jumps from the built-in hooks; no ruleset flush and no built-in policy change. Cleanup is jump-first. 14 fake-runner tests; local root dry-run prints the plan. Step 8 remains `[ ]` pending the live destructive run (`DoD: confirm: user`).
- [2026-10-25] Master Step 9 **premise re-decided, design only.** Measured the deployed fleet: `agx64` 63,198 MiB / 8 cores and `agx32` 30,990 MiB / 8 cores, both `tegrastats` and **no `nvidia-smi`**, no RDMA device (`/sys/class/infiniband` absent), `wg1` up. The original 512 GB pooled-UMA-over-ConnectX-7 premise cannot be established on 32/64 GB nodes, and tensor parallelism is already rejected for v1 (`CLUSTER_INFERENCE_DESIGN.md:382`). `plans/NOCTURNAL_BATCH_DESIGN.md` therefore replaces "pool memory" with a **time-boxed batch lease over independent whole-node jobs**: three consecutive all-idle samples (interactive SSH, WireGuard byte deltas, `nvidia-smi`/`tegrastats`) arm a window; any busy/stale/missing signal aborts or drains; only operator-supplied signed cluster jobs run; results are signed into `01_Inbox/nocturnal/` and never auto-promoted; no new port, capability or remote-shell path. Step 9's DoD was rewritten accordingly and remains `[ ]` — design adopts nothing and no code changed. `MISSION.md`, `USER_MANUAL.md`, `docs/master-control-plane.md` and the plan status reconciled. Cursor stays 8 (Step 8's live destructive leg is still `DoD: confirm: user`).
- [2026-10-25] STEP 9B implemented (9C–9G open). `shared/sparknet-idle.py` parses/collects interactive logind sessions, GPU utilisation (`nvidia-smi`, else `tegrastats` with a bounded timeout) and `wg show <if> transfer`; a missing/unreadable probe is `null` plus an error, never zero, and the module returns no idle verdict. `peer-node/services/sparknet-telemetry-push.py` loads it by path and adds `metrics.idle`; `contracts/telemetry-schema.json` documents the fields (no new kind/port/capability). Design correction from a live probe: the unprivileged pusher cannot read `wg show` on userspace WireGuard (`Permission denied`) and sysfs reports zero, so authoritative WireGuard counters must be read Master-side under a dedicated privileged reader; peers get no `CAP_NET_ADMIN`/sudo/setuid. Sampling reconciled to the existing 5-minute telemetry cadence (three clean samples ≈ 10 minutes of quiet). 10 new idle tests; telemetry, validate, `make ci CI_QUICK=1` and `make test-all` green. Step 9 remains `[ ]`; cursor stays 8; no commit.
- [2026-10-26] STEP 9C implemented (9D–9G open). `services/sparknet-wg-observer.py` is a root oneshot that reads `wg show <if> transfer` into a boot-scoped, 30-sample bounded snapshot at `/mnt/log/sparknet-wg.json`; `systemd/sparknet-wg-observer.service` + `.timer` are staged by `make wg-observer-unit`, not enabled. `services/sparknet-scheduler.py` now implements `plan`/`arm`/`status`/`abort`: signed-registry verification, revoked/expired exclusion, peer telemetry source/attribution/nonce checks, three consecutive all-idle samples, observer freshness/gap/counter checks, the 02:00–05:00 local window capped at 120 minutes and 06:00, a 10-minute plan TTL, two-step confirmation, alarming on drained evidence, and a persisted local event log. `assignments` stays `[]` and no dispatch, listener, signer or remote-shell surface exists. Arm refreshes the Master sample unless the last is <60 s old, so a prompt confirmation cannot self-fail the gap check. Malformed telemetry payloads and missing sources are busy, not dropped. 29 tests across `test_scheduler.py` / `test_wg_observer.py`; `master-node` spec/signer isolation tests and `make validate` green. Step 9 remains `[ ]` because 9D–9G and the live legs are open; cursor stays 8; no commit.
- [2026-10-26] STEP 8 deployed dry-run verified (destructive leg still unverified). Backed up the deployed scaffold, installed the current `services/sparknet-killswitch.py` + `scripts/sparknet-killswitch.sh` on the Master (`agx32` / host `blue-team`), and ran the dry-run through both the wrapper and `make -C master-node killswitch`. The plan named `wg1` and all 29 actions; the post-run baseline was unchanged (signer/anchor/firewall/ledger active, admin `200 healthy` with `unless-stopped`, `wg1` handshake live, `SPARKNET_EMERG_*` absent). No containment action was taken. The remote Makefile still does not forward `FORCE=1`; use the wrapper's explicit `--force` when the destructive leg is eventually approved. Step 8 remains `[ ]`; cursor stays 8.
- [2026-10-26] STEP 9D gated/blocking. Preconditions: Step 8 live destructive run + verified recovery (dry-run only so far), and cluster-job task ingress (adoption items 3–5 of CLUSTER_JOB_REALIZATION_DESIGN.md) with submit/status/result, acceptance checks, --execute-enabled off by default, construction/placement, reduce with signature verification and incompleteness markers — none satisfied. No dispatch code added; scheduler remains assignments=[] and has no dispatch/listener/signer path. Cursor stays 8.
- [2026-10-28] STEP 8 live containment + recovery completed (DoD: confirm: user). Captured baseline on `agx32`/`blue-team`. Ran `sudo env SPARKNET_WG_INTERFACE=wg1 /home/raxxar/sparknet/master-node/scripts/sparknet-killswitch.sh --force`: stopped disabled signer/anchor, removed admin restart policy/stopped admin, deleted `wg1`, installed `SPARKNET_EMERG_*` chains with the documented drops (no ruleset flush). Recovery: removed jumps/flush/delete chains, `systemctl enable --now sparknet-master-wireguard-anchor.service` restored `wg1` with live handshake, restored admin (`restart=unless-stopped`, healthy, HTTP 200), re-enabled signer/anchor/firewall/ledger; remote `sparknet-registry-deliver.*` absent. Overlay and admin surface verified healthy.
- [2026-10-28] STEP 9D partial: task ingress added to peer dispatch bridge loopback (`POST /v1/cluster/submit`, `GET /v1/cluster/status/<id>`, `GET /v1/cluster/result/<id>`), acceptance checks, `SPARKNET_CLUSTER_EXECUTE_ENABLED` off by default, no execution/placement/reduce; step 8 live verified. Scheduler dispatch integration still not started; 9D remains gated until items 4–5 adopted.
- [2026-10-31] Step 22 code complete: CONTEXT.md loaded into the Master terminal, scoped RFI responder over the allow-listed corpus, staged unit, tests. Master suite and bundle verify green; live signer/listener and cross-node delivery remain `DoD: confirm: user`.
- [2026-10-31] Step 22 complete and live on agx32: 8090 intake + RFI responder, registry re-signed to sequence 2 and delivered with `admin-supervise`, admin console feed/users verified, registry-delivery timer active.
- [2026-11-02] Step 24 **local implementation complete.** Added `memory-supervise`, signed memory admin actions, peer bridge forwarding to the local gateway, and a read-only Master Memory posture. No mirror is stored. `make ci`, master bundle verify and `make -C gospark ci` pass. Live status/content read remain `DoD: confirm: user`.
- [2026-11-03] Step 9 **reopened** after the audit: 9A–9D exist (9D task ingress only), 9E artifact commits, 9F optional timer and 9G live window do not; the archive's `[x]` was premature. Closed table is now Steps 1–8. Step 10 re-checked live: 4203 `disabled`/`inactive`, no third host, so the live ratification leg is blocked. Step 23's raw-KV note corrected (root 81H complete).
- [2026-11-03] Step 24 **live check — still open.** On agx32 the memory service (`4110`) and gateway (`4093`) are not listening, `.state/memory.local.token` is absent, and the running console returns 404 for `/api/memory`; live `memory_status`/content read remain `DoD: confirm: user`. Master `users`/`events`/`knowledge` over `admin-supervise` return 200 after the agx64 bridge restart. No commit.
- [2026-11-04] Step 10 **closed by operator scope decision** for the two-node `peer_pair`; 4203 stays staged, disabled and inactive for a future third node. Step 11 **live-verified**: `share.transfer` evidence captured, ledger block `c4ea7399…`, git commit and `verify_repo` ok. Step 12 **live-verified**: one finding plus signed reversible `authenticated`/`flagged` transitions. Step 24 **live-verified**: `memory_status` and `memory-read` returned live peer records. Step 9 9E/9F and the 9G code path are implemented; only the live 02:00–05:00 window remains. Registry sequence 8 carries the node key, `cluster-serve` and `memory-supervise`. No commit.
- [2026-11-04] **9G preflight.** Enabled the root `sparknet-wg-observer.timer` and repaired its shim (Makefile `$@` expansion + non-executable Python); `/mnt/log/sparknet-wg.json` is fresh. Peer telemetry push succeeded. Scheduler still reports busy operators, so the live 02:00–05:00 window remains. `make -C master-node units-check` green; full local suite green.
- [2026-11-04] **Learning snapshot share and all-user console.** `sparknet-distill-status` now writes a sanitized copy to `/srv/sparknet/share/learning/status.json` (no `state_dir`/errors); the 4221 file share serves it to the peer console over signed `p2p-sync`. Master console auth accepts authenticated `user` and `admin` for read-only pages. Live peer `/api/learning` returned `source master:4221`. No commit.

- [2026-11-05] Master PLAN Step 25 complete — admin-only WebUI v0.13.0. One `admin@sparknet.local`, signup off; old cluster2 user surface on `8181` retired after Jennifer's chat migrated to the peer; admin engine on loopback `4204` over `master-admin` (role vault never mounted). Live admin chat `webui-master-ok`; one admin in `/api/v1/users/`.
- [2026-11-10] **Issue triage writer.** Fabric 93B moved issue parsing/redaction/store/projection into `shared/sparknet-issue.py` and added the append-only `triage.jsonl` plus derived `triage.json`. Added `scripts/sparknet-issue-triage.py` and the `issue-triage` Make target. The console remains read-only and now renders the effective triage state. No live claim.
- [2026-11-10] **Step 28 live intake confirmed.** The live Master at `agx64` received the peer's signed `live-step91-issue` over `10.100.0.1:8090`, recorded it in `/mnt/log/sparknet-issues.jsonl`, rendered it in the read-only Issues tab, and closed it through the local triage CLI `done`/`wontfix`. The master bundle was rebuilt and verified. No other live surface is claimed.
- [2026-11-13] **Step 9G complete — live window.** Plans at 02:00/02:05/02:10 local produced three all-idle samples; `plan-ce065bc3f69236d4` armed as `lease-c417555d896f7134`; the signed `skill-eval` job returned `fail:1 invalid:0 total:1` with coverage `s1`; the Master aggregate and the peer signed result/manifest are under `01_Inbox/nocturnal/`; `abort` closed the lease. Model job not claimed (upstream down).
