# Nocturnal batch scheduler — independent nodes, one time-boxed lease

Status: **9A adopted, 9B implemented (2026-10-25), 9C implemented (2026-10-26), 9D blocked (2026-10-26), 9E–9G open.** This
note supersedes the literal reading of `MASTER_BUILD_PLAN.md` Step 9. It creates
no port, grants no capability and adds no scheduler daemon. 9B added the shared
idle collector and the telemetry `metrics.idle` fields. 9C adds the root
WireGuard observer and the `plan`/`arm`/`status`/`abort` lease state machine;
it still dispatches nothing and the service/timer are staged, not enabled.

## 1. The premise that does not survive contact with the fleet

The original architecture describes a **512 GB+ distributed pooled UMA** formed
over ConnectX-7 RDMA when every node is idle
(`Sparknet_Master_Architecture_Deployment_Summary.md:6,84`). That premise was
written for four DGX Spark machines with 128 GB unified memory each and a
high-speed interconnect. The fleet is not that fleet.

Measured on `agx64` and `agx32` on **2026-10-25**:

| Property | `agx64` | `agx32` |
|---|---|---|
| Memory | 63,198 MiB | 30,990 MiB |
| CPU | 8 ARMv8 cores | 8 ARMv8 cores |
| GPU tooling | `tegrastats`; **no `nvidia-smi`** | `tegrastats`; **no `nvidia-smi`** |
| RDMA | none (`/sys/class/infiniband` absent; no `ibv_devinfo`) | same |
| Overlay | `wg1` up | `wg1` up |
| Data link | `eth0` / `wlan0`; no ConnectX-7 | same |

The consequence is not a tuning problem. There is **no shared-memory fabric to
establish**. Two ARM nodes with 32/64 GB and a WireGuard overlay cannot present a
single GPU address space, and the fabric has already rejected the only design
that would: tensor parallelism / model sharding is **rejected for v1** because
it needs a different serving stack and pooled memory
(`CLUSTER_INFERENCE_DESIGN.md:382`). The honest cluster primitive is
map → reduce over independent model calls (`CLUSTER_INFERENCE_DESIGN.md:179`).

A scheduler that claimed to "pool memory" on this hardware would be a label
with no mechanism behind it. It would also be dangerous, because it would
encourage operators to schedule a model that cannot fit on any single node.

## 2. Decision — a batch lease, not a memory pool

**A nocturnal window is a time-boxed scheduling lease over independent nodes.**
It aggregates *capacity*, never memory.

- Each participant runs a **whole-node** signed cluster job. No model layer is
  split across nodes, no KV cache is shared, and no address space is remote.
- The Master schedules **which idle node runs which whole job**, not how a
  single job is partitioned across the fleet.
- "Pooled" survives only in the accounting sense: the window can use the sum of
  the nodes' independent capacity, one job per node at a time.
- Every job still needs its own signed `cluster-dispatch` / `cluster-serve`
  authorization. The lease **grants nothing**; it is a precondition saying the
  operator and the idle evidence agree that now is a safe time to dispatch.
- No new port, capability or transport: the scheduler uses the existing
  peer-intake telemetry (`8090`) and the existing cluster-job path. It does not
  open an SSH command channel.

This keeps the useful part of Step 9 — don't burn the fleet while people are
using it — and deletes the part the hardware cannot support.

## 3. The idle gate

Idle is **conjunctive and fail-closed**. Every required signal on every node
must be healthy and fresh. A missing tool, an unreadable counter, a stale
sample or an unknown state is **busy**, never idle.

### 3.1 Signals

| Signal | Probe | Busy if | Why this is the right signal |
|---|---|---|---|
| Interactive SSH | node-local session inventory (`loginctl list-sessions`, plus local `sshd` sessions), excluding the scheduler's own service account | any interactive TTY/remote session is present | A person at a keyboard is the strongest reason not to take the node. Counting inbound TCP alone would count the scheduler's own telemetry; a session inventory names the human. |
| WireGuard traffic | **Master-side** `wg show <if> transfer`, one peer row per node, read under a dedicated privileged scheduler wrapper; peer-pushed counters are advisory only | delta over the sample window exceeds the configured floor, or the counter went backwards / disappeared / cannot be read | The overlay is the only cross-node data path. On 2026-10-25 the unprivileged telemetry service on userspace WireGuard could not read `wg show` (`Permission denied`), and `/sys/class/net/wg1/statistics/*` reported zero. The peer therefore cannot be the authoritative source, and `sudo -n` from the service account is not an acceptable fix. Missing privilege is **busy**, never zero. |
| GPU activity | `nvidia-smi` where present; otherwise `tegrastats` on this fleet | utilisation above the configured floor, or the probe cannot be parsed/performed | Both AGX hosts have `tegrastats` and **no `nvidia-smi`**. A GPU check that requires `nvidia-smi` would make the scheduler permanently unable to arm on the only deployed fleet. |
| Node freshness | telemetry `issued_at`, envelope nonce, `sampled_at` | sample older than one telemetry cadence plus jitter, replayed, or from an unregistered/revoked peer | A stale sample is not evidence. The overlay source and registry supply attribution; the nonce stops replay. |

Supporting signals such as load average or disk I/O may **tighten** the gate,
but may never replace one of the required signals above.

### 3.2 Sampling rule

The scheduler requires **three consecutive all-idle samples at the telemetry
cadence**. The 70A timer currently pushes every five minutes, so a window needs
about ten minutes of quiet before it can arm; a later one-minute sampler can
tighten that without changing the gate. Any busy, missing or stale sample resets
the count to zero. It does not arm on a single quiet second, and it does not
average a burst of activity away.

The Master is a participant too. It runs the same local probes as every peer;
the scheduler cannot exempt the machine it runs on. WireGuard is the exception:
the Master reads its own view of every peer, because the unprivileged peer
service cannot read the counters and sysfs reports zero on this WireGuard
implementation.

### 3.3 What the gate does and does not prove

The peer reports its own idle state. A malicious or compromised peer can lie.
That is acceptable **only because the lease is not an authority boundary**: a
lying peer can make a bad scheduling decision for itself, but it cannot use the
window to obtain a capability its signed registry does not already grant, and it
cannot make another node execute an unsigned job. The Master can reduce its own
exposure by refusing a node whose telemetry is late, duplicated or
registry-inconsistent.

The gate is a **safety control, not an authorization control**. Stating the
difference is what keeps a future builder from putting a permission decision in
the scheduler.

## 4. Window lifecycle

```
DISARMED ──plan──> PROBING ──3 clean samples──> ARMED ──busy/expiry/abort──> DRAINING ──> CLOSED
                       │                                                      
                       └──────── busy/stale/cancel ──────────────────────────> DISARMED
```

- **DISARMED** is the default and the only state after a crash. A timer may
  *probe and notify*, but it must never arm or dispatch by itself.
- **PROBING** produces a plan: node-by-node evidence, the would-be assignment,
  and a `plan_id`. It dispatches nothing. The plan expires after ten minutes.
- **ARMED** requires an operator to confirm that specific `plan_id`; there is no
  force flag that skips the plan. Arming records:
  - `lease_id`, `started_at`, `expires_at`, `operator`, `reason`;
  - the exact node roster and the digest of the evidence that armed it;
  - the assignment list, bounded by each job's signed budget and expiry.
- **DRAINING** stops **new** dispatch immediately. In-flight jobs are allowed
  to reach their already-signed `expires_at`, or are cancelled through the task
  ingress if cancellation exists; the window never silently extends. A job
  whose expiry is later than the lease is refused at arming.
- **CLOSED** writes the artifact manifest and exits. A new window needs a new
  plan and a new operator confirmation; there is no resume-after-crash.

The lease is time-boxed by default to **02:00–05:00 local time, maximum 120
minutes**, and may not extend past 06:00. Those are proposal defaults, not
adopted settings.

### 4.1 Abort conditions

Any of these aborts arming or drains an armed window:

- any required signal becomes busy, stale, unreadable or absent;
- a node reboots, disappears, or its registry entry is revoked;
- the overlay interface or its counters disappear;
- the KillSwitch is armed or has run;
- the operator runs `abort` or sends SIGINT/SIGTERM;
- the lease reaches `expires_at`.

Abort is a **stop-new-work** operation, not a remote kill. The scheduler must
not gain a process-signalling channel to peers. A participant stops accepting
new subtasks when the signed job expiry or lease ends; its own guard remains
the only authority that can stop a running action.

## 5. What may run

- **Operator-supplied jobs only.** The scheduler does not invent work from the
  inbox, the web, telemetry, or a model's own suggestion. A nocturnal queue is
  a list of already-signed, bounded jobs; an empty queue is a valid outcome.
- **Cluster jobs only**, using the existing envelope and modes: a map → reduce
  over model calls. No shell jobs, no arbitrary remote commands, no model
  sharding, no memory donation.
- **Whole-node fit.** Placement checks the node's own memory against the job's
  declared model/profile with headroom; it never adds two nodes' memory to make
  a job "fit". A model that cannot fit on `agx32` is not scheduled there.
- **One job per node at a time.** No preemption and no oversubscription.
- **Deterministic placement.** Roster order is node id, ascending; assignment
  is a pure function of the queue and the roster. Thermal/load-based reordering
  would make the window unreproducible and is not in v1.
- **Bounded by both clocks.** Every job's `expires_at` is at or before the lease
  `expires_at`; an already-expired or unbounded job is refused.

## 6. Artifacts and vault commits

Artifacts are evidence, not editorial content. They land in an intake
directory and stop there.

- Each participant writes its signed result and a manifest under its own vault:
  `01_Inbox/nocturnal/<lease_id>/<job_id>/`.
- The manifest records: lease and job ids, participant, subtask ids, the
  signed-result hashes, model / version, corpus digest where applicable, start
  and end, and an explicit **coverage** field naming subtasks that never
  answered.
- The node commits only that directory, in its own vault, with a local commit
  message naming the lease. It does not push, rewrite history, or touch a
  protected path.
- Nothing is promoted to a distilled category automatically. The existing
  inbox/reviewer path is the only way an artifact becomes knowledge, so a bad
  batch output cannot become a page merely because the scheduler wrote it.
- No secrets, keys, `.env` contents, or unredacted personal pages are eligible
  inputs or outputs. The existing allow-list and guard rules still apply.

The Master's aggregated result follows the same pattern under its own
`01_Inbox/nocturnal/...`; the per-node results remain independently verifiable.

## 7. Security invariants

1. **No new authority.** The scheduler cannot sign, grant, revoke, escalate,
   approve a guard action, or execute a shell command.
2. **No new network edge.** It reads peer-pushed telemetry on `8090` and
   dispatches through the existing job path. It opens no listener and no SSH
   control channel.
3. **No silent idleness.** Missing or stale evidence is busy.
4. **No memory fiction.** Capacity is per node; a job fits one node or it does
   not run.
5. **No autonomous queue.** A human supplies the work; the scheduler supplies
   only the time window and the placement.
6. **No peer privilege widening.** WireGuard counters are read Master-side under
   a dedicated privileged reader; the unprivileged telemetry pusher never gets
   `CAP_NET_ADMIN`, a sudo rule, or a setuid helper just to observe idleness.
6. **No automatic ingestion.** Artifacts stay in the intake directory until a
   human reviews them.
7. **No lease reuse.** A restart, abort or expiry ends the lease; a new window
   is a new operator decision.
8. **No extension by in-flight work.** Signed job expiry caps every lease.

## 8. Adoption increments

Each increment is its own commit, with `make contract-test` green between them.
The design note itself adopts nothing.

1. **9A — this design.** Re-decide the premise; replace the Step 9 DoD with the
   batch-lease wording below. No code.
2. **9B — idle evidence.** Add the node-local collector fields to the existing
   telemetry `metrics` payload and tests for the three required signals,
   including the `tegrastats` path and every fail-closed case. This is the first
   contract-affecting increment and therefore touches both roles.
   **Implemented 2026-10-25**: `shared/sparknet-idle.py` measures interactive
   sessions, GPU utilisation and (where permitted) WireGuard counters; the
   pusher sends them under `metrics.idle`, and a missing probe is `null` plus an
   error. Authoritative WireGuard collection and the scheduler's privileged
   reader remain 9C work.
3. **9C — lease state machine.** Implement `plan`, `arm`, `status`, `abort`
   and injected-busy tests. Still dispatches nothing; default is dry-run.
   **Implemented 2026-10-26**: `services/sparknet-wg-observer.py` is a root
   oneshot (60 s timer, staged) that reads `wg show <if> transfer` and writes a
   bounded 30-sample, boot-scoped snapshot to `/mnt/log/sparknet-wg.json`.
   `services/sparknet-scheduler.py` verifies the signed registry, reads peer
   session/GPU evidence from telemetry, uses the observer for authoritative
   WireGuard deltas, requires three consecutive all-idle samples, and implements
   the 02:00–05:00 / 120-minute lease window. `plan` is dry-run; `arm` requires
   the exact `plan_id` plus `--confirm` and an operator/reason; `abort` stops new
   work without any peer signal. Assignments remain `[]` until 9D. The service
   and timer are staged by `make wg-observer-unit`, not enabled.
4. **9D — dispatch integration.** Connect the queue to the signed cluster-job
   path **after** task ingress (adoption items 3–5 of
   `CLUSTER_JOB_REALIZATION_DESIGN.md`). Task ingress (Seam E) exists on the peer
   dispatch bridge loopback as of 2026-10-28 (`/v1/cluster/submit|status|result`,
   acceptance checks, execute disabled by default) but construction/placement/reduce
   remain unadopted; no scheduler dispatch integration.
5. **9E — artifact commits.** Signed manifest, vault intake path, local commit,
   review-only handoff, and the refusal to promote automatically.
6. **9F — optional timer.** A timer may probe and notify; it may not arm.
7. **9G — live deploy.** A two-node window on `agx64`/`agx32` with an operator
   present. This remains `DoD: confirm: user` after Step 8's live leg.

## 9. Replacement DoD for Step 9

> (1) Idle detection on every node covers interactive SSH sessions, WireGuard
> byte deltas and GPU activity (`nvidia-smi` where available, `tegrastats` on
> the deployed AGX fleet), and treats a missing, stale or unreadable signal as
> busy. (2) Three consecutive all-idle samples are required; the scheduler then
> creates a time-boxed **batch lease**, never a pooled-memory fabric, and any
> non-idle/stale signal aborts arming or drains an armed window. (3) Only
> operator-supplied, signed, whole-node cluster jobs bounded by budget and
> expiry may run; no new port, capability or remote-shell path is introduced.
> (4) Results are signed, committed under each vault's
> `01_Inbox/nocturnal/<lease_id>/<job_id>/`, record incomplete coverage, and are
> never auto-promoted. (5) The default is dry-run; arming requires a two-step
> operator confirmation, and live deployment is `DoD: confirm: user`.

## 10. Options considered and rejected

| Option | Verdict | Reason |
|---|---|---|
| Literal 512 GB UMA pool over RDMA | **rejected** | The fleet has 32/64 GB per node, no RDMA device, and no ConnectX-7. The premise is hardware from a different deployment. |
| Tensor-parallel / model sharding | **rejected** | Already rejected for v1 (`CLUSTER_INFERENCE_DESIGN.md:382`); would need a different serving stack and a fast interconnect the nodes do not have. |
| Kubernetes / KAI scheduler | **rejected** | Two nodes, no container orchestrator, no dedicated scheduler. The operational surface would dwarf the workload. |
| SSH-driven idle probes and job execution | **rejected** | Creates a remote-shell authority path and makes the scheduler a de facto execution controller. The existing telemetry and signed-job paths are the correct boundaries. |
| Time-only night schedule | **rejected** | A clock is not evidence. A node with an active session at 02:30 must not be taken. |
| A single quiet sample as the trigger | **rejected** | One sample averages nothing and catches a gap between two busy periods. |
| Allow a subset of nodes when one is busy | **rejected for v1** | The Step 9 premise is "all nodes idle"; partial windows make the abort semantics ambiguous and are a later, separately argued policy. |
| Auto-ingest batch output as wiki pages | **rejected** | Scheduler output is untrusted text. It must pass the same review path as any other inbox arrival. |
| A force flag that skips the plan | **rejected** | The highest-risk autonomous step gets a two-step confirmation, not a shortcut. |

## 11. Provenance and open choices

Grounded in:

- Measured fleet facts, 2026-10-25: `agx64` 63,198 MiB / 8 cores / `tegrastats`
  / no `nvidia-smi` / no RDMA; `agx32` 30,990 MiB / 8 cores / same.
- `Sparknet_Master_Architecture_Deployment_Summary.md:6,84` (the obsolete
  512 GB premise).
- `CLUSTER_INFERENCE_DESIGN.md:179,382` (map→reduce, tensor parallelism
  rejected).
- `CLUSTER_JOB_REALIZATION_DESIGN.md` (signed envelopes, placement, task
  ingress, reduce, adoption order).
- `contracts/telemetry-schema.json` and `MASTER_OBSERVABILITY_DESIGN.md` (the
  existing `8090` peer-intake path and its no-authority rule).
- `contracts/ports.json` (`8090` peer-intake, `4223` vector, no new port here).
- `contracts/overlay.json` (the single-Master peer egress; no peer-to-peer
  dispatch added by this design).
- `master-node/plans/MASTER_BUILD_PLAN.md` Step 8 (KillSwitch precedence) and
  Step 9 (the reopened premise).

Open choices for the operator, not silently decided here:

1. Keep the **02:00–05:00 / 120-minute** default, or choose another window.
2. The WireGuard byte floor (proposal: 1 MiB per 60 s sample; only ever
   tightened, never used as the sole signal).
3. Whether the Master may be a job participant as well as the dispatcher.
4. Artifact retention under `01_Inbox/nocturnal/` and whether a later step adds
   a lease block to the ledger.
5. Whether any future hardware with RDMA reopens true memory pooling. This
   design does not; it would be a new design against measured hardware.
