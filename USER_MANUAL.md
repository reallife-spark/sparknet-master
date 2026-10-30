---
title: sparknet-master — user manual
updated: 2026-10-30
---

# sparknet-master — user manual

> The manual for the **master** role: the elected node that holds the
> operational key, signs the cluster's registry and approvals, and is the one
> place in the fabric where authority comes from.
>
> This repository is the `master-node/` subtree of the fabric, published
> standalone. It deliberately does **not** contain `contracts/` or `shared/`;
> see [§2](#2-what-is-and-is-not-here).
>
> The **master manual** for the whole system lives in the `sparknet`
> repository as `USER_MANUAL.md`.

---

## Table of contents

1. [What a master is](#1-what-a-master-is)
2. [What is and is not here](#2-what-is-and-is-not-here)
3. [Orientation](#3-orientation)
4. [The election arc](#4-the-election-arc)
5. [The three keys](#5-the-three-keys)
6. [The isolated signer](#6-the-isolated-signer)
7. [The services](#7-the-services)
8. [The scripts and units](#8-the-scripts-and-units)
9. [The manifests and the ledger](#9-the-manifests-and-the-ledger)
10. [The admin surface](#10-the-admin-surface)
11. [The vault](#11-the-vault)
12. [Build, run, test](#12-build-run-test)
13. [The gate](#13-the-gate)
14. [How to make a change correctly](#14-how-to-make-a-change-correctly)
15. [Configuration reference](#15-configuration-reference)
16. [Troubleshooting](#16-troubleshooting)
17. [Spec vs implemented](#17-spec-vs-implemented)
18. [Glossary](#18-glossary)

---

## 1. What a master is

A master is **a peer that won an election**. The cluster is a pair or a trio;
every member holds the same capabilities and runs the same services; one
additionally holds the operational key and signs. That is the entire
difference.

| Concern | Peer | Master |
|---|---|---|
| Signing key custody | never | **exclusive** — never leaves the machine |
| Registry authorship | never | **authoritative** |
| Overlay address | one address in the overlay range | `10.100.0.1` |
| Network egress | restricted to the Master only | **unrestricted** (the peer rule would blackhole the fabric) |
| Own vault, local inference | authoritative | authoritative |
| Revoke any node | never | yes, instantly, from its own side |
| Sign new authorisations | **never** | yes |

The egress asymmetry is the cleanest statement of the difference: a peer may
reach **only** the Master; the Master reaches everyone. The peer's firewall
rule is correct on a peer and actively harmful on a Master, which is why the
Master's firewall is a different rule entirely.

The security property that governs everything else:

> **Authority comes from key possession, not from a capability grant.**

A peer that somehow obtained the entire capability vocabulary would still be
unable to grant, revoke or escalate, because the signature it would need to
produce requires a private key it does not have. Capabilities say *what* a
node may do; the key says *whether anyone believes it.

**Who this manual is for:** a developer changing the master role — the
signer, the ledger, the election, the admin surface, the manifests — who needs
to know which contract the change must not violate and which gate will catch
it.

---

## 2. What is and is not here

The master role lives in two places, and the split matters:

- The **fabric** repository holds the contract (`contracts/`) and the one
  shared implementation (`shared/`). Both are loaded **by path** — never
  copied, because two copies of a signature-verifying service drift silently
  and then stop validating each other.
- This repository holds **only the master role**: its services, scripts,
  units, manifests, plans, tests and its own vault — plus the **parity
  loader**, which runs the *peer's* service files by path.

That last point is worth stating plainly, because it looks like a missing
dependency and is not: this role **runs the peer's node services**, not copies
of them. `make parity` proves it, and `tests/test_master_parity.py` fails the
build if a copy ever appears.

| You need | You get it from |
|---|---|
| The capability vocabulary, overlay, ports, identity schema, protocols | the fabric's `contracts/` |
| The signed canonical form, election, consensus, provenance code | the fabric's `shared/` |
| The peer's node services (run by path) | the fabric's `peer-node/` |
| The master's own services, scripts, units, manifests, plans, vault | **this repository** |
| A deployable master | a bundle, or the fabric's setup script |

**Cross-repository references in this manual are written as prose, not links.**
A relative link to `../contracts/capabilities.json` resolves in the fabric
checkout and is broken here, because this published repository does not contain
`contracts/`. Every link in this manual resolves inside this repository.

---

## 3. Orientation

Read [AGENTS.md](AGENTS.md) first: it is the role's charter and states the
layout, the memory and plan protocols, and the boundaries. This manual
explains the code.

| Path | What it is |
|---|---|
| `services/` | The twelve master services. Each is a single-file program with a `--help`. |
| `scripts/` | The 16 operational scripts: keys, approvals, registry publication and delivery, RFI answers, overlay, the KillSwitch. |
| `systemd/` | Nine units. |
| `manifests/` | The master's declared identity, trust root, registry schema and admin-surface intent. |
| `plans/` | The build plan, the admin plan, the pair-reformation design, the viability report, the EU AI Act compliance note. |
| `docs/` | The control-plane overview, the registry protocol, the role transition, the KillSwitch template, the unverifiable-claims register. |
| `00_System/` … `07_Archives/` | The vault, in the numbered PARA layout. |
| `concepts/`, `entities/`, `skills/`, `synthesis/`, `projects/`, `journal/`, `references/` | Legacy spellings — **symlinks** into the numbered layout. |
| `tests/` | The master's pytest suite. |
| `Makefile` | The role's entire command surface. |
| `MASTERSPIKE-manifest.json` | The MASTERSPIKE artefact manifest, shared with the peer role. |
| `blockchain/`, `security/`, `deployment/` | Legacy symlinks into `00_System/`. |

### 3.1 The numbered layout and the shims

The vault uses a numbered PARA layout, and **every legacy name stays a symlink
to its numbered home** — `concepts/` → `05_Knowledge/concepts/`,
`journal/` → `02_Daily/`, `blockchain/` → `00_System/blockchain/`, and so on.
Both spellings name **one file**, so a link written before the reorganisation
keeps resolving after it. `make shims-check` proves it; `tests/test_shims.py`
enforces it.

---

## 4. The election arc

The Master is not configured; it is **elected**. The arc:

```
   1. candidates        each member runs its part of the election
        │
   2. votes              each member casts ONE signed vote
        │                (deduplicated by member identity: three votes
        │                 for yourself is still one vote)
        3. trust root    a UNANIMOUS vote forms the cluster trust root
        │                naming the winner as Master
        4. keys          the winner forms three keys; the operational key
        │                is the one the fabric's authority derives from
        5. signer        the signer is enabled and signs a live registry
        6. registry      entries are signed per entry and distributed
        7. peers         peers verify, apply what they are permitted to
        │                apply, and refuse the rest
        8. survives      the trust root and the key survive a real reboot
```

Three properties of the arc are worth internalising:

- **A vote confers nothing.** `cluster-vote` is a say, not a grant.
- **The trust root is unanimous.** A trust root that is not unanimous is not
  formed; the cluster stays unelected rather than split.
- **Re-formation is a deliberate act.** The signer refuses to start against a
  trust root other than the one its ledger already records, unless it is given
  `--accept-requalification` explicitly. Rolling the Master back is a
  decision someone makes, not something a reboot can cause.

```sh
make election-approve EXPECT=<node> URL=... IDENTITY=... ROOT_DOC=... KEY_DIR=...
```

`EXPECT` names the node the vote must land on, so an election cannot
accidentally succeed for someone else.

---

## 5. The three keys

A master node forms **three** distinct Ed25519 keys, and the split *is* the
security model rather than a detail:

| Key | Purpose | Who holds it |
|---|---|---|
| **Cluster key** | participates in the election and the cluster trust root | the cluster members |
| **Operational key** | signs the registry and the approvals — the key the fabric's authority derives from | **the signer, alone** |
| **Identity key** | the node's own identity and fingerprint | the node |

```sh
make keygen     # generate the WireGuard + Ed25519 keypairs into the state dir
make keys       # alias for keygen
make signer     # print the signer's isolation posture: no key, no root, no socket
```

The operational key lives in the state directory at mode `0600`, and the state
directory resolves **outside** the vault — not merely gitignored, because the
admin surface bind-mounts the vault read-only into an LLM container, so a
gitignore would not have helped. `make keys-check` enforces both halves.

The key is held by **one** process: the isolated signer. Everything else in
this role is multi-user, LLM-driven, and reads configuration as input. If that
surface could reach the key, a prompt injection would grant itself the one
capability the peer roles withhold.

---

## 6. The isolated signer

`services/sparknet-signer.py` — *"It signs, and it does nothing else."*

```
usage: sparknet-signer.py [-h] [--node-id NODE_ID] [--root ROOT] [--key KEY]
                          [--socket SOCKET] [--ledger LEDGER]
                          [--accept-requalification] [--describe]
```

| Flag | Meaning |
|---|---|
| `--node-id` | This node's id; the trust root must name it Master. |
| `--root` | The cluster trust root the signer binds to. |
| `--key` | The operational key. |
| `--socket` | The unix socket to serve on. |
| `--ledger` | The ledger to append outcomes to. |
| `--accept-requalification` | Allow starting against a root other than the one this node's ledger records. Required for re-formation, refused by default. |
| `--describe` | Print the isolation posture and exit, without binding a socket. |

The isolation properties, each with a test behind it in
`tests/test_signer_isolation.py`:

- the socket is a **unix socket at mode 0600** inside the state directory's
  `signer/` directory;
- the signer holds **no root** and **no vault path**;
- the signer **re-derives the canonical bytes itself** and refuses anything
  else — a request is a *typed* registry entry or a guard approval naming one
  peer, one protected path and one piece of content, and the signer binds it to
  the trust root it was started with;
- every outcome is appended to the **ledger**;
- the signer is **not reachable from the admin surface**.

`make signer` prints the posture; `make signer-unit` stages the unit **without
enabling it** — enabling a key-holding process belongs to the election, not
to an install.

---

## 7. The services

Eight services.

### `sparknet-signer.py` — the isolated signer

See [§6](#6-the-isolated-signer). The only thing in the fabric that holds the
operational key.

### `sparknet-parity.py` — the parity loader

Loads the **peer's** service files by path. This is the mechanism that keeps
the two roles from drifting: there is one implementation of the guard, the
anchor, the bridge, and the rest, and the Master runs it rather than shipping
a copy.

```sh
make parity      # prove this role runs the peer's own service files
```

### `sparknet-ledger.py` — the hash-chained ledger

The Master's record of what it did and when. Every block carries the hash of
its predecessor, so a modified or removed block breaks the chain at the point
of the change rather than silently.

```sh
make ledger      # verify the chain
```

### `sparknet-admin-console.py` — the admin console

*Compose, sign, dispatch, and watch.* It can compose a request, hand it to
the signer, dispatch a cluster job and watch the result.

```sh
make console ARGS='users <node>'
make console ARGS='feed --ping'
```

### Distributing a registry

The Master **pushes** a signed registry publication to each peer's guard on 9090
(`POST /api/v1/registry`). Two commands:

```sh
make registry-publish REGISTRY=manifests/node-authorizations.json OUT=.state/registry
make registry-deliver PUBLICATION=.state/registry/current.json
```

`registry-publish` validates the document, refuses one naming another Master's
key, signs through the isolated signer (or `--offline`), and writes
`current.json` with a sequence that only increases. `registry-deliver` reads
each peer's address from the publication itself and pushes it; revoked entries
are delivered to as well, because the node being revoked has to learn about it.
A peer that refuses or is offline is recorded, and the command exits non-zero —
the installed `sparknet-registry-deliver.timer` retries every 60 s. Re-pushing a
publication a peer already installed is a success (the peer answers
`REGISTRY_ALREADY_INSTALLED`), so the steady state is a green unit; the anchor
address itself is skipped because it is this Master, not a peer.

### `sparknet-peer-intake.py` — the peer-intake listener

The Master's **peer-intake listener** on `8090`
(fabric Step 69C, re-scoped from the retired instant-push stub, which is deleted;
renamed at Step 70B when it gained a second route). It binds `10.100.0.1` only and
carries two routes. `POST /api/v1/telemetry` attributes the WireGuard-authenticated
source via the signed registry (refusing an unregistered, revoked or
`telemetry`-ungranted peer before reading the body), verifies the report with
`shared/sparknet-authz.py::verify_telemetry_report`, and records it as evidence.
`POST /api/v1/rfi-request` shares the registry gate but needs **no capability**
(asking is not reporting), verifies with `verify_rfi_request` (overlay fingerprint,
freshness, nonce — no signature), and queues one content-addressed artifact under
`/mnt/log/sparknet-rfi-requests` for the composer; it never answers. Both routes
carry no authority. `systemd/sparknet-peer-intake.service` is staged by
`make peer-intake-unit`, not enabled. `tests/test_peer_intake.py` binds a real socket
and covers each refusal. See `../../MASTER_OBSERVABILITY_DESIGN.md` and
`../../RFI_REQUEST_DESIGN.md`.

### `sparknet-killswitch.py` — the KillSwitch

The cluster-wide containment control. It is **root-gated in both modes** and
**dry-run by default**. `make killswitch` prints the plan; `make killswitch
FORCE=1` disables the five control units and the overlay anchor, stops the admin
container (after removing its restart policy), deletes the overlay interface, and
installs the `SPARKNET_EMERG_IN/OUT/FWD` iptables chains. It does not flush the
host ruleset or SSH to peers. It is not the peer's own containment script, which only
tears down *that* node; the peer has no copy or target for this one.

The implementation and its 14 fake-runner tests are complete. The destructive
run on a real Master is **not yet verified** (`DoD: confirm: user`). Recovery is
manual: remove the three iptables jumps/chains, re-enable the units you want, then bring the overlay
anchor back up. See `docs/killswitch-template.md`.

```sh
make killswitch              # dry-run
make killswitch FORCE=1      # destructive; root
```

### `sparknet-scheduler.py` — the nocturnal batch scheduler

The 9C state machine is built and tested, but it dispatches nothing. The fleet
has no RDMA and no shared GPU address space, so a window is a time-boxed **batch
lease** over independent, idle nodes, not pooled memory. `plan`, `arm`, `status`
and `abort` are implemented; `arm` requires the exact plan id, `--confirm` and an
operator reason, and assignments stay `[]` until 9D.

The authoritative WireGuard counters come from the root observer
(`sparknet-wg-observer.py`), which writes a bounded snapshot to
`/mnt/log/sparknet-wg.json`. Its service and 60-second timer are staged by
`make wg-observer-unit`, **not enabled**. The unprivileged peer telemetry service
still supplies session and GPU evidence; a missing probe is `null` plus an
error, never zero. Local idle samples accumulate across `plan` runs, so a real
window needs three probes at least five minutes apart. See
`plans/NOCTURNAL_BATCH_DESIGN.md`.

### `sparknet-share-ratify.py` — the share ratification service

The Master's side of a peer↔peer share: it accepts a share request only when
the peer's grant verifies against the signed registry, then issues a
Master-signed, time-boxed ratification. The two-hour clock is the Master's;
the request does not choose it.

```sh
python3 services/sparknet-share-ratify.py --request <request.json> --decision approve
```

### `sparknet-reflex-broker.py` — the reflex broker

The Master's **local-first sensor** on `4224` (overlay-only). It may rank,
annotate, route or flag; it **never** signs, grants, revokes, approves a guard
application or widens a permission. On timeout, low confidence, budget
exhaustion or any doubt it **abstains** and the caller falls back to the
deterministic path. The contract is `contracts/reflex-schema.json`; the unit is
staged by `make reflex-broker-unit` and is not enabled by an install.

### `sparknet-evidence-capture.py` — evidence capture

Validates one share-evidence event, writes it under the review repository's
`events/` directory, and records its digest in the ledger. It is the write side
of the accountability chain: an event that does not validate is refused rather
than stored.

```sh
make -C master-node evidence-capture
```

### `sparknet-review-agents.py` — the review agents

Applies a **review/trust-level transition** (authenticated / unauthenticated /
flagged) as a signed event, with the reason recorded. The previous level is part
of the input, so a transition cannot be replayed against a different starting
point.

```sh
make -C master-node review-agents
```

### `sparknet-wg-observer.py` — the WireGuard observer

The root observer that supplies the **authoritative** WireGuard counters to the
scheduler, written as a bounded snapshot to `/mnt/log/sparknet-wg.json`. It is
staged by `make wg-observer-unit`, **not enabled**: reading `wg show` as root is
an operator decision. A missing probe is `null` plus an error, never zero.

---

## 8. The scripts and units

### 8.1 The scripts

14 scripts, all `bash` with `set -euo pipefail`, all answering `--help` **and
changing nothing when they do**.

| Script | Purpose |
|---|---|
| `sparknet-master-env.sh` | The role's environment contract: the paths this role resolves — vault, peer node, state dir. |
| `sparknet-master-keygen.sh` | Generate the cluster, operational and identity keys into the state dir. |
| `sparknet-master-wireguard-anchor.sh` | The Master's overlay anchor. |
| `sparknet-wg-render-master.sh` | Render the Master's `wg0` from the registry. |
| `sparknet-registry-sign.sh` | Sign a registry entry. |
| `sparknet-registry-sign-socket.sh` | Sign a registry entry **through the signer socket**, recording a ledger block. |
| `sparknet-registry-verify.sh` | Verify a registry. |
| `sparknet-rfi-answer.sh` | Answer a queued RFI request: sign the answer, bind its digest, and address it to the requesting peer. |
| `sparknet-registry-publish.sh` | Sign+emit a registry **publication** (`<out>/current.json`). |
| `sparknet-registry-deliver.sh` | Push a signed publication to the peers' guards on 9090. |
| `sparknet-registry-revoke.sh` | Sign a **revoked** entry for an identity. |
| `sparknet-approval-issue.sh` | Issue a signed approval for a target and content. |
| `sparknet-approval-sign-socket.sh` | Sign an approval **through the signer socket**, recording a ledger block. |
| `sparknet-approval-deliver.sh` | Deliver an approval to a peer. |
| `sparknet-election-approve.sh` | Install the formed trust root. |
| `sparknet-killswitch.sh` | The Master KillSwitch wrapper; help-before-root, dry-run default, `FORCE=1` executes. |

The distinction between `sparknet-registry-sign.sh` and
`sparknet-registry-sign-socket.sh` is the one that matters operationally: the
first signs directly, the second goes **through the signer socket** and
records a ledger block. In production the second is the one to use — it is
the path that leaves an audit trail and the path that keeps the key in one
process. The same pair exists for approvals
(`sparknet-approval-issue.sh` / `sparknet-approval-sign-socket.sh`).

### 8.1.1 Issuing a guard approval

`guard-apply` is the one authority a peer cannot grant itself: only the
Master's key can mint an approval that the peer's guard will apply. The
envelope is fixed — one peer, one protected path, one piece of content, one
nonce — and the canonical bytes are produced by one implementation,
`../shared/sparknet-authz.py::guard_approval_message`, which the signer and
the peer both call. The narrative contract is
`../contracts/guard-protocol.md`; the machine-readable one is
`../contracts/guard-approval.json`.

```
make approval-issue TARGET=/etc/wireguard/wg1.conf CONTENT=/tmp/wg1.conf \
     PEER_FINGERPRINT=<sha256 of the peer's canonical identity>
make approval-sign-socket APPROVAL=<artifact>        # production: signs through the signer
make approval-deliver FINGERPRINT=<fp> APPROVAL=<artifact>   # POSTs to the peer
```

Three properties worth knowing before using them:

- **The envelope names the peer.** `peer_fingerprint` is the hash of the
  peer's canonical identity. A peer refuses an approval addressed to anybody
  else, so an approval minted for one node cannot be applied by another.
- **The envelope carries no capabilities.** The peer reads `guard-apply` from
  its own signed registry entry. An approval that carried its own capability
  would be able to grant the authority it is checked against.
- **The nonce is spent.** The Master refuses to issue the same nonce twice
  (`$SPARKNET_STATE_DIR/approval_nonces.json`), and the peer refuses a
  replayed `nonce`/`request_id` pair. The approval's window is bounded by the
  peer's replay policy — 60 seconds by default, so issue and deliver in one
  breath.

`approval-deliver` resolves the peer's address from the signed registry (the
fingerprint names the peer; the registry entry names its overlay address) and
POSTs to `http://10.100.0.x:9090/api/v1/critical-file/patch`. `--url`
overrides that for a one-off. The record it writes says whether the peer
accepted, and quotes the peer's own answer.

### 8.2 The units

Nine services and two timers in `systemd/`:

| Unit | Purpose |
|---|---|
| `sparknet-master-signer.service` | The isolated signer. |
| `sparknet-master-ledger.service` | The ledger. |
| `sparknet-master-parity.service` | The parity loader — the peer's services, run by path. |
| `sparknet-master-wireguard-anchor.service` | The overlay anchor. |
| `sparknet-master-firewall.service` | The Master's egress rule. |
| `sparknet-peer-intake.service` | The 8090 peer-intake listener (telemetry + RFI requests). Staged, not enabled. |
| `sparknet-registry-deliver.service` + `.timer` | Registry delivery to the peers, retried every 60 s. |
| `sparknet-reflex-broker.service` | The reflex broker on `4224`. Staged, not enabled. |
| `sparknet-wg-observer.service` + `.timer` | The root WireGuard observer for the scheduler. Staged, not enabled. |

`make units-check` asserts every unit in `systemd/` is enabled by the
Makefile — **nothing inert**. A unit that no target enables is a file that
looks like functionality and is not.

`make units` installs and enables them, and needs root. `UNIT_DIR` stages
only, without touching the system.

---

## 9. The manifests and the ledger

| File | Declares |
|---|---|
| `manifests/master-identity.json` | This node's identity and fingerprint. |
| `manifests/cluster-trust-root.json` | The formed trust root: the cluster's unanimous decision, naming the Master. |
| `manifests/node-identity.json` | The node identity template. |
| `manifests/registry.schema.json` | The registry document's schema. |
| `manifests/admin-surface.json` | **The admin surface's intent** — what it may reach and, the part that matters, what it may not. |

`manifests/admin-surface.json` is not a configuration file. It is a *statement
of intent that a test then checks*, so that the boundary is verified rather
than promised. It records:

- the capabilities the admin surface **is** granted: `telemetry`,
  `vault-read`, `vault-write`, `dispatch-bridge`, `guard-inspect`,
  `registry-draft`;
- the capability it is **explicitly not** granted: `sign`;
- the reason: the admin surface is multi-user and LLM-driven, so a prompt
  injection there is a normal Tuesday — and a signer reachable from there
  would invert the fabric's central thesis;
- the **signing boundary**: which process holds the key, which unit runs it,
  the transport (unix socket, mode 0600, inside the state directory's
  `signer/` directory), and that the admin surface does not reach it;
- the **role-scoped agents**: admin-geared agent definitions live in this
  role's own agent directory, so they are offered to a session started here
  and invisible to one started in a peer role.

`tests/test_admin_surface.py` fails the build if anything in that file grows a
signing capability. The file is the thing that keeps the intent and the
enforcement in agreement.

### 9.1 The ledger

The ledger is hash-chained: each block carries the hash of its predecessor.

```sh
make ledger                       # verify the chain
make provenance-verify            # verify the notes, the ledger and the approvals
STRICT=1 make provenance-verify
```

An approval is **dual-signed**: the note's own signature plus the approving
authority's. A note without a valid chain is evidence that something was
written, not that it was approved.

---

## 10. The admin surface

The admin surface is the Master's administrative plane. It is the part of the
system that is *supposed* to be usable by a human and by an LLM at the same
time, and it is therefore the part that needs the most care.

| Property | Value |
|---|---|
| Bind address | `10.100.0.1:8088` — the overlay address, not `0.0.0.0` |
| Transport | A unix socket for the signer, at mode 0600, inside the state directory |
| Holds a key | **never** |
| Holds root | never |
| Can sign | **never** — the capability is explicitly withheld, and a test enforces that |

The design is not "deny the dangerous call"; it is "the dangerous call is not
reachable from here". A deny rule governs a process that may later ignore it.
The signer is the thing that enforces the boundary, and
`manifests/admin-surface.json` is the thing that keeps the two in agreement.

An admin agent composes a **request** — a typed registry entry, or a guard
approval naming one peer, one path, one action — and hands it to an operator
or to the signer's own unit. The signer re-derives the canonical bytes,
binds them to its trust root, refuses anything else, and appends the outcome
to the ledger. The admin surface never holds a key, so the worst it can do is
**ask**; what happens to the ask is decided somewhere it cannot see.

The federation procedure — addressing, the route-class binding change, the
`admin-supervise` grant, the node agent, the console, and the rollback — is in
the fabric's `contracts/admin-federation-runbook.md`.

---

## 11. The vault

The master is also a **knowledge vault**, with its own `.env`, its own
category skeleton and its own `AGENTS.md`.

| Path | Holds |
|---|---|
| `00_System/` | `user.md`, `alpha-agent.md`, `schema.yaml`, `secrets-index.json`, `index.md`, `log.md` |
| `01_Inbox/` | unprocessed intake awaiting dispatch and signature |
| `02_Daily/` | journal entries and session memory (`YYYY-MM-DD.md`) |
| `03_Sources/` | external material and raw captures |
| `04_Evergreen/` | stable evergreen material |
| `05_Knowledge/` | `concepts/`, `entities/`, `skills/`, `synthesis/` |
| `06_Projects/` | per-project knowledge |
| `07_Archives/` | superseded material and vault snapshots |

**The skills resolve the vault from the nearest `.env`.** A session started
here resolves to *this* vault, not to the parent. Run `make wiki-preflight`
before using a skill; if it fails, run `make env-init` once. Never work around
the failure — a silent fallback resolves a *different* vault, and every page
lands there with no error at all.

```sh
make user-init          # generate the user key + fill 00_System/user.md (once)
make ingest             # land STDIN (or SRC=) as an unsigned note in 01_Inbox/
make provenance-append QUESTION=... DECISION=... AGENT=... MODEL=...
make wiki-preflight | wiki-status | wiki-lint | wiki-query
```

---

## 12. Build, run, test

### 12.1 Setup

```sh
make env-init        # write this vault's .env + the wiki dirs (idempotent)
make env-show        # print the paths this role resolves
make keygen          # generate the cluster/operational/identity keys
make user-init       # generate the user key + fill 00_System/user.md
```

### 12.2 The suite

```sh
make test            # the role's pytest suite (runs spec-check first)
make test-all        # alias for spec-check
make spec-check      # assert the spec/impl boundary has not rotted
make validate        # charter, plan, executables wired, and parity with the peer
make status          # where the build plan stands
make plan            # print the active plan step with its DoD
```

`make test` depends on `spec-check`, so the spec/impl boundary is asserted
before any test runs. A surface that has moved from "specified" to
"implemented" without the plan and the docs moving with it fails the build.

The suite:

| Test | Covers |
|---|---|
| `test_signer_isolation.py` | The signer's isolation: no key, no root, no socket, no admin-surface reachability. |
| `test_admin_surface.py` | The admin surface's capability list — fails if a signing capability appears. |
| `test_master_parity.py` | The role runs the peer's own service files, not copies. |
| `test_master_spec.py` | The spec/impl boundary. |
| `test_ledger.py` (via `make ledger`) | The hash-chained ledger. |
| `test_approval.py` | Signed approvals: issue, deliver, verify, refuse. |
| `test_registry_cli.py`, `test_registry_cli_step3.py` | The registry CLI: sign, verify, revoke. |
| `test_registry_dist.py` | Registry distribution end to end: publish → push → the peer's own guard installs, refuses a tampered artifact and a rollback, treats the timer's re-push as a no-op, and skips the master anchor. |
| `test_admin_console.py` | The admin console. |
| `test_killswitch.py` | The KillSwitch: both modes root-gated, dry-run by default, order, absent-vs-failure, the no-flush policy, and no peer copy. |
| `test_peer_intake.py` | The 8090 peer-intake listener over a real socket: registry attribution, the `telemetry` capability gate, revocation, replay, the RFI request route (no capability, queueing, replay), and the no-authority posture. |
| `test_rfi_transport.py` | The RFI answer transport: the signed answer, its digest and the `01_Inbox/` landing. |
| `test_registry_schema.py` | The registry schema: the document shape the Master signs and the peer verifies. |
| `test_evidence_and_review.py` | Evidence capture and the review/trust-level transition. |
| `test_reflex_broker.py` | The reflex broker: a sensor, never authority; abstain on doubt. |
| `test_scheduler.py` | The nocturnal scheduler's state machine (`plan` / `arm` / `status` / `abort`). |
| `test_share_ratify.py` | Share ratification: verify the peer's grant against the registry, then sign a time-boxed ratification. |
| `test_wg_observer.py` | The root WireGuard observer and its bounded snapshot. |
| `test_wg_anchor.py`, `test_wg_render.py` | The overlay anchor and the rendering. |
| `test_step1_keypair.py` | The three-key generation. |
| `test_master_scripts.py` | The role's scripts. |

### 12.3 The plan

`plans/MASTER_BUILD_PLAN.md` is this role's source of truth, and it is a
**Plan Protocol** plan: a `current:` cursor marks the step being worked, a
step is marked complete only after its DoD is verified, and every transition
appends a line to `log.md`.

```sh
make status   # steps done of steps total
make plan     # the active step and its DoD
```

The other documents in `plans/` are the design and review material:
`MASTER_ADMIN_PLAN.md`, `PAIR_REFORMATION_DESIGN.md`,
`PHASE_VIABILITY_REPORT.md`, `implementation-checklist.md`,
`compliance-eu-ai-act.md`, `scenarios-and-boms.md`, and
`Sparknet_Master_Architecture.md`.

`docs/` holds the role's own documentation:
`master-control-plane.md`, `registry-protocol.md`, `role-transition.md`,
`killswitch-template.md`, and `unverifiable-claims.md` — the last being the
register of claims that **cannot** be verified on this hardware, kept so that
nobody re-derives them by trying.

---

## 13. The gate

```sh
make keys-check      # no key material tracked; state-dir keys are 0600
make units-check     # every unit in systemd/ is enabled by this Makefile
make parity          # the peer's services are loaded by path
make ledger          # the ledger's chain verifies
make shims-check     # every legacy name is still a symlink
make precommit       # keys-check + secret scan + provenance-verify --strict
```

The **fabric-level** gate is authoritative for a merge into the fabric, and it
runs this role's suite as part of it. When you work against the published
`sparknet-master` repository, run the same targets there — the subtree is
identical, so the gate behaves the same.

The conventions the gate does not check for you:

- **One page per file**, in its category directory. Never scatter copies.
- **A script that mutates state fails closed** and says what it refused.
- **No secret in any tracked file** — reference the secret *path* only. A
  leaked key is rotated, not rewritten silently.
- **A claim must be verifiable.** If it cannot be checked, it belongs in
  `docs/unverifiable-claims.md` rather than in prose.
- **Conventional commits**; one logical change per commit.
- **`/etc` configuration is derived from the vault**, never the reverse.

---

## 14. How to make a change correctly

### 14.1 Adding a service

1. Write it under `services/` as a single-file program with a `--help` that
   changes nothing.
2. Give it a unit under `systemd/`.
3. Enable it from the Makefile, or exclude it explicitly with a reason. A unit
   nobody enables is a file that looks like functionality and is not.
4. Extend the role's suite.
5. If it touches a capability, a port, the overlay or the identity schema, it
   is a **contract** change: land it in the fabric's `contracts/` and both
   roles **in the same commit**, then run the fabric's contract test.

### 14.2 Touching the signer

The signer is the most constrained program in the fabric. Before changing it:

- keep the isolation properties: no root, no vault path, a 0600 unix socket,
  the canonical bytes re-derived internally, the outcome in the ledger;
- keep `--accept-requalification` opt-in. If a change makes re-formation
  happen implicitly, a reboot could silently move the cluster's authority;
- extend `tests/test_signer_isolation.py` in the same commit. The isolation
  properties are tested, not asserted in prose.

### 14.3 Touching the admin surface

- never add a signing capability to `manifests/admin-surface.json`;
- never make the admin surface reach the signer socket;
- if you add an agent to this role's agent directory, remember the role
  scoping: opencode resolves the **nearest** agent directory, so a file here
  is visible to a session started here and invisible to one started in a peer
  role.

`tests/test_admin_surface.py` enforces the first two; the role scoping is
enforced by the agent suite in the fabric.

### 14.4 Changing the ledger format

The chain is the audit trail. A format change must keep every existing block
verifiable, or come with a migration that is itself recorded in the ledger.
`make ledger` and `tests/test_approval.py` are the gates.

### 14.5 Writing documentation

- One page per file. Frontmatter `title` + `updated`; provenance pages add
  `source`/`license`/`type`.
- Cite sources. A distilled page without provenance is a guess — mark it as
  one.
- Check the plan cursor and the spec/impl boundary before making a claim.

---

## 15. Configuration reference

| Thing | Where | Notes |
|---|---|---|
| Vault env | `.env`, from `.env.example` | The template exposes a fixed key set; the suite asserts it. |
| Master identity | `manifests/master-identity.json` | A template. |
| Cluster trust root | `manifests/cluster-trust-root.json` | Formed by a unanimous election. |
| Registry schema | `manifests/registry.schema.json` | The document's shape; entries are signed per entry. |
| Admin-surface intent | `manifests/admin-surface.json` | Checked by a test. |
| State dir | `$SPARKNET_STATE_DIR` | Outside the vault: `$XDG_STATE_HOME/sparknet/master-node`, else `~/.local/state/…`. Dir `0700`, files `0600`, gitignored. |
| Signer socket | `$SPARKNET_STATE_DIR/signer/` | Unix socket, mode 0600. |
| Operational key | the state dir | Mode `0600`; never leaves the machine. |
| WireGuard templates | `configs/wireguard/` | Rendered at `0600`; `APPLY=1` to write. |
| Node compose env | the state dir | `spark.env` (or `spark-agx.env`); gitignored. |

**Secrets** live in the state dir and are referenced by path only. The
`secrets-index.json` in `00_System/` records *which* secret is stored where —
never the value.

**`/etc` configuration is derived from the vault, never the other way round.**
The install path prints the diff and does not write it: applying a malformed
netplan on a remote node can drop your SSH session, so that stays a human
decision.

---

## 16. Troubleshooting

| Symptom | Likely cause | Where to look |
|---|---|---|
| The signer refuses to start | The trust root does not name this node Master, or names a different root than the ledger records. | `--node-id`, `--root`; `--accept-requalification` for an intentional re-formation. |
| The signer starts and then exits | The ledger records a different root — the refusal is deliberate. | `make ledger`; `docs/role-transition.md`. |
| `make units-check` fails | A unit in `systemd/` is not enabled by the Makefile. | Enable it, or exclude it with a reason. |
| `make parity` fails | A copy of a peer service appeared in this role. | Delete the copy; the peer's files are loaded by path. |
| `make ledger` fails | The chain is broken — a block was modified or removed. | The chain under `00_System/blockchain/`. |
| `make keys-check` fails | Tracked key material, or a state-dir key with the wrong mode. | Rotate anything that was committed. |
| The admin surface is unreachable | It binds the overlay address `10.100.0.1:8088`, and the overlay is down. | `make env-show`; the overlay anchor unit. |
| The admin console cannot sign | By design. It composes a request; the signer decides. | `manifests/admin-surface.json`; `--socket` signing via `sparknet-registry-sign-socket.sh`. |
| `make shims-check` fails | A legacy category name is a real directory, not a symlink. | `make env-init` recreates the shims. |
| `make wiki-preflight` fails | The nearest `.env` is missing, so the skills would resolve a *different* vault. | `make env-init`. Never work around it. |
| `make spec-check` fails | The spec/impl boundary rotted: a surface moved without the plan or the docs moving with it. | `plans/MASTER_BUILD_PLAN.md`; `docs/unverifiable-claims.md`. |
| A peer refuses the registry | The peer's pinned Master key does not match the signer, or the entry's validity window has closed. | `make registry-verify`; the entry's `issued_at`/`expires_at`. |
| The KillSwitch only prints a plan | Dry-run is the default. | `make killswitch FORCE=1` as root; `docs/killswitch-template.md`. |

---

## 17. Spec vs implemented

Broadly, in this role:

- **Implemented and exercised** — the three-key generation, the isolated
  signer and its socket, the trust-root installation, the election approval
  path, the hash-chained ledger, the parity loader, the registry signing,
  verification, publication and revocation, the registry delivery channel
  (including the idempotent re-push and the anchor skip), the approval
  issue/deliver path (exercised against the peer's own guard daemon, loaded by
  path, so "the two sides agree" is a fact the suite enforces), the 8090
  peer-intake listener, the RFI answer transport, evidence capture, the review
  agents, the reflex broker, the admin console, the overlay anchor, the admin
  surface's capability boundary, the role-scoped agents, and the KillSwitch's
  implementation against a fake runner.
- **Built but not fully exercised in the field** — the cluster KillSwitch
  (the destructive run on a real Master is `DoD: confirm: user`), the
  nocturnal scheduler's state machine (it dispatches nothing yet), and the
  signer/election live legs on the production pair.
- **Contracted and scaffolding** — the master-side ports `4220`–`4223` (git,
  file-share, NAT gateway, vector embed) are spec-only, and the admin surface
  is provisioned but nothing binds `8088` in the shipped tree.
- **Deliberately parked** — the destructive legs of the deployment runbook
  (rollback; replace-Master re-formation) are documented and deliberately left
  unexecuted by operator decision. `plans/PAIR_REFORMATION_DESIGN.md` designs
  the re-formation; it does not perform it.

The honest test: **if you cannot point at a command that exercises it, it is
specified.** `docs/unverifiable-claims.md` is where the things that *cannot* be
checked on this hardware are recorded, so that nobody re-derives them by
trying.

---

## 18. Glossary

| Term | Meaning |
|---|---|
| **Master** | The elected node that holds the operational key and signs. |
| **Election** | The conversation by which cluster members decide who holds the signing key. |
| **Trust root** | The document recording the cluster's unanimous decision, naming the Master. |
| **Cluster key** | The key that participates in the election. |
| **Operational key** | The key the fabric's authority derives from; held by the signer alone. |
| **Identity key** | The node's own identity and fingerprint. |
| **Signer** | The one process that holds the operational key. |
| **Requalification** | Starting the signer against a trust root other than the one its ledger records. Refused by default. |
| **Ledger** | The hash-chained record of approvals and decisions. |
| **Parity** | The rule that this role runs the peer's service files by path rather than copies. |
| **Admin surface** | The Master's administrative plane; bound to the overlay address, holds no key. |
| **Registry** | The Master-signed statement of which node may hold which capability. Entries are signed per entry. |
| **Revocation** | A signed entry marking an identity revoked. Only the Master can sign one, and only the Master can remove one. |
| **KillSwitch** | The cluster-wide, root-gated containment and teardown. Master-side; no revoke. |
| **Containment** | One node's own root-gated teardown. Peer-side. A different thing. |
| **Spec-only** | Designed and contracted, no code, by deliberate role boundary. |
