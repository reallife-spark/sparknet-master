# sparknet master-node — agent charter

The **Master role** of the Sparknet fabric: the node that holds signing
authority over the overlay.

> **Status: built and running its own surface, and the election/signer arc is
> proven live on real hosts** (build plan Steps 14–18 + fabric Step 13). This
> role has `scripts/`, `services/` and `systemd/`. It runs the peer's services
> **by path** rather than copying them, keeps its own hash-chained ledger,
> generates its own keys into the state directory, has an **isolated signer**
> for the operational key, and declares an admin surface plus a `MASTERSPIKE`
> knowledge manifest.
>
> The consensus/election arc is **built and was proven live 2026-10-07**:
> `shared/sparknet-consensus.py` produces *and* verifies roots (Step 14); the
> two real hosts agx64/agx32 co-formed a 2/2 trust root naming agx64 Master
> over the deployed transport, and the signer ran in production as
> `sparknet-master-signer.service` on agx64 — it answered its own root-id,
> signed a live registry entry a still-peer verified, survived a real reboot,
> refused non-Master keys/unnamed nodes/tampered roots, and demonstrated a
> live revoke→peer-inert→re-authorize cycle. That 2026-10-07 root is archived;
> the **current** Step 57 pair is reversed — `agx32` Master
> (`sparknet-node-0002`, `10.100.0.1`) and `agx64` peer (`0001`,
> `10.100.0.2`), root `fa6f4fa5…`.
>
> The admin surface is **deployed on the live Master (agx32)**: the container
> `sparknet-admin-webui` runs the committed topology and binds `10.100.0.1:8088`
> (relocated 8080→8088, fabric Step 55). The overlay anchor carries
> `Before=docker.service`, so the address exists before any container binds it —
> without that ordering the container died at boot with `bind: cannot assign
> requested address` (exit 128). Reachability from an operator client is still
> `DoD: confirm: user`, Step 18. Phase 9's
> destructive legs (rollback; replace-Master re-formation with a new nonce)
> are documented in `contracts/deployment-runbook.md` and deliberately left
> unexecuted by operator decision — do not describe them as run. The signer
> unit stays excluded from `make units` by design: enabling a process that
> holds the Master signing key belongs to the election, not the role install.
> The overlay-reboot caveat is **closed** (2026-10-19): the tegra host has no
> kernel module (`CONFIG_WIREGUARD=n`), so `wg-quick` is unusable there. Both
> roles now bring the overlay up through the peer's `scripts/sparknet-wg-bringup.sh`
> (userspace `wireguard-go`), driven by an enabled systemd anchor unit —
> `sparknet-wireguard-anchor.service` (peer) and
> `sparknet-master-wireguard-anchor.service` (master), the latter in `make units`.
> A **real reboot of each host (2026-10-19)** restored the overlay unattended; on
> the master the admin container also auto-started and bound `10.100.0.1:8088`
> (the anchor carries `Before=docker.service`). The old ad-hoc
> `/root/scripts/sparknet-wg-restore.sh` is retired.

This is a standalone knowledge vault. A session started inside
`master-node/` resolves to *this* directory as its knowledge base, not to the
parent.

## Role in one paragraph

The Master is the only node that can grant authority. It holds the Ed25519
private key, signs the registry that says what each node may do, maintains the
WireGuard overlay at `10.100.0.1`, and can revoke any peer instantly from its
own side. Everything else in the fabric is subordinate to it. Its authority
comes from **key possession**, not from a capability grant — a peer holding the
same capability vocabulary without that key can verify, but can never grant,
revoke, or escalate.

**A Master is a peer that won an election, not a separate species.** A cluster is
a pair or a trio; each member holds the same capabilities and runs the same
services; one additionally holds the operational key and signs. That is the
entire difference, and it is why this role loads `../peer-node/services/*` by
path instead of carrying its own versions.

The peer role lives in `../peer-node/` and is implemented.

## The manual

[`USER_MANUAL.md`](USER_MANUAL.md) is the developer-facing manual for this
role: the election arc, the three keys, the isolated signer and its socket,
the ledger, the admin surface and its boundary, the vault, the gate, and how
to make a change correctly. It is published at the root of the
`sparknet-master` repository.

The **master manual** for the whole system lives in the `sparknet` repository
as `USER_MANUAL.md`; the contract and the shared implementation this role obeys
are named in prose there, because the published `sparknet-master` repository
carries this role and not the contract.

## Authority, precisely

| Capability | Mechanism |
|---|---|
| Grant capabilities | signs a registry entry with the Master private key |
| Revoke a node | signs `revoked: true`, removes the peer from its own `wg0` |
| Register a new peer | adds a `[Peer]` stanza to the Master's `wg0` |
| Authorize a `guard-apply` | signs an approval payload for one specific peer |
| Halt the fabric | the cluster KillSwitch (built Step 8; dry-run by default, live destructive run unverified) |

None of these are granted through the capability system. The capability
vocabulary in `../contracts/capabilities.json` governs what a **peer** may do.
The Master's own powers are implied by holding the private key, which is
exactly why that key must never leave this machine.

## Boundaries vs a peer

| Concern | Master |
|---|---|
| Signing key custody | **exclusive — never leaves** |
| Registry authorship | **authoritative** |
| Overlay address | `10.100.0.1` |
| Network egress | **unrestricted** — the peer egress rule pins traffic to the Master, and adopting it here would blackhole the fabric |
| Peers it holds | every authorized node, one stanza each |
| Containment | cluster-wide, from here |

A peer can be revoked and lose its anchor, and then it is inert: its guard
refuses to bind and refuses to apply, because it can no longer receive a valid
signature. The Master is the only party that can put it back, which is what
makes revocation meaningful rather than advisory.

The asymmetry in egress is the clearest statement of the difference between the
roles: a peer may reach only the Master; the Master reaches everyone. A rule
that is correct on a peer is actively harmful here.

## Layout (wiki category layout)

| Path | Holds |
|---|---|
| `concepts/` | distilled ideas and definitions |
| `entities/` | people, organisations, systems, products |
| `skills/` | reusable procedures (how-to pages) |
| `references/` | external material: docs, specs, transcripts, datasets |
| `synthesis/` | conclusions ACROSS two or more pages |
| `journal/` | dated entries and session notes |
| `projects/` | per-project knowledge |
| `sessions/` | per-session agent memory (`YYYY-MM-DD.md`) |
| `_raw/` | unprocessed captures — nothing is deleted from here |

Role-specific trees:

| Path | Holds |
|---|---|
| `configs/wireguard/` | the Master-side `wg0` peer stanza template |
| `manifests/` | node identity and the cluster trust root — templates, never live key material |
| `blockchain/` | the Master's hash-chained ledger (schema is the peer's, not duplicated) |
| `security/` | key custody, isolation and rotation policy |
| `docs/` | Master-side specifications |
| `plans/` | the build backlog and planning notes; also the master architecture blueprint and pre-split planning docs (architecture, deployment summary, viability/checklist, EU AI Act, BOMs) |
| `tests/` | specification-conformance and parity tests |

The executable surface:

| Path | Holds |
|---|---|
| `services/` | `sparknet-parity.py` (loads the peer's services by path), `sparknet-ledger.py` (verify only), `sparknet-signer.py` (**the only** process that holds the operational key) |
| `scripts/` | `sparknet-master-env.sh`, `sparknet-master-keygen.sh` |
| `systemd/` | parity + ledger units, plus the **signer unit** — which exists but is deliberately *not* in the `make units` set, because enabling a key-holding process is the election's decision, not an install side effect. `make signer-unit` stages it |

Three rules govern that surface:

1. **One copy of the peer's services.** `make parity` prints where each one
   resolved; `tests/test_master_parity.py` fails the build if a copy appears
   here. Two copies of a signature-verifying service would drift silently.
2. **No key material in the vault.** Keys live in `$SPARKNET_STATE_DIR/keys` at
   0600, referenced by path, and the state dir resolves *outside* this tree
   (`$XDG_STATE_HOME/sparknet/master-node`). Outside, not just gitignored: the
   admin surface bind-mounts this vault read-only into an LLM container, so
   gitignore would not have helped. `make keys-check` enforces both halves.
3. **Nothing inert.** Every file in those directories must be referenced by a
   unit or a make target, or the build fails. The signer is what makes this bite:
   the moment `sparknet-signer.py` existed without a unit, the build failed until
   the unit did.

## The contract this role obeys

`../contracts/` is the single source of truth for overlay addressing, the
capability vocabulary, the identity schema, ports and the guard protocol.
Changing anything a peer depends on is a **cross-role change**: edit the
contract, then update both roles in the same commit, then run
`make contract-test` at the parent.

`../shared/sparknet-authz.py` is the one implementation of the signed
authorization scheme. This role *signs* with it; a peer *verifies* with it.
Never copy it here.

`../shared/sparknet-consensus.py` is likewise the single implementation of
election and trust roots. A node forms **three** distinct Ed25519 keys, and the
split is the security model rather than a detail — see `security/key-management.md`.

## Memory Protocol

- `MEMORY.md` — **standing state only**, tiny: plan cursor, durable facts,
  blockers. Replace, never append indefinitely.
- `sessions/YYYY-MM-DD.md` — that session's full record. One file per day;
  sessions spanning midnight use the start date.
- Read `AGENTS.md`, `MISSION.md` and `INTENT.md` at session start: the charter,
  the role's purpose and the design contract behind it. Then read `MEMORY.md`
  and today's session file; write detail only to today's session file. Never
  back-write history into `MEMORY.md`.

## Plan Protocol

`plans/MASTER_BUILD_PLAN.md` is the single source of truth for Master work.

- Frontmatter `current:` marks the step being worked.
- Mark a step `[x]` **only** after its DoD is verified, then advance the cursor
  and write the plan back **immediately**.
- Append one line per transition to `log.md` (append-only audit trail).
- Terminal state is `current: done`. New roadmap work gets a **new** step; do
  not silently reuse a finished plan.
- A step whose DoD cannot be auto-verified is marked `DoD: confirm: user`.

## Canonical placement

- Distilled page → its category dir. Raw capture → `_raw/` until distilled.
- Logs and telemetry → `/mnt/log/`, not the vault and not `~/`.
- The Master private key lives in `$SPARKNET_STATE_DIR/keys` at mode 0600 and
  is **never** committed, referenced only by path.
- One page per file; no duplicate copies. Prefer editing an existing page over
  adding a near-duplicate; cross-link instead of copying.

## Wiki skill suite

**Vendored in this repository** at `../.opencode/skills/` — there is no global
skill farm dependency, so a bare clone or an extracted node bundle can run the
whole suite. Do not reach for a copy under `/mnt/nvme` or `~/.config/opencode`.

Before using any skill, resolve this vault explicitly:

```bash
# From a role subvault. Walks up to the nearest copy — no .git required, because a
# standalone bundle ships without one.
for d in "$PWD" "$(dirname "$PWD")"; do
  [ -f "$d/scripts/sparknet-wiki-env.sh" ] && { source "$d/scripts/sparknet-wiki-env.sh"; break; }
done
```

That prints the role, the role root and the `VAULT_PATH` the skills will use.
**If it fails, stop** — run `../scripts/sparknet-env-init.sh .` once. Do not work
around it: a silent fallback resolves a *different* vault and every page lands in
the wrong place with no error.

Config resolves from `.env` in this directory (`VAULT_PATH`) — never hard-code a
path in a page. `make wiki-preflight` runs the same check.

Run `/wiki-status` first, then `/wiki-ingest`, `/wiki-query`, `/wiki-lint`,
`/wiki-capture`, `/wiki-synthesize`, `/wiki-digest`, `/wiki-rebuild`,
`/daily-update`.

### Role-local sellable catalog

`master-node/.opencode/skills/` holds every unique skill whose license permits
commercial redistribution, plus the original dual MIT/Apache `skill-template`.
It is **sellable by construction**: MIT, Apache-2.0, BSD, ISC, CC0/Unlicense
and original dual MIT/Apache only. The restricted names (`docx`, `pdf`, `pptx`,
`xlsx`, `powerpoint`, `kimi-*`, `doc-coauthoring`, `verify`, the bundled
`claude-api`, `malware-analysis-static`, `template`) are excluded, as are
GPL/AGPL, CC BY-SA, modified-Apache and unclear licenses.

`claude-api` is retained only from its Apache-2.0 source and is marked
`tier: optional`, `standard: false`; it is not in the peer set and is not a
default skill. Counts, licenses, source paths and hashes are in
`.opencode/skills/.inventory.json`. Refresh with `make skills-sync`; verify
with `make skills-check`.

## Templates

| Template | Purpose |
| --- | --- |
| `deployment/vault-template/` | Starter `00_System/` set for a fresh vault (`cp` + `make user-init`). |
| `configs/wireguard/master-peer.template` | Master-side WireGuard peer stanza for `wg0`. |
| `docs/killswitch-template.md` | Cluster KillSwitch implementation, recovery, and preserved draft. |

## Boundaries

- **Scope discipline.** This vault holds Master-role sparknet knowledge.
  Peer-role material goes in `../peer-node/`; cross-role contracts in
  `../contracts/`.
- **No secrets.** Never commit tokens, keys or `.env` contents. Reference the
  secret *path* only. The Master private key is the most sensitive secret in
  the entire fabric.
- **The catalog is reference, not authorization.** The role-local catalog
  includes the Apache-2.0 cyber corpus, including offensive-security material.
  Loading a skill does not authorize an operation; operational offensive work
  still routes to `red`, defensive work to `blue`.
- Cite sources. A distilled page without provenance is a guess — mark it as one.
- **Do not overclaim what the live run proves.** The code on this role is real
  and tested, and the election→signer→registry arc was **deployed and proven
  live on real hosts on 2026-10-07** (agx64/agx32): a signed registry entry, a
  key crossing a process boundary, a reboot, and a revoke/restore cycle. That is
  a dated claim about those hosts, not a general production-fleet guarantee. On
  the development host nothing binds the overlay or admin surface. Say
  "implemented and tested", "deployed live on agx64/agx32 on 2026-10-07", or
  "unverified here" — never generalise the live run into an untested claim.
- **Distinguish what runs from what is specified.** This role now runs a real
  surface, so the temptation reverses: describing the signer, election or overlay
  anchoring as working when they are specified-only. Check the boundary before
  writing a claim about this role.
- **Never sign with anything but the operational key**, and never let a peer
  service load the signer. The admin surface is an LLM application that reads
  configuration as input; the key is isolated structurally, not by policy.