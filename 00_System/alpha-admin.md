---
title: alpha-admin — standing rules for this vault
updated: 2026-10-18
---

# alpha-admin — standing rules for this vault

These rules bind every agent writing in `master-node/`. The contract
(`../contracts/tracking-schema.json`) is the source of truth for the *shape*
of things; this file is the operating discipline: where you may write, what
you must sign, and what you must never hold.

## 1. The layout, and the shims

Vault content lives in the numbered dirs `00_System`–`07_Archives`. Each
legacy category name (`concepts/`, `references/`, `_raw/`, …) is a **symlink**
into that tree — one file, two names, never a second copy. Write to the
numbered path; the shim exists so the vendored wiki suite and older
instructions still resolve.

`_staging/` is real, not a shim (it is the skill review queue). `AGENTS.md`,
`MEMORY.md`, `MISSION.md` and `Makefile` stay at the root on purpose.

## 2. Where you may write

| Directory | Rule |
|---|---|
| `01_Inbox/` | **read-only until accepted.** Acceptance is recorded in the ledger as `inbox_acceptance`; only then is the item reviewed and, if untrusted, sanitized. |
| `03_Sources/` | **immutable.** Captured external material; you never edit a source, you cite it. |
| `02_Daily/`, `04_Evergreen/`, `05_Knowledge/`, `06_Projects/` | writable — with a tracking block and a signature (§3). |
| `00_System/` | governance. Rules change in the same commit as the code that enforces them; the user record is filled once and never re-keyed without `--force`. |
| `07_Archives/` | superseded material and snapshots. Prefer archiving over deleting. |

The **role trees** (`scripts/`, `services/`, `systemd/`, `security/`,
`manifests/`, `blockchain/`, `configs/`, `docs/`, `plans/`, `tests/`,
`deployment/`) are not vault content and do not take tracking blocks — the
peer and master charters differ in substance, and the role trees are the
substance.

## 3. Every note carries its provenance

A note in `01_Inbox`–`07_Archives` carries a `tracking` block in its
frontmatter: `schema`, `owner_id`/`owner_node`/`owner_ref`, `validity`,
`conversation`, `shares`, `agent`, `model`, `approvals`, `signature`.

- **Whoever writes a note re-signs it in the same operation** and bumps
  `updated`. `make provenance-verify` enforces this: unsigned content is
  `stale:content` (exit 2), a broken signature is `invalid` (exit 1).
- `validity.state` is a closed vocabulary. `signed` may be set **only** when
  the signature verifies against `00_System/user.md` — setting it otherwise
  is the falsification the signature exists to catch.
- A note whose signature verifies but whose `approvals[]` is empty is still
  a valid note: approvals are verified separately, against the ledger.
- Classification of an edit as `stale` vs `invalid` is **allowlist-based**
  (`compiler_allowlist` in the contract), never a percentage threshold — a
  numeric threshold is gameable by editing a little at a time, while
  producing a valid signature at all requires the private key.

```bash
make provenance-verify        # per-note outcomes + exit code
make precommit                # --strict: stale:content becomes failure
```

## 4. Approvals live only in the ledger

A ledger block with `data.event = "approval"` is the one approval record.
There is no `approvals.md` and nothing may be coded to one.

- **Only** `make provenance-append` (→ `shared/sparknet-provenance.py
  append-approval`) builds a block. No service, script or bridge may.
- Consent is dual: the user key signs the record, the node key
  countersigns it. Neither key alone can place a block.
- `approval_id` is `APL-YYYY-MM-DD-NNN` and must not already exist in the
  chain; `prev_hash` links every block to the last.

## 5. Secrets: resolve, never echo

- Secret *values* live under `$SPARKNET_STATE_DIR/` (mode 0700), gitignored
  and excluded from bundles. The vault holds **metadata only**:
  `00_System/secrets-index.json`.
- An agent resolves a value through the entry's `ref` at runtime, never
  echoes it, and never writes it into any file — not a page, not a log, not
  a commit message.
- The index schema has no field a value could hide in; `make
  provenance-verify` scans tracked files for registered values and
  key-shaped literals and fails if one appears.
- Key material: the private user key is `$SPARKNET_STATE_DIR/keys/user.ed25519`
  at 0600. `.gitignore` blocks `*.ed25519`, `*.pem`, `*.key`, `privkey*`,
  `id_ed25519*`, `*.seed`; `make keys-check` fails on a tracked match.
- The **operational** signing key (the one the elected Master signs
  authorizations with) is a separate concern: `services/sparknet-signer.py`
  is the only process designed to hold it. Its election→signer arc was
  **proven live on the real pair agx64/agx32 2026-10-07** (signer as
  `sparknet-master-signer.service`, a signed registry entry verified by a
  still-peer, reboot survival, a revoke→peer-inert→re-authorize cycle). What
  is still not built is the admin surface binding (build plan Step 18,
  `DoD: confirm: user`) and Phase 9's destructive legs. Do not blur the two
  keys in prose.

## 6. The Master is the infrastructure administrator — but not yet

The user has directed that the Master role carries the fabric's
infrastructure administration: the **git** repository, **file sharing**,
**NAT** for the overlay, and the **vector embeddings database**. That is a
role *responsibility*, contracted in `contracts/ports.json` as `spec-only`
and scoped in [[MASTER_ADMIN_PLAN]].

Nothing here may claim a listener exists: `contracts/ports.json` still marks
the admin services `spec-only` or `provisioned` — on this host nothing binds
`10.100.0.1:8088` (relocated from 8080, fabric Step 55; reachability
`DoD: confirm: user`, build plan Step 18) — until a runtime measurement
observes it. (The surface *is* deployed on the live Master agx32.) The election itself
is no longer the gap: it was proven live on agx64/agx32 2026-10-07 (role
charter). The peer vault's sign-off ("specified, not built") applies here
hardest, because the difference between "the Master administers git" and
"a git daemon is running" is exactly the overclaim this charter exists to prevent.

## 7. Writing discipline

- One page per file; cross-link instead of copying. Prefer editing an
  existing page over adding a near-duplicate.
- Cite sources — a distilled page without provenance is a guess, mark it as
  one. Provenance under `03_Sources/` may legitimately record what was true
  when it was captured; current surfaces must not hard-code host paths.
- Logs and telemetry → `/mnt/log/`, not the vault. Runtime caches →
  `$OPENCODE_DATA_DIR`.
- Never claim live verification of WireGuard, nftables, `chattr +i`,
  KillSwitch, signer or systemd behaviour: this host has none of them.
- Cross-role edits are atomic: touching anything peers depend on means
  editing `contracts/` and both roles in the same commit, then
  `make contract-test`.