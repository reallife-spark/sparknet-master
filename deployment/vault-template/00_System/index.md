---
title: sparknet vault index (template)
updated: 2026-10-18
---

# vault index

The vault's governance set, in the numbered layout. Every legacy category
name at the role root (`concepts/`, `references/`, `_raw/`, …) is a symlink
into these directories — one file, two names. The rules live in the role's
`alpha-*.md`; the charter is `AGENTS.md` at the role root.

Links on this page are wikilinks so they resolve whether the page is opened as
`00_System/index.md` or through the root `index.md` shim.

## Directories

| Dir | Holds |
|---|---|
| `00_System/` | governance: the role's `alpha-*` rules, `user`, `schema.yaml`, `secrets-index.json`, this index, `log.md` |
| `01_Inbox/` | capture-first intake — read-only until accepted |
| `02_Daily/` | dated entries and per-session memory (`YYYY-MM-DD.md`) |
| `03_Sources/` | external material and raw captures — immutable |
| `04_Evergreen/` | permanent atomic notes refined from sources |
| `05_Knowledge/` | the compiled wiki: `concepts/`, `entities/`, `skills/`, `synthesis/` |
| `06_Projects/` | per-project knowledge |
| `07_Archives/` | snapshots and superseded material |

## Commands

| Command | Does |
|---|---|
| `make provenance-verify` | per-note outcome + exit code (0 clean, 1 invalid, 2 stale) |
| `make user-init` | fill `user.md` once: keypair, 0600 private key, `.user.lock` |
| `make provenance-append` | the only way to build a ledger block |
| `make precommit` | `--strict` verification for the hook |
| `make wiki-preflight` | prove the wiki skills resolve *this* vault |
| `make help` | the full list |

## Where to start

- Session memory: `MEMORY.md`, then `02_Daily/<today>.md`
- Work in flight: `PLAN.md` — its `current:` field names the step
- The rules: the role's `alpha-*.md`
- The contract (single source of truth): `contracts/tracking-schema.json`
