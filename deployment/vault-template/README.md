# vault-template — the starter `00_System/` set for a sparknet vault

Every sparknet vault (fabric root, `peer-node/`, `master-node/`, and any role
added later) opens with the same governance set. This directory holds one
instantiable copy of it: the files a fresh vault needs **before** its first
note is signed.

The numbered skeleton itself is deliberately **not** here — `scripts/sparknet-env-init.sh`
creates `00_System`–`07_Archives`, the legacy-name shims and the vault's
`.env`, so the two never drift apart.

## Instantiate

```bash
# 1. skeleton: numbered dirs + shims + .env  (from the fabric root)
scripts/sparknet-env-init.sh <role-dir>

# 2. this set into the new vault's governance dir
cp -r deployment/vault-template/00_System/. <role-dir>/00_System/

# 3. fill the operator record ONCE — keypair into $SPARKNET_STATE_DIR,
#    receipt into 00_System/.user.lock
make -C <role-dir> user-init

# 4. prove it before the first note
make -C <role-dir> provenance-verify && make -C <role-dir> precommit
```

`sparknet-env-init.sh` accepts a role subvault (`peer-node/`,
`master-node/`) or the fabric root — **that is currently the closed list**;
a role with a new directory name needs the script's case updated first.
Do not work around it: a vault whose `.env` is missing resolves a *different*
vault through the wiki skills and every page lands there silently.

## What ships here

| File | Role |
|---|---|
| `00_System/index.md` | vault index — directories, commands, where to start |
| `00_System/user.md` | operator record, **unfilled**; `make user-init` writes `status`, `owner_id`, `owner_node` and the `key` block and never touches it again without `--force` |
| `00_System/schema.yaml` | pointer-only index of note conventions — `source.tracking` is pinned to `contracts/tracking-schema.json` by `tests/test_contracts.py`, keep it fabric-relative |
| `00_System/secrets-index.json` | empty metadata index (`sparknet-secret-index/1`); secret *values* live under `$SPARKNET_STATE_DIR/secrets/` at 0700, never here |
| `00_System/log.md` | the append-only audit trail, header only |

## What deliberately does **not** ship here

- **The rules file** — `alpha-agent.md` / `alpha-admin.md` is role-specific
  in substance (write permissions, boundaries, verification claims). Copy it
  from an existing role and edit it; do not invent one from this template.
- **`AGENTS.md`, `MISSION.md`, `INTENT.md`, `MEMORY.md`, `PLAN.md`** — the
  charter, purpose, design contract, standing state and plan cursor live at the
  role root, not in `00_System/`. They ship with the role bundle, so a fresh
  deployment has them before the first note is signed.
- **Key material of any kind.** The template is scanned by
  `make keys-check` and the provenance `scan` like every other tracked file;
  keys only ever land in `$SPARKNET_STATE_DIR/keys/` at 0600.
- **Shims** — `index.md`/`log.md` at the role root are symlinks created by
  `sparknet-env-init.sh` (never hand-made; `make shims-check` proves them).
