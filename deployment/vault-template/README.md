# vault-template — the starter `00_System/` set

Every sparknet vault opens with the same governance set. This directory holds
one instantiable copy of it: the files a fresh vault needs before its first
signed note. The numbered skeleton is created by
`scripts/sparknet-env-init.sh`, so the two never drift.

## Instantiate

```bash
scripts/sparknet-env-init.sh <role-dir>
cp -r deployment/vault-template/00_System/. <role-dir>/00_System/
make -C <role-dir> user-init
make -C <role-dir> provenance-verify
```

`env-init` accepts `peer-node/`, `master-node/` or the fabric root. A role with
a new directory name needs the script's case updated first. A missing `.env`
resolves a different vault through the wiki skills, and every page lands there
silently.

## What ships

| File | Role |
|---|---|
| `00_System/index.md` | navigation only |
| `00_System/user.md` | operator record, unfilled until `make user-init` |
| `00_System/schema.yaml` | pointer-only note conventions |
| `00_System/secrets-index.json` | empty metadata index; values live in state |
| `00_System/log.md` | append-only audit trail, header only |
| `00_System/platform.md` | uncaptured platform record; fill by capture |

## What does not ship

- **The rules file** — `alpha-agent.md`/`alpha-admin.md` is role-specific.
- **The five governance files** — `MISSION.md`, `INTENT.md`, `AGENTS.md`,
  `MEMORY.md`, `PLAN.md` live at the role root and ship with the role bundle.
- **`CONTEXT.md`** — generated at the role root by `make context-pack`; never
  copied by hand and never hand-edited.
- **Key material** — only `$SPARKNET_STATE_DIR/keys/` at 0600.
- **Shims** — `env-init` creates `index.md`/`log.md` and the legacy names.
