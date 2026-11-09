# Domain docs

The Master workspace uses the **single-context** layout.

## What to read

1. `AGENTS.md` — the Master charter; it wins on conflict.
2. `PLAN.md` — the active Master work order.
3. `GLOSSARY.md` — Master and authority vocabulary.
4. `docs/adr/` — accepted Master decisions.
5. `../contracts/` — the normative cross-role contracts, including
   `knowledge-flow.md`, `issue-schema.json` and `understand-schema.json`.

## Rules

- Authority comes from possession of the operational key, not from a document,
  a directory name or a model. Never describe it otherwise.
- An issue, a telemetry report, an approval or an admin response is not
  knowledge and must not enter the Master's answer corpus.
- Do not copy a contract into a Master document; link to it.
- Never place a key, token, private page or live host secret in `docs/`.
