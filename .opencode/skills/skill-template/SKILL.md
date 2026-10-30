---
name: skill-template
description: Original scaffold for authoring a new agent skill. Use when creating a skill from scratch, when a skill needs a valid frontmatter contract, or when you want a minimal testable skill layout with provenance and dual licensing.
license: MIT OR Apache-2.0
compatibility: opencode
metadata:
  audience: maintainers
  workflow: authoring
---

# Skill Template

A minimal, original scaffold for a new skill. It is deliberately small: one
`SKILL.md`, one validator, one example, and the two license texts. Copy the
directory to a new name, then replace this body.

## What to do

1. Rename the directory and the `name` field together. opencode requires them to
   match and only accepts lowercase words separated by single hyphens.
2. Write a description that says both what the skill does and when to use it.
   That description is the only text an agent sees before loading the skill.
3. Keep the body procedural. Put long reference material in `references/`, not
   in `SKILL.md`.
4. Add `scripts/` only when a command can do the work more reliably than prose.
5. Run the validator:

   ```bash
   python3 scripts/validate_skill.py .
   ```

6. Record any third-party dependency in `PROVENANCE.md` and `NOTICE`.

## Frontmatter contract

Required:

- `name` — must match the directory; `^[a-z0-9]+(-[a-z0-9]+)*$`; at most 64 chars.
- `description` — 1–1024 chars; says what and when.

Optional:

- `license` — SPDX expression, for example `MIT OR Apache-2.0`.
- `compatibility` — `opencode`.
- `metadata` — string-to-string map.

## Boundaries

- Do not copy another skill's prose or scripts. Write the procedure from public
  specifications and your own requirements.
- Do not put secrets, tokens, private keys, or host-specific absolute paths in a
  skill.
- Do not create nested `SKILL.md` files. opencode discovers every one of them.
- Prefer a small, testable procedure over a large prompt.

## Example

See `examples/example-skill.md` for a filled-in skeleton.
