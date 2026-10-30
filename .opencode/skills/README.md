# Role-local skill catalog — master

This directory is the **role-local** addition to the base suite at
`../../.opencode/skills/`. opencode discovers it when a session starts inside
`master-node/` (or a subdirectory), because config resolution walks up to the
nearest `.opencode/` directory.

- Role-local skills: **1652**
- Optional / non-standard: **1** (`claude-api`, master only)
- Base suite: **33** skills, shared at the fabric root
- Total visible in a role session: **1685**

## License policy

The catalog is sellable by construction:

- Allowed: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0,
  Unlicense, and the original dual `MIT OR Apache-2.0` skills.
- Excluded: proprietary/source-available, no-license/unclear, GPL/AGPL,
  CC BY-SA, and modified Apache terms.
- `claude-api` is kept only from the Apache-2.0 source and is marked
  `tier: optional`; it is not part of the peer set and is not a default skill.
- The only newly authored skill is `skill-template` (dual MIT/Apache-2.0).

## Provenance

`.inventory.json` records the source path, source repository, license, SHA-256
of `SKILL.md`, copied file count, skipped large/nested files, and variant
bodies. `THIRD_PARTY_NOTICES.md` is the human-readable companion. `LICENSES/`
holds the distinct license texts.

## Refresh and check

```bash
make -C master-node skills-sync
make -C master-node skills-check
```

The check fails on a missing skill, a name/frontmatter mismatch, a nested
`SKILL.md`, a symlink, a restricted license, or a manifest hash mismatch.
