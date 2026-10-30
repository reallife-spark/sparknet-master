# Variant of draft-release-notes

Source: `/mnt/nvme/github/loop-engineering/starters/changelog-drafter/.claude/skills/draft-release-notes`

Source repository: `loop-engineering`

License: `MIT`

This file preserves an alternate body for provenance. It is not named
`SKILL.md`, so opencode does not load it as a second skill.

---

---
name: draft-release-notes
description: Turn changelog-scan output into polished, categorized release notes draft. Propose only.
user_invocable: true
---

# Draft Release Notes (Claude)

Follow the exact structure and rules from the Grok `draft-release-notes` skill.

Output a clean `RELEASE_NOTES_DRAFT.md` (or clear section the loop can persist). Always flag breaking + security at top. End with review note for human.