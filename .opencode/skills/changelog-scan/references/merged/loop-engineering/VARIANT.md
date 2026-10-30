# Variant of changelog-scan

Source: `/mnt/nvme/github/loop-engineering/starters/changelog-drafter/.claude/skills/changelog-scan`

Source repository: `loop-engineering`

License: `MIT`

This file preserves an alternate body for provenance. It is not named
`SKILL.md`, so opencode does not load it as a second skill.

---

---
name: changelog-scan
description: Scan recent merges/PRs/commits for release note content. Structured output for drafter.
user_invocable: true
---

# Changelog Scan (Claude)

Same contract as the Grok version. Produce the per-item blocks + Scan Summary.

Key rules: cite PR numbers, surface breaking/security explicitly, ignore pure dep and bot noise unless security.