#!/usr/bin/env python3
"""Validate the frontmatter opencode needs for a skill to be loadable."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    out: dict[str, str] = {}
    key = None
    for line in text[3:end].splitlines():
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", line)
        if match:
            key = match.group(1)
            out[key] = match.group(2).strip()
        elif key and line.strip():
            out[key] += " " + line.strip()
    return out


def validate(skill_dir: Path) -> list[str]:
    skill_md = skill_dir / "SKILL.md"
    problems: list[str] = []
    if not skill_md.is_file():
        return [f"{skill_dir}: SKILL.md is missing"]
    meta = frontmatter(skill_md.read_text(encoding="utf-8"))
    name = meta.get("name", "")
    description = meta.get("description", "")
    if not name:
        problems.append("frontmatter has no `name`")
    else:
        if not NAME_RE.match(name):
            problems.append(f"name {name!r} must be lowercase-hyphenated")
        if len(name) > MAX_NAME:
            problems.append(f"name is {len(name)} chars; maximum is {MAX_NAME}")
        if name != skill_dir.name:
            problems.append(f"name {name!r} does not match directory {skill_dir.name!r}")
    if not description:
        problems.append("frontmatter has no `description`")
    elif len(description) > MAX_DESCRIPTION:
        problems.append(f"description is {len(description)} chars; maximum is {MAX_DESCRIPTION}")
    nested = [p for p in skill_dir.rglob("SKILL.md") if p.parent != skill_dir]
    if nested:
        problems.append(f"nested SKILL.md files would be discovered: {[str(p) for p in nested]}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skill_dir", nargs="?", default=".", type=Path)
    args = parser.parse_args()
    problems = validate(args.skill_dir.resolve())
    if problems:
        for problem in problems:
            print(f"skill-template: {problem}", file=sys.stderr)
        return 1
    print(f"skill-template: {args.skill_dir.name} is loadable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
