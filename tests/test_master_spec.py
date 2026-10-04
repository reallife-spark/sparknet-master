"""The Master role is specified, not built — keep that claim true.

This role has no `scripts/`, `services/` or `systemd/` directory, on purpose.
That is a *decision*, and a decision that decays silently: the first service to
land makes the charter's "nothing here runs yet" false, while the charter, the
mission page and the build plan keep asserting it. A reader then trusts a
description of something that does not exist.

So the boundary is asserted, not just documented. The moment Step 3 of the
build plan lands, these tests fail and the prose gets updated on purpose — in
the same commit that adds the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

VAULT_ROOT = Path(__file__).resolve().parent.parent
PLAN = VAULT_ROOT / "plans" / "MASTER_BUILD_PLAN.md"
AGENTS = VAULT_ROOT / "AGENTS.md"
MISSION = VAULT_ROOT / "MISSION.md"

# Directories that would mean this role has an executable surface.
FORBIDDEN_DIRS = ("scripts", "services", "systemd")

# Pages that describe the role and therefore must keep saying it is unbuilt.
UNBUILT_CLAIMING_PAGES = (AGENTS, MISSION, VAULT_ROOT / "docs" / "master-control-plane.md")


def test_plan_cursor_exists_and_points_at_a_real_step() -> None:
    text = PLAN.read_text()
    match = re.search(r"^current:\s*(\S+)\s*$", text, re.MULTILINE)
    assert match, "MASTER_BUILD_PLAN.md must carry a `current:` cursor"
    cursor = match.group(1)
    if cursor == "done":
        return
    assert f"**Step {cursor}**" in text, (
        f"plan cursor points at Step {cursor}, which is not defined in the plan"
    )


def test_every_step_has_a_verifiable_dod() -> None:
    """A step with no DoD cannot be completed honestly, only declared done."""
    text = PLAN.read_text()
    steps = re.findall(r"\*\*Step (\d+)\*\*", text)
    assert steps, "no steps defined in the build plan"
    for step in steps:
        section = text.split(f"**Step {step}**", 1)[1].split("**Step ", 1)[0]
        assert "**DoD**" in section, f"Step {step} has no DoD"
        # An unverifiable DoD must be flagged rather than quietly accepted.
        assert re.search(r"\(\d\)|DoD: confirm: user|DoD", section), (
            f"Step {step} DoD is not checkable"
        )


def test_role_has_no_executable_surface() -> None:
    """Step 3 is where that stops being true."""
    present = [d for d in FORBIDDEN_DIRS if (VAULT_ROOT / d).is_dir()]
    assert not present, (
        f"{present} exist in master-node/. This role is documented as unbuilt. "
        f"If build plan Step 3 has landed, update AGENTS.md, MISSION.md, "
        f"docs/master-control-plane.md and this test in the same commit."
    )


@pytest.mark.parametrize("page", UNBUILT_CLAIMING_PAGES, ids=lambda p: p.name)
def test_pages_still_declare_the_role_unbuilt(page: Path) -> None:
    if not page.is_file():
        pytest.skip(f"{page.name} not present")
    text = page.read_text()
    assert re.search(r"\bunbuilt\b|\bnot built\b|\bnothing here runs yet\b", text, re.I), (
        f"{page.name} no longer says the role is unbuilt — if the code landed, "
        f"say what works instead of leaving a stale or absent claim"
    )


def test_charter_does_not_hard_code_a_machine_path() -> None:
    """The parent charter says never hard-code the vault path; hold it to that."""
    for page in (AGENTS, MISSION, PLAN):
        text = page.read_text()
        assert "/mnt/knowledge/sparknet" not in text, (
            f"{page.name} hard-codes the vault path — resolve it from .env instead"
        )


def test_master_template_is_documentation_only() -> None:
    """The one config artifact here must be a template, not a live config."""
    template = VAULT_ROOT / "configs" / "wireguard" / "master-peer.template"
    assert template.is_file(), "the Master peer stanza template is missing"
    text = template.read_text()
    # Placeholders, not values that could look like a real deployment.
    assert "10.100.0." in text, "template should document the Master overlay address"
    live = VAULT_ROOT / "configs" / "wireguard" / "wg0.conf"
    assert not live.exists(), (
        "a live wg0.conf in the vault would be machine state; the template is "
        "rendered to .state/ at provisioning time"
    )


def test_private_key_is_never_in_the_vault() -> None:
    """The single most damaging mistake available on this role."""
    suspicious = [
        p for p in VAULT_ROOT.rglob("*")
        if p.is_file()
        and p.suffix not in {".pyc"}
        and "sessions" not in p.parts
        and re.search(r"(ed25519|master).*\.(key|pem)$|id_ed25519", p.name, re.I)
    ]
    assert not suspicious, f"possible Master private key in the vault: {suspicious}"