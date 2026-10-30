"""The Master role is built, and its pages must keep describing it accurately.

This file used to assert the *opposite*: that `scripts/`, `services/` and
`systemd/` did not exist, so the role could not drift into running code while the
charter still claimed it did not. That discipline was real, and it was retired the
moment the first executable surface landed — the module docstring predicted this
migration and named the discipline, and Step 15 of the build plan is where it
happens.

The replacement is not "stop asserting anything". It is the same instinct pointed
the other way: a role with code must be *wired*, and its pages must not describe
code that does not exist. So this file now asserts that each executable directory
is reachable from a unit or a make target, and that the claiming pages describe
what works.

Two assertions are carried over untouched, because they were never about whether
the role is built:

- `test_private_key_is_never_in_the_vault` — the operational key must never enter
  this vault, and building the role made that *more* important, not less.
- `test_master_template_is_documentation_only` — a rendered `wg0.conf` is machine
  state and does not belong here.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

VAULT_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = VAULT_ROOT.parent


PLAN = VAULT_ROOT / "plans" / "MASTER_BUILD_PLAN.md"
AGENTS = VAULT_ROOT / "AGENTS.md"
MISSION = VAULT_ROOT / "MISSION.md"
INTENT = VAULT_ROOT / "INTENT.md"

# Directories that make up this role's executable surface.
EXECUTABLE_DIRS = ("scripts", "services", "systemd")

#: Pages that describe the role and therefore must not describe code that is absent.
CLAIMING_PAGES = (AGENTS, MISSION, VAULT_ROOT / "docs" / "master-control-plane.md")

#: Every page the role ships under `docs/`. Each must declare its build state.
DOC_PAGES = tuple(sorted((VAULT_ROOT / "docs").glob("*.md")))

#: The build states a page may declare. Closed on purpose: "partly done" said in
#: six different spellings cannot be checked by anything, least of all by a reader.
BUILD_STATUSES = ("built", "partially-built", "unbuilt", "preserved-not-wired")

#: An orchestrator callout. A page that is not built carries one, so a reader
#: meets the caveat before the prose it caveats.
CALLOUT = re.compile(r"^>\s*\[!(warning|caution|important|note|info|tip)\]", re.MULTILINE)


def frontmatter(path: Path) -> dict[str, str]:
    """Parse the flat top-level frontmatter of a page.

    Hand-rolled for the same reason the fabric's own helpers are: there is no
    YAML dependency, and the keys read here (`status`, `title`, `updated`) are
    flat scalars. A nested block is ignored rather than half-parsed, so a future
    addition cannot make this lie.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def open_plan_steps(plan: Path) -> list[int]:
    """The steps the plan still lists as open."""
    steps = []
    for match in re.finditer(r"^- \[ \] \*\*Step (\d+)\*\*", plan.read_text(), re.MULTILINE):
        steps.append(int(match.group(1)))
    return steps


def test_plan_cursor_exists_and_points_at_a_real_step() -> None:
    text = PLAN.read_text()
    match = re.search(r"^current:\s*(\S+)\s*$", text, re.MULTILINE)
    assert match, "MASTER_BUILD_PLAN.md must carry a `current:` cursor"
    cursor = match.group(1)
    if cursor == "done":
        return
    assert f"**Step {cursor}**" in text, f"plan cursor points at Step {cursor}, which is not defined in the plan"


def test_every_step_has_a_verifiable_dod() -> None:
    """A step with no DoD cannot be completed honestly, only declared done."""
    text = PLAN.read_text()
    steps = re.findall(r"\*\*Step (\d+)\*\*", text)
    assert steps, "no steps defined in the build plan"
    for step in steps:
        section = text.split(f"**Step {step}**", 1)[1].split("**Step ", 1)[0]
        assert "**DoD**" in section, f"Step {step} has no DoD"
        assert re.search(r"\(\d\)|DoD: confirm: user|DoD", section), f"Step {step} DoD is not checkable"


def test_the_role_has_an_executable_surface() -> None:
    """A Master is a peer that won an election, so this role runs code.

    The assertion is now that the surface exists *and* is deliberate. A directory
    that appears with nothing wired to it is how a role accumulates code nobody
    starts, which is the same decay the old assertion was watching for.
    """
    for name in EXECUTABLE_DIRS:
        assert (VAULT_ROOT / name).is_dir(), (
            f"{name}/ is missing from master-node/. This role runs the peer's "
            f"services by path plus its own signer and scripts."
        )


def test_every_executable_directory_is_wired_to_something() -> None:
    """Nothing here may sit inert. Each surface must be reachable from a unit or
    a make target, so an unrunnable service is a build failure rather than a
    surprise at deploy time."""
    makefile = (VAULT_ROOT / "Makefile").read_text()
    units = "\n".join(u.read_text() for u in (VAULT_ROOT / "systemd").glob("*.service"))
    for name in EXECUTABLE_DIRS:
        entries = sorted(
            p.name for p in (VAULT_ROOT / name).iterdir() if p.is_file() and not p.name.endswith((".md", ".pyc"))
        )
        assert entries, f"{name}/ is empty"
        for entry in entries:
            referenced = entry in units or entry in makefile
            assert referenced, (
                f"{name}/{entry} is not referenced by any systemd unit or Makefile target, so nothing would ever run it"
            )


@pytest.mark.parametrize("page", CLAIMING_PAGES, ids=lambda p: p.name)
def test_pages_do_not_still_claim_the_role_is_unbuilt(page: Path) -> None:
    """The old claim is now false, and a stale claim is worse than none.

    A reader who sees "specified, not built" in a role that has a signer will
    either distrust the code or trust the prose. Neither is useful.
    """
    if not page.is_file():
        pytest.skip(f"{page.name} not present")
    text = page.read_text()
    stale = re.search(
        r"nothing here runs yet|is documented as unbuilt|"
        r"status:\s*\**specified, not built",
        text,
        re.I,
    )
    assert stale is None, (
        f"{page.name} still claims the role is unbuilt: {stale.group(0)!r}. Describe what works instead."
    )


def test_claiming_pages_name_something_real() -> None:
    """Not merely 'no longer says unbuilt' — must positively describe the surface."""
    for page in CLAIMING_PAGES:
        if not page.is_file():
            continue
        text = page.read_text()
        assert any(token in text for token in ("services/", "scripts/", "systemd/", "signer")), (
            f"{page.name} must describe the executable surface, not just deny it"
        )


def test_charter_does_not_hard_code_a_machine_path() -> None:
    """The parent charter says never hard-code the vault path; hold it to that."""
    for page in (AGENTS, MISSION, PLAN):
        text = page.read_text()
        assert "/mnt/knowledge/sparknet" not in text, (
            f"{page.name} hard-codes the vault path — resolve it from .env instead"
        )


# --- the spec/impl boundary, made detectable ------------------------------------
#
# Build plan Step 2 asked for one thing here: "make the 'specified, not built'
# status machine-detectable", so that it cannot silently rot into a false claim.
# Its original DoD (2) — "asserts this subvault declares itself unbuilt" — was
# true when the step was written and became false the moment the first
# executable surface landed (Step 15). Asserting it now would assert a lie, so
# the status is asserted in the direction that still holds: the role *declares*
# its build state, and the declaration must agree with the tree and the plan.


def test_the_intent_page_exists_and_declares_the_role() -> None:
    """INTENT is the design contract beside MISSION, not a signed note."""
    fields = frontmatter(INTENT)
    assert fields.get("role") == "master", "master-node/INTENT.md must declare role: master"
    assert fields.get("template") == "true", "master-node/INTENT.md must declare template: true"
    assert fields.get("intent") == "design-contract", "master-node/INTENT.md must declare intent: design-contract"


def test_the_role_declares_a_build_status_that_agrees_with_the_tree() -> None:
    """DoD (2), inverted honestly.

    The declaration lives in one place — `MISSION.md` — and is checked against
    reality in both directions: a role with code cannot call itself unbuilt,
    and a role with no code cannot call itself built.
    """
    declared = frontmatter(MISSION).get("status")
    assert declared in BUILD_STATUSES, (
        f"MISSION.md must declare a status from {list(BUILD_STATUSES)}, found {declared!r}"
    )
    has_surface = any((VAULT_ROOT / name).is_dir() for name in EXECUTABLE_DIRS)
    if has_surface:
        assert declared != "unbuilt", (
            "this role has scripts/, services/ and systemd/; declaring it unbuilt is the "
            "false claim Step 2 was reopened to stop"
        )
    else:
        assert declared == "unbuilt", "this role has no executable surface, so it cannot declare anything but 'unbuilt'"


def test_the_declared_status_agrees_with_the_plan() -> None:
    """A role whose plan still has open steps is not `built`.

    The plan is the work order; the declaration is the summary. When they
    disagree, the declaration is the one that rots, because nobody re-reads a
    status line while working through the plan.
    """
    declared = frontmatter(MISSION).get("status")
    assert declared in BUILD_STATUSES
    still_open = open_plan_steps(PLAN)
    if still_open:
        assert declared != "built", (
            f"the plan still has open steps {still_open}, so the role cannot declare itself built"
        )
    else:
        assert declared == "built", "every step in the plan is closed, so the role must declare itself built"


@pytest.mark.parametrize("page", DOC_PAGES, ids=lambda p: p.name)
def test_every_doc_page_declares_its_build_status(page: Path) -> None:
    """Each page states, machine-readably, what it describes.

    This is the "specified, not built" status made detectable: a reader — human
    or agent — can tell from the frontmatter alone whether the page describes
    something that runs.
    """
    declared = frontmatter(page).get("status")
    assert declared in BUILD_STATUSES, (
        f"{page.name} must declare a status from {list(BUILD_STATUSES)} in its frontmatter, found {declared!r}"
    )


@pytest.mark.parametrize("page", DOC_PAGES, ids=lambda p: p.name)
def test_a_doc_page_that_is_not_built_carries_a_marker(page: Path) -> None:
    """DoD (3): a page that is not built says so where the reader meets it.

    The frontmatter is for machines. The callout is for people: it has to be in
    the body, above the prose, or it protects nobody.
    """
    declared = frontmatter(page).get("status")
    if declared == "built":
        pytest.skip(f"{page.name} declares itself built")
    assert CALLOUT.search(page.read_text()), (
        f"{page.name} declares status {declared!r} but carries no callout; a page that is "
        "not built must say so in its body, not only in its frontmatter"
    )


@pytest.mark.parametrize("page", DOC_PAGES, ids=lambda p: p.name)
def test_a_doc_page_does_not_claim_this_role_has_no_surface(page: Path) -> None:
    """The stale claim, in the shape it actually took.

    The Master control-plane page said for months that this role "has no
    `scripts/`, `services/` or `systemd/` directory". Steps 15-16 made that
    false, and a page that still says it is worse than a page that says
    nothing.
    """
    stale = re.search(
        r"this role has no `?scripts/`?, `?services/`? or `?systemd/`? directory|"
        r"nothing on this page is implemented",
        page.read_text(),
        re.I,
    )
    assert stale is None, f"{page.name} still claims the role has no surface: {stale.group(0)!r}"


def test_master_template_is_documentation_only() -> None:
    """The one config artifact here must be a template, not a live config."""
    template = VAULT_ROOT / "configs" / "wireguard" / "master-peer.template"
    assert template.is_file(), "the Master peer stanza template is missing"
    text = template.read_text()
    # Placeholders, not values that could look like a real deployment.
    assert "10.100.0." in text, "template should document the Master overlay address"
    live = VAULT_ROOT / "configs" / "wireguard" / "wg0.conf"
    assert not live.exists(), (
        "a live wg0.conf in the vault would be machine state; the template is rendered to .state/ at provisioning time"
    )


def test_private_key_is_never_in_the_vault(state_dir) -> None:
    """The single most damaging mistake available on this role.

    Two claims, checked separately because one scan cannot make both.

    **Nothing key-shaped is tracked.** This is the claim that cannot be repaired by
    deleting a file, so it is asked of git rather than of the working tree: a key
    removed from disk but still in history is exactly the disaster.

    **Nothing key-shaped is in the vault proper.** The state dir is *outside* the
    vault entirely — `state_dir` comes from the env script, so there is no
    exclusion to carve out here. It used to be `<role>/.state`, excluded narrowly
    by exact path; that arrangement put the signing key under the admin surface's
    bind mount, so the exclusion was removed by moving the keys rather than by
    widening the glob.
    """
    import subprocess

    patterns = ("master-node/**.ed25519", "master-node/**.key", "master-node/**.pem", "master-node/**privkey*")
    tracked = subprocess.run(
        ["git", "-C", str(FABRIC_ROOT), "ls-files", *patterns],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    assert not tracked, (
        f"private key material is tracked by git: {tracked}. It is in history — "
        f"rotate the key; removing the file changes nothing."
    )

    assert state_dir not in VAULT_ROOT.parents and state_dir != VAULT_ROOT, (
        f"SPARKNET_STATE_DIR resolves to {state_dir}, inside the vault. The admin "
        f"surface bind-mounts this tree read-only into an LLM container, so a key "
        f"here is readable from it."
    )
    suspicious = [
        p
        for p in VAULT_ROOT.rglob("*")
        if p.is_file()
        and p.suffix not in {".pyc"}
        and "sessions" not in p.parts
        and not p.is_relative_to(state_dir)
        and re.search(r"\.(ed25519|key|pem|seed)$|id_ed25519|privkey", p.name, re.I)
    ]
    assert not suspicious, f"possible Master private key in the vault: {suspicious}"


def test_state_dir_private_keys_are_not_world_readable(state_dir) -> None:
    """`$SPARKNET_STATE_DIR` is the one place a private key may exist, so police it.

    Without this, "no key in the vault" is satisfied by moving every key into a
    world-readable directory — which is what a careless umask on a shared machine
    produces, and it fails without any error anyone would notice.
    """
    keys_dir = state_dir / "keys"
    if not keys_dir.is_dir():
        pytest.skip("no keys generated yet on this host (run `make keygen`)")

    mode_dir = stat.S_IMODE(keys_dir.stat().st_mode)
    assert mode_dir == 0o700, f"{keys_dir} is mode {oct(mode_dir)}; the key directory must be 0700"
    for key in keys_dir.glob("*.ed25519"):
        mode = stat.S_IMODE(key.stat().st_mode)
        assert mode == 0o600, (
            f"{key} is mode {oct(mode)}; a private half must be 0600. This is the "
            f"one assertion standing between a keygen run and a readable key."
        )


def test_the_identity_manifest_uses_the_contract_field_names():
    """A manifest whose field names drift from the contract hashes to nothing.

    `authz.fingerprint` deliberately ignores any field outside `IDENTITY_FIELDS`, so
    a renamed field does not raise and does not warn: the identity simply hashes
    differently from the one the contract describes, and the node is unreachable
    for reasons that look like a network fault. This manifest had drifted to
    `wireguard_pubkey_b64` while the contract, the peer manifest, authz and the
    docs all said `wireguard_public_key_b64`.
    """
    import importlib.util
    import json
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "master-node/manifests/node-identity.json").read_text())
    contract = json.loads((root / "contracts/identity-schema.json").read_text())

    spec = importlib.util.spec_from_file_location("spec_authz_field_check", root / "shared/sparknet-authz.py")
    authz = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = authz
    spec.loader.exec_module(authz)

    declared = tuple(contract["identity_fields"])
    assert declared == authz.IDENTITY_FIELDS, (
        "the contract and the one authz implementation disagree about which fields "
        "an identity is made of; the implementation is what actually hashes"
    )
    missing = [f for f in declared if f not in manifest]
    assert not missing, (
        f"the master identity manifest is missing {missing}, so its fingerprint "
        f"would be computed over a different set of fields than the contract says"
    )
