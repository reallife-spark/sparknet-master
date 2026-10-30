"""Step 18 — the admin surface, and the one capability it must not acquire.

Three of the four DoD items are checkable here. The fourth (`make wiki-preflight`)
is checked by the Makefile because it is a property of the resolved environment,
not of a file.

The test that matters most is `test_the_admin_surface_carries_no_signing_capability`.
The others check that a thing exists; that one checks that a boundary holds. An
admin surface is the one place in this fabric where a prompt injection is a
normal Tuesday, and the operational key grants everything the peer roles
deliberately withhold — so a surface that could reach it inverts the whole thesis.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parents[1]
FABRIC_ROOT = ROLE_ROOT.parent
AGENT_DIR = ROLE_ROOT / ".opencode" / "agents"
ADMIN_SURFACE = ROLE_ROOT / "manifests" / "admin-surface.json"
MASTERSPIKE = ROLE_ROOT / "MASTERSPIKE-manifest.json"
CONTRACTS = FABRIC_ROOT / "contracts"
CONFIGS = ROLE_ROOT / "configs" / "admin-surface"
COMPOSE = CONFIGS / "docker-compose.admin.yml"
TERMINAL_CONFIG = CONFIGS / "opencode.json"

#: The capability that must never appear in anything the admin surface loads.
SIGNING = "sign"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def surface() -> dict:
    return _load(ADMIN_SURFACE)


@pytest.fixture(scope="module")
def spike() -> dict:
    return _load(MASTERSPIKE)


# --- DoD (1) admin agents resolve through `opencode agent list` ----------------


def test_the_admin_agents_exist_on_disk():
    """Checked before the CLI, so a missing file gives a readable failure.

    Asserting against `opencode agent list` alone would report a missing agent and
    a malformed one identically, and the second is the more interesting bug.
    """
    declared = _load(ADMIN_SURFACE)["agents"]["expected"]
    assert declared, "the admin surface declares no agents, so DoD (1) has no subject"
    for agent in declared:
        path = AGENT_DIR / agent["file"]
        assert path.is_file(), f"{agent['file']} is declared in admin-surface.json but absent"
        text = path.read_text()
        assert text.startswith("---"), f"{agent['file']} has no frontmatter"
        assert re.search(r"^description:\s*\S", text, re.MULTILINE), (
            f"{agent['file']} has no description, so nothing can route to it"
        )
        assert re.search(r"^mode:\s*(primary|subagent|all)\s*$", text, re.MULTILINE), (
            f"{agent['file']} does not declare a mode"
        )


def test_the_admin_agents_resolve_through_the_opencode_cli(tmp_path):
    """DoD (1), and the DoD's "read via a file, never a pipe" is load-bearing.

    This was written the obvious way first — `capture_output=True` — and it failed
    for a reason that had nothing to do with the agents. `opencode agent list`
    prints the full permission block for every agent, which on this role is about
    12 MB. Piped into a buffer, that arrives truncated to roughly 1 MB, and the
    role's own agents are at the end of the alphabetical list, so they are the
    first thing lost. The failure reads as "`cluster-admin` does not resolve" —
    pointing squarely at the agent file, which is fine, while the real fault is
    two lines above it in this function.

    So the output goes to a file handle and the file is read afterwards. A
    truncated read now shows up as a size assertion instead of as a plausible lie
    about the agents.
    """
    if shutil.which("opencode") is None:
        pytest.skip("opencode CLI not on PATH; the on-disk test above still applies")

    out = tmp_path / "agent-list.txt"
    with out.open("w") as handle:
        result = subprocess.run(
            ["opencode", "agent", "list"],
            cwd=ROLE_ROOT,
            stdout=handle,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            check=False,
        )
    size = out.stat().st_size
    listing = out.read_text()
    assert result.returncode == 0, (
        f"`opencode agent list` exited {result.returncode} in {ROLE_ROOT}: {result.stderr[:400]}"
    )
    assert listing.strip(), "`opencode agent list` produced no output at all"
    # Guards the mechanism this test depends on. A future opencode that prints less
    # is fine; one that grows past what a pipe would carry is not, and the failure
    # would otherwise look like a broken agent file again.
    assert size == len(listing), (
        f"agent list is {size} bytes but {len(listing)} characters decoded; the listing is not being read whole"
    )
    assert size > 100_000, (
        f"`opencode agent list` produced only {size} bytes from {ROLE_ROOT}. Expected "
        f"the full listing including permission blocks; a short read drops the "
        f"role's own agents and makes this test lie."
    )

    # The role's own agents, and the fabric orchestrator they hand off to.
    for agent in _load(ADMIN_SURFACE)["agents"]["expected"]:
        assert re.search(rf"^{re.escape(agent['name'])}\s+\(", listing, re.MULTILINE), (
            f"{agent['name']} is on disk but `opencode agent list` does not resolve "
            f"it from {ROLE_ROOT}. A file opencode cannot see is not an agent."
        )
    assert re.search(r"^sparknet-node\s+\(", listing, re.MULTILINE), (
        "the fabric orchestrator does not resolve from the master role, so an admin "
        "session cannot hand work off the way the role's own agents expect"
    )


def test_the_admin_agents_are_role_scoped_not_fabric_wide():
    """They must not be offered to a peer session.

    These agents are admin-geared. An admin agent visible on a peer is an agent
    that will eventually be used on a peer, by a session that has no business
    asking about cluster authority.
    """
    for agent in _load(ADMIN_SURFACE)["agents"]["expected"]:
        assert not (FABRIC_ROOT / ".opencode" / "agents" / agent["file"]).exists(), (
            f"{agent['file']} is in the fabric agent dir, so it is offered to peer "
            f"sessions too. Admin agents belong to the master role."
        )
    assert _load(ADMIN_SURFACE)["agents"]["role_scoped"] is True


# --- DoD (2) MASTERSPIKE has all three layers ---------------------------------


def test_masterspike_declares_all_three_layers_non_empty(spike):
    """The llm-wiki shape is raw -> wiki -> schema, and all three must be present.

    Checked for non-emptiness rather than mere presence: an empty layer satisfies
    a key-existence check and contributes nothing, which is the failure mode a
    presence test cannot see.
    """
    for layer in ("raw", "wiki", "schema"):
        assert layer in spike, f"MASTERSPIKE has no `{layer}` layer"
        body = spike[layer]
        assert isinstance(body, dict) and body, f"the `{layer}` layer is empty"
        assert body.get("orientation") == "administration", (
            f"the `{layer}` layer is oriented to {body.get('orientation')!r}, not "
            f"administration. MASTERSPIKE is the Master's knowledge manifest; a "
            f"peer-shaped layer here is a layer serving the wrong role."
        )


def test_masterspike_raw_layer_names_real_authoritative_files(spike):
    """A raw layer pointing at files that do not exist is worse than an empty one.

    It reads as sourced. An agent citing a manifest entry lands nowhere and has no
    way to notice, because the manifest asserted the path was there.
    """
    entries = spike["raw"]["authoritative"]
    assert entries, "the raw layer lists no authoritative sources"
    for entry in entries:
        path = entry["path"]
        # Resolved by trying both roots rather than by prefix: a prefix rule would
        # quietly mis-resolve anything named outside contracts/, and the failure
        # would again be "the manifest cites a file that does not exist".
        candidates = [ROLE_ROOT / path, FABRIC_ROOT / path]
        assert any(candidate.exists() for candidate in candidates), (
            f"MASTERSPIKE names {path} as authoritative, but it does not exist. "
            f"An unsourced manifest entry is a claim dressed as a citation."
        )
        assert entry.get("why"), f"the {path} entry says what it is, not why it matters"


def test_masterspike_schema_layer_forbids_the_failures_this_role_repeats(spike):
    """The schema layer must name the specific failure modes, not just 'be accurate'."""
    rules = spike["schema"]["rules"]
    for rule in (
        "three_states_only",
        "cite_or_mark",
        "no_secrets",
        "specification_is_not_implementation",
        "negative_results_belong",
    ):
        assert rule in rules, (
            f"the schema layer omits `{rule}`. Each of these is a mistake this role "
            f"has actually made or is positioned to make."
        )
    assert spike["schema"]["governs"] == ["raw", "wiki"], (
        "the schema layer must declare that it governs the other two, or it is a third document rather than a rulebook"
    )


def test_masterspike_does_not_smuggle_in_a_model_choice(spike):
    """No base model is named, because none has been chosen.

    Writing one in would read as a decision somebody made. The manifest's own
    `not_a_model_choice` field is the assertion; this is the check that it stays
    true if the file is later edited by someone in a hurry.
    """
    text = MASTERSPIKE.read_text()
    assert "not_a_model_choice" in spike, "the manifest must state why it names no model"
    for pattern in (r'"model"\s*:', r'"base_model"\s*:', r'"model_id"\s*:'):
        assert not re.search(pattern, text), (
            "MASTERSPIKE names a model. No model has been selected for the admin "
            "surface, and a manifest that implies otherwise is the exact class of "
            "false claim this role's schema layer forbids."
        )


# --- DoD (3) the admin surface cannot sign ------------------------------------


def test_the_admin_surface_carries_no_signing_capability(surface):
    """The load-bearing assertion of this step.

    Checked against the declared surface, the agent config, the terminal config
    and the compose file together, because a boundary asserted in one place and
    contradicted in another is not a boundary.
    """
    assert SIGNING in surface["capabilities"]["explicitly_not_granted"], (
        "admin-surface.json must name `sign` as explicitly not granted. An "
        "omission is not a refusal: the next reader cannot tell a deliberate "
        "exclusion from an oversight."
    )
    assert SIGNING not in surface["capabilities"]["granted"]
    assert surface["signing_boundary"]["reached_from_here"] is False

    for agent in surface["agents"]["expected"]:
        text = (AGENT_DIR / agent["file"]).read_text()
        # An admin agent may *discuss* signing; it may not be granted it.
        for match in re.finditer(r"capabilit(?:y|ies)[^\n]*", text, re.IGNORECASE):
            assert not re.search(rf"\b{SIGNING}\b", match.group(0)), (
                f"{agent['file']} appears to grant the `{SIGNING}` capability: {match.group(0)[:120]!r}"
            )

    terminal = _load(TERMINAL_CONFIG)
    for section, rules in terminal["permission"].items():
        assert isinstance(rules, dict), f"the {section} permission block is not a mapping"
        for pattern, action in rules.items():
            if action != "deny":
                continue
            assert "sign" not in pattern or "signer.sock" in pattern, (
                f"the {section} block denies {pattern!r} — a broad deny on the word "
                f"`sign` would also block ordinary administration"
            )
    # The state dir and the socket are denied by name, which is what actually
    # separates the surface from the key.
    terminal_text = TERMINAL_CONFIG.read_text()
    assert "SPARKNET_STATE_DIR" in terminal_text, (
        "the terminal config never mentions the state dir, so nothing denies the key that lives in it"
    )


def test_the_admin_terminal_loads_the_role_identity_pages():
    """The operator-facing terminal must see the Master's purpose and contract."""
    terminal = _load(TERMINAL_CONFIG)
    assert {"AGENTS.md", "MISSION.md", "INTENT.md"} <= set(terminal["instructions"]), (
        "the admin terminal config must load AGENTS.md, MISSION.md and INTENT.md"
    )


def test_the_compose_file_mounts_no_key_and_no_signer_socket():
    """Config as committed, because that is what a redeploy actually restores.

    A panel customisation made by clicking does not come back; a bind mount
    committed to a file does. If someone adds the state dir here, the isolation is
    gone on the next redeploy even though nothing in the code changed.
    """
    # Only the non-comment lines. The file discusses the state dir at length in
    # comments precisely to say it must never be mounted, so a whole-file scan
    # would fail on the explanation. What matters is what the config *does*.
    code = [line for line in COMPOSE.read_text().splitlines() if line.strip() and not line.strip().startswith("#")]
    body = "\n".join(code)
    for forbidden in ("SPARKNET_STATE_DIR", "signer.sock", "/keys", ".ed25519"):
        assert forbidden not in body, (
            f"the admin compose file references {forbidden!r} outside a comment. The "
            f"surface may not mount anything that reaches the operational key."
        )
    assert "10.100.0.1:8088:8080" in body, "the admin page must bind the overlay address explicitly, not a wildcard"
    assert "0.0.0.0" not in body, (
        "the admin page must never bind a wildcard address; it is reachable only from inside the overlay"
    )
    assert "RAG_INGESTION_ENABLED" in body, (
        "Open WebUI's own RAG store must be disabled in config, or the vault stops being the only knowledge base"
    )


def test_the_compose_mounts_do_not_reach_the_signing_key():
    """The structural version of the check above, and the one that actually bites.

    `test_the_compose_file_mounts_no_key_and_no_signer_socket` reads the compose
    file's *text*. That is a proxy. On 2026-10-05 Step 1 generated the Master's
    real keypair into `<role>/.state/keys`, and this file mounted
    `../..:/workspace/sparknet:ro` — so
    `/workspace/sparknet/master-node/.state/keys/operational.ed25519` was readable
    from the admin container. Not because the compose file mentioned it; because of
    what the mount *contains*. Every text-based assertion above passed, and the
    Step 18 guarantee was false.

    So: resolve every host path the compose file bind-mounts, and require the state
    dir to sit outside all of them. This is what makes the boundary structural
    rather than a promise in a comment that also has to keep the keys elsewhere.
    """
    import os

    probe = subprocess.run(
        [
            "bash",
            "-c",
            f'. "{ROLE_ROOT}/scripts/sparknet-master-env.sh" >/dev/null && printf "%s" "$SPARKNET_STATE_DIR"',
        ],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "HOME": os.environ.get("HOME", "/nonexistent")},
    )
    state_dir = Path(probe.stdout.strip()).resolve()

    mounts = re.findall(r"-\s+(\.{1,2}/[^:\s]+):", COMPOSE.read_text())
    assert mounts, (
        "found no bind mounts in the compose file. If the admin surface stopped "
        "mounting the vault, this test is asserting nothing — fix the test."
    )

    covered = [(m, (COMPOSE.parent / m).resolve()) for m in mounts]
    for source, resolved in covered:
        assert state_dir != resolved and resolved not in state_dir.parents, (
            f"the state dir {state_dir} is inside the bind mount {source} -> {resolved}. "
            f"Anything mounted here is readable from the LLM-facing admin surface."
        )

    # The specific case that happened, named so the failure is legible later.
    vault_mounts = [r for _, r in covered if r in {ROLE_ROOT, FABRIC_ROOT}]
    assert vault_mounts, (
        "expected the admin surface to mount the vault read-only; if that changed, "
        "re-check that it still cannot see the signing key."
    )
    for vault in vault_mounts:
        stray = [p for p in vault.rglob("*.ed25519") if p.is_file() and ".local" not in p.parts]
        assert not stray, (
            f"key material inside {vault}, which is bind-mounted into the admin "
            f"surface: {stray}. Move it out rather than documenting why it is safe."
        )


def test_the_admin_port_is_contracted_as_provisioned_not_implemented():
    """A listener claim must match a listener, so 8088 says `provisioned`.

    The distinction the contract already draws between `implemented` and
    `provisioned` is exactly this: config exists, nothing binds it. Marking it
    `implemented` would put a false claim in the one file both roles read.
    """
    ports = _load(CONTRACTS / "ports.json")["ports"]
    assert "8088" in ports, "the admin surface has no port in contracts/ports.json"
    entry = ports["8088"]
    assert entry["implementation_state"] == "provisioned", (
        f"8088 is marked {entry['implementation_state']!r}. Nothing binds it on any "
        f"host, so `implemented` would be a claim about a listener that does not exist."
    )
    assert entry["bound_by"] == "master"
    assert entry["overlay_only"] is True
    assert entry["binds_to"] == "10.100.0.1"
    assert entry["runtime"] == "not-verifiable-here", (
        "8088 cannot be observed from a host with no overlay interface; recording "
        "it any other way would imply a measurement nobody made"
    )


def test_the_admin_agents_do_not_claim_a_fabric_that_does_not_exist(surface):
    """Prose truth for the agent files.

    An agent is read by an LLM deciding what to do next. One that describes the
    fabric as a standing production deployment produces confident, wrong actions —
    and unlike a stale wiki page, its output is acted on immediately.

    The boundary is subtle since 2026-10-07: the election/signer arc has been
    **proven live** on real hosts (a 2/2 trust root, the signer as
    ``sparknet-master-signer.service``, a live revocation demo). That proof does
    not make any of these true **now** for the operator of this role:
    ``make units`` deliberately excludes the signer unit (enabling a key-holding
    process is the election's decision, not an install side effect), nothing
    listens on the admin page yet, and Phase 9's destructive legs remain
    unexecuted. So the phrases below are still claims an agent must never make
    as standing facts.
    """
    stale = re.compile(
        r"election (?:is )?(?:working|running|deployed)|"
        r"signer is (?:running|deployed)|"
        r"fully operational|production ready",
        re.IGNORECASE,
    )
    for agent in surface["agents"]["expected"]:
        text = (AGENT_DIR / agent["file"]).read_text()
        match = stale.search(text)
        assert match is None, (
            f"{agent['file']} claims {match.group(0)!r}. The role's signer is not "
            f"enabled by `make units`, the admin page is not bound, and Phase 9's "
            f"destructive legs are unexecuted; an agent that says otherwise will be "
            f"acted on."
        )
    # And positively: the limitation must be stated, not merely absent.
    assert "cannot sign" in (AGENT_DIR / "cluster-admin.md").read_text().lower()


# --- DoD (4) is the Makefile's job, but the resolution is assertable ----------


def test_the_wiki_suite_resolves_this_role_as_its_own_vault():
    """DoD (4)'s substance: the skills must land in `master-node/`, not the parent.

    `make wiki-preflight` proves the resolution end to end; this asserts the
    thing that would make it fail, so the cause is legible when it does.
    """
    env = ROLE_ROOT / ".env"
    assert env.is_file(), "master-node/.env is missing; run `make env-init`"
    text = env.read_text()
    match = re.search(r'^VAULT_PATH="?([^"\n]+)"?', text, re.MULTILINE)
    assert match, ".env does not set VAULT_PATH"
    assert Path(match.group(1)).resolve() == ROLE_ROOT.resolve(), (
        f"VAULT_PATH resolves to {match.group(1)}, not this role. Every page a wiki "
        f"skill writes would land in the wrong vault, silently."
    )
    for skill in ("wiki-status", "wiki-ingest", "wiki-query", "wiki-lint"):
        assert (FABRIC_ROOT / ".opencode" / "skills" / skill / "SKILL.md").is_file(), (
            f"the vendored {skill} skill is missing; the role has no global skill farm to fall back on by design"
        )
