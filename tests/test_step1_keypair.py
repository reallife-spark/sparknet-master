"""Step 1: the Master role's real keypair, and what it is not.

Step 1's DoD asks for five things, and two of them were already contradictory
before any code ran:

* **"a keypair exists at `$SPARKNET_STATE_DIR/keys` at 0600"** and **`make
  keys-check` green**. Before this file, `keys-check` scanned the whole vault for
  key-shaped files, and `$SPARKNET_STATE_DIR` defaults to `<role>/.state` — inside
  the vault. Generating the keypair the DoD asks for therefore *broke* the check
  that the same DoD asks for. The check now asks git whether anything key-shaped is
  tracked, and separately polices the modes of the one directory where key
  material may legitimately live.

* **"`manifests/master-identity.json` describes the Master with `role: master`"**.
  Step 1 predates Step 13. Step 13 replaced the model in which the Master was a
  separate species with its own identity, and `tests/test_contracts.py::
  test_a_node_declares_itself_peer_until_it_is_elected` exists precisely to fail a
  deployment site that asserts authority it was not granted. The manifest says
  `role: peer`; what it names as `master` is the *role this subvault implements*,
  which is scope, not authority. That contradiction is recorded in the file and in
  the plan rather than resolved by quietly satisfying whichever test ran last.

Everything here is about the gap between *having a key* and *holding authority*.
Those are different, the second is strictly harder, and the most useful thing this
step can assert is that the first never quietly becomes the second.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import resolve_state_dir

VAULT_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = VAULT_ROOT.parent
MANIFEST = VAULT_ROOT / "manifests" / "master-identity.json"
NODE_IDENTITY = VAULT_ROOT / "manifests" / "node-identity.json"
PLAN = VAULT_ROOT / "plans" / "archive" / "MASTER_BUILD_PLAN_FULL_2026-10-30.md"

#: The three keypairs keygen mints. The split is the security model, so its shape
#: is part of this step's DoD rather than an implementation detail.
KEY_NAMES = ("cluster", "operational", "identity")


#: Resolved from the env script, never hardcoded. See conftest.py: the state dir
#: used to be `<role>/.state`, which is inside the tree the admin surface
#: bind-mounts, and every test that assumed that path would have gone on
#: cheerfully skipping against a directory that no longer held anything.
_KEY_DIR: Path | None = None


def _key_dir() -> Path:
    global _KEY_DIR
    if _KEY_DIR is None:
        _KEY_DIR = resolve_state_dir() / "keys"
    return _KEY_DIR


def _has_keys() -> bool:
    keys = _key_dir()
    return all((keys / f"{n}.ed25519").is_file() for n in KEY_NAMES)


needs_keys = pytest.mark.skipif(
    not _has_keys(),
    reason="no keypair on this host yet — run `make -C master-node keygen`",
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def authz():
    return _load("step1_authz", FABRIC_ROOT / "shared" / "sparknet-authz.py")


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST.read_text())


# --- DoD (1): a real keypair, protected, untracked ----------------------------


@needs_keys
@pytest.mark.parametrize("name", KEY_NAMES)
def test_each_private_half_exists_at_0600(name: str) -> None:
    key = _key_dir() / f"{name}.ed25519"
    assert key.is_file(), f"{key} is missing — run `make keygen`"
    mode = stat.S_IMODE(key.stat().st_mode)
    assert mode == 0o600, f"{key} is mode {oct(mode)}, expected 0600"


@needs_keys
def test_the_key_directory_is_0700() -> None:
    mode = stat.S_IMODE(_key_dir().stat().st_mode)
    assert mode == 0o700, (
        f"{_key_dir()} is mode {oct(mode)}. A private key directory that any local "
        f"user can list is a private key directory in name only."
    )


@needs_keys
def test_no_private_half_is_tracked_by_git() -> None:
    tracked = subprocess.run(
        [
            "git",
            "-C",
            str(FABRIC_ROOT),
            "ls-files",
            "master-node/.state/**",
            "master-node/**.ed25519",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    assert not tracked, (
        f"key material is tracked: {tracked}. It is in history — deleting the file "
        f"changes nothing and .gitignore is too late."
    )


@needs_keys
def test_the_legacy_state_path_stays_ignored_as_a_backstop() -> None:
    """.gitignore keeps covering `<role>/.state` even though nothing writes there.

    The state dir moved out, so this is belt-and-braces: if a future edit puts it
    back, or an operator exports the old path, gitignore is still the last thing
    between that and a committed private key.

    Skipped outside a git work tree. A node bundle ships without one, and
    `git check-ignore` exits 128 there rather than answering no — so asserting
    returncode 0 would fail every bundle for a reason that has nothing to do with
    keys. Found by `scripts/sparknet-bundle.sh --verify`.
    """
    probe = subprocess.run(
        ["git", "-C", str(FABRIC_ROOT), "check-ignore", "-q", "master-node/.state/keys/operational.ed25519"],
        capture_output=True,
        check=False,
    )
    if probe.returncode == 128:
        pytest.skip("not a git work tree (extracted node bundle)")
    assert probe.returncode == 0, (
        "master-node/.state/ is no longer gitignored. Nothing writes there any "
        "more, but an ignored path costs nothing and a committed key costs the key."
    )


@needs_keys
def test_each_public_half_is_a_real_public_key_for_its_private_half(
    authz,
) -> None:
    """Both halves from one invocation.

    A public half that does not match its private one is the quietest possible
    keygen bug: everything loads, every read works, and the node is simply
    unreachable. Asserted rather than assumed because it costs one derivation.
    """
    for name in KEY_NAMES:
        private_b64 = (_key_dir() / f"{name}.ed25519").read_text().strip()
        public_b64 = (_key_dir() / f"{name}.pub.b64").read_text().strip()
        key = authz.private_key_from_b64(private_b64)
        derived = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        assert derived == public_b64, (
            f"{name}.pub.b64 does not match {name}.ed25519. Either a second "
            f"keygen call overwrote one half, or the file was edited. A node with "
            f"this mismatch is unreachable for reasons that look like a network fault."
        )


@needs_keys
def test_no_two_keys_are_the_same_key(authz) -> None:
    """Three distinct keys, or the split means nothing.

    If the cluster key and the operational key were the same value, every node
    would hold a key that can sign a registry entry, and `key-management.md`'s
    central argument would be false in the one place it could be checked.
    """
    publics = {name: (_key_dir() / f"{name}.pub.b64").read_text().strip() for name in KEY_NAMES}
    assert len(set(publics.values())) == len(KEY_NAMES), (
        f"keys are not distinct: {publics}. The cluster key signs the root only; "
        f"if it equals the operational key, every member can sign registry entries."
    )


# --- DoD (2) and the Step 1 / Step 13 contradiction ---------------------------


def test_master_identity_exists_and_describes_this_role() -> None:
    assert MANIFEST.is_file(), f"{MANIFEST} is missing. Step 1 asks for a description of the Master role."


def test_the_master_manifest_declares_peer_and_explains_why(manifest: dict) -> None:
    """Step 1 asked for `role: master`. It gets `role: peer`, deliberately.

    A master-capable node that claims to *be* Master on disk is asserting
    authority it was not granted, and Step 13 removed exactly that model. The
    cross-role test enforces it; this one makes sure the file *says why*, so the
    next reader does not "fix" it back.
    """
    assert manifest["role"] == "peer", (
        f"master-identity.json claims {manifest['role']!r}. Authority comes from a "
        f"signed cluster trust root, not from a manifest or a directory name."
    )
    note = manifest.get("role_note", "")
    assert "Step 1" in note and "Step 13" in note, (
        "role_note must record that this contradicts Step 1 of the build plan and "
        "why Step 13 won. Without the citation, the next reader sees a manifest "
        "that disagrees with the plan and has no way to tell which is right."
    )


def test_the_role_scope_is_named_separately_from_the_identity_role(
    manifest: dict,
) -> None:
    """`role_implemented_by` is scope. It must not read like a grant."""
    assert manifest.get("role_implemented_by"), (
        "the manifest should still say which role this subvault implements — that "
        "is legitimate scope, and losing it makes the file read like a peer."
    )
    assert "role" not in set(manifest) - {"role", "role_note", "role_implemented_by"}, (
        "a second field named `role` would be a second role declaration, and two of them can disagree"
    )


def test_both_identity_manifests_agree_on_the_anchor(manifest: dict) -> None:
    """Two identity files, one address. Drift here is a routing failure."""
    node = json.loads(NODE_IDENTITY.read_text())
    assert manifest["overlay_ipv4"].split("/")[0] == "10.100.0.1", (
        f"the Master role is anchored at 10.100.0.1 per contracts/overlay.json; this says {manifest['overlay_ipv4']}"
    )
    assert node["overlay_ipv4"] != manifest["overlay_ipv4"], (
        "node-identity.json is the *template* and should carry an unset address; "
        "if it carries the Master's anchor, an unprovisioned deployment would "
        "collide with the real Master on the overlay"
    )


def test_the_manifest_does_not_claim_to_hold_the_operational_key(
    manifest: dict,
) -> None:
    """Generating a key is Step 1. Holding authority is election. Never the same."""
    operational = manifest["operational_key"]
    assert operational["path_never_committed"] is True
    assert "$SPARKNET_STATE_DIR" in operational["generated_to"], (
        "the manifest must name the state directory, not a vault path. A key path "
        "inside the vault is a key in git's next commit."
    )
    assert "elect" in operational["held"].lower() or "only when" in operational["held"].lower(), (
        f"held={operational['held']!r} — this must make clear that the key confers "
        f"authority only once a trust root names it"
    )


def test_the_manifest_states_the_election_path_actually_implemented(manifest: dict) -> None:
    """Point at the real mechanism, not an aspiration.

    `authority_path` is the chain from the verified root to the ledger record. If
    that chain changes, this string is the thing that will still be pointing at the
    old one, so a test asserts it names the files that exist.
    """
    election = manifest["election"]
    assert election["threshold"].startswith("2 of 2 or 3 of 3"), (
        "the threshold is n-of-n — 2 of 2 in a pair, 3 of 3 in the full cluster — "
        "and unanimity is the reason a majority was rejected; a different number "
        "here would be a consensus change"
    )
    chain = election["authority_path"]
    for token in ("trust-root.json", "sparknet-signer.py"):
        assert token in chain, (
            f"authority_path must name {token} — it is the chain that actually decides what this node may sign"
        )
    assert (VAULT_ROOT / "services" / "sparknet-signer.py").is_file(), (
        "authority_path names services/sparknet-signer.py and it does not exist"
    )


# --- DoD (3): the contract no longer carries authority nobody voted for --------


def test_the_contract_no_longer_says_the_placeholder_key_is_trackable() -> None:
    contract = json.loads((FABRIC_ROOT / "contracts" / "identity-schema.json").read_text())
    spec = contract["master_public_key"]
    assert spec["tracked"] is False, (
        "a tracked master public key was authoritative under the single-key model. "
        "Under a trust root the authoritative public half travels inside the root, "
        "so `tracked: true` here would invite exactly the model Step 13 replaced."
    )
    status = spec["shipped_value_status"]
    for marker in ("placeholder", "cannot sign", "trust root"):
        assert marker.lower() in status.lower(), (
            f"shipped_value_status must say the shipped key is a placeholder, that "
            f"it cannot sign, and that a trust root is what makes a key live. "
            f"Missing: {marker!r}"
        )


def test_the_contract_points_publication_at_the_root_not_a_file() -> None:
    contract = json.loads((FABRIC_ROOT / "contracts" / "identity-schema.json").read_text())
    published = contract["master_public_key"].get("published_to", "")
    assert "trust root" in published.lower(), (
        "a peer's trust in the signing key comes from the root it was handed. If "
        "the contract still names a file as the publication path, that file is a "
        "second root of authority nobody voted for."
    )


def test_the_shipped_key_file_is_still_a_fixture_and_says_so() -> None:
    """The file stays, because the peer's tests and the guard read it.

    Removed, every peer test that verifies a signature would break — and the
    correct fix for that is a fixture, not a lie in the contract.
    """
    fixture = FABRIC_ROOT / "peer-node" / "manifests" / "keys" / "master-ed25519.pub.b64"
    assert fixture.is_file(), (
        "the peer suite and sparknet-guard-d.py read this path. If it was removed, "
        "they must be updated in the same commit rather than left failing."
    )
    base64.b64decode(fixture.read_text().strip(), validate=True)


# --- DoD (4) and (5): gates, and a signed entry that verifies -------------------


def test_the_state_dir_is_outside_the_vault_entirely() -> None:
    """The state dir moved out of the vault, and that is now a load-bearing claim.

    It used to default to `<role>/.state`. That was defensible while it held
    nothing — bundle portability, and gitignore as the backstop — and it stopped
    being defensible the moment Step 1 put a real private key in it, because the
    admin surface bind-mounts this tree read-only into an LLM-driven container.
    `.gitignore` was never the problem; the problem was that the key was inside the
    mount at all, and gitignore cannot express "not reachable by a container".

    So the default is `$XDG_STATE_HOME`/`~/.local/state`, and this asserts the
    *resolved* location rather than trusting the docstring. `make keys-check` fails
    too if `SPARKNET_STATE_DIR` is overridden back inwards, because an operator
    setting the variable by hand is the most likely way to undo this.
    """
    state = resolve_state_dir().resolve()
    for inside in (VAULT_ROOT, FABRIC_ROOT):
        assert state != inside and inside not in state.parents, (
            f"SPARKNET_STATE_DIR resolves to {state}, which is inside {inside}. "
            f"The vault is bind-mounted read-only into the admin surface."
        )


def test_no_state_directory_survives_inside_the_role() -> None:
    """The old location must be gone, not merely unused.

    A leftover `<role>/.state/keys/` holding a stale keypair is worse than never
    having moved: `make keygen` will not rotate it, so it sits there indefinitely,
    and anyone reading the role sees two plausible signing keys.
    """
    stale = VAULT_ROOT / ".state"
    assert not stale.exists(), (
        f"{stale} still exists. Keys now live in {resolve_state_dir()}. Remove the "
        f"old directory — check it holds nothing live before deleting."
    )
    leftovers = [p for p in VAULT_ROOT.rglob("*.ed25519") if p.is_file()]
    assert not leftovers, f"key-shaped files inside the vault: {leftovers}"


def test_the_vault_references_the_state_dir_only_by_variable() -> None:
    """No committed file may hardcode where the keys live.

    An absolute host path in a template breaks every other host and gets "fixed"
    by pointing into the vault instead — the one place it must never point.

    Scanned over executable and config surface only. `*.md` and test docstrings
    are excluded on purpose: explaining the move *requires* naming the old path,
    and prose about `<role>/.state` is not a reference that resolves anything.
    Narrowing the scan to files that could actually open a file is what keeps it
    from flagging the documentation of the bug it prevents.
    """
    roots = [
        VAULT_ROOT / "services",
        VAULT_ROOT / "scripts",
        VAULT_ROOT / "configs",
        VAULT_ROOT / "manifests",
        VAULT_ROOT / "systemd",
    ]
    hardcoded = []
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if (
                p.is_file()
                and p.suffix in {".py", ".sh", ".yml", ".yaml", ".json"}
                and re.search(r"(?<!\$)\b\w*\.state/keys", p.read_text(errors="ignore"))
            ):
                hardcoded.append(p)
    makefiles = [VAULT_ROOT / "Makefile"]
    hardcoded += [p for p in makefiles if p.is_file() and ".state/keys" in p.read_text()]
    assert not hardcoded, (
        f"these files still hardcode a state-dir key path: {hardcoded}. The state "
        f"dir moved to $XDG_STATE_HOME; reference $SPARKNET_STATE_DIR instead."
    )


@needs_keys
def test_a_signed_entry_verifies_against_this_nodes_own_key(authz) -> None:
    """DoD (5), and the honest form of it.

    The entry is signed by the *generated* operational key and verified through
    `authz.evaluate`, the same path a peer uses. So this proves the keypair is
    real and loadable — it does **not** prove the node may sign anything in the
    fabric, because no trust root names it. Signing authority needs an election,
    and the signer refuses to start without one.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
    identity = {
        "node_id": "step1-selfcheck",
        "role": "peer",
        "wireguard_public_key_b64": (_key_dir() / "cluster.pub.b64").read_text().strip(),
        "overlay_ipv4": "10.100.0.9/32",
        "requested_capabilities": ["telemetry"],
    }
    private = authz.private_key_from_b64((_key_dir() / "operational.ed25519").read_text().strip())
    entry = authz.sign_authorization(identity, private, ["telemetry"], ttl_days=1, now=now)
    registry = {"authorizations": [entry]}
    public = authz.public_key_from_b64(entry["identity"] and (_key_dir() / "operational.pub.b64").read_text().strip())

    decision = authz.evaluate(identity, registry, public, now=now)
    assert decision.allowed, f"the operational key failed to verify its own entry: {decision.reason}"
    assert decision.capabilities == ["telemetry"]

    # And it fails closed against a different key — a key that signs correctly is
    # not the same claim as a key that is authorised.
    other = authz.public_key_from_b64((_key_dir() / "cluster.pub.b64").read_text().strip())
    denied = authz.evaluate(identity, registry, other, now=now)
    assert not denied.allowed, (
        "an entry verified under the wrong public key. The signature check is not "
        "binding the signer to the key the verifier expects."
    )
    assert denied.reason == authz.REASON_BAD_SIGNATURE, denied.reason
    assert timedelta  # keep the import honest


def test_nothing_in_the_state_dir_is_referenced_as_authority_by_a_template(
    manifest: dict,
) -> None:
    """A template pointing at a *state* path is wrong; pointing at a role path is not.

    `generated_to` naming `$SPARKNET_STATE_DIR/keys/...` is correct. A template
    claiming the key is at a vault-relative path would put it in git. Guarded so
    the next edit does not make that mistake quietly.
    """
    generated = manifest["operational_key"]["generated_to"]
    assert not generated.startswith("/mnt/"), (
        "an absolute host path in a committed template breaks every other host and "
        "tends to get 'fixed' by pointing at the vault instead, which is the one "
        "path that must never hold a key"
    )
    assert not (VAULT_ROOT / "manifests" / "keys").exists() or not list(
        (VAULT_ROOT / "manifests" / "keys").glob("*.ed25519")
    ), "no private key under manifests/keys/ in this role"


def test_the_plan_records_the_step_1_step_13_contradiction() -> None:
    """A contradiction resolved in code must be recorded where the plan is.

    Whoever reads Step 1 will read `role: master` and see `role: peer` on disk. If
    the plan does not say why, the most likely outcome is that someone "fixes" the
    manifest back and breaks the elected model.
    """
    text = PLAN.read_text()
    step1 = text[text.index("## Step 1") : text.index("## Step 2")]
    assert "Step 13" in step1, (
        "Step 1's `role: master` DoD contradicts Step 13's elected model and the "
        "resolution must be written into Step 1 itself."
    )


def test_state_dir_is_not_shipped_in_a_bundle() -> None:
    """A bundle must never carry keys, so the exclusion is asserted, not hoped for."""
    script = (FABRIC_ROOT / "scripts" / "sparknet-bundle.sh").read_text()
    assert ".state" in script, (
        "sparknet-bundle.sh must exclude .state/ from the bundle. The tar exclusion "
        "list is the only thing standing between a generated key and a shipped "
        "artefact."
    )
    for pattern in ("--exclude=.state", "--exclude='.state'"):
        if pattern in script:
            break
    else:
        assert any(".state" in line and "exclude" in line for line in script.splitlines()), (
            "found no --exclude for .state in the bundle script"
        )


def test_keys_check_and_the_suite_agree_about_what_the_state_dir_is() -> None:
    """Two independent guards, one policy.

    `make keys-check` and `test_state_dir_private_keys_are_not_world_readable` in
    `test_master_spec.py` enforce the same rule by different means. If one starts
    skipping the state dir and the other does not, the intent has drifted and
    nobody will notice until a key is readable.
    """
    makefile = (VAULT_ROOT / "Makefile").read_text()
    assert "expected 600" in makefile and "expected 700" in makefile, (
        "the Makefile target no longer checks modes; the suite and the make target must enforce the same rule"
    )
    spec = (VAULT_ROOT / "tests" / "test_master_spec.py").read_text()
    assert "0o600" in spec and "0o700" in spec, "the python guard no longer checks modes; see above"
    assert os.sep == "/", "this file's mode expectations are written for posix stat"
