"""Master parity: this role runs the peer's services, and there is provably one copy.

The peer already has a guard that verifies Master signatures and a dispatch
bridge. A master is a peer that won an election, so it runs those same files
rather than its own versions of them.

These tests assert the resolution *and* the single copy. A second copy of
`sparknet-guard-d.py` appearing under `master-node/` is the failure this whole
step exists to prevent: the two would drift, and the drift would show up as
signatures that verify on one node and fail on another.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
PEER_ROOT = FABRIC_ROOT / "peer-node"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def parity():
    return _load("sparknet_parity", ROLE_ROOT / "services" / "sparknet-parity.py")


def test_parity_resolves_to_the_peer_services_directory(parity):
    assert parity.peer_services_dir() == (PEER_ROOT / "services").resolve(), (
        "this role must run the peer's services from the peer's own directory"
    )


@pytest.mark.parametrize("name", ["sparknet-guard-d.py", "sparknet-dispatch-bridge.py"])
def test_each_service_resolves_to_the_peers_own_file(parity, name):
    resolved = Path(parity.resolved_paths()[name])
    assert resolved == (PEER_ROOT / "services" / name).resolve(), (
        f"{name} resolved to {resolved}, which is not the peer's own file"
    )
    assert resolved.is_file()


def test_loading_a_service_yields_the_peers_module(parity):
    """Not just the right path — the loaded module must be the peer's code."""
    module = parity.load_peer_service("sparknet-guard-d.py")
    source = (PEER_ROOT / "services" / "sparknet-guard-d.py").read_text()
    assert module.__file__ == str((PEER_ROOT / "services" / "sparknet-guard-d.py").resolve())
    # A distinctive string from the peer's implementation must be present, proving
    # the peer's code ran rather than something merely named like it.
    assert "10.100.0.1" in source
    assert hasattr(module, "main"), "the peer's guard exposes main(); this did not"


def test_loading_is_idempotent(parity):
    first = parity.load_peer_service("sparknet-guard-d.py")
    second = parity.load_peer_service("sparknet-guard-d.py")
    assert first is second, (
        "loading twice produced two module objects; a module identity used as a "
        "cache key would then miss and re-execute the peer's service"
    )


def test_only_declared_peer_services_may_be_loaded(parity):
    with pytest.raises(parity.ParityError, match="not a peer service"):
        parity.load_peer_service("sparknet-signer.py")
    with pytest.raises(parity.ParityError, match="not a peer service"):
        parity.load_peer_service("../../../etc/passwd")


def test_parity_fails_loudly_instead_of_using_a_local_copy(parity, monkeypatch, tmp_path):
    """No fallback to a private copy. Silently running something different from
    what the peer runs is the exact failure this module exists to prevent."""
    monkeypatch.setenv("SPARKNET_PEER_NODE", str(tmp_path))
    monkeypatch.setattr(parity, "ROLE_ROOT", tmp_path)
    monkeypatch.setattr(parity.Path, "exists", lambda self: False)
    with pytest.raises(parity.ParityError) as excinfo:
        parity.peer_services_dir()
    message = str(excinfo.value)
    assert "will not" in message and "private copy" in message, (
        f"the error must say why it refuses, not merely that it failed: {message}"
    )


def test_no_duplicate_service_files_under_master_node():
    """The single-copy rule, asserted on the filesystem rather than by trust."""
    duplicates = [
        p
        for p in (ROLE_ROOT / "services").rglob("*.py")
        if p.name in ("sparknet-guard-d.py", "sparknet-dispatch-bridge.py")
    ]
    assert not duplicates, (
        f"the peer's services were copied into this role: {duplicates}. Load them "
        f"by path instead — two copies would drift silently."
    )


def test_parity_does_not_reach_the_signer(parity):
    """The operational key is the one thing parity must never hand out."""
    source = (ROLE_ROOT / "services" / "sparknet-parity.py").read_text()
    assert "signer" not in parity.PEER_SERVICES
    # The word appears in prose; what matters is that it is never imported.
    assert "import sparknet_signer" not in source
    assert "sparknet-signer" not in parity.PEER_SERVICES
    report = parity.parity_report()
    assert any("signer" in entry for entry in report["not_reachable_from_here"]), (
        "parity_report must state what it cannot reach, so the isolation is visible to an operator rather than implied"
    )
