"""Step 5: the Master issues guard approvals a peer will actually accept.

The test that matters is the last one: it signs on this side and applies on a
peer stub — the peer's *own* guard daemon, loaded by path — so "the two agree"
is a fact this suite enforces instead of an inference from reading both
implementations.

That leg was missing entirely, and it was hiding a three-way disagreement. The
Master's issuer signed ``{target, content_digest}``, the isolated signer signed
``{peer_fingerprint, guard_protocol_version, target_path, action}`` and the peer
verified ``{file_path, content_b64, content_sha256, issued_at, expires_at,
nonce, request_id}``. Every side was internally consistent, every side's own
tests passed, and no approval the Master could produce was one a peer would
accept. The rule now lives once, in ``shared/sparknet-authz.py``.

The peer's *write* leg needs euid 0 and ``chattr``, so the peer stub runs in
``--dry-run``: it performs the whole verification path — signature, peer
binding, replay, content digest, protected path, capability — and audits the
decision, without touching the filesystem. Writing a protected file is a
target-node step, and the peer's own suite says the same.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
GUARD = FABRIC_ROOT / "peer-node" / "services" / "sparknet-guard-d.py"
GUARD_ROUTE = "/api/v1/critical-file/patch"


def _load_authz():
    """The one shared implementation, by path — the reason there is one."""
    spec = importlib.util.spec_from_file_location(
        "sparknet_authz_approval", FABRIC_ROOT / "shared" / "sparknet-authz.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


authz = _load_authz()


# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def master_state(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey]:
    """A throwaway Master state dir holding one operational key.

    The test does not use the real signing key: what is under test is the
    protocol, not the custody of a secret.
    """
    key = Ed25519PrivateKey.generate()
    state = tmp_path / "master-state"
    keys = state / "keys"
    keys.mkdir(parents=True)
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    key_file = keys / "operational.ed25519"
    key_file.write_text(base64.b64encode(raw).decode() + "\n")
    key_file.chmod(0o600)
    return state, key


@pytest.fixture
def peer_vault(tmp_path: Path, master_state) -> tuple[Path, Path]:
    """A minimal peer vault: manifests, a registry granting guard-apply, a target."""
    _state, key = master_state
    vault = tmp_path / "peer"
    (vault / "manifests" / "keys").mkdir(parents=True)

    target = tmp_path / "protected.txt"
    target.write_text("# original\n")

    identity = {
        "node_id": "peer-test",
        "role": "peer",
        "wireguard_public_key_b64": base64.b64encode(b"\x11" * 32).decode(),
        "overlay_ipv4": "10.100.0.9/32",
        "requested_capabilities": ["telemetry", "p2p-sync", "guard-apply"],
    }
    (vault / "manifests" / "node-identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    (vault / "manifests" / "critical-manifest.json").write_text(
        json.dumps({"protected_paths": [str(target)]}, indent=2) + "\n"
    )
    (vault / "manifests" / "security-policies.json").write_text(
        json.dumps({"wireguard": {"master_anchor_ip": "10.100.0.1"}}, indent=2) + "\n"
    )

    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").write_text(base64.b64encode(public).decode() + "\n")
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").chmod(0o600)

    entry = authz.sign_authorization(identity, key, ["telemetry", "p2p-sync", "guard-apply"])
    registry = {
        "schema_version": "1.0",
        "master_public_key_b64": base64.b64encode(public).decode(),
        "authorizations": [entry],
    }
    (vault / "manifests" / "node-authorizations.json").write_text(json.dumps(registry, indent=2) + "\n")
    return vault, target


def _peer_fingerprint(vault: Path) -> str:
    identity = json.loads((vault / "manifests" / "node-identity.json").read_text())
    return authz.fingerprint(identity)


# --- helpers -----------------------------------------------------------------


def _issue(
    state: Path,
    target: str,
    content: Path,
    fingerprint: str,
    out: Path,
    *,
    nonce: str | None = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ, "SPARKNET_STATE_DIR": str(state)}
    command = [
        "make",
        "-C",
        str(ROLE_ROOT),
        "approval-issue",
        f"TARGET={target}",
        f"CONTENT={content}",
        f"PEER_FINGERPRINT={fingerprint}",
        f"OUT={out}",
    ]
    return subprocess.run(command, capture_output=True, text=True, env=env)


def _issue_with_nonce(
    state: Path, target: str, content: Path, fingerprint: str, out: Path, nonce: str
) -> subprocess.CompletedProcess:
    env = {**os.environ, "SPARKNET_STATE_DIR": str(state)}
    command = [
        "bash",
        str(ROLE_ROOT / "scripts" / "sparknet-approval-issue.sh"),
        "--target",
        target,
        "--content",
        str(content),
        "--peer-fingerprint",
        fingerprint,
        "--nonce",
        nonce,
        "--out",
        str(out),
    ]
    return subprocess.run(command, capture_output=True, text=True, env=env)


def _deliver(
    fingerprint: str,
    approval: Path,
    out: Path,
    *,
    url: str | None = None,
    registry: Path | None = None,
) -> subprocess.CompletedProcess:
    command = [
        "make",
        "-C",
        str(ROLE_ROOT),
        "approval-deliver",
        f"FINGERPRINT={fingerprint}",
        f"APPROVAL={approval}",
        f"OUT={out}",
    ]
    if url:
        command.append(f"URL={url}")
    if registry:
        command.append(f"REGISTRY={registry}")
    return subprocess.run(command, capture_output=True, text=True)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_guard(vault: Path, port: int) -> subprocess.Popen:
    """The peer's own guard daemon, loaded by path, on loopback."""
    process = subprocess.Popen(
        [
            sys.executable,
            str(GUARD),
            "--vault-root",
            str(vault),
            "--listen",
            "127.0.0.1",
            "--port",
            str(port),
            "--bind-any",
            "--dry-run",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"the peer guard died: {process.stderr.read() if process.stderr else ''}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/status", timeout=1) as response:
                if response.status == 200:
                    return process
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    process.terminate()
    raise AssertionError("the peer guard never started listening")


# --- the envelope ------------------------------------------------------------


def test_issue_produces_the_canonical_envelope(master_state, tmp_path: Path) -> None:
    """Exactly the fields the peer will accept — no more, no fewer."""
    state, _key = master_state
    content = tmp_path / "new.txt"
    content.write_text("# new\n")
    out = tmp_path / "approval.json"

    result = _issue(state, "/etc/wireguard/wg1.conf", content, "f" * 64, out)
    assert result.returncode == 0, result.stderr

    artifact = json.loads(out.read_text())
    approval = artifact["approval"]
    assert set(approval) == set(authz.GUARD_APPROVAL_FIELDS), (
        f"the approval carries {sorted(set(approval) - set(authz.GUARD_APPROVAL_FIELDS))} outside "
        f"the canonical envelope"
    )
    assert approval["peer_fingerprint"] == "f" * 64
    assert approval["file_path"] == "/etc/wireguard/wg1.conf"
    assert base64.b64decode(approval["content_b64"]) == b"# new\n"
    assert approval["content_sha256"] == authz.hashlib.sha256(b"# new\n").hexdigest()


def test_the_signature_covers_the_canonical_bytes(master_state, tmp_path: Path) -> None:
    """What the Master signs is what the peer verifies — the same rule."""
    state, key = master_state
    content = tmp_path / "new.txt"
    content.write_text("# new\n")
    out = tmp_path / "approval.json"
    assert _issue(state, "/etc/wireguard/wg1.conf", content, "f" * 64, out).returncode == 0

    artifact = json.loads(out.read_text())
    message = authz.guard_approval_message(artifact["approval"])
    key.public_key().verify(base64.b64decode(artifact["signature_b64"]), message)


def test_the_envelope_carries_no_capabilities(master_state, tmp_path: Path) -> None:
    """The peer reads guard-apply from its own registry entry. An approval that
    carried capabilities could grant the authority it is checked against."""
    state, _key = master_state
    content = tmp_path / "new.txt"
    content.write_text("# new\n")
    out = tmp_path / "approval.json"
    assert _issue(state, "/etc/wireguard/wg1.conf", content, "f" * 64, out).returncode == 0

    approval = json.loads(out.read_text())["approval"]
    assert "capabilities" not in approval


def test_issue_refuses_to_issue_the_same_nonce_twice(master_state, tmp_path: Path) -> None:
    """A nonce the peer has already seen is dead on arrival there, so the Master
    refuses to issue it again rather than mint an approval that cannot work."""
    state, _key = master_state
    content = tmp_path / "new.txt"
    content.write_text("# new\n")

    first = _issue_with_nonce(state, "/etc/wireguard/wg1.conf", content, "f" * 64, tmp_path / "a.json", "abc123")
    assert first.returncode == 0, first.stderr

    second = _issue_with_nonce(state, "/etc/wireguard/wg1.conf", content, "f" * 64, tmp_path / "b.json", "abc123")
    assert second.returncode != 0, "the Master issued the same nonce twice"
    assert "again" in second.stderr


def test_issue_refuses_without_a_peer_fingerprint(master_state, tmp_path: Path) -> None:
    """An approval that names no peer could be applied by any peer."""
    state, _key = master_state
    content = tmp_path / "new.txt"
    content.write_text("# new\n")
    env = {**os.environ, "SPARKNET_STATE_DIR": str(state)}
    result = subprocess.run(
        [
            "bash",
            str(ROLE_ROOT / "scripts" / "sparknet-approval-issue.sh"),
            "--target",
            "/etc/wireguard/wg1.conf",
            "--content",
            str(content),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert "peer-fingerprint" in result.stderr


# --- delivery ----------------------------------------------------------------


def test_deliver_refuses_an_approval_addressed_to_another_peer(master_state, peer_vault, tmp_path: Path) -> None:
    """The Master must not deliver one peer's approval to another."""
    state, _key = master_state
    vault, target = peer_vault
    content = tmp_path / "new.txt"
    content.write_text("# patched\n")
    out = tmp_path / "approval.json"
    assert _issue(state, str(target), content, _peer_fingerprint(vault), out).returncode == 0

    result = _deliver("a" * 64, out, tmp_path / "record.json")
    assert result.returncode != 0, "the Master delivered an approval to the wrong peer"
    assert "addresses" in result.stderr


def test_deliver_refuses_without_an_address(master_state, peer_vault, tmp_path: Path) -> None:
    """No registry, no URL: no delivery. Guessing an address would be worse."""
    state, _key = master_state
    vault, target = peer_vault
    content = tmp_path / "new.txt"
    content.write_text("# patched\n")
    out = tmp_path / "approval.json"
    assert _issue(state, str(target), content, _peer_fingerprint(vault), out).returncode == 0

    result = _deliver(
        _peer_fingerprint(vault),
        out,
        tmp_path / "record.json",
        registry=tmp_path / "no-such-registry.json",
    )
    assert result.returncode != 0
    assert "cannot resolve" in result.stderr


def test_deliver_resolves_the_peer_address_from_the_registry(master_state, peer_vault, tmp_path: Path) -> None:
    """The fingerprint names the peer; the signed registry names its address."""
    state, _key = master_state
    vault, target = peer_vault
    fingerprint = _peer_fingerprint(vault)
    content = tmp_path / "new.txt"
    content.write_text("# patched\n")
    out = tmp_path / "approval.json"
    assert _issue(state, str(target), content, fingerprint, out).returncode == 0

    registry = tmp_path / "registry.json"
    registry.write_text((vault / "manifests" / "node-authorizations.json").read_text())

    # The registry names 10.100.0.9, which is not reachable here: the point is
    # that the address came from the registry, not from a guess.
    result = _deliver(fingerprint, out, tmp_path / "record.json", registry=registry)
    assert result.returncode != 0, "delivery to an unreachable peer must fail loudly"
    record = json.loads((tmp_path / "record.json").read_text())
    assert record["url"] == "http://10.100.0.9:9090/api/v1/critical-file/patch"
    assert record["delivered"] is False
    assert record["error"]


# --- the two sides, together -------------------------------------------------


def test_the_peer_applies_what_the_master_signed(master_state, peer_vault, tmp_path: Path) -> None:
    """Sign here, apply there: the peer's own guard, loaded by path.

    This is the DoD's fourth leg. It is the only test that could have caught
    the three-way disagreement between the Master's issuer, the signer and the
    peer — and the only one that proves the two sides *agree* rather than
    proving each side agrees with itself.
    """
    state, _key = master_state
    vault, target = peer_vault
    fingerprint = _peer_fingerprint(vault)

    content = tmp_path / "new.txt"
    content.write_text("# patched by the master\n")
    approval = tmp_path / "approval.json"
    assert _issue(state, str(target), content, fingerprint, approval).returncode == 0

    port = _free_port()
    daemon = _start_guard(vault, port)
    try:
        record_file = tmp_path / "record.json"
        result = _deliver(
            fingerprint,
            approval,
            record_file,
            url=f"http://127.0.0.1:{port}{GUARD_ROUTE}",
        )
        assert result.returncode == 0, result.stderr + result.stdout

        record = json.loads(record_file.read_text())
        assert record["delivered"] is True
        assert record["status"] == 200
        body = json.loads(record["response"])
        assert body["status"] == "PATCH_VERIFIED_DRY_RUN"
        assert body["file_path"] == str(target)
        assert body["content_sha256"] == authz.hashlib.sha256(b"# patched by the master\n").hexdigest()

        ledger = json.loads((vault / "blockchain" / "guard-audit.json").read_text())
        assert ledger["blocks"][-1]["event"] == "patch_verified_dry_run"
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)


def test_the_peer_refuses_an_approval_addressed_to_another_peer(master_state, peer_vault, tmp_path: Path) -> None:
    """The peer binds an approval to itself; a valid signature is not enough."""
    state, _key = master_state
    vault, target = peer_vault

    content = tmp_path / "new.txt"
    content.write_text("# patched by the master\n")
    approval = tmp_path / "approval.json"
    assert _issue(state, str(target), content, "b" * 64, approval).returncode == 0

    port = _free_port()
    daemon = _start_guard(vault, port)
    try:
        record_file = tmp_path / "record.json"
        result = _deliver(
            "b" * 64,
            approval,
            record_file,
            url=f"http://127.0.0.1:{port}{GUARD_ROUTE}",
        )
        assert result.returncode != 0, "the peer accepted an approval addressed to somebody else"
        record = json.loads(record_file.read_text())
        assert record["status"] == 403
        assert json.loads(record["response"])["code"] == "wrong_peer"
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)


def test_the_peer_refuses_an_approval_without_the_capability(master_state, peer_vault, tmp_path: Path) -> None:
    """A peer whose registry entry does not grant guard-apply stays inert, even
    for an approval the Master signed."""
    state, key = master_state
    vault, target = peer_vault

    # Re-sign the registry without guard-apply.
    registry_path = vault / "manifests" / "node-authorizations.json"
    registry = json.loads(registry_path.read_text())
    identity = json.loads((vault / "manifests" / "node-identity.json").read_text())
    registry["authorizations"] = [authz.sign_authorization(identity, key, ["telemetry"])]
    registry_path.write_text(json.dumps(registry, indent=2) + "\n")

    content = tmp_path / "new.txt"
    content.write_text("# patched by the master\n")
    approval = tmp_path / "approval.json"
    assert _issue(state, str(target), content, _peer_fingerprint(vault), approval).returncode == 0

    port = _free_port()
    daemon = _start_guard(vault, port)
    try:
        record_file = tmp_path / "record.json"
        result = _deliver(
            _peer_fingerprint(vault),
            approval,
            record_file,
            url=f"http://127.0.0.1:{port}{GUARD_ROUTE}",
        )
        assert result.returncode != 0
        record = json.loads(record_file.read_text())
        assert record["status"] == 403
        assert json.loads(record["response"])["code"] == "capability_missing"
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
