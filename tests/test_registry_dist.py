"""Step 6: the registry distribution channel, end to end.

The unit tests prove the rule; this suite proves the *channel*: a publication
signed on the Master side is pushed to the peer's own guard daemon (loaded by
path), installed, and the capabilities a node holds change as a result. That is
DoD 3 and 4 in one test, and DoD 5 is the same test with a clock around it.

The last test is the one the step was reopened for: an older publication - one
in which a just-revoked peer is still authorised - is what an attacker with
write access to the channel would replay. The peer refuses it, so a revocation
cannot be undone by serving yesterday's registry.
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
PEER_ROLE = FABRIC_ROOT / "peer-node"
PUBLICATION_ROUTE = "/api/v1/registry"


def _load_authz():
    """The one shared implementation, by path — the reason there is one."""
    spec = importlib.util.spec_from_file_location("sparknet_authz_dist", FABRIC_ROOT / "shared" / "sparknet-authz.py")
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
    """A throwaway Master state dir with one operational key pair."""
    key = Ed25519PrivateKey.generate()
    state = tmp_path / "master-state"
    keys = state / "keys"
    keys.mkdir(parents=True)
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    (keys / "operational.ed25519").write_text(base64.b64encode(raw).decode() + "\n")
    (keys / "operational.ed25519").chmod(0o600)
    (keys / "operational.pub.b64").write_text(_public_b64(key) + "\n")
    return state, key


def _public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()


def _identity(node_id: str = "peer-test") -> dict:
    return {
        "node_id": node_id,
        "role": "peer",
        "wireguard_public_key_b64": base64.b64encode(b"\x11" * 32).decode(),
        "overlay_ipv4": "10.100.0.9",
        "requested_capabilities": ["telemetry", "guard-apply"],
    }


def _registry(key: Ed25519PrivateKey, identity: dict, *, revoked: bool = False) -> dict:
    capabilities = [] if revoked else ["telemetry", "guard-apply"]
    entry = authz.sign_authorization(identity, key, capabilities, revoked=revoked)
    return {
        "schema_version": "1.0",
        "master_public_key_b64": _public_b64(key),
        "authorizations": [entry],
    }


@pytest.fixture
def peer_vault(tmp_path: Path, master_state) -> Path:
    """A minimal peer vault, with nothing installed yet."""
    _state, key = master_state
    vault = tmp_path / "peer"
    (vault / "manifests" / "keys").mkdir(parents=True)
    (vault / "blockchain").mkdir(parents=True)
    (vault / "manifests" / "node-identity.json").write_text(json.dumps(_identity(), indent=2) + "\n")
    (vault / "manifests" / "critical-manifest.json").write_text(json.dumps({"protected_paths": []}, indent=2) + "\n")
    (vault / "manifests" / "security-policies.json").write_text(
        json.dumps({"wireguard": {"master_anchor_ip": "10.100.0.1"}}, indent=2) + "\n"
    )
    (vault / "manifests" / "keys" / "master-ed25519.pub.b64").write_text(_public_b64(key) + "\n")
    return vault


# --- helpers -----------------------------------------------------------------


def _publish(state: Path, registry: dict, out_dir: Path, *, sequence: int | None = None) -> subprocess.CompletedProcess:
    registry_file = out_dir.parent / "registry.json"
    registry_file.write_text(json.dumps(registry, indent=2) + "\n")
    env = {**os.environ, "SPARKNET_STATE_DIR": str(state)}
    command = [
        str(ROLE_ROOT / "scripts" / "sparknet-registry-publish.sh"),
        "--registry",
        str(registry_file),
        "--out",
        str(out_dir),
        "--offline",
    ]
    if sequence is not None:
        command += ["--sequence", str(sequence)]
    return subprocess.run(command, capture_output=True, text=True, env=env)


def _deliver(publication: Path, fingerprint: str, url: str) -> subprocess.CompletedProcess:
    command = [
        str(ROLE_ROOT / "scripts" / "sparknet-registry-deliver.sh"),
        "--publication",
        str(publication),
        "--peer",
        fingerprint,
        "--url",
        url,
        "--timeout",
        "10",
    ]
    return subprocess.run(command, capture_output=True, text=True)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start_guard(vault: Path, port: int) -> subprocess.Popen:
    """The peer's own guard, not a stub — the code that would run on the node."""
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


@pytest.fixture
def running_guard(peer_vault: Path):
    port = _free_port()
    process = _start_guard(peer_vault, port)
    try:
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def _post(port: int, publication: dict, path: str = PUBLICATION_ROUTE) -> tuple[int, dict]:
    body = json.dumps(publication).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _status(port: int) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/status", timeout=5) as response:
        return json.loads(response.read())


def _fingerprint(vault: Path) -> str:
    return authz.fingerprint(json.loads((vault / "manifests" / "node-identity.json").read_text()))


def _installed_registry(vault: Path) -> dict:
    return json.loads((vault / "manifests" / "node-authorizations.json").read_text())


# --- the artifact ------------------------------------------------------------


def test_publication_carries_exactly_the_envelope(master_state, tmp_path: Path) -> None:
    state, key = master_state
    out = tmp_path / "pub"
    result = _publish(state, _registry(key, _identity()), out)
    assert result.returncode == 0, result.stderr

    artifact = json.loads((out / "current.json").read_text())
    assert set(artifact) == set(authz.REGISTRY_PUBLICATION_FIELDS) | {"signature_b64"}
    assert artifact["sequence"] == 1
    # The peer's own rule accepts it — the test does not hand-roll verification.
    assert authz.verify_registry_publication(artifact, key.public_key()) == authz.registry_digest(artifact["registry"])


# --- DoD 3, 4 and 5 ----------------------------------------------------------


def test_guard_installs_publication_and_a_revocation_lands(
    master_state, peer_vault: Path, running_guard: int, tmp_path: Path
) -> None:
    state, key = master_state
    fingerprint = _fingerprint(peer_vault)
    url = f"http://127.0.0.1:{running_guard}{PUBLICATION_ROUTE}"

    out = tmp_path / "pub-v1"
    assert _publish(state, _registry(key, _identity()), out).returncode == 0
    started = time.time()
    delivered = _deliver(out / "current.json", fingerprint, url)
    assert delivered.returncode == 0, delivered.stdout + delivered.stderr
    elapsed = time.time() - started

    assert _status(running_guard)["registry_sequence"] == 1
    decision = authz.evaluate(_identity(), _installed_registry(peer_vault), key.public_key(), now=_now())
    assert decision.allowed
    assert "guard-apply" in decision.capabilities

    # DoD 5: revocation reaches the peer within the documented window. The push
    # is immediate; the 60 s timer is the bound when the first push fails.
    out_v2 = tmp_path / "pub-v2"
    assert _publish(state, _registry(key, _identity(), revoked=True), out_v2).returncode == 0
    assert _deliver(out_v2 / "current.json", fingerprint, url).returncode == 0
    assert _status(running_guard)["registry_sequence"] == 2

    revoked = authz.evaluate(_identity(), _installed_registry(peer_vault), key.public_key(), now=_now())
    assert not revoked.allowed
    assert revoked.reason == authz.REASON_REVOKED
    assert elapsed < 60, "a single push should not need the re-delivery interval"


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


# --- refusals ----------------------------------------------------------------


def test_replaying_an_older_publication_is_refused(
    master_state, peer_vault: Path, running_guard: int, tmp_path: Path
) -> None:
    state, key = master_state
    fingerprint = _fingerprint(peer_vault)
    url = f"http://127.0.0.1:{running_guard}{PUBLICATION_ROUTE}"

    v1 = tmp_path / "pub-v1"
    v2 = tmp_path / "pub-v2"
    assert _publish(state, _registry(key, _identity()), v1).returncode == 0
    assert _publish(state, _registry(key, _identity(), revoked=True), v2).returncode == 0
    assert _deliver(v1 / "current.json", fingerprint, url).returncode == 0
    assert _deliver(v2 / "current.json", fingerprint, url).returncode == 0

    # Yesterday's registry still names this node as authorised. Re-delivering it
    # must not resurrect the capability.
    replay = _deliver(v1 / "current.json", fingerprint, url)
    assert replay.returncode != 0
    assert "stale_publication" in replay.stdout + replay.stderr
    assert _status(running_guard)["registry_sequence"] == 2
    assert not authz.evaluate(_identity(), _installed_registry(peer_vault), key.public_key(), now=_now()).allowed


def test_tampered_content_is_refused_before_install(
    master_state, peer_vault: Path, running_guard: int, tmp_path: Path
) -> None:
    state, key = master_state
    out = tmp_path / "pub"
    assert _publish(state, _registry(key, _identity()), out).returncode == 0
    artifact = json.loads((out / "current.json").read_text())

    # 1. Edit the document under the digest: the envelope's own check catches it.
    forged = json.loads(json.dumps(artifact))
    forged["registry"]["authorizations"][0]["capabilities"] = ["guard-apply", "root"]
    status, body = _post(running_guard, forged)
    assert status == 400
    assert body["code"] == "malformed_publication"

    # 2. Recompute the digest so the envelope is consistent, but sign with a key
    #    that is not the pinned Master: the signature check catches it.
    other = Ed25519PrivateKey.generate()
    unsigned = {
        "sequence": artifact["sequence"],
        "published_at": artifact["published_at"],
        "registry": forged["registry"],
        "registry_sha256": authz.registry_digest(forged["registry"]),
    }
    forged["registry_sha256"] = unsigned["registry_sha256"]
    forged["signature_b64"] = authz.sign_bytes(other, authz.registry_publication_message(unsigned))
    status, body = _post(running_guard, forged)
    assert status == 403
    assert body["code"] == "bad_signature"

    # 3. A document signed by us but naming a different Master key is a
    #    different fabric's registry, and says so.
    mismatched = _registry(key, _identity())
    mismatched["master_public_key_b64"] = _public_b64(other)
    unsigned = {
        "sequence": 2,
        "published_at": artifact["published_at"],
        "registry": mismatched,
        "registry_sha256": authz.registry_digest(mismatched),
    }
    body_bytes = authz.registry_publication_message(unsigned)
    tampered = {**unsigned, "signature_b64": authz.sign_bytes(key, body_bytes)}
    status, body = _post(running_guard, tampered)
    assert status == 403
    assert body["code"] == "wrong_master_key"

    # Nothing was installed by any of the three.
    assert _status(running_guard)["registry_sequence"] == 0
    assert not (peer_vault / "manifests" / "node-authorizations.json").exists()


def test_registry_route_is_not_a_discovery_surface(running_guard: int) -> None:
    """Push only: there is nothing to GET, and no other path to POST to."""
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(f"http://127.0.0.1:{running_guard}{PUBLICATION_ROUTE}", timeout=5)
    assert raised.value.code == 404

    status, _body = _post(running_guard, {"anything": True}, path="/api/v1/elsewhere")
    assert status == 404


# --- the offline path --------------------------------------------------------


def test_offline_client_installs_the_same_way(master_state, peer_vault: Path, tmp_path: Path) -> None:
    """A node with no daemon can still be recovered — under the same rule."""
    state, key = master_state
    out = tmp_path / "pub"
    assert _publish(state, _registry(key, _identity()), out).returncode == 0

    env = {**os.environ, "SPARKNET_VAULT_ROOT": str(peer_vault), "SPARKNET_FABRIC_ROOT": str(FABRIC_ROOT)}

    # Dry-run verifies and writes nothing — the operator can inspect before it
    # lands. Doing it first is the point; after install the same publication is
    # a replay (below).
    dry = subprocess.run(
        [
            "bash",
            str(PEER_ROLE / "scripts" / "sparknet-registry-fetch.sh"),
            "--publication",
            str(out / "current.json"),
            "--dry-run",
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert dry.returncode == 0, dry.stderr
    assert json.loads(dry.stdout)["status"] == "REGISTRY_VERIFIED_DRY_RUN"
    assert not (peer_vault / "manifests" / "node-authorizations.json").exists()

    installed = subprocess.run(
        [
            "bash",
            str(PEER_ROLE / "scripts" / "sparknet-registry-fetch.sh"),
            "--publication",
            str(out / "current.json"),
            "--json",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert installed.returncode == 0, installed.stderr
    assert json.loads(installed.stdout)["status"] == "REGISTRY_INSTALLED"
    assert authz.evaluate(_identity(), _installed_registry(peer_vault), key.public_key(), now=_now()).allowed

    status = subprocess.run(
        ["bash", str(PEER_ROLE / "scripts" / "sparknet-registry-fetch.sh"), "--status", "--json"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert status.returncode == 0, status.stderr
    report = json.loads(status.stdout)
    assert report["sequence"] == 1
    assert "guard-apply" in report["capabilities"]

    # A replay is refused with the same code the guard sends.
    replay = subprocess.run(
        ["bash", str(PEER_ROLE / "scripts" / "sparknet-registry-fetch.sh"), "--publication", str(out / "current.json")],
        capture_output=True,
        text=True,
        env=env,
    )
    assert replay.returncode == 1
    assert "stale_publication" in replay.stderr
