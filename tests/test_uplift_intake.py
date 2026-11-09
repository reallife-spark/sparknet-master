"""The 8091 uplift intake: signed peer inventory and artifact storage."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
FABRIC_ROOT = ROLE_ROOT.parent
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    return load_by_path(name, path)


@pytest.fixture(scope="module")
def authz():
    return _load("uplift_authz", FABRIC_ROOT / "shared" / "sparknet-authz.py")


@pytest.fixture(scope="module")
def service():
    return _load("uplift_service", ROLE_ROOT / "services" / "sparknet-uplift-intake.py")


@pytest.fixture(scope="module")
def pusher():
    return _load("uplift_pusher", FABRIC_ROOT / "scripts" / "sparknet-uplift-push.py")


def _keys(tmp_path: Path, authz):
    private_b64, public_b64 = authz.generate_keypair()
    state = tmp_path / "state"
    (state / "keys").mkdir(parents=True)
    key_path = state / "keys" / "node.ed25519"
    key_path.write_text(private_b64)
    key_path.chmod(0o600)
    pub_path = tmp_path / "node.pub.b64"
    pub_path.write_text(public_b64)
    return state, key_path, pub_path, private_b64, public_b64


def _registry(tmp_path: Path, authz, *, capabilities: list[str] | None = None, overlay: str = "127.0.0.1/32") -> Path:
    master = Ed25519PrivateKey.generate()
    identity = {
        "node_id": "peer-1",
        "role": "peer",
        "wireguard_public_key_b64": "a2V5",
        "overlay_ipv4": overlay,
        "requested_capabilities": ["model-uplift"] if capabilities is None else capabilities,
    }
    entry = authz.sign_authorization(
        identity,
        master,
        ["model-uplift"] if capabilities is None else capabilities,
        ttl_days=1,
        now=datetime.now(timezone.utc),
    )
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "master_public_key_b64": authz.public_key_b64(master.public_key()),
                "authorizations": [entry],
            }
        )
    )
    return path


def _free_port() -> int:
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _serve(service, tmp_path: Path, authz, *, capabilities=None):
    state, _key_path, pub_path, _private, _public = _keys(tmp_path, authz)
    registry = service.Registry(_registry(tmp_path, authz, capabilities=capabilities))
    keys = {"peer-1": authz.load_public_key(pub_path)}
    intake = service.Intake(state=tmp_path / "uplift", registry=registry, keys=keys)
    port = _free_port()
    listener = service.serve(intake, bind="127.0.0.1", port=port)
    listener.start()
    return listener, None, port, state


def _client_env(pusher, monkeypatch, state: Path, port: int):
    monkeypatch.setenv("SPARKNET_NODE_ID", "peer-1")
    monkeypatch.setenv("SPARKNET_STATE_DIR", str(state))
    monkeypatch.setenv("SPARKNET_SHARED_DIR", str(FABRIC_ROOT / "shared"))
    monkeypatch.setenv("SPARKNET_UPLIFT_ENDPOINT", f"http://127.0.0.1:{port}")
    assert pusher._key() is not None


def test_inventory_and_snapshot_round_trip(service, authz, pusher, tmp_path, monkeypatch):
    listener, _thread, port, state = _serve(service, tmp_path, authz)
    try:
        _client_env(pusher, monkeypatch, state, port)
        records = [
            {
                "schema": "sparknet-inventory/1",
                "node_id": "peer-1",
                "kind": "user",
                "object_id": "u-1",
                "user_id": "u-1",
                "email": "user@example.test",
                "role": "user",
                "status": "active",
                "source": "open-webui",
            }
        ]
        body = json.dumps({"schema": "sparknet-uplift/1", "node_id": "peer-1", "inventory": records}).encode()
        assert pusher.send("inventory", body, {"rows": 1}, endpoint=f"http://127.0.0.1:{port}") is True
        stored = (tmp_path / "uplift" / "inventory" / "peer-1.jsonl").read_text()
        assert "user@example.test" in stored

        snapshot = b"snapshot-bytes"
        manifest = {"collection": "sparknet-peer", "sha256": pusher._sha256(snapshot), "size": len(snapshot)}
        assert pusher.send("snapshot", snapshot, manifest, endpoint=f"http://127.0.0.1:{port}") is True
        files = list((tmp_path / "uplift" / "snapshots" / "peer-1" / "sparknet-peer").glob("*.snapshot"))
        assert files and files[0].read_bytes() == snapshot
    finally:
        listener.stop()


def test_a_tampered_snapshot_manifest_is_refused(service, authz, pusher, tmp_path, monkeypatch):
    listener, _thread, port, state = _serve(service, tmp_path, authz)
    try:
        _client_env(pusher, monkeypatch, state, port)
        body = b"snapshot-bytes"
        manifest = {"collection": "sparknet-peer", "sha256": "0" * 64, "size": len(body)}
        assert pusher.send("snapshot", body, manifest, endpoint=f"http://127.0.0.1:{port}") is False
        assert not list((tmp_path / "uplift" / "snapshots").rglob("*.snapshot"))
    finally:
        listener.stop()


def test_a_peer_without_model_uplift_is_refused(service, authz, pusher, tmp_path, monkeypatch):
    listener, _thread, port, state = _serve(service, tmp_path, authz, capabilities=[])
    try:
        _client_env(pusher, monkeypatch, state, port)
        body = json.dumps({"inventory": []}).encode()
        assert pusher.send("inventory", body, {"rows": 0}, endpoint=f"http://127.0.0.1:{port}") is False
        assert not (tmp_path / "uplift" / "inventory" / "peer-1.jsonl").exists()
    finally:
        listener.stop()
