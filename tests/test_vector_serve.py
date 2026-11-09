"""The 4223 listener: signed query, capability gate, no silent empty answers."""

from __future__ import annotations

import json
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
SHARED = ROLE_ROOT.parent / "shared"
NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    return load_by_path(name, path)


@pytest.fixture(scope="module")
def authz():
    return _load("vector_serve_authz", SHARED / "sparknet-authz.py")


@pytest.fixture(scope="module")
def service():
    return _load("vector_serve_service", ROLE_ROOT / "services" / "sparknet-vector-serve.py")


class FakeVector:
    def __init__(self):
        self.indexed = []

    def open_checked(self, scope, vault, data):
        return {"name": f"sparknet-{scope}"}

    def query_candidates(self, scope, data, collection, query, n_results):
        return [
            {"id": f"{scope}:one#0", "path": "one.md", "document": "a small passage", "distance": 0.1},
            {"id": f"{scope}:two#0", "path": "two.md", "document": "another passage", "distance": 0.2},
        ][:n_results]

    def cmd_index(self, scope, vault, data):
        self.indexed.append(scope)


def _registry(tmp_path: Path, authz, master, capabilities: list[str]) -> Path:
    identity = {
        "node_id": "peer-1",
        "role": "peer",
        "wireguard_public_key_b64": "a2V5",
        "overlay_ipv4": "10.100.0.2/32",
        "requested_capabilities": capabilities,
    }
    entry = authz.sign_authorization(identity, master, capabilities, ttl_days=3650, now=NOW)
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


def _store(service, authz, tmp_path, http_key, capabilities=None):
    master = Ed25519PrivateKey.generate()
    registry = _registry(tmp_path, authz, master, ["cluster-dispatch"] if capabilities is None else capabilities)
    fake = FakeVector()
    return (
        service.VectorStore(
            fabric_vault=tmp_path,
            shared_vault=tmp_path,
            state_root=tmp_path / "vector",
            registry_path=registry,
            trusted_keys={"peer-1": http_key.public_key()},
            authz=authz,
            vector=fake,
        ),
        fake,
    )


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_query_requires_the_cluster_capability(service, authz, tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    store, _ = _store(service, authz, tmp_path, key, capabilities=[])
    router = service.router_for(store)
    status, body = router(
        "POST", "/v1/query", {"collection": "fabric", "query": "x", "top_k": 2}, {"verified_key_id": "peer-1"}
    )
    assert status == 403
    assert body["reason"] == "no-capability"


def test_signed_query_over_the_listener(service, authz, tmp_path: Path):
    http = _load("vector_serve_http", SHARED / "sparknet-http.py")
    key = Ed25519PrivateKey.generate()
    store, _ = _store(service, authz, tmp_path, key)
    port = _free_port()
    server = http.serve(
        service.router_for(store),
        bind="127.0.0.1",
        port=port,
        public_keys={"peer-1": key.public_key()},
    )
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        status, body = http.post_json(
            f"http://127.0.0.1:{port}",
            "POST",
            "/v1/query",
            {"collection": "fabric", "query": "passage", "top_k": 2},
            key,
        )
        assert status == 200, body
        assert [hit["path"] for hit in body["hits"]] == ["one.md", "two.md"]
        assert body["hits"][0]["snippet"] == "a small passage"

        status, _ = http.post_json(
            f"http://127.0.0.1:{port}",
            "POST",
            "/v1/query",
            {"collection": "fabric", "query": "passage", "top_k": 2},
            Ed25519PrivateKey.generate(),
        )
        assert status == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_top_k_and_collection_are_bounded(service, authz, tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    store, _ = _store(service, authz, tmp_path, key)
    router = service.router_for(store)
    identity = {"verified_key_id": "peer-1"}
    status, body = router("POST", "/v1/query", {"collection": "fabric", "query": "x", "top_k": 21}, identity)
    assert (status, body["reason"]) == (400, "bad-top-k")
    status, body = router("POST", "/v1/query", {"collection": "peer", "query": "x", "top_k": 2}, identity)
    assert (status, body["reason"]) == (400, "unknown-collection")
    status, body = router("POST", "/v1/query", {"collection": "shared", "query": "", "top_k": 2}, identity)
    assert (status, body["reason"]) == (400, "bad-query")


def test_shared_collection_is_a_separate_index(service, authz, tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    store, _fake = _store(service, authz, tmp_path, key)
    router = service.router_for(store)
    status, body = router(
        "POST", "/v1/query", {"collection": "shared", "query": "x", "top_k": 1}, {"verified_key_id": "peer-1"}
    )
    assert status == 200
    assert body["hits"][0]["id"].startswith("shared:")
    assert (store.state_root / "shared") != (store.state_root / "fabric")
