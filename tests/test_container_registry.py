"""The private OCI registry: token gate, content addressing and path safety."""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import threading
from pathlib import Path

ROLE_ROOT = Path(__file__).resolve().parent.parent
TOKEN = "test-registry-token-0123456789"


def _load():
    spec = importlib.util.spec_from_file_location(
        "sparknet_container_registry", ROLE_ROOT / "services" / "sparknet-container-registry.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


registry = _load()


def _fixture(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "registry"
    blob = b"image-layer-bytes"
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    (blobs / digest.removeprefix("sha256:")).write_bytes(blob)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{"mediaType": "application/octet-stream", "digest": digest, "size": len(blob)}],
    }
    manifests = root / "manifests" / "sparknet" / "demo"
    manifests.mkdir(parents=True)
    (manifests / "v1.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root, digest


def _get(port: int, path: str, token: str | None = TOKEN) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    result = response.status, dict(response.getheaders()), body
    connection.close()
    return result


def _serve(tmp_path: Path, root: Path):
    server = registry.RegistryHTTPServer(("127.0.0.1", 0), registry.Store(root), TOKEN)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_registry_requires_bearer_token(tmp_path: Path):
    root, _ = _fixture(tmp_path)
    server, thread = _serve(tmp_path, root)
    try:
        status, headers, _ = _get(server.server_port, "/v2/", token=None)
        assert status == 401
        assert headers["WWW-Authenticate"].startswith("Bearer")
        status, _, body = _get(server.server_port, "/v2/")
        assert status == 200
        assert json.loads(body)["name"] == "sparknet-registry"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_registry_serves_manifest_and_blob_with_digests(tmp_path: Path):
    root, blob_digest = _fixture(tmp_path)
    server, thread = _serve(tmp_path, root)
    try:
        status, headers, body = _get(server.server_port, "/v2/sparknet/demo/manifests/v1")
        assert status == 200
        assert headers["Docker-Content-Digest"] == "sha256:" + hashlib.sha256(body).hexdigest()
        status, headers, blob = _get(server.server_port, f"/v2/sparknet/demo/blobs/{blob_digest}")
        assert status == 200
        assert blob == b"image-layer-bytes"
        assert headers["Docker-Content-Digest"] == blob_digest
        status, _, tags = _get(server.server_port, "/v2/sparknet/demo/tags/list")
        assert status == 200
        assert json.loads(tags)["tags"] == ["v1"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_registry_rejects_traversal_and_wrong_digest(tmp_path: Path):
    root, _ = _fixture(tmp_path)
    server, thread = _serve(tmp_path, root)
    try:
        status, _, _ = _get(server.server_port, "/v2/../../etc/manifests/v1")
        assert status == 404
        status, _, _ = _get(server.server_port, "/v2/sparknet/demo/blobs/sha256/" + "0" * 64)
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_token_file_must_not_be_group_readable(tmp_path: Path):
    path = tmp_path / "token"
    path.write_text(TOKEN)
    path.chmod(0o644)
    try:
        registry.read_token(path, None)
    except registry.RegistryError as exc:
        assert exc.code == "token-mode"
    else:
        raise AssertionError("a group-readable token file was accepted")

    path.chmod(0o600)
    assert registry.read_token(path, None) == TOKEN


def test_non_loopback_bind_is_refused(tmp_path: Path, monkeypatch):
    token = tmp_path / "token"
    token.write_text(TOKEN)
    token.chmod(0o600)
    monkeypatch.setattr(registry, "serve", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("served")))
    result = registry.main(["--bind", "0.0.0.0", "--token-file", str(token), "--describe"])
    assert result == 0
    result = registry.main(["--bind", "0.0.0.0", "--token-file", str(token)])
    assert result == 2
