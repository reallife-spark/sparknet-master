"""Master admin proxy: registry-only targets and a verifiable signed assertion."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from sparknet_loader import load_by_path

ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "master-node" / "services" / "sparknet-admin-proxy.py"
proxy = load_by_path("sparknet_admin_proxy_test", SERVICE)
authz = load_by_path("authz_admin_proxy_test", ROOT / "shared" / "sparknet-authz.py")
sso = load_by_path("sso_admin_proxy_test", ROOT / "shared" / "sparknet-sso.py")

FINGERPRINT = "140e0dc554e18b883922bd5164f576eee0c1d6d08ebf5f7d3c052948257c36c7"
ENTRIES = [
    {
        "identity": {"node_id": "peer-fixture-01", "overlay_ipv4": "10.100.0.2/32"},
        "fingerprint": FINGERPRINT,
    }
]


def _keypair():
    private_b64, _public = authz.generate_keypair()
    return authz.private_key_from_b64(private_b64)


def test_resolve_target_uses_only_the_registry() -> None:
    target = proxy.resolve_target("peer-fixture-01", ENTRIES)
    assert target.node_id == "peer-fixture-01"
    assert target.url == "https://10.100.0.2:8182"
    assert proxy.resolve_target(FINGERPRINT, ENTRIES).node_id == "peer-fixture-01"
    with pytest.raises(proxy.ProxyError, match="never a URL"):
        proxy.resolve_target("http://10.100.0.2:8181", ENTRIES)
    with pytest.raises(proxy.ProxyError, match="no registry entry"):
        proxy.resolve_target("peer-unknown", ENTRIES)


def test_forward_signs_a_verifiable_assertion_and_strips_identity_headers() -> None:
    key = _keypair()
    target = proxy.resolve_target("peer-fixture-01", ENTRIES)
    captured = {}

    class Response:
        status = 200

        def __init__(self) -> None:
            self.headers = {"X-User-Role": "admin"}

        def read(self) -> bytes:
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(request):
        captured["url"] = request.full_url
        captured["headers"] = {name.lower(): value for name, value in request.header_items()}
        return Response()

    status, headers, body = proxy.forward(
        target,
        "/admin/users",
        private_key=key,
        master_node_id="master-1",
        admin_email="admin@example.test",
        admin_role="admin",
        groups=["sparknet-admins"],
        extra_headers={
            "X-User-Email": "attacker@example.test",
            "X-Auth-Request-Groups": "other",
            "X-Request-Id": "r1",
        },
        opener=opener,
        now=1760000000,
    )
    assert (status, headers, body) == (200, {"X-User-Role": "admin"}, b'{"ok": true}')
    assert captured["url"] == "https://10.100.0.2:8182/admin/users"
    assert "x-user-email" not in captured["headers"], "a caller-supplied identity header must not survive"
    assert captured["headers"]["x-request-id"] == "r1"
    packed = captured["headers"]["x-sparknet-assertion"]
    assertion = json.loads(base64.b64decode(packed))
    ok, reason = sso.verify_assertion(
        assertion,
        key.public_key(),
        expected_node_id="peer-fixture-01",
        expected_fingerprint=FINGERPRINT,
        now=__import__("datetime").datetime.fromtimestamp(1760000000, __import__("datetime").timezone.utc),
    )
    assert (ok, reason) == (True, "")
    assert assertion["email"] == "admin@example.test"
    assert assertion["role"] == "admin"
    assert assertion["target_fingerprint"] == FINGERPRINT


def test_parse_node_path_is_strict() -> None:
    assert proxy.parse_node_path("/nodes/peer-fixture-01/admin/users") == ("peer-fixture-01", "/admin/users")
    with pytest.raises(proxy.ProxyError):
        proxy.parse_node_path("/admin/users")
    with pytest.raises(proxy.ProxyError):
        proxy.parse_node_path("/nodes//admin/users")


def test_server_forwards_only_registry_targets_with_an_admin_identity(tmp_path) -> None:
    import http.client
    import json as _json

    registry = tmp_path / "registry.json"
    registry.write_text(_json.dumps({"authorizations": ENTRIES}), encoding="utf-8")
    calls = []

    def fake_forward(target, path, **kwargs):
        calls.append((target, path, kwargs))
        return 200, {"Content-Type": "application/json", "X-Test": "1"}, b'{"ok": true}'

    server = proxy.build_server(
        registry=registry,
        private_key=_keypair(),
        master_node_id="master-1",
        port=0,
        forward_fn=fake_forward,
    )
    server.start()
    try:
        port = server.servers[0].server_address[1]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "GET",
            "/nodes/peer-fixture-01/admin/users",
            headers={"X-User-Email": "admin@example.test", "X-User-Role": "admin"},
        )
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("X-Test") == "1"
        assert _json.loads(response.read()) == {"ok": True}
        connection.close()
        assert calls[0][0].node_id == "peer-fixture-01"
        assert calls[0][1] == "/admin/users"
        assert calls[0][2]["admin_email"] == "admin@example.test"

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/nodes/peer-fixture-01/admin/users", headers={"X-User-Email": "x@example.test"})
        assert connection.getresponse().status == 403
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "GET",
            "/nodes/peer-unknown/admin/users",
            headers={"X-User-Email": "admin@example.test", "X-User-Role": "admin"},
        )
        assert connection.getresponse().status == 404
        connection.close()
    finally:
        server.stop()
