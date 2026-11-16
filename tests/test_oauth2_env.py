"""oauth2-proxy env renderer: one node, one secret, no stdout leak."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from sparknet_loader import load_by_path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "master-node" / "scripts" / "sparknet-oauth2-env.py"
renderer = load_by_path("sparknet_oauth2_env_test", SCRIPT)


def _identity(tmp_path: Path) -> Path:
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / "clients.json").write_text(
        json.dumps(
            {
                "sparknet-node-0002": {
                    "client_id": "sparknet-node-0002",
                    "client_secret": "client-secret-for-test-000000000000",
                    "redirect_uri": "https://10.100.0.2:8182/oauth2/callback",
                }
            }
        ),
        encoding="utf-8",
    )
    return identity


def test_render_writes_a_private_env_and_preserves_the_cookie(tmp_path: Path) -> None:
    identity = _identity(tmp_path)
    target = renderer.render(identity_dir=identity, node_id="sparknet-node-0002", issuer="https://10.100.0.1:9443")
    assert target.is_file()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    text = target.read_text(encoding="utf-8")
    for key in (
        "OAUTH2_PROXY_PROVIDER=oidc",
        "OAUTH2_PROXY_OIDC_ISSUER_URL=https://10.100.0.1:9443",
        "OAUTH2_PROXY_CLIENT_ID=sparknet-node-0002",
        "OAUTH2_PROXY_CLIENT_SECRET=client-secret-for-test-000000000000",
        "OAUTH2_PROXY_REDIRECT_URL=https://10.100.0.2:8182/oauth2/callback",
        "OAUTH2_PROXY_GROUPS_CLAIM=groups",
        "OAUTH2_PROXY_PROVIDER_CA_FILE=/etc/sparknet/identity/dex-ca.crt",
    ):
        assert key in text, key
    first = (identity / "oauth2-secrets.json").read_bytes()
    renderer.render(identity_dir=identity, node_id="sparknet-node-0002", issuer="https://10.100.0.1:9443")
    assert (identity / "oauth2-secrets.json").read_bytes() == first


def test_render_refuses_a_missing_client(tmp_path: Path) -> None:
    identity = _identity(tmp_path)
    try:
        renderer.render(identity_dir=identity, node_id="sparknet-node-9999", issuer="https://10.100.0.1:9443")
    except renderer.EnvError as exc:
        assert "no OIDC client" in str(exc)
    else:
        raise AssertionError("a missing client must be refused")
