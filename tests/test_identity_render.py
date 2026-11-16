"""Master identity renderer: clients, secrets, TLS and the admin CA."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import yaml
from cryptography import x509
from sparknet_loader import load_by_path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "master-node" / "scripts" / "sparknet-identity-render.py"
renderer = load_by_path("sparknet_identity_render_test", SCRIPT)

FINGERPRINT = "140e0dc554e18b883922bd5164f576eee0c1d6d08ebf5f7d3c052948257c36c7"


def _registry(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "authorizations": [
                    {
                        "identity": {
                            "node_id": "sparknet-node-0002",
                            "role": "peer",
                            "overlay_ipv4": "10.100.0.2/32",
                        },
                        "fingerprint": FINGERPRINT,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _render(tmp_path: Path, *extra: str) -> tuple[int, str, str]:
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = renderer.main(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--registry",
                str(_registry(tmp_path / "registry.json")),
                "--issuer",
                "https://10.100.0.1:9443",
                "--master-node-id",
                "sparknet-node-0001",
                "--master-overlay",
                "10.100.0.1/32",
                *extra,
            ]
        )
    return code, out.getvalue(), err.getvalue()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_render_writes_clients_secrets_tls_and_ca(tmp_path: Path) -> None:
    code, out, err = _render(tmp_path, "--json")
    assert code == 0, err
    identity = tmp_path / "state" / "identity"
    config = yaml.safe_load((identity / "dex" / "config.yaml").read_text(encoding="utf-8"))
    assert config["issuer"] == "https://10.100.0.1:9443"
    clients = {client["id"]: client for client in config["staticClients"]}
    assert set(clients) == {"sparknet-node-0001", "sparknet-node-0002"}
    assert clients["sparknet-node-0001"]["redirectURIs"] == ["https://10.100.0.1:8092/oauth2/callback"]
    assert clients["sparknet-node-0002"]["redirectURIs"] == ["https://10.100.0.2:8182/oauth2/callback"]
    secrets = [client["secret"] for client in config["staticClients"]]
    assert len(set(secrets)) == 2 and all(len(secret) >= 24 for secret in secrets)
    connector = config["connectors"][0]["config"]
    assert connector["host"] == "127.0.0.1:3890"
    assert connector["userSearch"]["baseDN"] == "ou=people,dc=sparknet,dc=local"
    assert connector["groupSearch"]["nameAttr"] == "cn"
    assert "client_secret" not in out, "the renderer summary must never print a secret"
    assert "LLDAP_LDAP_USER_PASS" not in out
    for path in (
        identity / "dex" / "config.yaml",
        identity / "clients.json",
        identity / "secrets.json",
        identity / "lldap.env",
        identity / "tls" / "server.key",
        identity / "admin-ca" / "ca.key",
    ):
        assert path.is_file(), path
        assert _mode(path) == 0o600, (path, oct(_mode(path)))
    assert _mode(identity / "tls" / "server.crt") == 0o644
    assert _mode(identity / "admin-ca" / "ca.crt") == 0o644


def test_tls_certificate_and_admin_ca_are_well_formed(tmp_path: Path) -> None:
    code, _out, err = _render(tmp_path)
    assert code == 0, err
    identity = tmp_path / "state" / "identity"
    tls_cert = x509.load_pem_x509_certificate((identity / "tls" / "server.crt").read_bytes())
    san = tls_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert x509.IPAddress(__import__("ipaddress").ip_address("10.100.0.1")) in san
    ca = x509.load_pem_x509_certificate((identity / "admin-ca" / "ca.crt").read_bytes())
    constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is True
    assert constraints.path_length == 0


def test_admin_cert_issue_uses_the_configured_email_and_ca(tmp_path: Path) -> None:
    code, out, err = _render(tmp_path, "--issue-admin-cert", "Admin@Example.Test")
    assert code == 0, err
    identity = tmp_path / "state" / "identity"
    cert_path = identity / "admin-certs" / "admin@example.test.crt"
    key_path = identity / "admin-certs" / "admin@example.test.key"
    assert cert_path.is_file() and key_path.is_file()
    assert "admin@example.test" in out
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert x509.RFC822Name("Admin@Example.Test") in san or x509.RFC822Name("admin@example.test") in san
    ca = x509.load_pem_x509_certificate((identity / "admin-ca" / "ca.crt").read_bytes())
    assert cert.issuer == ca.subject
    assert _mode(key_path) == 0o600


def test_rerun_preserves_secrets_and_client_ids(tmp_path: Path) -> None:
    assert _render(tmp_path)[0] == 0
    identity = tmp_path / "state" / "identity"
    before_clients = (identity / "clients.json").read_bytes()
    before_secrets = (identity / "secrets.json").read_bytes()
    assert _render(tmp_path)[0] == 0
    assert (identity / "clients.json").read_bytes() == before_clients
    assert (identity / "secrets.json").read_bytes() == before_secrets


def test_an_empty_registry_still_bootstraps_the_master_client(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text('{"authorizations": []}', encoding="utf-8")
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = renderer.main(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--registry",
                str(empty),
                "--issuer",
                "https://10.100.0.1:9443",
                "--master-node-id",
                "sparknet-node-0001",
                "--master-overlay",
                "10.100.0.1/32",
                "--json",
            ]
        )
    assert code == 0, err.getvalue()
    summary = json.loads(out.getvalue())
    assert summary["clients"] == ["sparknet-node-0001"]


def test_server_cert_is_signed_by_the_admin_ca(tmp_path: Path) -> None:
    code, _out, err = _render(tmp_path, "--issue-server-cert", "sparknet-node-0002:10.100.0.2")
    assert code == 0, err
    identity = tmp_path / "state" / "identity"
    cert = x509.load_pem_x509_certificate((identity / "node-certs" / "sparknet-node-0002.crt").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert x509.IPAddress(__import__("ipaddress").ip_address("10.100.0.2")) in san
    ca = x509.load_pem_x509_certificate((identity / "admin-ca" / "ca.crt").read_bytes())
    assert cert.issuer == ca.subject
    assert _mode(identity / "node-certs" / "sparknet-node-0002.key") == 0o600
