#!/usr/bin/env python3
"""Render the Master-hosted identity stack (Dex OIDC + lldap directory).

This is deploy-time code, not a running service. It writes the files the
identity compose stack mounts:

    $SPARKNET_STATE_DIR/identity/
      secrets.json             0600  lldap secrets, preserved on re-run
      clients.json             0600  node id -> OIDC client id/secret
      lldap.env                0600  lldap runtime environment
      dex/config.yaml          0600  Dex OIDC config with per-node clients
      tls/server.crt|key       0644/0600  TLS for the issuer address
      admin-ca/ca.crt|key      0644/0600  fabric admin CA (offline break-glass)
      admin-certs/<slug>.crt|key 0644/0600  issued admin client certificates

The client list comes from the signed registry: each entry's
`identity.node_id`, `identity.overlay_ipv4` and `identity.role` decide the
client id and redirect URI. A registry with no entries still gets the Master's
own client, so a fresh deployment can bootstrap. Per-node secrets are generated
once and preserved; re-running the renderer never rotates a live client.

No secret is printed. The summary names paths and client ids only.

`contracts/sso-identity.md` and ADR 0022 are the design; this script is the
deployment translation.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

try:
    import yaml
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError as exc:  # pragma: no cover - deploy hosts install requirements
    raise SystemExit(f"identity renderer needs PyYAML and cryptography: {exc}") from exc

ROLE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROLE_ROOT / "manifests" / "node-authorizations.json"
DEFAULT_ISSUER = "https://10.100.0.1:9443"
DEFAULT_LDAP_BASE_DN = "dc=sparknet,dc=local"
DEFAULT_NODE_PORT = 8182
DEFAULT_MASTER_PORT = 8092
DEFAULT_ADMIN_CERT_DAYS = 90
CA_DAYS = 3650
TLS_DAYS = 825


class RenderError(Exception):
    """A refusal the operator can act on."""


def _state_dir(explicit: str | Path | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("SPARKNET_STATE_DIR", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".local" / "state" / "sparknet" / "master-node"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _write_public(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, 0o644)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RenderError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RenderError(f"{path} must contain an object")
    return data


def _entrypoint(overlay: str, port: int) -> str:
    host = str(overlay).split("/", 1)[0]
    return f"https://{host}:{port}"


def _registry_clients(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    clients: dict[str, dict[str, Any]] = {}
    for entry in entries:
        identity = entry.get("identity") or {}
        node_id = str(identity.get("node_id") or "").strip()
        overlay = str(identity.get("overlay_ipv4") or "").strip()
        if not node_id or not overlay:
            continue
        role = str(identity.get("role") or "peer")
        port = DEFAULT_MASTER_PORT if role == "master" else DEFAULT_NODE_PORT
        clients[node_id] = {
            "node_id": node_id,
            "role": role,
            "overlay": overlay,
            "redirect_uri": f"{_entrypoint(overlay, port)}/oauth2/callback",
        }
    return clients


def _ensure_secrets(path: Path) -> dict[str, str]:
    existing = _load_json(path)
    values = {
        "lldap_jwt": str(existing.get("lldap_jwt") or secrets.token_urlsafe(64)),
        "lldap_key_seed": str(existing.get("lldap_key_seed") or secrets.token_urlsafe(64)),
        "lldap_admin_password": str(existing.get("lldap_admin_password") or secrets.token_urlsafe(32)),
    }
    if existing != values or not path.exists():
        _write_private(path, json.dumps(values, indent=2, sort_keys=True) + "\n")
    return values


def _ensure_client_secrets(path: Path, clients: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    existing = _load_json(path)
    merged: dict[str, dict[str, Any]] = {}
    for node_id, client in sorted(clients.items()):
        old = existing.get(node_id) or {}
        secret = old.get("client_secret")
        if not isinstance(secret, str) or len(secret) < 24:
            secret = secrets.token_urlsafe(48)
        merged[node_id] = {
            **client,
            "client_id": node_id,
            "client_secret": secret,
            "redirect_uri": client["redirect_uri"],
        }
    if merged != existing:
        _write_private(path, json.dumps(merged, indent=2, sort_keys=True) + "\n")
    return merged


def _ensure_tls(directory: Path, issuer: str) -> tuple[Path, Path]:
    cert_path = directory / "tls" / "server.crt"
    key_path = directory / "tls" / "server.key"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    host = issuer.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        san = x509.IPAddress(ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=TLS_DAYS))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
    )
    _write_public(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def _ensure_admin_ca(directory: Path) -> tuple[Path, Path, Any]:
    cert_path = directory / "admin-ca" / "ca.crt"
    key_path = directory / "admin-ca" / "ca.key"
    if cert_path.exists() and key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert_path, key_path, key
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sparknet Admin CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
    )
    _write_public(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path, key


def issue_admin_cert(directory: Path, email: str, *, days: int = DEFAULT_ADMIN_CERT_DAYS) -> tuple[Path, Path]:
    """Issue one admin client certificate signed by the fabric admin CA.

    The private key is written 0600 on the Master. Transfer it to the admin's
    hardware token or protected store, then remove the local copy; the contract
    does not require the Master to retain it.
    """
    if not isinstance(email, str) or "@" not in email:
        raise RenderError("admin certificate email must be a non-empty address")
    ca_cert_path, _ca_key_path, ca_key = _ensure_admin_ca(directory)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    slug = "".join(char for char in email.lower() if char.isalnum() or char in ".-_@")[:80]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, email)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = directory / "admin-certs" / f"{slug}.crt"
    key_path = directory / "admin-certs" / f"{slug}.key"
    _write_public(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
    )
    return cert_path, key_path


def issue_server_cert(directory: Path, node_id: str, overlay: str, *, days: int = TLS_DAYS) -> tuple[Path, Path]:
    """Issue one node server certificate signed by the fabric admin CA.

    The Master proxy trusts the admin CA, so one CA covers the node admin
    ingress (8182) and the offline admin client certificates. The private key
    is copied to that node's state dir at 0600; it never enters the tree.
    """
    if not node_id or not overlay:
        raise RenderError("server certificate needs a node id and an overlay address")
    ca_cert_path, _ca_key_path, ca_key = _ensure_admin_ca(directory)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    host = str(overlay).split("/", 1)[0]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(host))]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    slug = "".join(char for char in node_id if char.isalnum() or char in "-_")[:80]
    cert_path = directory / "node-certs" / f"{slug}.crt"
    key_path = directory / "node-certs" / f"{slug}.key"
    _write_public(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
    )
    return cert_path, key_path


def _dex_config(
    *,
    issuer: str,
    bind_host: str,
    tls_cert: Path,
    tls_key: Path,
    ldap_base_dn: str,
    ldap_bind_dn: str,
    ldap_password: str,
    clients: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    static_clients = [
        {
            "id": client["client_id"],
            "name": client["node_id"],
            "secret": client["client_secret"],
            "redirectURIs": [client["redirect_uri"]],
        }
        for client in sorted(clients.values(), key=lambda item: item["node_id"])
    ]
    return {
        "issuer": issuer,
        "storage": {"type": "memory"},
        "web": {
            "https": f"{bind_host}:{issuer.rsplit(':', 1)[-1]}",
            "tlsCert": str(tls_cert),
            "tlsKey": str(tls_key),
        },
        "oauth2": {"skipApprovalScreen": True, "responseTypes": ["code"]},
        "staticClients": static_clients,
        "connectors": [
            {
                "type": "ldap",
                "id": "lldap",
                "name": "Sparknet",
                "config": {
                    "host": "127.0.0.1:3890",
                    "insecureNoSSL": True,
                    "bindDN": ldap_bind_dn,
                    "bindPW": ldap_password,
                    "usernamePrompt": "Sparknet username",
                    "userSearch": {
                        "baseDN": f"ou=people,{ldap_base_dn}",
                        "filter": "(objectClass=person)",
                        "username": "uid",
                        "idAttr": "uid",
                        "emailAttr": "mail",
                        "nameAttr": "cn",
                    },
                    "groupSearch": {
                        "baseDN": f"ou=groups,{ldap_base_dn}",
                        "filter": "(objectClass=groupOfNames)",
                        "userMatchers": [{"userAttr": "uid", "groupAttr": "member"}],
                        "nameAttr": "cn",
                    },
                },
            }
        ],
        "frontend": {"issuer": "Sparknet", "theme": "dark"},
        "logger": {"level": "info"},
    }


def render(
    *,
    state_dir: str | Path | None,
    registry: str | Path,
    issuer: str,
    bind_host: str,
    ldap_base_dn: str,
    master_node_id: str,
    master_overlay: str,
    issue_cert_for: str | None = None,
    issue_server_cert_specs: list[str] | None = None,
) -> dict[str, Any]:
    state = _state_dir(state_dir)
    identity = state / "identity"
    identity.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    registry_path = Path(registry)
    if registry_path.exists():
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        entries = list(data.get("authorizations") or [])
    clients = _registry_clients(entries)
    clients.setdefault(
        master_node_id,
        {
            "node_id": master_node_id,
            "role": "master",
            "overlay": master_overlay,
            "redirect_uri": f"{_entrypoint(master_overlay, DEFAULT_MASTER_PORT)}/oauth2/callback",
        },
    )
    secrets_bundle = _ensure_secrets(identity / "secrets.json")
    client_records = _ensure_client_secrets(identity / "clients.json", clients)
    tls_cert, tls_key = _ensure_tls(identity, issuer)
    _ensure_admin_ca(identity)
    ldap_bind_dn = f"uid=admin,ou=people,{ldap_base_dn}"
    config = _dex_config(
        issuer=issuer,
        bind_host=bind_host,
        tls_cert=Path("/etc/dex/tls/server.crt"),
        tls_key=Path("/etc/dex/tls/server.key"),
        ldap_base_dn=ldap_base_dn,
        ldap_bind_dn=ldap_bind_dn,
        ldap_password=secrets_bundle["lldap_admin_password"],
        clients=client_records,
    )
    _write_private(identity / "dex" / "config.yaml", yaml.safe_dump(config, sort_keys=False))
    lldap_env = "\n".join(
        [
            f"LLDAP_JWT_SECRET={secrets_bundle['lldap_jwt']}",
            f"LLDAP_KEY_SEED={secrets_bundle['lldap_key_seed']}",
            f"LLDAP_LDAP_USER_PASS={secrets_bundle['lldap_admin_password']}",
            f"LLDAP_LDAP_BASE_DN={ldap_base_dn}",
            "LLDAP_LDAP_USER_DN=admin",
            "LLDAP_LDAP_USER_EMAIL=admin@sparknet.local",
            "LLDAP_LDAP_USER_DISPLAY_NAME=Sparknet Admin",
            "LLDAP_HTTP_URL=http://127.0.0.1:17170",
            "LLDAP_HTTP_PORT=17170",
            "LLDAP_LDAP_PORT=3890",
            "",
        ]
    )
    _write_private(identity / "lldap.env", lldap_env)
    issued: dict[str, str] = {}
    if issue_cert_for:
        cert_path, key_path = issue_admin_cert(identity, issue_cert_for)
        issued = {"cert": str(cert_path), "key": str(key_path)}
    issued_servers: dict[str, str] = {}
    for spec in issue_server_cert_specs or []:
        node_id, _, overlay = spec.partition(":")
        if not node_id or not overlay:
            raise RenderError(f"--issue-server-cert wants NODE_ID:OVERLAY, got {spec!r}")
        cert_path, key_path = issue_server_cert(identity, node_id, overlay)
        issued_servers[node_id] = str(cert_path)
    return {
        "state_dir": str(state),
        "identity_dir": str(identity),
        "issuer": issuer,
        "tls_cert": str(tls_cert),
        "tls_key": str(tls_key),
        "clients": sorted(client_records),
        "admin_ca": str(identity / "admin-ca" / "ca.crt"),
        "issued": issued,
        "issued_servers": issued_servers,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the Master identity stack (Dex + lldap)")
    parser.add_argument("--state-dir", type=Path, default=None)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    parser.add_argument("--bind-host", default="10.100.0.1")
    parser.add_argument("--ldap-base-dn", default=DEFAULT_LDAP_BASE_DN)
    parser.add_argument("--master-node-id", default=os.environ.get("SPARKNET_NODE_ID", "sparknet-node-0001"))
    parser.add_argument("--master-overlay", default="10.100.0.1/32")
    parser.add_argument("--issue-admin-cert", default=None, metavar="EMAIL")
    parser.add_argument(
        "--issue-server-cert",
        action="append",
        default=[],
        metavar="NODE_ID:OVERLAY",
        help="issue one node admin-ingress server certificate signed by the admin CA",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        summary = render(
            state_dir=args.state_dir,
            registry=args.registry,
            issuer=args.issuer,
            bind_host=args.bind_host,
            ldap_base_dn=args.ldap_base_dn,
            master_node_id=args.master_node_id,
            master_overlay=args.master_overlay,
            issue_cert_for=args.issue_admin_cert,
            issue_server_cert_specs=args.issue_server_cert,
        )
    except (RenderError, OSError, ValueError) as exc:
        print(f"[identity-render] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True) if args.json else _human(summary))
    return 0


def _human(summary: dict[str, Any]) -> str:
    lines = [
        f"identity dir: {summary['identity_dir']}",
        f"issuer:       {summary['issuer']}",
        f"TLS cert:     {summary['tls_cert']}",
        f"admin CA:     {summary['admin_ca']}",
        f"clients:      {', '.join(summary['clients'])}",
    ]
    if summary["issued"]:
        lines.append(f"admin cert:   {summary['issued']['cert']}")
        lines.append(f"admin key:    {summary['issued']['key']} (0600; move it to the admin token)")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
