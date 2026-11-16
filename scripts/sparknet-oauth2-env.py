#!/usr/bin/env python3
"""Render one node's oauth2-proxy environment file for the admin ingress.

The file is consumed by the `oauth2-proxy` service in the SSO overlay. It holds
the node's OIDC client id/secret, the redirect URL, the issuer and a per-node
cookie secret. All of it is generated from the rendered `clients.json` and kept
0600; the script prints only the path and the client id.

`contracts/sso-identity.md` and ADR 0022 are the design. This is deployment
plumbing, not a second identity implementation.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any


class EnvError(Exception):
    """A refusal the operator can act on."""


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise EnvError(f"{path} must contain an object")
    return data


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def render(
    *,
    identity_dir: str | Path,
    node_id: str,
    issuer: str,
    ca_file: str = "/etc/sparknet/identity/dex-ca.crt",
    out: str | Path | None = None,
) -> Path:
    identity = Path(identity_dir)
    clients = _load(identity / "clients.json")
    client = clients.get(node_id)
    if not isinstance(client, dict):
        raise EnvError(f"no OIDC client for {node_id!r} in {identity / 'clients.json'}")
    client_id = str(client.get("client_id") or node_id)
    client_secret = str(client.get("client_secret") or "")
    redirect = str(client.get("redirect_uri") or "")
    if not client_secret or not redirect:
        raise EnvError(f"client {node_id!r} is missing its secret or redirect URI")
    secrets_path = identity / "oauth2-secrets.json"
    secrets_bundle = _load(secrets_path)
    cookies = secrets_bundle.get("cookie_secrets")
    if not isinstance(cookies, dict):
        cookies = {}
    cookie = cookies.get(node_id)
    if not isinstance(cookie, str) or len(cookie) not in (16, 24, 32):
        cookie = secrets.token_hex(16)  # 32 ASCII bytes; oauth2-proxy accepts 16/24/32
        cookies[node_id] = cookie
        secrets_bundle["cookie_secrets"] = cookies
        _write_private(secrets_path, json.dumps(secrets_bundle, indent=2, sort_keys=True) + "\n")
    env = {
        "OAUTH2_PROXY_PROVIDER": "oidc",
        "OAUTH2_PROXY_OIDC_ISSUER_URL": issuer,
        "OAUTH2_PROXY_CLIENT_ID": client_id,
        "OAUTH2_PROXY_CLIENT_SECRET": client_secret,
        "OAUTH2_PROXY_REDIRECT_URL": redirect,
        "OAUTH2_PROXY_COOKIE_SECRET": cookie,
        "OAUTH2_PROXY_COOKIE_SECURE": "true",
        "OAUTH2_PROXY_EMAIL_CLAIM": "email",
        "OAUTH2_PROXY_EMAIL_DOMAINS": "*",
        "OAUTH2_PROXY_GROUPS_CLAIM": "groups",
        "OAUTH2_PROXY_SET_XAUTHREQUEST": "true",
        "OAUTH2_PROXY_UPSTREAM": "static://202",
        "OAUTH2_PROXY_HTTP_ADDRESS": "127.0.0.1:4180",
        "OAUTH2_PROXY_SKIP_PROVIDER_BUTTON": "true",
        # Dex only skips its approval page when the client does not force it.
        "OAUTH2_PROXY_APPROVAL_PROMPT": "none",
        "OAUTH2_PROXY_PROVIDER_CA_FILE": ca_file,
        # The Dex issuer is self-signed on the overlay; the admin ingress is
        # still TLS, and this only relaxes the proxy's verification of Dex.
        "OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY": "true",
        "OAUTH2_PROXY_REVERSE_PROXY": "true",
        "OAUTH2_PROXY_SCOPE": "openid profile email groups",
    }
    target = Path(out) if out else identity / f"oauth2-{node_id}.env"
    _write_private(target, "\n".join(f"{key}={value}" for key, value in env.items()) + "\n")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render one node's oauth2-proxy env")
    parser.add_argument("--identity-dir", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--issuer", default="https://10.100.0.1:9443")
    parser.add_argument("--ca-file", default="/etc/sparknet/identity/dex-ca.crt")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        target = render(
            identity_dir=args.identity_dir,
            node_id=args.node_id,
            issuer=args.issuer,
            ca_file=args.ca_file,
            out=args.out,
        )
    except (EnvError, OSError) as exc:
        print(f"[oauth2-env] {exc}", file=sys.stderr)
        return 1
    summary = {"node_id": args.node_id, "env": str(target)}
    print(json.dumps(summary, sort_keys=True) if args.json else f"{args.node_id}: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
