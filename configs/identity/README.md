# Identity stack — Master-hosted OIDC

This stack is the human-identity root for the fabric (`contracts/sso-identity.md`,
ADR 0022). It is **not** a knowledge or authority channel: it authenticates a
human; the registry and the isolated signer remain the authority.

## Components

| Service | Role | Bind |
|---|---|---|
| **Dex** | OIDC issuer; static per-node clients; LDAP connector | `10.100.0.1:9443` (overlay only) |
| **lldap** | user/group directory; admin UI | `127.0.0.1:3890` (LDAP) and `127.0.0.1:17170` (UI) |

Groups are the role baseline:

- `sparknet-admins` → Open WebUI `admin` on every node;
- `sparknet-users` → Open WebUI `user`.

A human in neither group is refused at online login. A per-node signed
`set_user_role` override wins on that node and is flagged when it disagrees with
the IdP group.

## Render

```sh
SPARKNET_STATE_DIR=~/.local/state/sparknet/master-node \
  master-node/scripts/sparknet-identity-render.py --json
```

The renderer writes under `$SPARKNET_STATE_DIR/identity/`:

- `dex/config.yaml` (0600) and `clients.json` (0600);
- `lldap.env` (0600) and `secrets.json` (0600);
- `tls/server.crt` / `tls/server.key` (0644 / 0600), self-signed for the
  overlay issuer address and replaceable with a CA-issued pair;
- `admin-ca/ca.crt` / `admin-ca/ca.key` (0644 / 0600) for the offline admin
  client-certificate path.

The client list comes from the signed registry. Each node gets its **own**
OIDC client and secret; redirect URI is
`https://<overlay>:8088/oauth2/callback` for the Master and
`https://<overlay>:8181/oauth2/callback` for a peer. Re-running the renderer
preserves existing secrets; it never rotates a live client silently.

## Run

```sh
export SPARKNET_IDENTITY_DIR="$SPARKNET_STATE_DIR/identity"
docker compose -f master-node/configs/identity/docker-compose.identity.yml up -d
```

Then create the two groups in the lldap UI on `http://127.0.0.1:17170` and add
the human admin to `sparknet-admins`. The lldap admin password is in
`secrets.json` on the Master (0600); do not copy it into the tree.

## Offline admin certificate

```sh
master-node/scripts/sparknet-identity-render.py --issue-admin-cert you@example.invalid
```

This issues a 90-day client certificate signed by the admin CA. Move the
private key to the admin's hardware token or protected store, then remove the
local copy. Each node's auth gateway verifies it against `admin-ca/ca.crt`
(public only). Expired or revoked certificates fail closed offline; the CRL is
refreshed when the node can reach the Master.

## What this does not do

- No Open WebUI password is shared across nodes.
- No user database is shared; per-node Open WebUI state is not copied.
- No signer key is touched. Dex authenticates; the signer signs.
- No live claim: this page describes the rendered deployment. OIDC discovery,
  login, mTLS and the browser surfaces are target-host checks.
