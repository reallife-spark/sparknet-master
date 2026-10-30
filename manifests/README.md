# manifests/ — where the elected Master publishes what it signs

This directory is **author, not reader**. It holds the templates that describe this
node's identity and the cluster trust root it will be judged against. It
deliberately does **not** hold the registry.

## What is here

| File | Holds | Live or template |
|---|---|---|
| `node-identity.json` | this node's identity: `node_id`, `role`, `wireguard_public_key_b64`, `overlay_ipv4`, `requested_capabilities` | template — `node_id` is `REPLACE_WITH_NODE_ID` |
| `cluster-trust-root.json` | the root that names the elected Master | fail-closed template — `master_node_id: null`, no signatures |
| `registry.schema.json` | a **symlink** to `../../contracts/registry-schema.json` | never a copy — `test_registry_schema.py` fails if it becomes one |

`role` is `peer` in the identity manifest, and that is not a placeholder. **A node
is a peer until it is elected.** Nothing in this directory can make a node Master;
only a trust root signed by every member (2 of 2 in a pair, 3 of 3 in a trio) can, and that arrives at runtime.

## What is not here, and why

**The registry.** It lives at `manifests/node-authorizations.json` on each node
that receives it, and is produced by `../services/sparknet-signer.py`. A second
hand-maintained copy here would be exactly the drift `../../shared/README.md`
forbids: two copies of a signed document, of which only one is the one that was
signed.

**Any key material.** Private keys live in `$SPARKNET_STATE_DIR/keys` at mode
`0600` and are referenced by path only. `make keys-check` fails the build if a
key ever appears in this directory.

## How an entry counts

An authorization is valid only if **both** of these hold, and neither is
sufficient alone:

1. The entry's signature verifies under the `master_pubkey` named by a **valid
   cluster trust root**. The root decides *whose key counts*.
2. The entry is well-formed, unexpired and unrevoked, and its `capabilities` are
   all in the vocabulary. `../../shared/sparknet-authz.py` decides *whether the
   entry means anything*.

Implemented once, in `../../shared/sparknet-authz.py`, and specified once, in
`../../contracts/identity-schema.json`. Neither is restated here.

## How distribution works

Distribution is built. The Master signs a **publication** (the registry, its
digest and a monotonic sequence; `contracts/registry-publication.json`) and
pushes it to each peer's guard on `9090`:

```sh
make registry-publish REGISTRY=manifests/node-authorizations.json OUT=.state/registry
make registry-deliver PUBLICATION=.state/registry/current.json
```

`sparknet-registry-deliver.service` + `.timer` retry every 60 s. The acceptance
rule is shared (`shared/sparknet-registry-install.py`), so the Master and the
peer cannot disagree: a lower sequence is a rollback and is refused, the exact
publication already installed is a no-op (`REGISTRY_ALREADY_INSTALLED`), and an
equal sequence with a different digest is a fork and is refused. The overlay
anchor (`10.100.0.1`) is skipped because it is the Master itself, not a peer.
A peer's copy is still operator-visible and verifiable offline, but it is no
longer operator-supplied.

## Why the schema is not duplicated here

Copying the identity schema into this directory would create a second statement of
what an identity is. `fingerprint()` in `sparknet-authz.py` hashes exactly the
fields in `contracts/identity-schema.json` and **ignores anything else**, so a
field renamed here does not raise an error and does not warn — the identity simply
hashes differently from the one the contract describes, and the node becomes
unreachable for reasons that look like a network fault.

`test_master_spec.py::test_the_identity_manifest_uses_the_contract_field_names`
exists because this directory had already drifted once, by exactly one field
name.
