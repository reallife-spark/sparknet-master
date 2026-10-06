# Key management on the elected Master

This role holds the most sensitive secret in the fabric: the **operational key**,
which signs every registry entry and every approval. Building the role did not
make that safer or less important to get right — it made it the thing this vault
exists to protect.

## Three keys, and why the split is not pedantry

| Key | Signs | Who holds it | Count |
|---|---|---|---|
| **cluster** | the cluster trust root only | every member | 3 |
| **operational** | registry entries, approvals, guard-apply payloads | only the elected Master | 1 |
| **identity** | this node's own authorization envelope | every node | 3 |

If one key did all three jobs, then any member's key — present on every node — would
be a key that could sign a registry entry. Every node would be a Master-in-waiting.
The cluster key is deliberately weak on its own: it can only help form a root, and
forming a root needs **all three** signatures. A single stolen cluster key is one
of three required signatures, which is nothing.

## Where they live

```
$SPARKNET_STATE_DIR/keys/
  cluster.ed25519       0600
  identity.ed25519      0600
  operational.ed25519   0600    ← Master only
  *.pub.b64             0644    ← public, safe to publish
```

Never in the vault. `tests/test_master_spec.py::test_private_key_is_never_in_the_vault`
fails the build if a key-shaped file appears here, and that assertion was carried
over untouched from when this role was empty — building the role was not a reason to
relax it.

`SPARKNET_STATE_DIR` resolves **outside the vault**, to
`$XDG_STATE_HOME/sparknet/master-node` (falling back to
`~/.local/state/sparknet/master-node`). It used to default to `<role>/.state`, and
that turned out to be the wrong place for exactly one reason: Step 1 put a real
private key there, and `configs/admin-surface/docker-compose.admin.yml` bind-mounts
this vault read-only into the LLM-facing admin container. The key was therefore
readable at `/workspace/sparknet/master-node/.state/keys/operational.ed25519`,
while every isolation test still passed — they read the compose file's *text*, and
the key was reachable through the mount rather than mentioned in it.

`.gitignore` was never the real defence and is not what was fixed. Gitignore answers
"will this be committed"; the mount answered "who else can read it". Docker cannot
exclude a subdirectory from a bind mount, so the fix was to put the key somewhere
that is not under the mount at all. Three things now hold it in place:

- `make keys-check` fails if `SPARKNET_STATE_DIR` is overridden back inside the
  vault, which is the most likely way for an operator to undo this by hand.
- `tests/test_admin_surface.py::test_the_compose_mounts_do_not_reach_the_signing_key`
  resolves every bind-mount source in the compose file and requires the state dir
  to sit outside all of them.
- `tests/test_step1_keypair.py` asserts the resolved location, and that no
  `<role>/.state` survives.

The peer role keeps `<vault>/.state`, deliberately and not by oversight: no admin
surface mounts the peer vault, so it has no equivalent exposure, and moving it would
cost bundle portability for no security gain.

## The operational key is isolated, not merely protected

The Master is also a peer: it runs Open WebUI, a dispatch bridge, and agent ports.
A key that authorises the whole fabric sitting beside an LLM-driven multi-user web
surface would invert the fabric's central premise — the thing the peer roles
deliberately withhold would be one prompt injection away.

So the operational key is loaded by **one process only**, `services/sparknet-signer.py`
(Step 17), which:

- signs and does nothing else,
- exposes a unix socket, never a TCP port,
- accepts only canonical bytes already authorised by a valid cluster trust root,
- shares no volume, and no network namespace, with the peer services.

This is structural on purpose. A `deny` rule in a permission file is a policy
statement that the governed surface may later ignore — and here the governed
surface is an LLM application that reads configuration as input. Isolation is the
only control that does not depend on the governed thing cooperating.

`services/sparknet-parity.py` explicitly cannot reach the signer; `tests/` asserts
it.

## Rotation and revocation

| Act | Threshold | Effect |
|---|---|---|
| Revoke a node | 1 signature | node is inert; cannot receive a valid signature |
| Replace the Master | 3 of 3 | new root, old operational key distrusted |
| Re-form membership | 3 of 3 | new root with different membership |

Unilateral revocation is safe because it is a denial: it removes reach and adds
nothing. Unilateral *replacement* would hand the key to whoever committed the
change, so it requires unanimity. That asymmetry is the same reasoning recorded in
`../../contracts/capabilities.json` under `escalation_note`.

## What is not verified here

- **No live cluster exists on the development host.** No key has signed a real
  registry entry, no election has been run between three machines, and no key has
  ever crossed a process boundary. Every claim in this document is about the code
  path, not about observed fabric behaviour.
- **Containment is architectural, not penetration-tested.** The tests assert the
  topology — the signer is unreachable from the peer surface — which is not the same
  as having tried to break it.
- **Interim signing is weaker.** While the Master is unbuilt, grants are signed by
  an operator holding the key offline and distributed by hand. There is no
  revocation channel in that arrangement, and `../../contracts/identity-schema.json`
  records it as weaker rather than equivalent.
