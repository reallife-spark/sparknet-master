---
type: user-record
schema: sparknet-user/1
status: unfilled
owner_id: ""
owner_node: ""
role: owner
immutable: true
authorised_senders: []
---

# user record

The operator's identity for this node, and the public half of the key that
every note signature in this vault verifies against.

**This file is public by design.** It carries `public_key_b64`, the
`fingerprint` of that key, and the `owner_id` every tracking block attributes
to — nothing else. The frontmatter keys are an allowlist
(`USER_RECORD_KEYS` in `shared/sparknet-provenance.py`, pinned to
`contracts/tracking-schema.json: user_record.fields`): an unknown key, a
private key block, or a base64 run outside `public_key_b64` fails the suite.

## Fill it once

```bash
make user-init        # from the role root
```

That generates the Ed25519 pair through `shared/sparknet-authz.py`, writes
the private half to `$SPARKNET_STATE_DIR/keys/user.ed25519` at mode 0600
(gitignored, never bundled), fills the fields above, and records the file's
sha256 in `00_System/.user.lock`.

After the first fill:

- a second run is a quiet no-op — the key every existing signature verifies
  against stands;
- a run without the receipt is **refused**, not guessed at;
- `--force` re-keys deliberately and says so: every signature already made
  against the old key becomes `stale`/`invalid` and must be re-signed.

## `authorised_senders`

An empty list means *nobody may push work onto this node* — the inbox policy
in `contracts/tracking-schema.json` fails closed. Filling it is an operator
decision: an email or peer identity that appears here may be treated as
peer-origin when it arrives in `01_Inbox/`; anything else is refused.

## `owner_id`

`U-#####`, assigned once per node. `owner_id` + `owner_node` is unique across
the fabric, and every tracking block in `01_Inbox`–`07_Archives` carries it.
`owner_ref` always points back at this file (`00_System/user.md`), so a note
is attributable without asking anything else where it came from.

The user key **consents and attributes**; it grants no capability. Authority
comes from key possession over the capability vocabulary — see
`contracts/capabilities.json`.
