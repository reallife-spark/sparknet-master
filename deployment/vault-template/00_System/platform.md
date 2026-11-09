---
type: platform-record
schema: sparknet-platform/1
status: uncaptured
captured_at: null
hostname: null
os: null
machine: null
release: null
platform: null
running_as_root: null
snapshot_ref: manifests/user-env-manifest.json
---

# platform record

The computer system this node's agents operate on, captured rather than asserted.

This is the unfilled template. Fill it by running the capture, which writes this
file and `manifests/user-env-manifest.json` together in one probe:

```bash
scripts/sparknet-identity-capture.sh
```

Do not fill it in by hand. A hand-written platform record states what someone
believes the host is, and the capture exists to replace that belief — an agent
that reasons about permissions, container images or wheel availability from a
guessed `machine` is reasoning about a different computer.

The contract for this record is `contracts/tracking-schema.json`
(`platform_record`): the fields, the generation rule, and the requirement that
every field here equals the snapshot it references.

`running_as_root` is a fact about the capturing process, not a permission. This
record grants nothing and widens nothing.
