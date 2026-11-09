---
title: Fleet memory control
updated: 2026-11-02
status: partially-built
---

> [!warning] **Built and locally tested; live node legs are pending operator confirmation.**
> The contracts, Go store, gateway, node wiring and adapters are implemented and
> covered by the local gates. A live node start, browser capture and a live Master
> read-through are `DoD: confirm: user`.

# Fleet memory control

The Master governs fleet memory without storing a mirror.

## What it can see

- counts, capture posture, retention, share references and delegate run status
  from telemetry and signed admin requests;
- content only through an on-demand `memory_read` action, executed by the peer's
  gateway after the peer verifies `memory-supervise`.

The Master does not run a peer's memory service, does not copy a peer's store and
does not feed the response into its own RAG. The peer writes the read to its
`0600` memory audit; the user's Memory page shows the access log.

## Actions

`memory_status`, `memory_policy_set`, `memory_read` and `memory_purge` are signed
admin actions. The peer bridge checks the Master signature, the target, the
registry and `memory-supervise` before forwarding to the local Python gateway.
Policy changes and purges are explicit operator decisions, not automatic
remediation.

## Capability

`memory-supervise` is sensitive and issued by the Master. A peer without it
refuses every memory admin action, even with a valid Master signature. The
capability grants no write to the user's vault; it only admits the signed
request to the peer's gateway.


## Operator commands

```sh
# metadata only
bin/sparknet-admin-console.py memory --target sparknet-node-0001

# policy request (signed; the peer applies it locally)
bin/sparknet-admin-console.py memory-policy --target sparknet-node-0001   --user user-07 --policy '{"capture":true,"retention_days":90}'

# on-demand content read (signed; transient)
bin/sparknet-admin-console.py memory-read --target sparknet-node-0001   --user user-07 --memory-query "release decision"

# explicit purge (signed; leaves a peer audit record)
bin/sparknet-admin-console.py memory-purge --target sparknet-node-0001   --user user-07 --memory-ids mem-1,mem-2 --reason "user erasure request"
```

The console page is read-only; it shows counts and posture. The CLI above is
the write path because it composes a signed request for the isolated signer.
## Limits

- No permanent mirror, no bulk scrape and no answer corpus.
- `memory_read` is scoped to one user/project and bounded by the gateway.
- The Master's AI must not ingest the response as knowledge.
- Live `memory_status` and content read are `DoD: confirm: user`.
