# Issue tracker

The Master workspace uses a **local markdown tracker** for its own work and
receives peer work items over a signed route.

## Local tracker

- Root: `.scratch/issues/`
- One issue per file: `.scratch/issues/<id>.md`
- Frontmatter: `sparknet-issue/1` from `../contracts/issue-schema.json`.
- `.scratch/` is machine-local and gitignored.

## Peer intake

The Master listener is `services/sparknet-peer-intake.py`:

- Route: `POST /api/v1/issues` on 8090.
- Authentication: signed node request through `shared/sparknet-http.py`, then a
  registered, non-revoked overlay fingerprint.
- Capability: peer-held `issue-report`.
- Checks: schema, digest, expiry, nonce replay, redaction.
- Trusted keys: `SPARKNET_ISSUE_KEYRING` (default `/etc/sparknet/issue-keys.json`)
  is a JSON object `{node_id: public_key_b64}` the operator creates from each
  peer's node public key. The key binds the signer; the registry entry binds the
  overlay address and the `issue-report` capability.
- Store: `/mnt/log/sparknet-issues.jsonl`, append-only; triage history is
  `<state-dir>/issues/triage.jsonl`, with `triage.json` derived from it.

The Master records and tracks. It never executes an issue as a command, never
installs it into a vault and never serves it as knowledge.

## Triage

The five labels are `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human` and `wontfix`. See `triage-labels.md`. The Master console
exposes the recorded issues at `GET /api/issues` and the Issues tab, read-only.
A local triage transition is written with:

```sh
python3 scripts/sparknet-issue-triage.py \
  --node-id sparknet-node-0002 --issue-id fix-token \
  --status triaged --label ready-for-agent --note "reproduced"
```

The command appends to `triage.jsonl` and refreshes the derived `triage.json`.
It does not sign, grant authority or send anything to a peer.
