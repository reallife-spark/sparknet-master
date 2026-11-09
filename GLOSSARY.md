# Master glossary

- **Master** — the elected signing role; it holds the operational key and
  supplies authority and scoped fabric knowledge.
- **operational key** — the Ed25519 private key that signs registry entries,
  approvals and scoped answers. It never leaves the Master.
- **signer** — the isolated process that holds the operational key and signs
  only for an allowlisted caller.
- **registry** — the signed list of node identities, capabilities, overlay
  addresses and revocations.
- **approval** — a Master-signed authorization for one protected change or one
  admin action; it is not knowledge.
- **intake** — the 8090/8091 listeners that accept telemetry, RFI requests,
  issue reports and consented uplift.
- **uplift** — consented training/backup data. It is never served as knowledge.
- **issue** — a peer work item recorded on the issue intake. It is tracked, not
  executed, and never enters a vault or the answer corpus.
- **understand graph** — the derived `.ua/knowledge-graph.json`; a build
  artifact, never authority.
