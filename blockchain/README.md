# blockchain/

The elected Master's hash-chained ledger. Same schema and same chain rules as
the peer's — see `../../peer-node/blockchain/ledger.schema.json`, which is the
normative statement and is not duplicated here.

Why the Master keeps one of its own: it records the events a peer cannot observe,
namely the agreement that made it the Master. An election outcome, a trust-root
formation, a re-formation and every signature the signer produces are Master-side
facts. A peer ledger records what happened *to that peer*; only the Master's can
record who decided what.

The two ledgers are not merged and not synchronised. They are per-node records
with the same schema, and a share that needs to move an event between them uses
the share protocol in `../../contracts/share-protocol.md` — not a direct write.
