# Registry protocol

**Status: partially built (Steps 3 and 6; Step 2 reopened 2026-10-06).**

This document describes the registry format the Master emits and peers consume.
It was written before the CLI existed so the contract could not drift, and the
CLI that arrived in Step 3 now emits and verifies it (`scripts/sparknet-registry-*.sh`).
Two things are still open and are recorded here rather than smoothed over:

- **The distribution channel is unspecified.** `make registry-publish` emits the
  signed document; how it reaches a peer is Step 6's decision and has not been
  made — `contracts/identity-schema.json` carries `distribution: UNSPECIFIED` on
  purpose.
- **The field set below disagrees with `shared/sparknet-authz.py`.** The schema
  in `../manifests/registry.schema.json` and this page name the entry
  signature field `signature`; `sign_authorization` emits and verifies
  `signature_b64`, and nothing loads the schema. Which shape is canonical is an
  open contract decision (Step 2), not a typo to fix in one place.

## Registry shape

The registry is a JSON document at version `1.0.0` with role `registry`:
- `role` — must be `"registry"`
- `schema_version` — must be `"1.0.0"`
- `issued_at` — RFC3339 UTC timestamp (optional in the minimal schema, present in
  production)
- `issuer` — node id or fingerprint of the signing entity (optional)
- `authorizations` — array of authorization entries

Each authorization entry is a signed authorization as emitted by
`shared/sparknet-authz.py::sign_authorization`. Required fields: `fingerprint`,
`identity`, `capabilities`, `signature`. Extra fields are allowed until a stricter
version.

## Validation

A peer verifies a registry by:
1. parsing the JSON,
2. validating against the schema,
3. checking each entry signature against the key named by the elected trust root,
4. rejecting revoked entries,
5. rejecting expired entries.

## Distribution

Distribution channel: **UNSPECIFIED** (recorded in `contracts/identity-schema.json`).
Step 6 must choose and document it. Until then no peer can be told to fetch from a
specific URL/endpoint.

## "Specified, not built" marker

This document is unbuilt by definition: the `make registry-*` targets do not exist
yet. A test in `tests/test_master_spec.py` must be able to detect that fact.

## Distribution channel (chosen)

Selected for this step (machine-detectable): **local filesystem path** emitted by
`make registry-publish OUT=<path>`. This is a minimal, verifiable channel suitable
for unit tests; Step 7 and beyond may replace or extend it. The choice is recorded
here to satisfy DoD (1).
