---
title: MASTER_ADMIN_PLAN — the Master as infrastructure administrator
type: plan
role: master
status: spec
updated: 2026-10-06
---

# MASTER_ADMIN_PLAN — the Master as infrastructure administrator

The user has directed that the Master role carries the fabric's
infrastructure administration in addition to its signing authority. This plan
scopes what that means and — by the charter's rule — what it does **not**
mean yet.

Everything here is **SPEC ONLY**. No code, no daemon, no populate. The four
services below exist in `contracts/ports.json` as `spec-only` ports
(`4220`–`4223`); until a port flips to `provisioned` or `implemented`, saying
"the Master runs git" is the same overclaim as saying the signer is deployed.

## The administrator contract

| Subsystem | Port | What administration means |
|---|---|---|
| Git | `4220 git-repo` | hosts the fabric repository; manages the authorized-key allowlist; creates/clones/mirrors repositories on request |
| File sharing | `4221 file-share` | hosts shared volumes for the fabric; peers mount or fetch them over the overlay |
| NAT | `4222 nat-gateway` | keeps overlay NAT state coherent for peers behind NAT; complements PersistentKeepalive on `51820` |
| Vector embeddings DB | `4223 vector-embed` | hosts the shared semantic store; roles and wiki skills query it over the overlay |

These are **infrastructure services**, not authority-plane operations. They
carry no signed authorization message, which is why they are `overlay_only`,
bound to `10.100.0.1`, and twice removed from the signing key: the key lives
in the isolated signer process, and none of these services may reach it.

## Boundaries

- **Role responsibility, not a build order.** The charter contract says the
  Master *administers* these systems; it does not say they exist. Flipping a
  port from `spec-only` requires real scaffolding and a `runtime_why`
  measurement — the same gate as any other fabric port.
- **Overlay-only by design.** Each binds `10.100.0.1`, never a wildcard, so a
  compromised infrastructure service is reachable only by peers on the
  fabric, not from the WAN.
- **Not a copy of the peer.** The peer's `4201` share-intake is a signed
  handoff between two peers; the Master's `4221` is the fabric's shared
  volume. Same word "share", two different planes.
- **No key adjacency.** No admin subsystem may load, invoke or proxy to the
  signer. That boundary is structural, same as it is for the admin surface.

## Where this is tracked

- Ports: `contracts/ports.json` (`4220`–`4223`, `spec-only`, `bound_by:
  master`)
- Role spec: `docs/master-control-plane.md` (Components + Responsibilities
  sections)
- Gate: `tests/test_contracts.py` requires every non-implemented port to say
  so and point at a real plan — this file is that plan for the four admin
  services. The build backlog for the role itself remains
  `plans/MASTER_BUILD_PLAN.md`.