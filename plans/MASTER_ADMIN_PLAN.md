---
title: MASTER_ADMIN_PLAN — the Master as infrastructure administrator
type: plan
role: master
status: built
updated: 2026-11-03
---

# MASTER_ADMIN_PLAN — the Master as infrastructure administrator

The user has directed that the Master role carries the fabric's
infrastructure administration in addition to its signing authority. This plan
scopes what that means and — by the charter's rule — what it does **not**
mean yet.

All four are **built and live** (2026-10-31): `4220` is a read-only bare git
mirror, `4221` is a signed read-only file share, `4222` is signed status/dry-run
with no write path, and `4223` serves `sparknet-fabric`/`sparknet-shared`.
None can reach the signer.

## The administrator contract

| Subsystem | Port | What administration means |
|---|---|---|
| Git | `4220 git-repo` | **live** — read-only bare mirror over git-daemon; no receive-pack |
| File sharing | `4221 file-share` | **live** — signed read-only list/fetch under `/srv/sparknet/share` |
| NAT | `4222 nat-gateway` | **live** — signed status and dry-run only; `changes` is always empty |
| Vector embeddings DB | `4223 vector-embed` | **live** — signed overlay queries against `sparknet-fabric` and explicit `sparknet-shared`; opt-in `.venv-vector` |

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

- Ports: `contracts/ports.json` (all four implemented/live; `bound_by: master`)
- Role spec: `docs/master-control-plane.md` (Components + Responsibilities
  sections)
- Gate: `tests/test_contracts.py` requires every non-implemented port to say
  so and point at a real plan — this file is that plan for the four admin
  services. The build backlog for the role itself remains
  `plans/MASTER_BUILD_PLAN.md`.