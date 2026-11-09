---
title: Unverifiable claims
type: audit
role: master
status: partially-built
updated: 2026-10-22
---

# Unverifiable claims (Step 19 DoD: confirm: user)

> [!warning] Not verifiable on this host
> This development host has no cluster, no wireguard kernel module and nothing
> bound. The list below is what **cannot** be checked from here — it needs a
> live deployment. What *was* verified live on real hosts is listed under it,
> dated and attributed, so a reader can tell the two apart instead of taking
> silence for a negative.

## Not verifiable from here

- A live **three-node** cluster and its member-loss policy. The election itself
  was proven on a two-host pair, not a trio.
- Re-formed root propagation after a member loss.
- Rollback and the replace-Master re-formation. Both are documented in
  [`../../contracts/deployment-runbook.md`](../../contracts/deployment-runbook.md)
  and were deliberately left unexecuted by operator decision — do not describe
  them as run.
- Reachability of the admin surface from an operator client
  (`10.100.0.1:8088`; Step 18's open leg).

## Verified live on real hosts, dated

- **2026-10-07** — agx64 and agx32 co-formed a 2/2 trust root naming agx64
  Master over the deployed transport; the signer ran as
  `sparknet-master-signer.service` on agx64, signed a live registry entry a
  still-peer verified, survived a real reboot, refused non-Master keys, unnamed
  nodes and tampered roots, and demonstrated a live revoke→peer-inert→
  re-authorize cycle.
- **2026-10-19** — a real reboot of each host restored the overlay unattended
  (userspace `wireguard-go` driven by the anchor unit); on the Master the admin
  container auto-started and bound `10.100.0.1:8088`.

## Still specified, not built

- Registry distribution to a peer (build plan Step 6) — there is no channel, so
  revocation propagation cannot be measured.
- The four admin services `4220`–`4223` are built/live on the pair as of
  2026-10-31: read-only git, read-only file share, NAT status/dry-run, and the
  signed vector store. Their live reachability is a two-node observation, not a
  fleet-wide claim.
