# sparknet master-node — Session Memory

> Standing state only. Read at session start; **replace, never append**.
> The plan and its cursor live in `plans/MASTER_BUILD_PLAN.md` — this file
> mirrors it, it does not own it. Per-session detail belongs in
> `sessions/YYYY-MM-DD.md`.

Updated: 2026-10-04

## Standing State

- **Plan cursor**: `plans/MASTER_BUILD_PLAN.md` `current: 1` — Step 1
  (keypair and registry substrate).
- **Vault**: this directory (`master-node/`), categories: concepts, entities,
  skills, references, synthesis, journal.
- **Config**: `.env` (`VAULT_PATH`); staged writes: false.
- **Fabric root**: parent directory, holding `contracts/` and `shared/`.
  Override with `SPARKNET_FABRIC_ROOT`.
- **Blockers**: none technically. The whole role is unbuilt, which is the
  expected starting state rather than a fault.

## Key Standing Facts

- **Nothing in this role runs yet.** There is no `scripts/`, `services/` or
  `systemd/` directory, by deliberate choice. This subvault is specification
  and backlog; `plans/MASTER_BUILD_PLAN.md` is the work order.
- The Master holds the only Ed25519 private key in the fabric. It never leaves
  this machine and is never committed. A peer holding the same capability
  vocabulary without that key can verify but never grant.
- The shipped `master-ed25519.pub.b64` is a **bootstrap** key whose private
  half was discarded — it cannot sign. Step 1 of the build plan replaces it.
- The peer egress rule (wlan pinned to `10.100.0.1`) must never be adopted on
  the Master. It would blackhole the fabric. See `docs/network-posture.md`.
- `../shared/sparknet-authz.py` is the single implementation of the signed
  canonical form. This role signs with it; peers verify with it. Never copy it.
- `guard-apply` cannot be granted to any peer until Step 4 (approval issuer)
  exists — the capability is defined and enforced, but nothing can issue it.
- The peer's live WireGuard, nftables, `chattr +i` and systemd behaviour is
  unverified on the development host; do not claim otherwise.