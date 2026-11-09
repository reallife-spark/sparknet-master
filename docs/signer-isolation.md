---
title: Signer isolation — root-owned key, group socket, caller allowlist
role: master
status: built
updated: 2026-11-08
---

# Signer isolation: root-owned key, group socket, caller allowlist

The signer is the one process that holds the operational key. Two boundaries
must hold at once:

1. **The peer user cannot read the key.** The key and trust root are owned by
   root and mode 0600. Running the signer as root is acceptable for this
   boundary because the peer, its vault and its AI surfaces run as the peer
   user; a process that is already root has the host.
2. **The peer user cannot sign arbitrary operations.** The signer socket lives
   in a setgid directory (group `sparknet-signer`, mode 2770), the socket is
   mode 0660, and the peer user is in that group. The signer then enforces an
   exact `--allow-caller` executable/script allowlist, so a random peer process
   cannot ask for a signature even though it can open the socket.

The live `agx64` unit therefore runs `User=root` with a root-owned key, a
group-owned socket, and the service/script allowlist. The tracked unit remains
generic; a deployment adds the group and mode locally.

## What the unit needs

- `SPARKNET_NODE_ID` and `SPARKNET_STATE_DIR` as explicit `Environment=` lines
  (do not make a root service read the peer's `.env`).
- `/etc/sparknet/keys` or the state dir key root-owned 0600.
- `sparknet-signer` group; peer user added to it.
- `StateDirectory` is not needed for the signer itself.
- Ledger file root:sparknet-signer 0640 so the peer's read-only ledger unit can
  verify it. The signer also assigns a new ledger file the directory's group;
  set the directory setgid (`2775`) as a belt-and-braces measure.

## Optional dedicated uid

`--allow-uid UID` exists for a future dedicated signer account, but a signer
running as a different unprivileged user cannot read the peer's `/proc` entries
on current kernels, so the exact executable allowlist cannot identify the
caller. Use `--allow-uid` only when the socket group is the intended boundary,
and keep the key root-owned. The live deployment uses the stronger allowlist.
