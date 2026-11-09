---
title: 4203 live three-node preparation
role: master
status: partially-built
updated: 2026-10-31
---

> [!warning] 4203 is built and loopback-rehearsed, but it is **not enabled**
> on the two-node pair and no third host exists yet. Do not add a fake third
> registry entry.

# 4203 live three-node preparation

Status: **built and loopback-rehearsed; not enabled on the two-node pair.**
`4203` exists to arbitrate a `master_governed` share, which starts at three
registry nodes. The current live pair is `peer_pair` and needs no ratification,
so enabling 4203 here would only add an unexercised socket.

## Preconditions for the live leg

1. A third node with its own identity, overlay address and Ed25519 transport key
   is registered and signed by the Master. Its public key is placed in the
   Master's trusted-key directory, one file per node:
   `$SPARKNET_STATE_DIR/share-keys/<node_id>.pub.b64`.
2. The signed registry has **three** live entries. Sequence 5 is the next
   publish after the current sequence 4. A three-entry registry changes
   `mode_for()` to `master_governed`; every subsequent share needs 4203.
3. The Master's signer is running; the 4203 listener never signs. Human
   approval uses `make -C master-node share-ratify-approve SHARE_ID=...`, which
   reads the queue and calls the isolated signer socket.
4. No third host is available today. Do not fabricate a registry entry or a key
   just to make `mode_for()` return three; that would be a false membership
   claim, not a rehearsal.

## Stage the unit (does not enable it)

Render the absolute-path unit from the role root; review it before installing:

```sh
make -C /home/raxxar/sparknet/master-node share-ratify-unit \
  > /tmp/sparknet-share-ratify.service
sudo install -Dm644 /tmp/sparknet-share-ratify.service \
  /etc/systemd/system/sparknet-share-ratify.service
sudo systemctl daemon-reload
# Do NOT enable on the pair. The unit is staged for the three-node leg.
```

The listener queues a verified request; it has no signer and no key. It binds
`10.100.0.1:4203` only.

## Exercise on the three-node fleet

1. Start `sparknet-share-ratify.service`; `make share-ratify-list` is empty.
2. A peer with `cluster-dispatch` or `cluster-serve` submits a grant-bound
   request to `POST /v1/share/request`. The listener verifies the key against
   the trusted-key directory, binds `request.node_id` to the verified key, and
   returns `202` with `queue: human-approval-required`.
3. `make share-ratify-list` shows `pending`; `systemctl status` shows no signer
   activity. This is the no-auto-ratify proof.
4. A human runs `make share-ratify-approve SHARE_ID=...` (or `refuse`). The
   service signs through the isolated signer and stores the signed envelope in
   the queue.
5. Deliver the signed `share.ratify` message to **both** peers. Each peer's
   `sparknet-share-serve.py` verifies the pinned Master signature before the
   regime lifts the endpoint to `authenticated` with `flagged` retained.
6. Record queue state, signature digest, peer endpoint trust and registry
   sequence in the dated transcript.

## Rollback

Stop `sparknet-share-ratify.service`, remove no queue records (they are
evidence), and return the peers to the two-node mode only by publishing a
registry with two entries. A share already opened under `master_governed` is
re-evaluated by the regime; do not hand-edit its state.

## Staged on the live Master (2026-10-31)

`/etc/systemd/system/sparknet-share-ratify.service` is installed but **disabled
and inactive** on agx32. The state directory is 0700, the trusted-key directory
contains only `sparknet-node-0001.pub.b64`, and port 4203 is not bound. This is
the correct two-node posture; the unit exists for the third-node leg.

## Existing evidence

- `master-node/tests/test_share_ratify.py` covers the signed listener, durable
  queue, key-ring/node binding, restart and no-auto-ratify.
- `make share-rehearsal` drives a three-node offer→accept→payload→4203 queue→
  human-signed lift over real loopback listeners (10/10).
- The two-node live pair has exercised 4201/4202 but not 4203; that remains
  `DoD: confirm: user` until a third node exists.
