# systemd/

| Unit | Role |
|---|---|
| `sparknet-master-parity.service` | Proves the peer's services still load by path |
| `sparknet-master-ledger.service` | Verifies the Master's hash chain |

Deliberately absent for now, and each is a numbered build-plan step rather than an
oversight:

- the **signer** — Step 17. It is the one unit that may touch the operational key,
  and it lands with its own isolation rather than as a stub here.
- the **election timer** — Step 14's implementation, once there is something to
  vote with. A timer that votes for nobody is noise.

The peer's units (`sparknet-guard-daemon`, `sparknet-wireguard-anchor`,
`sync`, `wifi-guard`) are **not** copied here. This role runs them by path through
`services/sparknet-parity.py`; a second copy would drift.
