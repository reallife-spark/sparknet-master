# systemd/

| Unit | Role |
|---|---|
| `sparknet-master-parity.service` | Proves the peer's services still load by path |
| `sparknet-master-ledger.service` | Verifies the Master's hash chain |
| `sparknet-master-signer.service` | The isolated signer (Steps 15–18); stages the operational key |
| `sparknet-master-firewall.service` | Applies the Master's ordinary iptables policy |
| `sparknet-master-wireguard-anchor.service` | Brings up the Master's overlay (`10.100.0.1`) |
| `sparknet-peer-intake.service` | Peer→Master intake on `8090` (fabric Steps 69C/70B); staged, not enabled |
| `sparknet-reflex-broker.service` | Reflex broker control surface; staged, not enabled |
| `sparknet-wg-observer.service` / `.timer` | Root WireGuard evidence for the nocturnal scheduler; staged, not enabled |
| `sparknet-registry-deliver.service` / `.timer` | Delivers a signed registry publication to peers |
| `sparknet-container-registry.service` | Private loopback OCI distribution; staged, needs a 0600 token file |

`make wg-observer-unit` stages the observer and its timer but enables neither.
The service is a root oneshot; the timer only wakes it every 60 seconds. A root
timer is an operator decision, and Step 9G owns the live deployment.

The peer's units (`sparknet-guard-daemon`, `sparknet-wireguard-anchor`,
`sync`, `wifi-guard`) are **not** copied here. This role runs them by path through
`services/sparknet-parity.py`; a second copy would drift.

`sparknet-killswitch.py` is not a unit. It is an operator-invoked, root-gated,
dry-run-by-default control that disables the units above and installs
emergency iptables chains; see `docs/killswitch-template.md`.
