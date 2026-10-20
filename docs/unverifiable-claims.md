# Unverifiable claims (Step 19 DoD: confirm: user)

None of the following were verified on this host:
- Live three-node cluster and actual election
- Operational trust root deployed in production
- Signed production registry entry distributed to peers
- Overlay interface/wireguard/nftables active on 10.100.0.1
- Open WebUI/admin surface listening on 10.100.0.1:8088 (relocated from 8080, fabric Step 55; deployed on the live Master agx32, not verifiable from this dev host)
- Actual signer process running (isolated, not deployed)
- N=3 member-loss policy enacted; re-formed root propagation

These require a live deployment; marked as DoD: confirm: user.
