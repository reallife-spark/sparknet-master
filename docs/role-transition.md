# Role transition: peer -> master (election request)

A peer may request to become master via a signed election request. On approval by the existing master and re-formation of the trust root (per consensus protocol), the node transitions to master role without losing permissions/containers/makefile artifacts.

Flow:
1. Peer signs election_request {node_id, operational_pubkey, nonce, ts} with identity key.
2. Submit to current master (e.g. 8090).
3. Master verifies, records. If granted, trust root re-formed naming this node's operational key as master.
4. Node receives trust root; role manifest flips (peer->master), services by path remain identical (charter: master loads peer services by path). Containers/make targets unchanged.
