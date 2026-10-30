# Deployment Scenarios & Hardware BOMs

Status: **current as of 2026-10-26.** This page describes the deployed
`agx64`/`agx32` pair. The original 512 GB+ ConnectX-7 blueprint is retained only
as historical provenance in
[`Sparknet_Master_Architecture_Deployment_Summary.md`](Sparknet_Master_Architecture_Deployment_Summary.md);
it is not the fabric's hardware or Nocturnal design.

## Measured fleet

| Node | Role | Memory | CPU | GPU tooling | RDMA | Overlay |
|---|---|---:|---:|---|---|---|
| `agx64` | peer (`sparknet-node-0001`) | 63,198 MiB | 8 ARMv8 cores | `tegrastats`; no `nvidia-smi` | none | `wg1 10.100.0.2/32` |
| `agx32` | Master (`sparknet-node-0002`) | 30,990 MiB | 8 ARMv8 cores | `tegrastats`; no `nvidia-smi` | none | `wg1 10.100.0.1/32` |

Both hosts use the dedicated `10.99.0.0/30` cable underlay (`agx32` `.1`,
`agx64` `.2`) plus `wlan0` as the LAN path. There is no ConnectX-7, no
`/sys/class/infiniband`, and no shared GPU address space.

## Scenarios

1. **Same-site pair (current).** Two AGX hosts on one LAN, joined by the
   WireGuard overlay and the direct cable underlay. Daytime work stays
   node-local; a Nocturnal lease may schedule whole-node batch jobs on idle
   participants.
2. **Campus / multi-building.** The same pair over a routed LAN or VPN. No
   new fabric primitive: the overlay and signed authority plane are unchanged,
   but latency and link loss make local work the default.
3. **Geographically distributed.** Not deployed and not supported as a pooled
   fabric. WireGuard can carry the authority plane, but there is no RDMA or
   shared memory to stretch across sites; a Nocturnal lease would remain
   whole-node and would need a new latency/failure design.

## Network and containment

- WireGuard overlay `wg1`: Master anchor `10.100.0.1`, peer `10.100.0.2`.
- Underlay: `10.99.0.0/30`, static and never-default.
- The deployed host firewall is **iptables** (`SPARKNET-FW-IN` /
  `SPARKNET-FW-FWD`); `nft` is not installed on the fleet.
- The Master's cluster KillSwitch installs `SPARKNET_EMERG_*` iptables chains.
  It is not the peer's local containment script.
- WLAN emergency routing remains a peer network concern; it does not create a
  second authority path.

## BOM

- 2 × AGX-class ARM hosts with 32 GiB / 64 GiB unified memory.
- 8 ARMv8 cores per host.
- 1 × direct Ethernet underlay cable.
- 2 × LAN/WLAN paths.
- No ConnectX-7, no RoCEv2, no DMA-BUF P2P, no 512 GB pooled UMA.
- No NVFP4 Blackwell tensor-core claim: the deployed AGX fleet is not
  Blackwell.

## Nocturnal mode

Nocturnal mode is **not** a pooled-memory fabric. It is a time-boxed batch
lease over independent nodes running whole-node jobs. See
[`NOCTURNAL_BATCH_DESIGN.md`](NOCTURNAL_BATCH_DESIGN.md).
