# Sparknet Node Template Planning (2026-10-03)

> [!warning] **Historical planning input, not current hardware or status.**
> The session below assumed ConnectX-7/RDMA and a 512 GB+ pooled Nocturnal UMA.
> The deployed `agx64`/`agx32` pair has no RDMA, no shared GPU address space and
> no ConnectX-7; Nocturnal mode is a batch lease over independent nodes. See
> [`scenarios-and-boms.md`](scenarios-and-boms.md). The plan phases are retained
> as provenance.

This document captures the planning session for ingesting the Sparknet Master Architecture & Deployment Summary (Google Doc) and restating the execution plan.

## Session Inputs
- Google Doc: https://docs.google.com/document/d/1KEwbDSPSg3T8MaQPrmEODsxSkSohGLkBPIJVwktuioQ/edit?usp=drivesdk
- Exported text saved to: `master-node/plans/Sparknet_Master_Architecture_Deployment_Summary.md`
- Existing blueprint: /mnt/knowledge/sparknet/Sparknet_Enterprise_Architecture_Blueprint.md

## Key Architectural Requirements (from Google Doc)
- EU AI Act Article 14 (Human Oversight): Plan → Permission → Execute workflow
- Security: KillSwitch (root-restricted), immutable critical paths with signed Master approvals, WG-isolated guard daemon
- Hardware as proposed in that session: ConnectX-7 RoCEv2 DMA-BUF, MTU 9000, dual-tier (Daytime/Nocturnal), WLAN emergency routing with nftables. The deployed fleet has none of the RDMA/ConnectX-7 hardware; its firewall is iptables.
- Portable hidden vault: /mnt/knowledge/.sparknet/ (manifests, compose, ledger, state)
- Hybrid NVFP4 Diffusion, Vault Curator, permissioned Ed25519-signed hash-chained ledger
- User-space P2P sync: sparknet-sync.sh + systemd --user timer
- Critical: Identify/document local user system, operate strictly within user privileges, safely access user credentials, API calls originate from user computer → node (relay model)

## Plan Phases
0. Save Google Doc + planning doc to plans/ (DONE)
1. Push sparknet to GitHub BEFORE changes
2. Ingest & distill materials into knowledge structure
3. Fix vault service/path/venv design (vault/path/venv-agnostic; wrappers, absolute paths, explicit env)
4. Build DGX Spark Node Template (with user-env introspection, privilege scoping, relay model)
5. Documentation, validation, integration

