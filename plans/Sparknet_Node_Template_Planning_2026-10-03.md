# Sparknet Node Template Planning (2026-10-03)

This document captures the planning session for ingesting the Sparknet Master Architecture & Deployment Summary (Google Doc) and restating the execution plan.

## Session Inputs
- Google Doc: https://docs.google.com/document/d/1KEwbDSPSg3T8MaQPrmEODsxSkSohGLkBPIJVwktuioQ/edit?usp=drivesdk
- Exported text saved to: `master-node/plans/Sparknet_Master_Architecture_Deployment_Summary.md`
- Existing blueprint: /mnt/knowledge/sparknet/Sparknet_Enterprise_Architecture_Blueprint.md

## Key Architectural Requirements (from Google Doc)
- EU AI Act Article 14 (Human Oversight): Plan → Permission → Execute workflow
- Security: KillSwitch (root-restricted), immutable critical paths with signed Master approvals, WG-isolated guard daemon
- Hardware: ConnectX-7 RoCEv2 DMA-BUF, MTU 9000, dual-tier (Daytime/Nocturnal), WLAN emergency routing with nftables
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

