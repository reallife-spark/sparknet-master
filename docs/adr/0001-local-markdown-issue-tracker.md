# 0001 — Local markdown issue tracker and signed peer intake

## Status

Accepted (2026-11-09).

## Context

The Master needs to track peer work items without reading a peer's vault and
without widening the telemetry channel's closed `kind` vocabulary.

## Decision

Keep a local markdown tracker under `.scratch/issues/` for Master work. Receive
peer issues as signed work-item reports on `POST /api/v1/issues` (8090) under
the peer-held `issue-report` capability, and store them append-only at
`/mnt/log/sparknet-issues.jsonl`.

## Consequences

- Issues are evidence and work items, never authority and never knowledge.
- The telemetry schema keeps its closed kind list.
- The Master can triage and display issues without a peer-vault read.
- A peer without `issue-report` sends nothing; the route refuses it before the
  body is read.
