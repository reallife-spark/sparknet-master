# EU AI Act Compliance (Article 14 - Human Oversight)

## Plan → Permission → Execute Workflow

All agentic state mutations must follow this gate:

1. **Plan**: Agent compiles read-only proposal/diff (what will change, why, impact, rollback plan)
2. **Permission**: Open WebUI renders interactive Allow/Deny approval cards. Unattended tasks require explicit operator validation.
3. **Execute**: Operations execute only after human sign-off within strict user privilege boundaries (UID:GID)

## Audit Trail
Approvals recorded in permissioned ledger with Ed25519 signatures and SHA-256 hash chaining (see blockchain/ledger schema).

## Implementation Notes
- Approval hooks integrated via dispatch bridge (services/sparknet-dispatch-bridge.py)
- Guard daemon enforces master-signed approvals for critical path mutations
