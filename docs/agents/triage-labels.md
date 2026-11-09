# Triage labels

The closed label vocabulary for the local issue tracker. The strings are the
labels; the table is the meaning.

| Label | Meaning | Who acts |
|---|---|---|
| `needs-triage` | New or reopened; nobody has decided what it is yet. | A human or the `triage` skill |
| `needs-info` | The report cannot be acted on without a missing fact. | Reporter, then triage again |
| `ready-for-agent` | Scoped, reproducible and safe for an agent to start. | An agent, with a plan step |
| `ready-for-human` | Needs an operator decision, access or judgment. | A human |
| `wontfix` | Deliberately not being done; record why. | Closer |

## Rules

- Exactly one of the five is the triage state; `needs-info` is not a parking
  lot for an issue nobody wants.
- A free-form label may be added for search, but it never gates work.
- `ready-for-agent` is a statement that the issue is safe to start, not a
  capability grant. The agent still follows `AGENTS.md` and the plan protocol.
- A `wontfix` issue stays in the tracker with its reason; deletion loses the
  decision.
