# sparknet master-node — agent charter

The **Master role** of the Sparknet fabric: the node that holds signing
authority over the overlay.

> **Status: specified, not built.** This subvault contains contracts,
> configuration templates, specifications and a prioritized build plan. There
> is deliberately no `scripts/`, `services/` or `systemd/` directory here yet —
> nothing would run. Work the backlog in `plans/MASTER_BUILD_PLAN.md`; the
> first step is to earn the right to create those directories.

This is a standalone knowledge vault. A session started inside
`master-node/` resolves to *this* directory as its knowledge base, not to the
parent.

## Role in one paragraph

The Master is the only node that can grant authority. It holds the Ed25519
private key, signs the registry that says what each node may do, maintains the
WireGuard overlay at `10.100.0.1`, and can revoke any peer instantly from its
own side. Everything else in the fabric is subordinate to it. Its authority
comes from **key possession**, not from a capability grant — a peer holding the
same capability vocabulary without that key can verify, but can never grant,
revoke, or escalate.

The peer role lives in `../peer-node/` and is implemented.

## Authority, precisely

| Capability | Mechanism |
|---|---|
| Grant capabilities | signs a registry entry with the Master private key |
| Revoke a node | signs `revoked: true`, removes the peer from its own `wg0` |
| Register a new peer | adds a `[Peer]` stanza to the Master's `wg0` |
| Authorize a `guard-apply` | signs an approval payload for one specific peer |
| Halt the fabric | the cluster KillSwitch (specified, not built) |

None of these are granted through the capability system. The capability
vocabulary in `../contracts/capabilities.json` governs what a **peer** may do.
The Master's own powers are implied by holding the private key, which is
exactly why that key must never leave this machine.

## Boundaries vs a peer

| Concern | Master |
|---|---|
| Signing key custody | **exclusive — never leaves** |
| Registry authorship | **authoritative** |
| Overlay address | `10.100.0.1` |
| Network egress | **unrestricted** — the peer egress rule pins traffic to the Master, and adopting it here would blackhole the fabric |
| Peers it holds | every authorized node, one stanza each |
| Containment | cluster-wide, from here |

A peer can be revoked and lose its anchor, and then it is inert: its guard
refuses to bind and refuses to apply, because it can no longer receive a valid
signature. The Master is the only party that can put it back, which is what
makes revocation meaningful rather than advisory.

The asymmetry in egress is the clearest statement of the difference between the
roles: a peer may reach only the Master; the Master reaches everyone. A rule
that is correct on a peer is actively harmful here.

## Layout (wiki category layout)

| Path | Holds |
|---|---|
| `concepts/` | distilled ideas and definitions |
| `entities/` | people, organisations, systems, products |
| `skills/` | reusable procedures (how-to pages) |
| `references/` | external material: docs, specs, transcripts, datasets |
| `synthesis/` | conclusions ACROSS two or more pages |
| `journal/` | dated entries and session notes |
| `projects/` | per-project knowledge |
| `sessions/` | per-session agent memory (`YYYY-MM-DD.md`) |
| `_raw/` | unprocessed captures — nothing is deleted from here |

Role-specific trees:

| Path | Holds |
|---|---|
| `configs/wireguard/` | the Master-side `wg0` peer stanza template |
| `manifests/` | Master identity and registry schema — **not present yet**; it arrives with Step 1, because a Master manifest needs a real signing key |
| `docs/` | Master-side specifications |
| `plans/` | the build backlog and planning notes |
| `tests/` | specification-conformance tests (no implementation to test yet) |

There is intentionally no `scripts/`, `services/` or `systemd/` yet.

## The contract this role obeys

`../contracts/` is the single source of truth for overlay addressing, the
capability vocabulary, the identity schema, ports and the guard protocol.
Changing anything a peer depends on is a **cross-role change**: edit the
contract, then update both roles in the same commit, then run
`make contract-test` at the parent.

`../shared/sparknet-authz.py` is the one implementation of the signed
authorization scheme. This role *signs* with it; a peer *verifies* with it.
Never copy it here.

## Memory Protocol

- `MEMORY.md` — **standing state only**, tiny: plan cursor, durable facts,
  blockers. Replace, never append indefinitely.
- `sessions/YYYY-MM-DD.md` — that session's full record. One file per day;
  sessions spanning midnight use the start date.
- Read `MEMORY.md` and today's session file at session start; write detail only
  to today's session file. Never back-write history into `MEMORY.md`.

## Plan Protocol

`plans/MASTER_BUILD_PLAN.md` is the single source of truth for Master work.

- Frontmatter `current:` marks the step being worked.
- Mark a step `[x]` **only** after its DoD is verified, then advance the cursor
  and write the plan back **immediately**.
- Append one line per transition to `log.md` (append-only audit trail).
- Terminal state is `current: done`. New roadmap work gets a **new** step; do
  not silently reuse a finished plan.
- A step whose DoD cannot be auto-verified is marked `DoD: confirm: user`.

## Canonical placement

- Distilled page → its category dir. Raw capture → `_raw/` until distilled.
- Logs and telemetry → `/mnt/log/`, not the vault and not `~/`.
- The Master private key lives in `$SPARKNET_STATE_DIR/keys` at mode 0600 and
  is **never** committed, referenced only by path.
- One page per file; no duplicate copies. Prefer editing an existing page over
  adding a near-duplicate; cross-link instead of copying.

## Wiki skill suite

**Vendored in this repository** at `../.opencode/skills/` — there is no global
skill farm dependency, so a bare clone or an extracted node bundle can run the
whole suite. Do not reach for a copy under `/mnt/nvme` or `~/.config/opencode`.

Before using any skill, resolve this vault explicitly:

```bash
# From a role subvault. Walks up to the nearest copy — no .git required, because a
# standalone bundle ships without one.
for d in "$PWD" "$(dirname "$PWD")"; do
  [ -f "$d/scripts/sparknet-wiki-env.sh" ] && { source "$d/scripts/sparknet-wiki-env.sh"; break; }
done
```

That prints the role, the role root and the `VAULT_PATH` the skills will use.
**If it fails, stop** — run `../scripts/sparknet-env-init.sh .` once. Do not work
around it: a silent fallback resolves a *different* vault and every page lands in
the wrong place with no error.

Config resolves from `.env` in this directory (`VAULT_PATH`) — never hard-code a
path in a page. `make wiki-preflight` runs the same check.

Run `/wiki-status` first, then `/wiki-ingest`, `/wiki-query`, `/wiki-lint`,
`/wiki-capture`, `/wiki-synthesize`, `/wiki-digest`, `/wiki-rebuild`,
`/daily-update`.

## Boundaries

- **Scope discipline.** This vault holds Master-role sparknet knowledge.
  Peer-role material goes in `../peer-node/`; cross-role contracts in
  `../contracts/`.
- **No secrets.** Never commit tokens, keys or `.env` contents. Reference the
  secret *path* only. The Master private key is the most sensitive secret in
  the entire fabric.
- **Offensive security is out of scope** for a general/default agent session.
  Route offensive work to the `red` role and defensive work to `blue`.
- Cite sources. A distilled page without provenance is a guess — mark it as one.
- **Do not claim live verification.** Nothing on this role runs yet, and the
  peer's live network behaviour is unverified on the development host.
- **Distinguish specification from implementation.** This subvault describes
  what the Master must do. Nothing here should read as though it already does.