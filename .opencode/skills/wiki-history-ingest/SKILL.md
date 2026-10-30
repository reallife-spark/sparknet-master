---
name: wiki-history-ingest
description: >
  Unified history ingest for agent conversation/session sources. Use when the user says
  "/wiki-history-ingest claude", "/wiki-history-ingest copilot", "/wiki-history-ingest codex",
  "/wiki-history-ingest hermes", "/wiki-history-ingest openclaw", "/wiki-history-ingest pi",
  or asks to ingest agent history without naming the underlying tool. This is self-contained —
  each tool's data layout and parsing rules are embedded below. Also supports
  `/wiki-history-ingest auto` to infer the tool from context.
  Does NOT trigger for general copilot usage questions, searching sessions, or backing up history.
---

# Unified History Ingest

Self-contained skill for distilling agent conversation history into the Obsidian wiki.
Covers **Claude**, **Codex**, **Copilot**, **Hermes**, **OpenClaw**, and **Pi**.

Use `wiki-ingest` for **documents/content sources** — this skill is for **agent history sources only**.

## Routing

| Subcommand | Tool |
|---|---|
| `claude` | Claude Code (CLI + Desktop app) |
| `codex` | Codex CLI |
| `copilot` | GitHub Copilot CLI |
| `hermes` | Hermes agent |
| `openclaw` | OpenClaw agent |
| `pi` | Pi coding agent |
| `auto` | Infer from context (paths, file names, user phrasing) |

**Auto-routing rules:**
- `~/.claude` or Claude session/memory artifacts → Claude
- `~/.copilot`, `session-store.db`, VS Code copilot-chat transcripts → Copilot
- `~/.codex` or rollout/session index artifacts → Codex
- `~/.hermes` or Hermes memories/session artifacts → Hermes
- `~/.openclaw` or OpenClaw MEMORY.md/session JSONL artifacts → OpenClaw
- `~/.pi/agent/sessions` or Pi session JSONL artifacts → Pi
- If ambiguous, ask one short clarification.

---

## Shared Workflow

### Before You Start

1. **Resolve config** — follow the Config Resolution Protocol in `llm-wiki/SKILL.md` (walk up CWD for `.env` → `~/.wiki/config` → prompt setup). This gives `VAULT_PATH` and the tool-specific history path (see each tool section for the env var name and default).
2. Read `.manifest.json` at the vault root to check what has already been ingested.
3. Read `index.md` at the vault root to understand what the wiki already contains.
4. **Project Scoping (Claude only)** — read `WIKI_SKIP_PROJECTS` from config (comma-separated substrings). Exclude any project directory whose name contains one of them from every step.

### Ingest Modes

**Append Mode (default):** Check `.manifest.json` for each source file. Only process files not in the manifest, or files whose modification time is newer than `ingested_at`. This is usually what you want.

**Full Mode:** Process everything regardless of manifest. Use after `wiki-rebuild` or if the user explicitly asks.

### Conversation Sampling Heuristic

A history path can hold hundreds of conversations/sessions — do not try to read them all.

- **If the project already has pre-distilled content** (memory files, checkpoints, summaries), ingest those first, then also process conversations not yet in the manifest.
- **If no pre-distilled content**, read only the **3 most recent** conversations/sessions (by mtime) to characterize the project.
- Always report what you sampled vs skipped (e.g. "7 memory files + 4 new conversations ingested, 14 unchanged skipped").

### Cluster by Topic

Do not create one wiki page per conversation/session. Instead:

- Group extracted knowledge **by topic** across conversations.
- A single conversation about "debugging auth + setting up CI" → two separate topics.
- Three conversations across different days about "React performance" → one merged topic.
- Use `cwd`/`repository` to infer project scope.

### Distill into Wiki Pages

Route extracted knowledge using existing wiki conventions:

| What you found | Where it goes |
|---|---|
| Project architecture decisions | `projects/<name>/concepts/` |
| Project-specific debugging/techniques | `projects/<name>/skills/` |
| General concept the user learned | `concepts/` (global) |
| Recurring problem across projects | `skills/` (global) |
| A tool/service used | `entities/` (global) |
| Cross-session patterns | `synthesis/` (global) |

**Project overview pages** — named `<name>.md` (not `_project.md`) so Obsidian graph view shows a distinct node label.

**Distill the knowledge, not the conversation.** Don't write "In a session on March 15, the user asked about X." Write the knowledge itself, with the session as source attribution.

**Frontmatter on every new/updated page:**
```yaml
summary: "1–2 sentences, ≤200 chars, answering 'what is this page about?'"
base_confidence: 0.42
lifecycle: draft
lifecycle_changed: <ISO date today>
provenance:
  extracted: 0.3
  inferred: 0.7
  ambiguous: 0.0
```
Leave `lifecycle` unchanged on update.

**Provenance markers** (per `llm-wiki` convention):
- `^[extracted]` — directly grounded in explicit session/memory content (memory files, pre-distilled summaries, explicit assistant statements).
- `^[inferred]` — synthesizing patterns across sessions, generalizations, "what the user really meant" interpretations.
- `^[ambiguous]` — user changed their mind across sessions, or assistant/user contradicted each other.

### Update Manifest, Journal, and Hot.md

**`.manifest.json`** — for each source file processed, add/update with `ingested_at`, `size_bytes`, `modified_at`, `source_type`, `project`, `pages_created`, `pages_updated`. Also update the `projects` section with session counts.

**`log.md`** — append:
```
- [TIMESTAMP] <TOOL>_HISTORY_INGEST projects=N conversations=M pages_updated=X pages_created=Y mode=append|full
```

**`hot.md`** — update **Recent Activity** with a one-line summary; keep last 3 operations. Update `updated` frontmatter field.

### Privacy and Compliance

- Distill and synthesize — do not copy raw conversation text verbatim.
- Skip anything that looks like secrets, API keys, passwords, tokens.
- `reasoningText`/`reasoningOpaque` (Copilot) — internal reasoning; skip entirely.
- If you encounter personal/sensitive content, ask the user before including it.
- References to other people — keep minimal and purpose-bound.

### QMD Refresh After Vault Writes

QMD is a search index, not the source of truth. If `$QMD_WIKI_COLLECTION` is empty or unset, skip. Run only after this skill has written vault markdown. If QMD refresh fails, report separately — do not roll back vault changes.

```bash
${QMD_CLI:-qmd} update
# If vectors/embeddings needed:
${QMD_CLI:-qmd} embed
# Verify:
${QMD_CLI:-qmd} ls "$QMD_WIKI_COLLECTION"
```

Record one of:
- `QMD refreshed: update + embed + verified`
- `QMD refreshed: update only + verified`
- `QMD skipped: QMD_WIKI_COLLECTION unset`
- `QMD skipped: qmd CLI unavailable`
- `QMD failed: <short error summary>`

---

## Tool: Claude Code

**Config:** `VAULT_PATH` + `CLAUDE_HISTORY_PATH` (defaults to `~/.claude`).

**Key data sources by value:**
1. Memory files (`~/.claude/projects/*/memory/*.md`) — pre-distilled, wiki-ready.
2. Conversation JSONL (CLI + Desktop app transcripts) — rich but noisy.
3. Audit logs (`audit.jsonl` in Desktop sessions) — tool-call record of what the agent did.
4. Session metadata (`sessions/*.json`, `local_*.json`) — context (project, CWD, when).

### Claude Data Layout

**Source 1 — CLI sessions (`~/.claude/`):**
```
~/.claude/
├── projects/
│   ├── -Users-name-project-a/
│   │   ├── <session-uuid>.jsonl      # Conversation transcript
│   │   └── memory/
│   │       ├── MEMORY.md             # Memory index
│   │       ├── user_*.md             # User profile memories
│   │       ├── feedback_*.md         # Workflow feedback memories
│   │       └── project_*.md          # Project context memories
├── sessions/                         # Session metadata (JSON)
├── extracted/                        # Pre-extracted signal-only JSON (optional)
├── history.jsonl                     # Global session history
├── tasks/                            # Subagent task data
└── plans/                            # Saved plans
```

**Source 2 — Desktop app (`~/Library/Application Support/Claude/local-agent-mode-sessions/`):**
```
<outer-uuid>/<inner-uuid>/
├── local_<session-uuid>.json         # Session metadata
└── local_<session-uuid>/
    ├── audit.jsonl                   # Tool calls, file reads, commands
    └── .claude/projects/<path-encoded>/<uuid>.jsonl  # Transcript (same format as CLI)
```

> Pre-check: many users are CLI-only. Confirm the Desktop sessions directory is non-empty before walking this structure:
> ```bash
> DESKTOP_SESSIONS="$HOME/Library/Application Support/Claude/local-agent-mode-sessions"
> [ -d "$DESKTOP_SESSIONS" ] && find "$DESKTOP_SESSIONS" -name "audit.jsonl" | head -1
> ```

### Claude — Pre-extraction (recommended)

Raw JSONL files are 80–90% noise. Run `scripts/extract-jsonl.py` (from the wiki repo) to strip tool_use/thinking/progress blocks, achieving 50–200× size reduction:
```bash
# First run — extract everything
python3 "$WIKI_REPO/scripts/extract-jsonl.py" --skip tsg,autom8
# Incremental
python3 "$WIKI_REPO/scripts/extract-jsonl.py" --since "$(date -v-1d +%Y-%m-%d)" --skip tsg,autom8
```
Extracted files at `~/.claude/extracted/<project>/<session-id>.json` contain `turns[].{role, text}`.

### Claude — Step 1: Survey and Compute Delta

Scan both data locations and compare against `.manifest.json`. Use `scripts/manifest.py` if available for canonical path expansion:
```bash
python3 "$WIKI_REPO/scripts/manifest.py" delta "$VAULT_PATH" \
  --scan "$CLAUDE_HISTORY_PATH/projects/*/memory/*.md"
```
Classify: **New** (not in manifest), **Modified** (mtime newer), **Unchanged** (skip in append mode).

### Claude — Step 2: Parse Conversation JSONL

Resolution order per session:
1. `~/.claude/extracted/<project>/<session-id>.json` — prefer (compact, signal-only).
2. `~/.claude/projects/<project>/<session-id>.jsonl` — fallback (raw, noisy).

**Pre-extracted file:** iterate `turns[].{role, text}` directly. Top-level fields (`cwd`, `start_ts`, `n_user_words`) give project context.

**Raw JSONL (fallback):** Each line is a JSON object. Filter to `type: "user"` and `type: "assistant"` only. For assistant entries, extract `text` content blocks — skip `thinking` and `tool_use`. Skip `type: "progress"`, `type: "file-history-snapshot"`, and subagent conversations (under `subagents/`).

### Claude — Step 3: Parse Audit Logs (Desktop only)

For each `audit.jsonl` under `local-agent-mode-sessions/`, extract:
- **File access patterns** — which files does the agent repeatedly touch? Note as project references.
- **Shell commands** — recurring Bash commands reveal build/test/deploy workflows → `skills/` page.
- **Tool call sequences** — recurring execution patterns worth capturing.
- **Error patterns** — failed tool calls reveal pain points.
- **MCP tool calls** — which external services/APIs the project integrates with.

Cross-reference with the paired transcript for *what happened* (audit) + *why* (conversation).

### Claude — Step 4–5: Cluster + Distill

Follow the shared clustering and distillation rules above.

**Claude-specific manifest source_types:** `claude_conversation`, `claude_memory`, `claude_audit_log`, `claude_desktop_session`.

---

## Tool: Codex CLI

**Config:** `VAULT_PATH` + `CODEX_HISTORY_PATH` (defaults to `~/.codex`).

**Key data sources by value:**
1. `session_index.jsonl` — best inventory for IDs, titles, freshness.
2. `sessions/**/rollout-*.jsonl` — rich structured transcript events.
3. `history.jsonl` — useful fallback/timeline aid if enabled.

Avoid ingesting SQLite internals unless the user explicitly asks.

### Codex Data Layout

```
~/.codex/
├── sessions/                          # Session rollout logs by date
│   └── YYYY/MM/DD/
│       └── rollout-<timestamp>-<id>.jsonl
├── archived_sessions/                 # Archived rollout logs
├── session_index.jsonl                # Lightweight index of thread id/name/updated_at
├── history.jsonl                      # Local transcript history (if persistence enabled)
├── config.toml                        # User config (contains history settings)
└── state_*.sqlite / logs_*.sqlite     # Runtime DBs (skip)
```

### Codex — Step 1: Survey

Scan `CODEX_HISTORY_PATH` and compare against `.manifest.json`. Report concise delta.

### Codex — Step 2: Parse Session Index

`session_index.jsonl` entries: `{"id":"...","thread_name":"...","updated_at":"..."}`. Use to build canonical inventory, prioritize recent sessions, map rollout IDs to human-readable names.

### Codex — Step 3: Parse Rollout JSONL

Each `rollout-*.jsonl` line is an event envelope:
```json
{"timestamp": "...", "type": "session_meta|turn_context|event_msg|response_item", "payload": {...}}
```

**Extract:** user intent and assistant-visible outputs. Favor `response_item` records with user/assistant message content. Use `event_msg` selectively for meaningful milestones.

**Skip:** token accounting, tool plumbing with no semantic content, raw command output (unless reusable), repeated plan snapshots.

**Privacy:** rollout logs can include injected instructions and secrets — do not ingest verbatim system/developer prompts or credentials.

### Codex — Step 4–5: Cluster + Distill

Follow shared rules. **Codex source_types:** `codex_rollout`, `codex_index`, `codex_history`.

---

## Tool: GitHub Copilot CLI

**Config:** `VAULT_PATH` + `COPILOT_HISTORY_PATH` (defaults to `~/.copilot/session-state`) + `COPILOT_VSCODE_STORAGE_PATH` (VS Code `workspaceStorage`; ask user if absent).

**Key data sources by value:**
1. **Checkpoints** (`session-store.db` checkpoints table + `checkpoints/*.json`) — pre-distilled summaries. Gold.
2. **Session summaries** (`session-store.db` sessions.summary + `index.md`) — one-paragraph synopsis per session.
3. **Turns** (`session-store.db` turns + `events.jsonl` / transcript JSONL) — full conversation, rich but verbose.
4. **Memory artifacts** (`memory-tool/memories/<id>/plan.md`) — user-saved structured notes.
5. **File access patterns** (`session_files` table) — high-value project files.
6. **Session refs** (`session_refs` table) — commits/PRs/issues linked to sessions.
7. **`vscode.metadata.json`** — workspace folder, branch, `customTitle` (user-set session label).

### Copilot Data Layout

**Source 1 — CLI sessions (`~/.copilot/session-state/`):**
```
~/.copilot/session-state/<session-uuid>/
├── workspace.yaml              # Metadata (id, cwd, created_at, updated_at)
├── vscode.metadata.json        # VS Code context
├── events.jsonl                # Full event log
├── index.md                    # Session summary (written at session end)
├── checkpoints/                # Mid-session summaries
│   └── <uuid>.json             # title, overview, work_done, technical_details, next_steps
├── files/                      # Session artifacts
└── research/                   # Research artifacts
```

**Source 2 — Global SQLite (`~/.copilot/session-store.db`):**
```sql
sessions        — id, cwd, repository, branch, summary, created_at, updated_at, host_type
turns           — session_id, turn_index, user_message, assistant_response, timestamp
checkpoints     — session_id, checkpoint_number, title, overview, work_done, technical_details, next_steps
session_files   — session_id, file_path, tool_name, turn_index, first_seen_at
session_refs    — session_id, ref_type (commit/pr/issue), ref_value, turn_index
```

**Source 3 — VS Code (`<workspaceStorage>/<hash>/GitHub.copilot-chat/`):**
```
transcripts/<session-uuid>.jsonl
memory-tool/memories/<base64-session-id>/plan.md
```

### Copilot — Step 1: Survey

Scan all three locations. For `session-store.db`, run:
```sql
SELECT s.id, s.cwd, s.repository, s.branch, s.summary, s.updated_at,
       COUNT(DISTINCT t.turn_index) AS turn_count,
       COUNT(DISTINCT c.id)         AS checkpoint_count
FROM sessions s
LEFT JOIN turns t ON t.session_id = s.id
LEFT JOIN checkpoints c ON c.session_id = s.id
GROUP BY s.id ORDER BY s.updated_at DESC;
```
Build unified inventory per session UUID.

### Copilot — Step 2: Ingest Checkpoints + Summaries First

From `session-store.db`:
```sql
SELECT s.id, s.cwd, s.repository, s.branch, s.summary,
       c.checkpoint_number, c.title, c.overview, c.work_done,
       c.technical_details, c.important_files, c.next_steps, c.created_at
FROM checkpoints c JOIN sessions s ON c.session_id = s.id
ORDER BY s.updated_at DESC, c.checkpoint_number ASC;
```
From per-session `checkpoints/*.json`: read `overview`, `work_done`, `technical_details`, `important_files`, `next_steps`. Also read `index.md` as session summary.

### Copilot — Step 3: Parse Session Turns

From `session-store.db` (preferred):
```sql
SELECT turn_index, user_message, assistant_response, timestamp
FROM turns WHERE session_id = '<uuid>' ORDER BY turn_index ASC;
```
From `events.jsonl`: filter to `session.start`, `user.message`, `assistant.message` types. For `assistant.message`: extract `data.content` (text), skip `data.reasoningText` (internal reasoning), skim `data.toolRequests` for file access patterns. Skip `tool.execution_end`.

### Copilot — Step 4: Process Memory Artifacts

VS Code `memory-tool/memories/<base64-id>/plan.md`: decode base64 → session UUID. Treat as high-quality user-authored content → `skills/` or `concepts/` pages.

### Copilot — Step 5: Extract File + Ref Patterns

From `session-files`:
```sql
SELECT repository, file_path, COUNT(*) AS touch_count
FROM session_files GROUP BY repository, file_path ORDER BY touch_count DESC;
```
From `session_refs`:
```sql
SELECT session_id, ref_type, ref_value, turn_index FROM session_refs ORDER BY session_id;
```

### Copilot — Step 6–7: Cluster + Distill

Follow shared rules. **Copilot source_types:** `copilot_session`, `copilot_checkpoint`, `copilot_transcript`, `copilot_memory_artifact`.

---

## Tool: Hermes Agent

**Config:** `VAULT_PATH` + `HERMES_HISTORY_PATH` (defaults to `~/.hermes`).

**Key data sources by value:**
1. `memories/*.md` / `memories/*.json` — curated persistent knowledge (highest signal).
2. `sessions/**/*.jsonl` — structured turn-by-turn transcripts (rich but noisy).
3. `config.yaml` — metadata only; rarely worth ingesting.

Skip `.hub/` internals and `skills/` directory.

### Hermes Data Layout

```
~/.hermes/
├── memories/          # Persistent agent memories (markdown or JSON)
│   └── *.md / *.json
├── sessions/          # Session transcripts (if session logging enabled)
│   └── YYYY-MM-DD/<session-id>.jsonl
├── config.yaml        # User config
└── .hub/              # Skills Hub state (skip)
```

### Hermes — Step 1: Survey

Scan `HERMES_HISTORY_PATH` and compare against `.manifest.json`.

### Hermes — Step 2: Parse Memories First

Hermes memories are either:
- **Markdown** — structured prose with optional frontmatter; ingest directly.
- **JSON** — `{"content": "...", "created_at": "...", "tags": [...]}`.

Extract the core knowledge claim. Note tags (they often map to wiki categories). Merge into appropriate wiki pages.

### Hermes — Step 3: Parse Session JSONL

Each line is an event envelope:
```json
{"role": "user", "content": "..."}
{"role": "assistant", "content": "..."}
{"type": "tool_use", "name": "...", "input": {...}}
{"type": "tool_result", "content": "..."}
```

**Extract:** assistant conclusions/patterns/decisions. High-signal user turns. Skip low-information follow-ups. Tool calls as context only. Skip token accounting, plumbing, repeated plan echoes.

**Privacy:** do not ingest verbatim system/developer prompts or credentials.

### Hermes — Step 4–5: Cluster + Distill

Follow shared rules. **Hermes source_types:** `hermes_memory`, `hermes_session`.

---

## Tool: OpenClaw Agent

**Config:** `VAULT_PATH` + `OPENCLAW_HISTORY_PATH` (defaults to `~/.openclaw`).

**Key data sources by value:**
1. `workspace/MEMORY.md` — long-term durable facts (highest signal).
2. `workspace/memory/YYYY-MM-DD.md` — daily notes (recent = active project context).
3. `agents/*/sessions/<id>.jsonl` — session transcripts (rich but noisy).
4. `agents/*/sessions/sessions.json` — session index.
5. `workspace/DREAMS.md` — optional summaries; ingest if present.

Skip `credentials/` entirely. Skip `agents/*/agent/models.json` (runtime config).

### OpenClaw Data Layout

```
~/.openclaw/
├── openclaw.json                    # Global config
├── credentials/                     # Auth tokens (skip entirely)
├── workspace/
│   ├── MEMORY.md                    # Long-term memory (loaded every session)
│   ├── DREAMS.md                    # Optional dream diary / summaries
│   └── memory/YYYY-MM-DD.md         # Daily notes
└── agents/<agentId>/
    ├── agent/models.json            # Agent config (skip)
    └── sessions/
        ├── sessions.json            # Session index
        └── <sessionId>.jsonl        # Session transcript (JSONL, append-only)
```

### OpenClaw — Step 1: Survey

Scan `OPENCLAW_HISTORY_PATH` and compare against `.manifest.json`.

### OpenClaw — Step 2: Parse MEMORY.md First

Plain markdown, human-readable. Contains durable facts about user preferences, environment, recurring patterns, decisions, and project-specific notes. Read in full; cluster by topic.

### OpenClaw — Step 3: Parse Daily Notes

`workspace/memory/YYYY-MM-DD.md` — time-stamped notes from that day's sessions. Prioritize last 30–90 days. Extract active project context, patterns/techniques, recurring blockers.

### OpenClaw — Step 4: Parse Session JSONL

JSONL, append-only, one JSON object per line:
```json
{"role": "user", "content": "...", "timestamp": "..."}
{"role": "assistant", "content": "...", "timestamp": "..."}
{"role": "tool", "name": "...", "content": "...", "timestamp": "..."}
```

**Extract:** assistant conclusions/decisions/patterns. High-signal user turns. Tool calls as context only (extract if the result contains a reusable insight). Cross-reference `sessions.json` for names/labels before opening transcripts.

### OpenClaw — Step 5–6: Cluster + Distill

Follow shared rules. **OpenClaw source_types:** `openclaw_memory`, `openclaw_daily_note`, `openclaw_session`, `openclaw_dreams`.

---

## Tool: Pi Coding Agent

**Config:** `VAULT_PATH` + `PI_HISTORY_PATH` (defaults to `~/.pi/agent/sessions`).

**Key data sources by value:**
1. **`message` entries** (`user` + `assistant`) — full conversation transcripts.
2. **`compaction` entries** — pre-synthesized summaries of older context. Gold.
3. **`branch_summary` entries** — summaries of abandoned approaches.
4. **`bashExecution` entries** — concrete commands run; workflow patterns.
5. **`session_info` entries** — session name for topic inference.

Skip `model_change`, `thinking_level_change`, `custom` (extension state), `label` entries.

### Pi Data Layout

```
~/.pi/agent/sessions/
└── --<cwd-path>--/                    # Working directory with / replaced by -
    └── <timestamp>_<uuid>.jsonl       # Session JSONL file
```

Each `.jsonl` is a sequence of JSON objects. First line = `session` header; subsequent lines = tree entries with `id` and `parentId`.

**Entry types:**

| `type` | Purpose | Ingest? |
|---|---|---|
| `session` | Header: `cwd`, `version`, `id`, `timestamp` | Metadata only |
| `message` | Conversation turn | **Primary source** |
| `session_info` | Display name via `/name` | For session title |
| `compaction` | Context compaction summary | **High signal** |
| `branch_summary` | Summary when switching branches via `/tree` | **High signal** |
| `model_change` | Model switch event | Skip |
| `thinking_level_change` | Thinking level change | Skip |
| `custom` | Extension state | Skip |

**Message roles inside `message` entries:** `user`, `assistant`, `toolResult`, `bashExecution`, `branchSummary`, `compactionSummary`.

### Pi — Step 1: Survey

```bash
find ~/.pi/agent/sessions -name "*.jsonl" -type f
```
For each session, record: path, `cwd` (decoded from parent dir name: `--<path>--` → `/path`), session name (latest `session_info` entry), mtime, manifest status.

### Pi — Step 2: Parse Session JSONL

Build the active branch (tree structure):
1. Parse all entries into a map by `id`.
2. Find the current leaf (entry with no children, or last `message`).
3. Walk `parentId` chain from leaf → root to get active path.
4. Reverse so it's chronological.

**Extract from active path:**
- `session` header: `cwd`, `timestamp`, `parentSession`.
- `session_info`: `name` for topic inference.
- `message` (`role: "user"`): `content` text (skip images).
- `message` (`role: "assistant"`): extract `text` blocks; skip `thinking` blocks; note `toolCall` blocks.
- `message` (`role: "toolResult"`): summarize outcomes, not full output.
- `message` (`role: "bashExecution"`): command + exit code; recurring commands reveal workflows.
- `compaction`/`branch_summary`: read `summary` verbatim (already distilled).

**Skip:** `thinking` content blocks, image blocks, raw tool outputs >500 chars (summarize), token accounting, repeated plan echoes.

**Privacy:** do not ingest verbatim system/developer prompts. Redact sensitive data from `toolCall` arguments and bash outputs.

### Pi — Step 3–4: Cluster + Distill

Follow shared rules. **Pi source_types:** `pi_session`.

---

## References

Supplementary data format documentation is in `references/` alongside this file:

- `references/claude-data-format.md`
- `references/copilot-data-format.md`
- `references/codex-data-format.md`
- `references/hermes-data-format.md`
- `references/openclaw-data-format.md`

These provide field-level parsing details for each tool's data structures. Consult them when the sections above do not cover a specific edge case.
