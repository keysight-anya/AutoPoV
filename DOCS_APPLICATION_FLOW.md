# AutoPoV — Agent Workflow and System Behaviour

This document describes how the AutoPoV agent system behaves from the moment a scan is triggered through to final report delivery. Every stage is executed autonomously by a specialised agent.

---

## Agent System Overview

AutoPoV is a **multi-agent system** built on a LangGraph state machine. The graph is compiled once at startup and persists as a singleton. When a scan is submitted, the graph is invoked with an initial state and runs to completion without external prompting — each agent node perceives the current state, acts, and passes control to the next agent via conditional routing edges.

The full agent loop:

```
Perceive (read state) → Decide (route condition) → Act (call tool / LLM) → Observe (update state) → Route → repeat
```

---

## Phase 1 — Scan Intake

A scan is triggered in one of four ways:

| Entry Point | Endpoint | Source |
|---|---|---|
| Git repository | `POST /api/scan/git` | Cloned from URL |
| ZIP archive | `POST /api/scan/zip` | Uploaded file |
| Raw code paste | `POST /api/scan/paste` | Inline string |
| Webhook event | `POST /api/webhook/github` or `/gitlab` | Push / PR event |

The API layer:
1. Validates the API key (SHA-256 hash comparison) and checks the per-key rate limit (10 agent runs/min)
2. Creates a scan record with a UUID `scan_id` and initial status `created`
3. Resolves the source — clones the repo, extracts the ZIP, or saves the raw code to a workspace path
4. Dispatches the agent graph as a background task using a dedicated event loop
5. Returns `{"scan_id": "..."}` immediately — the agents run asynchronously

---

## Phase 2 — Ingestion Agent

**Node:** `ingest_code`

The Ingestion Agent prepares the codebase for semantic retrieval by all downstream agents:

- Walks the file tree, ignoring non-code files and build artefacts
- Splits each file into overlapping chunks (4000 chars, 200-char overlap)
- Embeds each chunk using `openai/text-embedding-3-small` (online) or `sentence-transformers/all-MiniLM-L6-v2` (offline)
- Stores chunks and embeddings in **ChromaDB** under a `scan_id`-scoped collection
- Logs file and chunk counts in real time

This step is non-fatal — if embedding fails, agents continue with direct file reads.

---

## Phase 3 — Discovery Agents

**Node:** `run_codeql`

Three discovery strategies run in sequence, and their findings are merged and deduplicated:

### 3a — CodeQL Static Discovery Agent

If CodeQL is available:
1. Detects the codebase language from file extensions (Python, JavaScript, Java, C/C++, Go, Ruby, PHP)
2. Creates a CodeQL database from the source root
3. Runs a language-specific `.ql` query for each requested CWE
4. Parses the SARIF output — each result becomes a candidate finding with `confidence: 0.8`
5. Cleans up the database after all queries complete

If CodeQL is unavailable, the agent falls back to the LLM-only analysis path.

### 3b — Heuristic Scout Agent

Runs in parallel regardless of CodeQL availability:
- Applies regex pattern libraries for each CWE across every code file
- Fast, zero-cost — surfaces candidates the Investigator Agent must later confirm
- Candidate confidence: `0.35`

### 3c — LLM Scout Agent

Runs if `SCOUT_LLM_ENABLED=true`:
- Selects the largest files (up to `SCOUT_MAX_FILES`, default 25)
- Sends batched file snippets to the reasoning model with a structured prompt requesting vulnerability candidates
- Respects `SCOUT_MAX_COST_USD` — aborts if cost threshold is exceeded
- Returns structured JSON with file path, line, CWE, reason, and confidence

All three streams merge into a single deduplicated candidate list keyed on `(filepath, line_number, cwe_type)`.

---

## Phase 4 — Investigator Agent

**Node:** `investigate` (loops once per finding)

The Investigator Agent performs deep analysis on each candidate in sequence:

1. **Context retrieval** — fetches the code around the flagged line (±50 lines)
2. **RAG retrieval** — queries ChromaDB for semantically related code chunks
3. **Joern CPG analysis** (CWE-416 only) — runs Joern to trace use-after-free data flows
4. **Reasoning** — sends the assembled context to the reasoning model with a structured investigation prompt
5. **Verdict parsing** — extracts `REAL` / `FALSE_POSITIVE`, confidence score (0–1), explanation, and vulnerable code snippet
6. **Cost tracking** — reads actual token usage from the API response and calculates cost per model pricing table
7. **Learning Store write** — records model, CWE, language, verdict, confidence, and cost to `data/learning.db`

The **Policy Agent** (`app/policy.py`) selects the reasoning model before each investigation call:
- `auto` → OpenRouter routes automatically
- `fixed` → uses `MODEL_NAME`
- `learning` → queries the Learning Store for the model with the best confirmed/cost score for this CWE + language

Only findings where `verdict == "REAL"` and `confidence >= 0.7` proceed to PoV generation.

---

## Phase 5 — PoV Generator Agent

**Node:** `generate_pov`

For each confirmed finding, the PoV Generator Agent writes a working exploit:

1. Retrieves full file content from ChromaDB or disk
2. Detects the target language from the codebase
3. Sends the vulnerable code, explanation, and language context to the reasoning model with a structured exploit-generation prompt
4. The agent is instructed that the script **must print `VULNERABILITY TRIGGERED`** when it successfully triggers the vulnerability
5. Stores the generated script in the finding state

If generation fails, the finding is marked `pov_generation_failed`.

---

## Phase 6 — Validation Agent

**Node:** `validate_pov`

The Validation Agent applies a **three-tier escalating proof strategy**:

| Tier | Method | Condition |
|---|---|---|
| 1 | **Static analysis** | Checks the PoV script for correct exploit patterns and attack structure |
| 2 | **Unit test execution** | Runs the PoV in an isolated Python/language harness and checks for `VULNERABILITY TRIGGERED` in output |
| 3 | **Docker execution** | Fallback — runs the PoV in a sandboxed container with no network, 512 MB RAM cap, 1 CPU, 60s timeout |

If static analysis achieves ≥ 80% confidence → confirmed without execution.
If the unit test triggers the vulnerability → confirmed.
Otherwise → Docker execution agent runs.

If validation fails after `MAX_RETRIES` (default 2) attempts, the PoV Generator Agent is invoked again with feedback.

---

## Phase 7 — Routing and Loop Logic

After each finding is resolved (confirmed / skipped / failed), the graph's conditional router:

1. Increments `current_finding_idx`
2. Checks if more findings remain
3. If yes → routes back to the Investigator Agent for the next finding
4. If no → marks the scan `completed`, records `end_time`, and exits the graph

This loop is the core of the agentic architecture — the graph is not a linear script but a stateful cycle that processes each finding through the full agent stack.

---

## Phase 8 — Results and Reporting

When the agent graph completes:

- The Scan Manager serialises the final state to `results/runs/<scan_id>.json`
- Appends a summary row to `results/runs/scan_history.csv`
- Optionally saves a codebase snapshot to `results/snapshots/<scan_id>/` (if `SAVE_CODEBASE_SNAPSHOT=true`)
- Confirmed PoV scripts are saved to `results/povs/`
- The Report Generator can produce `results/<scan_id>_report.json` and `results/<scan_id>_report.pdf` on demand

---

## Real-Time Agent Observability

While the agent graph runs, every `_log()` call:
1. Appends to `state["logs"]` in the LangGraph state
2. Immediately writes to the Scan Manager's in-memory log buffer (thread-safe)
3. Is streamed to subscribers via SSE at `GET /api/scan/<scan_id>/stream?api_key=...`

Both the web dashboard and the CLI poll/stream these logs to surface what each agent is doing in real time.

---

## Agent Model Routing and Self-Improvement

The **Policy Agent** (`app/policy.py`) makes model routing decisions at two points:
- Before each `investigate` node invocation
- Before each `generate_pov` node invocation

It queries the **Learning Store** (`data/learning.db`) for:
```sql
-- Score = confirmed findings / (total cost + small constant)
SELECT model, confirmed / (cost + 0.01) AS score
FROM investigations
WHERE cwe=? AND language=?
GROUP BY model ORDER BY score DESC
```

In `learning` mode, the top-scoring model is selected automatically. The system improves with each scan — more data means better routing.

---

## API Surface

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/api/scan/git` | API Key | Trigger agent run on Git repo |
| `POST` | `/api/scan/zip` | API Key | Trigger agent run on ZIP upload |
| `POST` | `/api/scan/paste` | API Key | Trigger agent run on code paste |
| `GET` | `/api/scan/{id}` | API Key | Poll agent run status + findings |
| `GET` | `/api/scan/{id}/stream` | API Key (query param) | Stream live agent logs (SSE) |
| `POST` | `/api/scan/{id}/cancel` | API Key | Cancel a running agent run |
| `POST` | `/api/scan/{id}/replay` | API Key (rate-limited) | Replay findings against new models |
| `GET` | `/api/history` | API Key | Paginated agent run history |
| `GET` | `/api/report/{id}` | API Key | Download report (JSON or PDF) |
| `GET` | `/api/learning/summary` | API Key | Agent performance stats |
| `GET` | `/api/metrics` | API Key | System-wide scan metrics |
| `GET` | `/api/config` | API Key | System config + tool availability |
| `GET` | `/api/health` | None | Health check |
| `POST` | `/api/keys/generate` | Admin Key | Mint a new API key |
| `GET` | `/api/keys` | Admin Key | List all API keys |
| `DELETE` | `/api/keys/{id}` | Admin Key | Revoke an API key |
| `POST` | `/api/admin/cleanup` | Admin Key | Remove old result files |
| `POST` | `/api/webhook/github` | HMAC | GitHub push → agent run |
| `POST` | `/api/webhook/gitlab` | Token | GitLab push → agent run |

Interactive API docs: `http://localhost:8000/api/docs`

---

## Authentication Model

| Key Type | Stored As | Used For | Validated By |
|---|---|---|---|
| Admin Key | Plaintext in `.env` | Key management endpoints | `hmac.compare_digest` (timing-safe) |
| API Key | SHA-256 hash in `data/api_keys.json` | All agent operation endpoints | Hash comparison, debounced `last_used` writes |

API keys are rate-limited to 10 agent runs per 60 seconds per key. `last_used` timestamps are batched in memory and flushed to disk every 30 seconds — not on every request.

