# AutoPoV Application Flow

This document describes how the project works today, based on the current FastAPI backend, LangGraph workflow, CLI, and React frontend.

## Entry Points

A scan can currently start from:

- `POST /api/scan/git`
- `POST /api/scan/zip`
- `POST /api/scan/paste`
- GitHub or GitLab webhook endpoints
- the web UI
- the CLI in `cli/autopov.py`

All scan-triggering API endpoints create a scan immediately and then continue work asynchronously in a background task.

## Authentication and Request Handling

There are two distinct access patterns:

- Browser UI:
  - requests come from an allowed frontend origin
  - the backend sets an `autopov_csrf` cookie
  - mutating requests must send the matching `X-CSRF-Token`
  - the backend system key is used internally, so a user API key is not required for standard web usage
- External clients:
  - use Bearer API keys
  - scan-triggering routes are rate-limited to 10 scans per 60 seconds per key

For SSE log streaming, token auth can also be supplied via query string for EventSource compatibility.

## Scan Creation

When a scan is created:

1. `ScanManager.create_scan()` allocates a UUID scan ID.
2. The active scan record is persisted to `results/runs/active/<scan_id>.json`.
3. The scan is initialized with `status="created"` and `progress=0`.
4. A background task prepares the source input and starts the LangGraph workflow.

Git scans additionally move through `checking` and `cloning` states before analysis begins.

## Source Preparation

Current source handling:

- Git:
  - checks accessibility first
  - clones to a scan-specific workspace
- ZIP:
  - stores the upload at `/tmp/autopov/<scan_id>/upload.zip`
  - extracts it through the source handler
- Paste:
  - writes the supplied code to a temporary workspace

Once the source path is known, the scan manager starts the asynchronous graph run.

## Model Resolution

The backend requires an explicit selected model.

- If the request includes a model override, that model is used.
- Otherwise the backend uses the saved selected model from Settings.
- Online models require an OpenRouter key.
- Offline models require the Ollama runtime and the selected model to be installed.

The current curated model lists are:

- Online: `openai/gpt-5.2`, `anthropic/claude-opus-4.6`
- Offline: `llama4`, `glm-4.7-flash`, `qwen3`

## LangGraph Workflow

The current graph in `app/agent_graph.py` is:

```text
ingest_code
  -> run_codeql
  -> log_findings_count
  -> investigate
      -> generate_pov or log_skip
  -> validate_pov
      -> run_in_docker or refine_pov or log_failure
  -> log_confirmed / log_skip / log_failure
      -> investigate next finding or end
```

The graph is stateful and processes findings one by one after discovery.

## Stage 1: Mandatory Ingestion

`ingest_code` always attempts vector-store ingestion first.

Current behavior:

- `RAG_REQUIRED=true` makes ingestion mandatory
- code is chunked and embedded
- per-scan retrieval data is prepared for downstream investigation
- if no source chunks are indexed, the scan fails instead of quietly continuing

This is stricter than older docs that described ingestion as optional.

## Stage 2: Agentic Discovery

The graph then enters `run_codeql`, which now acts as the broader discovery stage rather than only a CodeQL-only pass.

Discovery currently combines:

- language profiling
- CodeQL when available
- Semgrep fallback or supplemental analysis
- heuristic scouting
- optional LLM scouting

Findings are deduplicated before investigation. Discovery is open-ended by default, and scans are not created with a fixed CWE list.

## Stage 3: Investigation

`investigate` performs the deeper per-finding analysis.

Typical inputs include:

- file-local code context
- retrieved RAG context
- optional tool output such as Joern analysis when relevant
- the currently selected model

The investigator decides whether a candidate is credible enough to continue and records explanation, confidence, cost, and model usage metadata.

## Stage 4: PoV Generation

`generate_pov` creates an exploit or proof artifact for findings that pass the investigation threshold.

The generated payload is stored in scan state and later included in result output if retained by validation and reporting.

## Stage 5: Validation and Refinement

`validate_pov` is the first validation stage.

The current implementation can:

- run static validation logic
- use harness-based execution through the PoV tester
- trigger a refinement loop when feedback indicates the PoV may be repairable

If validation still needs runtime proof, the graph routes to `run_in_docker`.

## Stage 6: Runtime Proof

`run_in_docker` is the final proof stage when runtime confirmation is required.

Docker proof is especially important when a finding cannot be confirmed from static reasoning or harness execution alone.

## Stage 7: Logging and Iteration

After each finding reaches a terminal per-finding state:

- `log_confirmed`
- `log_skip`
- or `log_failure`

the graph checks whether more findings remain. If so, it loops back to `investigate`. Otherwise it ends.

## Persistence and Recovery

The scan manager persists active state continuously.

Current persistence behavior:

- active scans are written under `results/runs/active/`
- completed results are written under `results/runs/`
- interrupted in-flight scans are restored as `interrupted` after backend restart
- optional code snapshots are stored under `results/snapshots/<scan_id>/`

This allows replay and postmortem inspection even when the original working directory is gone.

## Result Generation

When a scan completes, the backend stores:

- overall scan status
- logs
- findings
- language metadata
- cost and token usage
- proof metadata

Reports can then be generated on demand as:

- JSON
- PDF

through `GET /api/report/{scan_id}`.

## Frontend Flow

The React frontend follows this flow:

1. Home page starts a scan from Git, ZIP, or pasted code.
2. The app navigates to `/scan/<scan_id>`.
3. The progress page polls `GET /api/scan/{scan_id}` every 2 seconds.
4. It also opens an SSE connection to `/api/scan/{scan_id}/stream`.
5. Terminal scan states redirect to `/results/<scan_id>`.
6. Results view loads the saved result or falls back to report retrieval.

The Settings page manages:

- selected model and mode
- optional OpenRouter key saved through the backend
- API keys
- webhook configuration

## CLI Flow

The CLI mirrors the same backend flow:

- `scan` accepts Git URLs, ZIP files, and local directories
- local directories are zipped before upload
- `paste` reads from stdin
- `results`, `history`, `report`, `cancel`, and `replay` operate against backend endpoints

The CLI uses the selected backend model unless `--model` is provided.

## Replay Flow

Replay works from a previously saved scan result:

1. the original findings are loaded
2. optionally only confirmed findings are retained
3. the backend reuses the original codebase path or a saved snapshot
4. a new scan is created with preloaded findings

Important current behavior: although the replay request schema accepts a list of models, the implementation currently launches replay scans using the backend's currently configured model.

## Practical Notes

- The app is discovery-first and CWE-agnostic by default.
- The backend currently reports fixed routing in `/api/config`.
- The web UI is first-party and CSRF-protected rather than API-key-driven.
- CLI and external integrations still need API keys.
