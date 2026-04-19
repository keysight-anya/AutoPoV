# AutoPoV

AutoPoV is a FastAPI and React application for autonomous codebase security scanning. It accepts a GitHub/GitLab repository URL, a ZIP or TAR archive upload, individual file uploads, or raw pasted code (a single code chunk). It runs a hybrid discovery pipeline, investigates candidate findings with an LLM, generates Proof-of-Vulnerability (PoV) scripts for credible findings, and validates them through static checks, adaptive reconnaissance, harness execution, and isolated Docker runtime proof.

The system is discovery-first and CWE-agnostic. Scans do not require a CWE list. A single selected model is used consistently for all LLM steps — investigation, PoV generation, refinement, and coordination — routed through a unified LLM dispatcher.

## Current Architecture

The backend is a LangGraph stateful workflow with these stages:

1. `ingest_code`: mandatory vector-store ingestion (ChromaDB RAG).
2. `run_codeql`: agentic discovery — language profiling, CodeQL, Semgrep, heuristic scouting, optional LLM scouting.
3. `probe_target`: preflight probe — builds target with ASan, runs binary, captures binary name, input surface, baseline exit code/stderr, help text, and subcommands.
4. `investigate`: per-finding LLM analysis with RAG context and optional Joern/trace output.
5. `generate_pov`: PoV generation using probe reconnaissance data — deterministic harness fallback or LLM-generated script, format-aware payload selection.
6. `validate_pov`: static validation (rejects cmake/make self-compile, wrong binary name, language mismatch) and harness-based execution.
7. `coordinate_pov`: meta-reasoning retry coordinator — selects action (refine_payload, refine_format, change_surface, abandon) using the selected model.
8. `refine_pov`: up to 3 LLM-guided refinement rounds with injected error context and diversity hints.
9. `run_in_docker`: isolated runtime proof in a language-matched Docker container (native/python/node/go/java/php/ruby/browser).
10. `evaluate_oracle`: signal classification — crash signal, sanitizer output, stdout marker, ASAN-disabled exit-code anomaly.
11. Logging nodes (`log_confirmed`, `log_skip`, `log_failure`) iterate to next finding or terminate.

Key implementation details:

- RAG ingestion is mandatory when `RAG_REQUIRED=true` (ChromaDB).
- Discovery is open-ended; scans are created with an empty CWE list.
- The selected model must be set explicitly in Settings or passed as a CLI override.
- All LLM calls go through `get_verifier()._get_llm(model, purpose)` — offline routes to Ollama, online routes to OpenRouter. No direct model instantiation elsewhere.
- Online scans require an OpenRouter API key.
- Offline scans require a locally installed Ollama model (e.g. `qwen3`, `glm-4.7-flash`, `llama4`).
- The preflight probe builds the target binary with ASan and captures runtime surface data used by all downstream PoV steps.
- PoV byte payloads use double-escaped literals (`\\xff`, `\\x00`) inside f-string templates to prevent null-byte injection.
- The binary locator scores candidates from CMake/Meson/Make test targets with a deny-score (-999) to avoid picking the build tool itself.
- Results, active scan snapshots, reports, and optional code snapshots are written under `results/`.

## Repository Layout

```text
AutoPoV/
+-- agents/                    # Discovery, probe, investigation, PoV generation, runtime, oracle, and helper agents
+-- app/                       # FastAPI app, LangGraph orchestration, config, auth, reporting
+-- cli/                       # Click-based CLI client
+-- frontend/                  # React + Vite web application
+-- semgrep-rules/             # Custom Semgrep OWASP rules
+-- codeql_queries/            # Custom CodeQL queries (BufferOverflow, IntegerOverflow, SqlInjection, UseAfterFree)
+-- docker/proof-images/       # Per-language Dockerfiles for isolated proof execution
+-- data/                      # API keys, learning DB, ChromaDB vector data, prompt/result cache
+-- results/                   # Active run snapshots, reports, PoV artifacts, code snapshots
+-- tests/                     # Backend tests
```

Important backend modules:

- `app/main.py`: API routes and startup wiring
- `app/agent_graph.py`: LangGraph workflow and scan state machine (180KB)
- `app/scan_manager.py`: scan persistence, active snapshots, history, cancellation, replay
- `app/auth.py`: system key, API keys, CSRF, and rate limiting
- `app/source_handler.py`: ZIP, TAR, file upload, folder upload, and raw code paste handling
- `agents/agentic_discovery.py`: discovery orchestration
- `agents/probe_runner.py`: preflight probe — ASan build, binary surface detection, baseline capture
- `agents/investigator.py`: LLM investigation and evidence gathering
- `agents/verifier.py`: PoV generation, refinement, format payloads, binary name resolution (208KB)
- `agents/static_validator.py`: pre-execution PoV safety checks
- `agents/pov_coordinator.py`: retry meta-reasoning coordinator
- `agents/oracle_policy.py`: signal classification and confirmation logic
- `agents/pov_tester.py` and `agents/docker_runner.py`: proof execution and binary locator (134KB + 111KB)

## Supported Models

The backend configuration exposes these curated model choices:

- Online (requires OpenRouter API key):
  - `openai/gpt-5.2`
  - `anthropic/claude-opus-4.6`
- Offline (requires local Ollama):
  - `qwen3`
  - `glm-4.7-flash`
  - `llama4`

All models are routed through a single dispatcher (`get_verifier()._get_llm()`). You must select one explicitly in the web Settings page before running scans, unless the CLI request provides `--model`.

## Authentication Model

Current behavior differs between the web UI and external clients:

- Web UI:
  - uses a system key managed by the backend
  - relies on allowed frontend origins plus a CSRF cookie/header pair
  - does not require a user-supplied API key for normal in-browser operation
- CLI and external integrations:
  - use generated API keys
  - send Bearer auth
  - scan-triggering endpoints are rate-limited to 10 requests per 60 seconds per key
- Admin/API key management:
  - managed through the API and web Settings page
  - keys are stored hashed in `data/api_keys.json`

## Quick Start

### Prerequisites

- Python 3.12 recommended
- Node.js 20+
- Docker
- OpenRouter API key for online mode, or Ollama for offline mode
- CodeQL optional but recommended
- Joern optional

### Local Setup

```bash
git clone <repository-url>
cd AutoPoV

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd frontend
npm install
cd ..
```

Create `.env` from `.env.example`, then set at minimum:

```env
ADMIN_API_KEY=change_me
MODEL_MODE=online
MODEL_NAME=openai/gpt-5.2
OPENROUTER_API_KEY=sk-or-v1-...
FRONTEND_URL=http://localhost:5173
```

### Docker Compose

`docker-compose.yml` currently starts:

- `backend` on port `8000`
- `ollama` on port `11434`
- `frontend` on port `5173`

Start the stack with:

```bash
docker compose up --build
```

### Running Without Docker Compose

The repository also includes helper scripts such as `run.sh`, `start-all.sh`, and `start-autopov.sh`, but the current maintained deployment path is the FastAPI backend plus the Vite frontend, optionally via Docker Compose.

## Web Workflow

The React app exposes these main pages:

- Home: start scans from Git URL, ZIP, or pasted code
- Scan Progress: live polling plus SSE logs, cancel and force-stop controls
- Results: findings, proof artifacts, report download, OpenRouter usage summary
- History / Scan Manager: inspect active and historical scans, cleanup and cache actions
- Settings: model selection, API key management, webhook setup
- Metrics, Docs, and Policy: telemetry and reference views

The frontend talks to the backend through `frontend/src/api/client.js`, uses CSRF bootstrapping via `GET /api/health`, and streams logs from `GET /api/scan/{scan_id}/stream`.

## CLI Usage

The CLI is implemented in `cli/autopov.py`.

Examples:

```bash
python cli/autopov.py scan https://github.com/user/repo.git
python cli/autopov.py scan /path/to/code --model anthropic/claude-opus-4.6
python cli/autopov.py paste --language python < vulnerable.py
python cli/autopov.py results <scan_id>
python cli/autopov.py report <scan_id> --format pdf
python cli/autopov.py history
python cli/autopov.py keys generate --admin-key <admin_key> --name ci-bot
```

The CLI uses `AUTOPOV_API_URL` and `AUTOPOV_API_KEY` when available.

## API Summary

Core endpoints in the current backend:

- `GET /api/health`
- `GET /api/config`
- `GET /api/balance`
- `GET /api/benchmarks`
- `POST /api/benchmarks/{benchmark_id}/install`
- `POST /api/scan/git` — scan from GitHub/GitLab URL
- `POST /api/scan/zip` — scan from uploaded ZIP or TAR archive
- `POST /api/scan/paste` — scan from raw pasted code (code chunk)
- `POST /api/scan/benchmark` — scan from installed benchmark
- `GET /api/scan/{scan_id}`
- `GET /api/scan/{scan_id}/stream` — SSE log stream
- `POST /api/scan/{scan_id}/cancel`
- `POST /api/scan/{scan_id}/stop`
- `DELETE /api/scan/{scan_id}`
- `POST /api/scan/{scan_id}/replay`
- `GET /api/scans/active`
- `DELETE /api/scans/all`
- `GET /api/history`
- `GET /api/report/{scan_id}`
- `GET /api/metrics`
- `GET /api/learning/summary`
- `GET /api/settings`
- `POST /api/settings`
- `GET /api/keys`
- `POST /api/keys/generate`
- `DELETE /api/keys/{key_id}`
- GitHub and GitLab webhook endpoints

Interactive docs are available at `http://localhost:8000/api/docs`.

## Current Notes and Constraints

- The backend advertises `routing_mode: fixed` from `/api/config`, and scans run against the selected model only.
- Replay currently requires a `models` list in the request payload, but the implementation creates replay scans using the currently configured backend model.
- The web UI treats API keys as optional for browser use (CSRF-protected system key), but Bearer keys are required for CLI and external automation.
- Snapshot directories under `results/snapshots/` can be used when the original source path is no longer available.
- The preflight probe (`probe_runner.py`) must succeed for PoV generation to use surface/binary data; if the probe fails, the system falls back to heuristic scaffold generation.
- The static validator rejects PoV scripts that attempt to self-compile the target (cmake/make/gcc/clang patterns) since the binary is pre-built by the harness and available via `TARGET_BINARY`.
- API keys are stored hashed (SHA-256) in `data/api_keys.json` and loaded into memory at backend startup — a restart is required after adding new keys via `add_api_key.py`.

## Output Artifacts

AutoPoV writes:

- active scan snapshots: `results/runs/active/`
- saved scan results and history: `results/runs/`
- generated reports: `results/<scan_id>_report.json` and `.pdf`
- PoV scripts and proof artifacts: `results/povs/` and `results/proof_artifacts/`
- optional source snapshots: `results/snapshots/<scan_id>/`

## Tests

Backend tests live under `tests/`. To add a new API key for CLI or external use:

```bash
python3 add_api_key.py
docker restart autopov-backend
```

To generate a batch scan with the offline model:

```bash
python3 add_api_key.py
NEWKEY=$(python3 add_api_key.py 2>/dev/null | grep 'Added new API key:' | awk '{print $NF}')
docker restart autopov-backend ; sleep 15
echo '{"results":[]}' > batch_offline_state.json
python3 -u batch_scan.py --model qwen3 --key "$NEWKEY" --poll 30 --timeout 3600 2>&1 | tee batch_run.log
```
