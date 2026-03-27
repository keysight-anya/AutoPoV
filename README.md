# AutoPoV

AutoPoV is a FastAPI and React application for autonomous codebase security scanning. It ingests a repository, ZIP archive, or pasted code, runs a hybrid discovery pipeline, investigates candidate findings with an LLM, generates proof-of-vulnerability payloads for credible findings, and validates them through static checks, harness execution, and Docker runtime proof.

The current implementation is discovery-first and CWE-agnostic by default. Scans do not require a CWE list, and the backend currently runs with an explicit selected model rather than dynamic per-step policy routing.

## Current Architecture

The backend is a LangGraph workflow with these stages:

1. `ingest_code`: mandatory vector-store ingestion for RAG.
2. `run_codeql`: agentic discovery that combines language profiling, CodeQL/Semgrep fallbacks, heuristics, and optional LLM scouting.
3. `investigate`: LLM investigation of each candidate finding.
4. `generate_pov`: PoV generation for findings judged real enough to continue.
5. `validate_pov`: static and harness-based validation.
6. `refine_pov`: retry loop when validation feedback suggests the exploit can be improved.
7. `run_in_docker`: runtime proof in Docker when required.
8. logging nodes that either continue to the next finding or finish the scan.

Key implementation details:

- RAG ingestion is mandatory when `RAG_REQUIRED=true`.
- Discovery is open-ended; scans are created with an empty CWE list.
- The selected model must be set explicitly in Settings or passed as a CLI override.
- Online scans require an OpenRouter API key.
- Offline scans require a locally installed Ollama model.
- Results, active scan snapshots, reports, and optional code snapshots are written under `results/`.

## Repository Layout

```text
AutoPoV/
+-- agents/                    # Discovery, investigation, PoV, runtime, and helper agents
+-- app/                       # FastAPI app, LangGraph orchestration, config, auth, reporting
+-- cli/                       # Click-based CLI client
+-- frontend/                  # React + Vite web application
+-- semgrep-rules/             # Semgrep rules used by discovery
+-- codeql_queries/            # Custom CodeQL queries
+-- data/                      # API keys, learning DB, vector data
+-- results/                   # Active run snapshots, reports, snapshots, artifacts
+-- tests/                     # Backend tests
```

Important backend modules:

- `app/main.py`: API routes and startup wiring
- `app/agent_graph.py`: LangGraph workflow and scan state machine
- `app/scan_manager.py`: scan persistence, active snapshots, history, cancellation, replay
- `app/auth.py`: system key, API keys, CSRF, and rate limiting
- `agents/agentic_discovery.py`: discovery orchestration
- `agents/investigator.py`: LLM investigation and evidence gathering
- `agents/verifier.py`: PoV generation and refinement
- `agents/pov_tester.py` and `agents/docker_runner.py`: proof execution

## Supported Models

The backend configuration currently exposes these curated model choices:

- Online:
  - `openai/gpt-5.2`
  - `anthropic/claude-opus-4.6`
- Offline:
  - `llama4`
  - `glm-4.7-flash`
  - `qwen3`

You must select one explicitly in the web Settings page before running scans, unless the CLI request provides `--model`.

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
- `POST /api/scan/git`
- `POST /api/scan/zip`
- `POST /api/scan/paste`
- `GET /api/scan/{scan_id}`
- `GET /api/scan/{scan_id}/stream`
- `POST /api/scan/{scan_id}/cancel`
- `POST /api/scan/{scan_id}/stop`
- `DELETE /api/scan/{scan_id}`
- `POST /api/scan/{scan_id}/replay`
- `GET /api/scans/active`
- `GET /api/history`
- `GET /api/report/{scan_id}`
- `GET /api/metrics`
- `GET /api/learning/summary`
- `GET /api/settings`
- `POST /api/settings`
- `GET /api/keys`
- `POST /api/keys/generate`
- `DELETE /api/keys/{key_id}`
- webhook endpoints for GitHub and GitLab

Interactive docs are available at `http://localhost:8000/api/docs`.

## Current Notes and Constraints

- The backend advertises `routing_mode: fixed` from `/api/config`, and scans run against the selected model.
- Replay currently requires a `models` list in the request payload, but the implementation creates replay scans using the currently configured backend model.
- The web UI treats API keys as optional for browser use, but they are still needed for CLI and external automation.
- Snapshot directories under `results/snapshots/` can be used when the original source path is no longer available.

## Output Artifacts

AutoPoV writes:

- active scan snapshots: `results/runs/active/`
- saved scan results and history: `results/runs/`
- generated reports: `results/<scan_id>_report.json` and `.pdf`
- PoV artifacts: `results/povs/`
- optional source snapshots: `results/snapshots/<scan_id>/`

## Tests

Backend tests live under `tests/` and the repository root includes additional test scripts such as `test_scan.py`, `test_bg_task.py`, and `test_api_key.py`.
