# AutoPoV — Autonomous Proof-of-Vulnerability Agent

AutoPoV is a fully agentic vulnerability research platform. A multi-agent system built on LangGraph orchestrates every stage of the security workflow: code ingestion, static analysis, LLM-powered investigation, exploit generation, and execution validation — all without human intervention per finding. It is designed for academic benchmarking, red-team research, and automated security pipeline integration.

---

## What Makes It Agentic

AutoPoV is not a pipeline of scripts. It is a **stateful agent graph** where:

- Each stage is an autonomous **agent node** that perceives context, reasons, acts, and reports back.
- The graph makes **autonomous routing decisions** — whether to generate an exploit, retry, skip, or end.
- Agents call **external tools** (CodeQL, Docker, ChromaDB, Joern) and react to their output.
- A **Policy Agent** dynamically selects which reasoning model each agent should use, per task, per language, per CWE.
- A **Learning Store** records every agent decision and outcome, feeding a self-improvement loop that makes the Policy Agent smarter over time.

---

## Agent Roster

| Agent | Role |
|---|---|
| **Ingestion Agent** | Chunks and embeds the entire codebase into a vector store for semantic retrieval |
| **Heuristic Scout Agent** | Rapidly pattern-matches across all files to surface candidate vulnerability locations |
| **LLM Scout Agent** | Autonomously proposes candidate vulnerabilities by reasoning over file content |
| **Investigator Agent** | Performs deep LLM + RAG analysis on each candidate — returns `REAL` or `FALSE_POSITIVE` with a confidence score |
| **PoV Generator Agent** | Writes a working exploit script for every confirmed finding |
| **Validation Agent** | Verifies the exploit via static analysis, unit test harness, or Docker execution — in that order |
| **Docker Execution Agent** | Runs unvalidated exploits in a sandboxed container as a final proof step |
| **Policy Agent** | Routes each agent's reasoning task to the optimal model based on historical performance |

---

## Agentic Workflow

```
                    ┌─────────────────────────────────────────┐
                    │            AGENT GRAPH (LangGraph)       │
                    └─────────────────────────────────────────┘

  Code Input ──► Ingestion Agent ──► Heuristic/LLM Scout Agents
                                              │
                                       CodeQL Analysis
                                              │
                                     Merge + Deduplicate
                                              │
                                    ┌─── Investigator Agent ───┐
                                    │  (per finding, in loop)  │
                                    │   REAL / FALSE_POSITIVE  │
                                    └──────────┬───────────────┘
                               confidence ≥ 0.7│
                                    ┌─── PoV Generator Agent ──┐
                                    │   (writes exploit script)│
                                    └──────────┬───────────────┘
                                    ┌─── Validation Agent ─────┐
                                    │  static → unit test →    │
                                    │  Docker (escalating)     │
                                    └──────────┬───────────────┘
                                        confirmed / failed / retry
                                              │
                                    ┌─── Policy Agent ─────────┐
                                    │  records outcome to       │
                                    │  Learning Store (SQLite)  │
                                    └──────────────────────────┘
                                              │
                                      More findings? ──► loop
                                              │ (none left)
                                            END
```

---

## Feature Summary

- **Multi-source ingestion** — Git repo clone, ZIP upload, local directory, raw code paste
- **20+ CWE detection** — OWASP Top 10 and beyond, across Python, JavaScript, Java, C/C++, Go, Ruby, PHP
- **Autonomous exploit generation** — each agent-confirmed vulnerability gets a working PoV script
- **Hybrid validation** — agents escalate through static → unit test → Docker proof
- **Adaptive model routing** — the Policy Agent picks the best-performing model per stage, CWE, and language
- **Self-improving agents** — the Learning Store tracks confirmed/cost ratios so the system improves with every scan
- **Real-time streaming** — live agent logs pushed via SSE to both the web UI and CLI
- **Rate-limited, keyed access** — two-tier auth (Admin Key for management, API Keys for agent operations)
- **Webhook integration** — GitHub/GitLab push events autonomously trigger agent runs
- **Scan replay** — re-run any prior agent findings against different reasoning models for benchmarking
- **LangSmith tracing** — full agent trace visibility for debugging and research

---

## Repository Layout

```
AutoPoV/
├── agents/                    # Autonomous agent implementations
│   ├── ingest_codebase.py     # Ingestion Agent — chunking, embedding, RAG
│   ├── heuristic_scout.py     # Heuristic Scout Agent — pattern-based discovery
│   ├── llm_scout.py           # LLM Scout Agent — model-driven discovery
│   ├── investigator.py        # Investigator Agent — deep LLM + RAG analysis
│   ├── verifier.py            # PoV Generator Agent — exploit script generation
│   ├── static_validator.py    # Static Validation Agent
│   ├── unit_test_runner.py    # Unit Test Validation Agent
│   ├── pov_tester.py          # PoV Test Harness Agent
│   └── docker_runner.py       # Docker Execution Agent
│
├── app/                       # FastAPI backend + agent orchestration
│   ├── agent_graph.py         # LangGraph state machine (the agent graph)
│   ├── policy.py              # Policy Agent — model routing logic
│   ├── learning_store.py      # Learning Store — agent outcome persistence
│   ├── scan_manager.py        # Scan lifecycle and background execution
│   ├── auth.py                # Two-tier authentication + rate limiting
│   ├── main.py                # REST API surface
│   ├── config.py              # Environment-driven configuration
│   ├── git_handler.py         # Git clone + accessibility checks
│   ├── source_handler.py      # ZIP and raw code handling
│   ├── webhook_handler.py     # GitHub/GitLab webhook processing
│   └── report_generator.py    # JSON + PDF report generation
│
├── frontend/                  # React + Vite + Tailwind web UI
├── cli/                       # Rich CLI tool (autopov.py)
├── codeql_queries/            # Custom CodeQL .ql files
├── semgrep-rules/             # Semgrep OWASP ruleset
├── data/                      # API keys, ChromaDB, learning.db
├── results/                   # Scan output, PoV scripts, reports
└── tests/                     # Pytest test suite
```

---

## Quick Start

### Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.11+ | Backend agents and API |
| Node.js 20+ | Frontend dashboard |
| Docker Desktop | Agent exploit execution (PoV proof step) |
| OpenRouter API key | Agent reasoning (online mode) |
| CodeQL CLI | Static discovery agent (optional but recommended) |
| Joern | CPG analysis for CWE-416 agents (optional) |

### 1. Clone and Install

```bash
git clone <repository-url>
cd AutoPoV

# Backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd frontend && npm install && cd ..
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` — minimum required fields:

```env
OPENROUTER_API_KEY=sk-or-v1-...       # Agent reasoning provider
ADMIN_API_KEY=your_strong_secret      # Admin key for key management
MODEL_MODE=online                     # online (OpenRouter) or offline (Ollama)
ROUTING_MODE=auto                     # auto | fixed | learning
```

### 3. Start the System

```bash
./run.sh both          # Backend (port 8000) + Frontend (port 5173)
./run.sh backend       # API + agent system only
./run.sh frontend      # Dashboard only
```

### 4. Provision an API Key

The **Admin Key** manages access. The **API Key** is what agents and users authenticate with.

```bash
# Via CLI
python cli/autopov.py keys generate --admin-key your_admin_key --name mykey

# Via API
curl -X POST http://localhost:8000/api/keys/generate?name=mykey \
  -H "Authorization: Bearer your_admin_key"
```

Save the returned `apov_...` key — it is shown only once.

---

## Usage

### Web Dashboard

1. Open `http://localhost:5173`
2. Go to **Settings** → enter your API key
3. Choose a scan input: **Git URL**, **ZIP upload**, or **Paste code**
4. Select target CWEs (or leave blank for all 20+)
5. Submit — the agent system starts immediately
6. Watch live agent logs stream in real-time on the progress page
7. Review confirmed vulnerabilities, PoV scripts, and validation evidence in Results
8. Download JSON or PDF report

### CLI

The CLI provides the same agent capabilities from your terminal:

```bash
# Scan a Git repository (interactive model selection)
python cli/autopov.py scan https://github.com/user/repo.git

# Scan with a specific model
python cli/autopov.py scan https://github.com/user/repo.git --model openai/gpt-4o

# Scan a local directory
python cli/autopov.py scan /path/to/code

# Scan specific CWEs only
python cli/autopov.py scan https://github.com/user/repo.git --cwe CWE-89 --cwe CWE-79

# View agent results as a table
python cli/autopov.py results <scan_id>

# Download PDF report
python cli/autopov.py report <scan_id> --format pdf

# View scan history
python cli/autopov.py history --limit 20

# Key management
python cli/autopov.py keys generate --admin-key <admin_key> --name team
python cli/autopov.py keys list --admin-key <admin_key>
```

Set `AUTOPOV_API_KEY` in your environment to avoid passing `--api-key` every time:
```bash
export AUTOPOV_API_KEY=apov_...
```

### REST API

All agent operations are available via the REST API. Interactive docs at `http://localhost:8000/api/docs`.

```bash
# Trigger an agent run on a Git repository
curl -X POST http://localhost:8000/api/scan/git \
  -H "Authorization: Bearer apov_your_key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/user/repo.git", "cwes": ["CWE-89", "CWE-79"]}'

# Poll agent progress
curl http://localhost:8000/api/scan/<scan_id> \
  -H "Authorization: Bearer apov_your_key"

# Stream live agent logs (SSE)
curl "http://localhost:8000/api/scan/<scan_id>/stream?api_key=apov_your_key"

# Cancel a running agent run
curl -X POST http://localhost:8000/api/scan/<scan_id>/cancel \
  -H "Authorization: Bearer apov_your_key"

# Replay findings against different models (benchmarking)
curl -X POST http://localhost:8000/api/scan/<scan_id>/replay \
  -H "Authorization: Bearer apov_your_key" \
  -H "Content-Type: application/json" \
  -d '{"models": ["anthropic/claude-3.5-sonnet"], "include_failed": false}'

# Download report
curl "http://localhost:8000/api/report/<scan_id>?format=pdf" \
  -H "Authorization: Bearer apov_your_key" -o report.pdf

# Agent learning summary (model performance stats)
curl http://localhost:8000/api/learning/summary \
  -H "Authorization: Bearer apov_your_key"

# Admin: clean up old result files
curl -X POST "http://localhost:8000/api/admin/cleanup?max_age_days=30" \
  -H "Authorization: Bearer your_admin_key"
```

---

## Configuration Reference

### Core Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OPENROUTER_API_KEY` | API key for agent reasoning (OpenRouter) | — |
| `ADMIN_API_KEY` | Admin key for key management endpoints | — |
| `MODEL_MODE` | `online` (OpenRouter) or `offline` (Ollama) | `online` |
| `MODEL_NAME` | Fixed model name when `ROUTING_MODE=fixed` | `openai/gpt-4o` |
| `ROUTING_MODE` | `auto` / `fixed` / `learning` | `auto` |
| `AUTO_ROUTER_MODEL` | OpenRouter auto-routing model ID | `openrouter/auto` |
| `DOCKER_ENABLED` | Enable Docker for PoV execution agent | `true` |
| `MAX_COST_USD` | Per-scan cost ceiling | `100.0` |

### Agent Routing Modes

| Mode | Behaviour |
|---|---|
| `auto` | OpenRouter selects the best available model per request |
| `fixed` | All agents use `MODEL_NAME` |
| `learning` | The Policy Agent queries the Learning Store and routes to the model with the best confirmed/cost ratio per CWE + language. Falls back to `auto` if insufficient data. |

### Agent Scout Settings

| Variable | Description | Default |
|---|---|---|
| `SCOUT_ENABLED` | Enable heuristic + LLM scout agents | `true` |
| `SCOUT_LLM_ENABLED` | Enable LLM Scout Agent | `true` |
| `SCOUT_MAX_FILES` | Max files the LLM Scout Agent analyses | `25` |
| `SCOUT_MAX_COST_USD` | Cost cap for the LLM Scout Agent per scan | `0.10` |
| `SCOUT_MAX_FINDINGS` | Max candidates any scout agent can surface | `200` |

### CodeQL Agent Settings

| Variable | Description | Default |
|---|---|---|
| `CODEQL_CLI_PATH` | Path to CodeQL binary | `codeql` |
| `CODEQL_PACKS_BASE` | Base directory for CodeQL query packs | `/usr/local/codeql/packs` |

---

## Supported CWEs

The agent system covers 20 CWE categories by default:

| Category | CWEs |
|---|---|
| **Injection** | CWE-89 (SQL), CWE-79 (XSS), CWE-94 (Code), CWE-78 (Command) |
| **Access Control** | CWE-22 (Path Traversal), CWE-352 (CSRF), CWE-306 (Missing Auth), CWE-287 (Broken Auth) |
| **Memory Safety** | CWE-119 (Buffer Overflow), CWE-416 (Use After Free), CWE-190 (Integer Overflow) |
| **Sensitive Data** | CWE-312 (Cleartext Storage), CWE-798 (Hardcoded Credentials), CWE-200 (Info Disclosure) |
| **Cryptography** | CWE-327 (Broken Crypto) |
| **Design** | CWE-502 (Deserialization), CWE-918 (SSRF), CWE-434 (Unrestricted Upload), CWE-611 (XXE), CWE-400 (DoS), CWE-384 (Session Fixation), CWE-601 (Open Redirect) |

---

## Agent Learning and Performance Tracking

Every agent decision is recorded in `data/learning.db` (SQLite):

- The **Investigator Agent** records: model used, CWE, language, verdict, confidence, cost
- The **PoV Execution Agent** records: model used, CWE, success/failure, validation method, cost

Query performance directly:
```bash
sqlite3 data/learning.db

-- Best investigation models by confirmed-per-dollar
SELECT model,
       SUM(CASE WHEN verdict='REAL' THEN 1 ELSE 0 END) AS confirmed,
       ROUND(SUM(cost_usd), 4) AS total_cost,
       ROUND(SUM(CASE WHEN verdict='REAL' THEN 1.0 ELSE 0 END) / (SUM(cost_usd)+0.01), 1) AS score
FROM investigations GROUP BY model ORDER BY score DESC;

-- Best PoV agent models by success rate
SELECT model, SUM(success) AS wins, COUNT(*) AS total,
       ROUND(SUM(success)*1.0/COUNT(*), 2) AS success_rate
FROM pov_runs GROUP BY model ORDER BY success_rate DESC;
```

Or via API:
```bash
curl http://localhost:8000/api/learning/summary \
  -H "Authorization: Bearer apov_your_key"
```

---

## Security Architecture

- **Two-tier auth** — Admin Key (operator only, HMAC-safe comparison) → API Keys (SHA-256 hashed, never stored in plaintext)
- **Rate limiting** — 10 agent runs per API key per 60 seconds
- **Agent sandboxing** — all PoV executions run in Docker containers with no network, 512 MB RAM, 1 CPU, 60s timeout
- **Result TTL** — admin-triggered cleanup of scan results older than N days (`POST /api/admin/cleanup`)

---

## Webhooks

Configure GitHub or GitLab to autonomously trigger agent runs on push:

1. Go to repository **Settings → Webhooks**
2. Set Payload URL: `http://your-server:8000/api/webhook/github`
3. Set the same secret as `GITHUB_WEBHOOK_SECRET` in `.env`
4. Select **Push** and **Pull Request** events

The webhook handler verifies the HMAC signature and fires a full agent run automatically.

---

## Benchmarking

Re-run agent findings across multiple models to compare performance:

```bash
# Via API replay
curl -X POST http://localhost:8000/api/scan/<original_scan_id>/replay \
  -H "Authorization: Bearer apov_your_key" \
  -H "Content-Type: application/json" \
  -d '{"models": ["openai/gpt-4o", "anthropic/claude-3.5-sonnet"], "include_failed": true}'

# Analyse all historical runs
python analyse.py
```

---

## Testing

```bash
pytest tests/ -v
# or
./run.sh test
```

---

## Research

AutoPoV is designed for research in:
- Autonomous agentic security workflows
- LLM-driven vulnerability detection and exploit generation
- Multi-agent coordination and self-improving routing
- SAST tool benchmarking and hybrid analysis pipelines
- Automated Proof-of-Vulnerability generation at scale

---

## Acknowledgments

- **LangGraph / LangChain** — agentic state machine and tool orchestration
- **CodeQL** — static discovery and SARIF analysis
- **ChromaDB** — vector store for agent RAG context
- **OpenRouter** — unified LLM provider for agent reasoning
- **Docker** — sandboxed agent exploit execution
