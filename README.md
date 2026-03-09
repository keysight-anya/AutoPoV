# AutoPoV - Autonomous Proof-of-Vulnerability Framework

AutoPoV is a full-stack research prototype that implements a hybrid agentic framework for vulnerability benchmarking in industrial codebases. It combines static analysis (CodeQL, Joern) with AI-powered reasoning (LLMs via LangGraph) to detect, verify, and benchmark vulnerabilities.

## Features

- **Multi-Source Code Ingestion**: Git repositories, ZIP uploads, file/folder uploads, raw code paste
- **AI-Powered Detection**: Uses LLMs (GPT-4o, Claude, Llama3, Mixtral) for semantic vulnerability analysis
- **Proof-of-Vulnerability (PoV)**: Automatically generates and executes PoV scripts in Docker
- **Benchmarking**: Compare LLM performance on vulnerability detection metrics
- **Multiple CWE Support**: CWE-119 (Buffer Overflow), CWE-89 (SQL Injection), CWE-416 (Use After Free), CWE-190 (Integer Overflow)
- **Web UI**: React-based dashboard with real-time scan progress
- **CLI Tool**: Command-line interface for automation
- **Webhooks**: GitHub/GitLab integration for auto-triggering scans
- **LangSmith Integration**: Trace and debug LangGraph agent runs

## Architecture

```
autopov/
├── app/                    # FastAPI backend
│   ├── main.py            # API endpoints
│   ├── agent_graph.py     # LangGraph workflow
│   ├── scan_manager.py    # Scan orchestration
│   └── ...
├── agents/                 # LangGraph agent components
│   ├── ingest_codebase.py # Code chunking & embedding
│   ├── investigator.py    # LLM vulnerability analysis
│   ├── verifier.py        # PoV generation
│   └── docker_runner.py   # Docker execution
├── frontend/              # React + Vite + Tailwind
├── cli/                   # Click CLI tool
├── codeql_queries/        # CodeQL .ql files
└── tests/                 # Pytest test suite
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop (for PoV execution)
- (Optional) CodeQL CLI
- (Optional) Joern

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd autopov
```

2. Create virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
cd ..
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your API keys
```

### Running the Application

Start both backend and frontend:
```bash
./run.sh both
```

Or start individually:
```bash
./run.sh backend   # API server on http://localhost:8000
./run.sh frontend  # Web UI on http://localhost:5173
```

### API Key Setup

1. Set admin key in `.env`:
```bash
ADMIN_API_KEY=your_secure_random_key
```

2. Generate API key via CLI:
```bash
python cli/autopov.py keys generate --admin-key your_admin_key
```

3. Or use the settings page in the web UI.

## Usage

### Web UI

1. Open http://localhost:5173
2. Enter your API key in Settings
3. Select scan type (Git, ZIP, or Paste)
4. Choose model and CWEs
5. Start scan and view results

### CLI

```bash
# Scan a Git repository
autopov scan https://github.com/user/repo.git --model openai/gpt-4o

# Scan local directory
autopov scan /path/to/code --model anthropic/claude-3.5-sonnet

# View results
autopov results <scan_id> --output table

# Generate report
autopov report <scan_id> --format pdf
```

### API

```bash
# Start a scan
curl -X POST http://localhost:8000/api/scan/git \
  -H "Authorization: Bearer your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://github.com/user/repo.git",
    "model": "openai/gpt-4o",
    "cwes": ["CWE-89", "CWE-119"]
  }'

# Get scan status
curl http://localhost:8000/api/scan/<scan_id> \
  -H "Authorization: Bearer your_api_key"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API key | - |
| `ADMIN_API_KEY` | Admin key for API key generation | - |
| `MODEL_MODE` | `online` or `offline` | online |
| `MODEL_NAME` | LLM model name | openai/gpt-4o |
| `DOCKER_ENABLED` | Enable Docker for PoV execution | true |
| `MAX_COST_USD` | Maximum cost limit | 100.0 |

### Models

**Online (via OpenRouter):**
- openai/gpt-4o
- anthropic/claude-3.5-sonnet

**Offline (via Ollama):**
- llama3:70b
- mixtral:8x7b

## Benchmarking

Analyze scan results and compare models:

```bash
python analyse.py
```

Generates:
- `results/benchmark_summary.csv` - CSV summary
- `results/benchmark_report.json` - Detailed report

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Or use the run script:
```bash
./run.sh test
```

## Supported CWEs

| CWE | Name | Description |
|-----|------|-------------|
| CWE-119 | Buffer Overflow | Improper bounds checking |
| CWE-89 | SQL Injection | Unsanitized user input in SQL |
| CWE-416 | Use After Free | Dangling pointer dereference |
| CWE-190 | Integer Overflow | Arithmetic overflow/wraparound |

## Docker Safety

PoV scripts run in isolated Docker containers with:
- No network access
- Memory limits (512MB default)
- CPU limits
- Timeout (60s default)

## Webhooks

Configure GitHub/GitLab webhooks to auto-trigger scans:

1. Go to repository Settings > Webhooks
2. Add webhook URL: `http://your-server:8000/api/webhook/github`
3. Set secret in environment variables
4. Select "Push" and "Pull Request" events

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Research

This project is designed for academic research in:
- LLM-based vulnerability detection
- Automated exploit generation
- SAST tool benchmarking
- AI security analysis

## Acknowledgments

- LangChain/LangGraph for agent framework
- CodeQL for static analysis
- ChromaDB for vector storage
- OpenRouter for LLM API access
