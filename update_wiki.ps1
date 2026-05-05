# AutoPoV Wiki Update Script
# Run from PowerShell: .\update_wiki.ps1
# Prereq: wiki already cloned to C:\Users\EndUser\autopov-wiki-check

$wikiDir = "C:\Users\EndUser\autopov-wiki-check"

# ─────────────────────────────────────────────
# 1. Home.md
# ─────────────────────────────────────────────
$homeContent = @'
# AutoPoV Wiki

Welcome to the AutoPoV wiki — the authoritative reference for the AutoPoV autonomous vulnerability research platform.

## What is AutoPoV?

AutoPoV is an autonomous, multi-agent security research platform that discovers, investigates, and confirms vulnerabilities in source codebases. Given a target (Git repository, ZIP/TAR archive, file upload, or raw code paste), it runs an 11-stage LangGraph pipeline that produces validated Proof-of-Vulnerability (PoV) scripts with real crash evidence.

## Quick Navigation

| Section | Description |
|---|---|
| [Getting Started](Getting-Started) | Installation, configuration, and first scan |
| [Architecture & Design](Architecture-&-Design) | System layers, 11-stage pipeline, LLM routing |
| [Agent System](Agent-System) | All agents: scouts, investigator, verifier, oracle |
| [Backend Services](Backend-Services) | FastAPI, scan manager, source handling |
| [Scan Management API](Scan-Management-API) | REST endpoints for initiating and monitoring scans |
| [API Reference](API-Reference) | Authentication, streaming, reports, webhooks |
| [Frontend Dashboard](Frontend-Dashboard) | React UI components and page layouts |
| [Deployment & Operations](Deployment-&-Operations) | Docker Compose, environment, operations |
| [Troubleshooting & FAQ](Troubleshooting-&-FAQ) | Common issues and resolutions |

## Supported Input Modes

| Mode | Endpoint | Notes |
|---|---|---|
| Git repository | `POST /api/scan/git` | GitHub, GitLab, Bitbucket; private repos via token |
| ZIP archive | `POST /api/scan/zip` | Path-traversal protected extraction |
| TAR archive | `POST /api/scan/tar` | gzip, bz2, xz supported |
| File/folder upload | `POST /api/scan/upload` | Multipart; directory structure preserved |
| Raw code paste | `POST /api/scan/paste` | Single-file with language inference |

## 11-Stage Pipeline

```
ingest → discover → probe → investigate → generate → validate → coordinate → refine → docker → oracle → log
```

1. **ingest** — Code chunked and embedded into ChromaDB for RAG
2. **discover** — CodeQL + HeuristicScout + LLMScout find candidates
3. **probe** — Preflight: binary name, baseline exit code, attack surface, ASAN status
4. **investigate** — LLM + RAG deep analysis with optional Joern CPG
5. **generate** — Language-aware PoV script generation (C, Python, Go, Node, etc.)
6. **validate** — Static validator gates self-compile and cmake patterns
7. **coordinate** — Oracle policy reviews PoV and pre-approves execution plan
8. **refine** — LLM retry loop with failure analysis (up to N attempts)
9. **docker** — PoV executed in language-specific proof container
10. **oracle** — Signal classification: crash_signal, sanitizer, stdout_marker, self_report_only, non_evidence
11. **log** — Findings, costs, and oracle verdict persisted

## Supported CWE Targets

- CWE-89 (SQL Injection)
- CWE-79 (XSS)
- CWE-119 (Buffer Overflow / Memory Corruption)
- CWE-190 (Integer Overflow)
- CWE-416 (Use-After-Free)
- CWE-22 (Path Traversal)
- CWE-78 (Command Injection)

## Proof Container Types

`native` · `python` · `node` · `go` · `java` · `php` · `ruby` · `browser`

## LLM Support

- **Online**: OpenRouter (GPT-4o, Claude 3.5, Gemini Pro, Qwen, DeepSeek, etc.)
- **Offline**: Ollama (qwen2.5-coder, codellama, deepseek-coder, etc.)
- Unified routing: `get_verifier()._get_llm(model, purpose)` — no direct instantiation
'@
Set-Content -Path "$wikiDir\Home.md" -Value $homeContent -Encoding UTF8
Write-Host "✓ Home.md updated"

# ─────────────────────────────────────────────
# 2. Agent System.md  — append new section before ## Conclusion
# ─────────────────────────────────────────────
$agentSystemPath = "$wikiDir\Agent System.md"
$agentSystemContent = Get-Content $agentSystemPath -Raw

$newAgentSection = @'

### ProbeTarget (Preflight Stage)
- Role: Gather ground-truth information about the compiled target binary before PoV generation.
- Responsibilities:
  - Locate the correct built binary using the build-native binary locator (scoring-based, excludes CMake test artefacts and shell scripts).
  - Run the binary with no args to capture baseline exit code and stderr.
  - Detect ASAN/UBSAN instrumentation status.
  - Enumerate known subcommands and help text via `--help`.
  - Record observed attack surface (CLI flags, file paths, stdin, network).
- Data structures:
  - `probe_binary_name`, `probe_baseline_exit_code`, `probe_baseline_stderr`
  - `observed_surface`, `known_subcommands`, `help_text`, `asan_disabled`
- Implementation notes:
  - Binary locator apply deny-set scoring: `-999` for `CMakeFiles/Check*`, `_codeql_build_dir`, shell scripts.
  - Probe data flows directly into PoV generation prompts.

### CoordinatePov (Oracle Pre-Approval Stage)
- Role: Policy agent that reviews a generated PoV before Docker execution.
- Responsibilities:
  - Check PoV language matches target (no Python/shell wrapping a native binary without valid reason).
  - Verify PoV uses the correct binary path from probe data.
  - Reject PoVs that attempt self-compilation inside the container.
  - Pre-approve or request refinement with structured feedback.
- Data structures:
  - `coordinate_approved: bool`, `coordinate_feedback: str`

### EvaluateOracle (Result Classification Stage)
- Role: Classify the Docker execution result into a confirmed verdict.
- Oracle signal hierarchy (highest priority first):
  1. `crash_signal` — Process killed by SIGSEGV, SIGABRT, SIGBUS, etc.
  2. `sanitizer_output` — ASAN/UBSAN/MSAN output in stderr
  3. `stdout_marker` — `VULNERABILITY TRIGGERED` printed AND exit code non-zero
  4. `self_report_only` — Marker printed but exit=0, no crash (not confirmed)
  5. `non_evidence` — Exit 0, no marker, no signal (PoV ran but found nothing)
- Implementation notes:
  - `self_report_only` is explicitly NOT confirmed — requires real crash signal.
  - ASAN-disabled fallback: if `asan_disabled=true`, `stdout_marker` threshold is lowered.

'@

# Insert new sections before the ## Conclusion line
$agentSystemContent = $agentSystemContent -replace '(## Conclusion\r?\nAutoPoV)', ($newAgentSection + '$1')
Set-Content -Path $agentSystemPath -Value $agentSystemContent -Encoding UTF8
Write-Host "✓ Agent System.md updated"

# ─────────────────────────────────────────────
# 3. Architecture & Design.md — append new section before ## Appendices
# ─────────────────────────────────────────────
$archPath = "$wikiDir\Architecture `& Design.md"
$archContent = Get-Content $archPath -Raw

$newArchSection = @'

### 11-Stage LangGraph Pipeline
The current pipeline implements eleven distinct graph nodes:

| Stage | Node | Key Action |
|---|---|---|
| 1 | ingest_code | ChromaDB chunking & embedding |
| 2 | run_codeql | CodeQL + autonomous scouts |
| 3 | probe_target | Preflight binary probe |
| 4 | investigate | LLM + RAG + optional Joern |
| 5 | generate_pov | Language-aware PoV generation |
| 6 | validate_pov | Static validator (blocks cmake/self-compile) |
| 7 | coordinate_pov | Oracle pre-approval policy |
| 8 | refine_pov | Retry with failure analysis |
| 9 | run_in_docker | Proof container execution |
| 10 | evaluate_oracle | Signal classification |
| 11 | log_outcome | Persist finding + costs |

### Unified LLM Routing Design
All agents obtain LLM instances via `get_verifier()._get_llm(model, purpose)`:
- `MODEL_MODE=online` → OpenRouter (any model slug)
- `MODEL_MODE=offline` → Ollama (local endpoint)
- No direct `ChatOpenAI` / `ChatOllama` instantiation anywhere outside this method

### Build-Native Binary Locator
Scoring system for selecting the correct compiled binary:
- Base score from file size, executable bit, and proximity to source root
- **Deny set** (score -999): `CMakeFiles/Check*`, `_codeql_build_dir/`, shell scripts (`file` magic: ELF check), `*.bin` without ELF header, autoconf artefacts (`configure~`, `config.status`)
- Final selection: highest scoring non-denied binary matching the project name

### Oracle Signal Classification
```
crash_signal       ← SIGSEGV/SIGABRT/SIGBUS  →  confirmed ✓
sanitizer_output   ← ASAN/UBSAN stderr        →  confirmed ✓
stdout_marker+exit ← TRIGGERED + exit!=0      →  confirmed ✓
self_report_only   ← TRIGGERED + exit=0       →  NOT confirmed ✗
non_evidence       ← exit=0, no marker        →  NOT confirmed ✗
```

'@

$archContent = $archContent -replace '(## Appendices\r?\n)', ($newArchSection + '$1')
Set-Content -Path $archPath -Value $archContent -Encoding UTF8
Write-Host "✓ Architecture and Design.md updated"

# ─────────────────────────────────────────────
# 4. Getting Started.md — expand Quick Start section
# ─────────────────────────────────────────────
$gsPath = "$wikiDir\Getting Started.md"
$gsContent = Get-Content $gsPath -Raw

$oldInputLine = "- Select a scan input (Git URL, ZIP upload, or paste code)"
$newInputLine = "- Select a scan input: Git URL, ZIP upload, TAR archive, file/folder upload, or paste code"
$gsContent = $gsContent.Replace($oldInputLine, $newInputLine)

# Also update the input sources table in First Scan Workflow
$oldFlowLine = 'A["Select Input Source"]'
$newFlowLine = 'A["Select Input Source\n(Git / ZIP / TAR / Upload / Paste)"]'
$gsContent = $gsContent.Replace($oldFlowLine, $newFlowLine)

# Add TAR to the supported sources in the Architecture section
$oldArchNote = "- Backend: FastAPI application exposing REST endpoints and managing agent orchestration"
$newArchNote = @'
AutoPoV supports five input modes:

| Mode | Endpoint |
|---|---|
| Git repository | `POST /api/scan/git` |
| ZIP archive | `POST /api/scan/zip` |
| TAR archive | `POST /api/scan/tar` |
| File/folder upload | `POST /api/scan/upload` |
| Raw code paste | `POST /api/scan/paste` |

- Backend: FastAPI application exposing REST endpoints and managing agent orchestration
'@
$gsContent = $gsContent.Replace($oldArchNote, $newArchNote)

Set-Content -Path $gsPath -Value $gsContent -Encoding UTF8
Write-Host "✓ Getting Started.md updated"

# ─────────────────────────────────────────────
# 5. Scan Management API - Scan Initiation Endpoints.md — add TAR section
# ─────────────────────────────────────────────
$scanInitPath = "$wikiDir\Scan Management API - Scan Initiation Endpoints.md"
$scanInitContent = Get-Content $scanInitPath -Raw

$tarSection = @'

### Endpoint: POST /api/scan/tar
Purpose: Upload a TAR archive (gzip, bz2, or xz compressed) and initiate a scan.

- Method: POST
- Path: /api/scan/tar
- Authentication: Bearer API Key (with rate limit enforcement)
- Request: multipart/form-data
  - file: UploadFile (required, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz)
  - model: string (form field, default: openai/gpt-4o)
  - cwes: string (comma-separated list, default: "CWE-89,CWE-119,CWE-190,CWE-416")
- Response: 201 Created with ScanResponse

Processing logic:
- Validates authentication and rate limit
- Creates a scan record via Scan Manager
- Background task:
  - Saves uploaded TAR to temporary path
  - Extracts TAR to scan source directory with path traversal protection
  - Supports gzip (`r:gz`), bz2 (`r:bz2`), and xz (`r:xz`) modes
  - Updates scan with extracted path
  - Executes scan asynchronously using Scan Manager

Security considerations:
- Path traversal prevention: all members checked against extraction root
- Compression bombs: file size limits enforced before extraction
- Enforces rate limiting per API key

Rate limiting:
- 10 scans per minute per API key

Example request:
- Headers: Authorization: Bearer apov_..., Content-Type: multipart/form-data
- Body: file=<TAR.GZ>, model=openai/gpt-4o, cwes=CWE-89,CWE-119

Example response:
- 201 Created: { "scan_id": "...", "status": "created", "message": "TAR archive scan initiated" }

**Section sources**
- [app/main.py](file://app/main.py)
- [app/source_handler.py:79-124](file://app/source_handler.py#L79-L124)

'@

# Insert TAR section after the ZIP section
$insertMarker = "### Endpoint: POST /api/scan/paste"
$scanInitContent = $scanInitContent.Replace($insertMarker, $tarSection + $insertMarker)

# Update Introduction to mention TAR
$oldIntro = "- POST /api/scan/paste: Direct code paste scanning"
$newIntro = "- POST /api/scan/tar: TAR archive upload scanning (gzip, bz2, xz)" + "`n" + $oldIntro
$scanInitContent = $scanInitContent.Replace($oldIntro, $newIntro)

Set-Content -Path $scanInitPath -Value $scanInitContent -Encoding UTF8
Write-Host "✓ Scan Management API - Scan Initiation Endpoints.md updated"

# ─────────────────────────────────────────────
# 6. Commit and push
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "All wiki files updated. Now committing and pushing..."
Set-Location $wikiDir
git add .
git status
git commit -m "docs: update wiki with 11-stage pipeline, probe/oracle stages, TAR input, Home.md"
git push origin master
Write-Host ""
Write-Host "Done! Wiki pushed to https://github.com/keysight-anya/AutoPoV/wiki"
