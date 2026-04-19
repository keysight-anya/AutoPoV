# AutoPoV Application Flow

This document describes how the project works today, based on the current FastAPI backend, LangGraph workflow, CLI, and React frontend.

## Entry Points

A scan can start from:

- `POST /api/scan/git` — GitHub or GitLab repository URL
- `POST /api/scan/zip` — uploaded ZIP or TAR archive (`.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`)
- `POST /api/scan/paste` — raw pasted code (single code chunk, any supported language)
- `POST /api/scan/benchmark` — pre-installed benchmark target
- GitHub or GitLab webhook endpoints
- the web UI (Home page: Git URL tab, ZIP upload tab, or Paste tab)
- the CLI in `cli/autopov.py`

All scan-triggering API endpoints create a scan record immediately and continue work asynchronously in a background task.

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

All source input types are handled by `app/source_handler.py`:

- **Git**: accessibility check → clone to scan-specific workspace via `app/git_handler.py`
- **ZIP**: uploaded to `/tmp/autopov/<scan_id>/upload.zip` → extracted with path-traversal and compression-ratio validation; single root dir is flattened
- **TAR / TAR.GZ / TAR.BZ2 / TAR.XZ**: same extraction pipeline as ZIP, symlinks rejected
- **File upload**: individual files copied, directory structure optionally preserved
- **Folder upload**: entire folder tree copied
- **Paste / Code chunk**: raw code string written to a temporary file with the correct extension inferred from the declared language

Security limits applied during archive extraction:
- Max upload size: `MAX_UPLOAD_SIZE_MB` (default 500MB)
- Max decompressed size: `MAX_ARCHIVE_UNCOMPRESSED_MB`
- Max file count: `MAX_ARCHIVE_FILES`
- Max compression ratio: `MAX_ARCHIVE_COMPRESSION_RATIO` (bomb protection)
- Path traversal and symlink rejection on every member

Once the source path is resolved, the scan manager starts the asynchronous LangGraph run.

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
  -> run_codeql (discovery: CodeQL + Semgrep + heuristics + LLM scout)
  -> log_findings_count
  -> probe_target (preflight: ASan build, binary name, surface, baseline)
  -> investigate (per-finding LLM analysis + RAG + optional Joern)
      -> generate_pov or log_skip
  -> validate_pov (static checks + harness)
      -> coordinate_pov (retry meta-reasoning)
      -> run_in_docker or refine_pov (x3) or log_failure
  -> log_confirmed / log_skip / log_failure
      -> investigate next finding or end
```

The graph is stateful and processes findings sequentially after discovery.

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

## Stage 3: Preflight Probe

`probe_target` runs before investigation and PoV generation.

What it captures:

- `probe_binary_name`: exact name of the built binary (e.g. `xmlwf`, `jhead`, `cjson`)
- `probe_baseline_exit_code` and `probe_baseline_stderr`: clean-run reference for ASAN-disabled oracle fallback
- `observed_surface`: `file_argument | stdin | argv_only | network | unknown` (inferred from help text)
- `known_subcommands` and `help_text`: injected into PoV generation prompts
- `asan_disabled`: set when ASan is not available (triggers exit-code-anomaly oracle path)

Probe data flows into every downstream step: investigation prompts, PoV scaffold generation, refinement error injection, and oracle signal evaluation.

## Stage 4: Investigation

`investigate` performs the deeper per-finding analysis.

Typical inputs include:

- file-local code context
- retrieved RAG context
- optional tool output such as Joern analysis when relevant
- the currently selected model

The investigator decides whether a candidate is credible enough to continue and records explanation, confidence, cost, and model usage metadata.

## Stage 5: PoV Generation

`generate_pov` creates an exploit script for findings that pass the investigation threshold.

Generation paths:

- **Deterministic harness fallback** (`_build_binary_surface_block`): format-aware file fuzzer using pre-built payload arrays (`.jpg`, `.png`, `.gif`, `.xml`, `.json`, `.bmp`, `.tif`, `.webp`, etc.), triggered when LLM context is too small or surface is well-known.
- **C library harness** (`c_library_harness`): inline C driver for library-only targets (no standalone binary).
- **LLM-generated script**: qwen3/glm-4.7-flash/llama4 via Ollama, or OpenRouter for online models. Prompt includes `probe_binary_name`, `observed_surface`, `help_text`, `known_subcommands`, and `repo_input_hints`.

All byte payloads in f-string templates use double-escaped literals (`\\xff`, `\\x00`) to prevent null-byte injection into generated Python source.

The generated PoV is stored in scan state.

## Stage 6: Static Validation

`validate_pov` runs `static_validator.py` before any execution.

Rejects:

- Self-compile patterns: `subprocess.run.*cmake`, `subprocess.run.*gcc`, `subprocess.run.*make`, etc.
- Wrong binary name: `TARGET_SYMBOL != probe_binary_name`
- Empty `TARGET_BINARY` without fallback
- Language mismatch

Allows execution to proceed; oracle decides the outcome.

## Stage 7: Retry Coordination

`coordinate_pov` uses the selected model (via `get_verifier()._get_llm()`) to reason over the retry history and select one of:

- `refine_payload`: try different byte payload
- `refine_format`: change file format or input method
- `change_surface`: switch from file to stdin or vice versa
- `abandon`: skip this finding

## Stage 8: Refinement

`refine_pov` runs up to 3 times.

## Stage 9: Runtime Proof

`run_in_docker` executes the PoV in an isolated language-matched proof container.

Container images available under `docker/proof-images/`:

- `native` — C/C++ targets with ASan runtime
- `python` — Python scripts
- `node` — JavaScript/Node.js
- `go` — Go binaries
- `java` — Java/JVM
- `php` — PHP scripts
- `ruby` — Ruby scripts
- `browser` — headless browser targets

The binary locator inside `docker_runner.py` scores candidate binaries using CMake/Meson/Make build metadata, assigning -999 to test binaries and build tools to avoid false picks.

## Stage 10: Oracle Evaluation

Oracle signal classification in `agents/oracle_policy.py`:

- `crash_signal`: SIGSEGV (139), SIGABRT (134), exit code -11, -6
- `sanitizer_output`: AddressSanitizer `heap-buffer-overflow`, `use-after-free`, `stack-buffer-overflow`; UBSan output
- `stdout_marker`: `VULNERABILITY TRIGGERED` in stdout
- **ASAN-disabled fallback**: baseline exit clean (0/1/2) + exploit exited with signal code + ≥2 new meaningful stderr lines vs baseline
- `non_evidence`: no crash signal; finding recorded as unproven
- `ambiguous_signal`: partial evidence; low-confidence confirmation

## Stage 11: Logging and Iteration

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
- The backend reports fixed routing in `/api/config`; all LLM calls use the single selected model.
- All LLM routing goes through `get_verifier()._get_llm(model, purpose)` — offline routes to Ollama, online to OpenRouter. No hardcoded model instantiation.
- The web UI is first-party and CSRF-protected rather than API-key-driven for browser users.
- CLI and external integrations need Bearer API keys; add them with `python3 add_api_key.py` and then restart the backend.
- Archive uploads support `.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz` with security limits on size, file count, and compression ratio.
- Paste/code-chunk scans write raw code to a temporary file with extension inferred from the declared language (supports 20+ languages).
- The preflight probe is the single authoritative source for binary name, input surface, baseline signals, and help text — all fed downstream to generation and oracle evaluation.
