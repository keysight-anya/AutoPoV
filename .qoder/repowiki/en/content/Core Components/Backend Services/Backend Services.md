# Backend Services

<cite>
**Referenced Files in This Document**
- [app/main.py](file://app/main.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/scan_manager.py](file://app/scan_manager.py)
- [app/config.py](file://app/config.py)
- [app/auth.py](file://app/auth.py)
- [app/git_handler.py](file://app/git_handler.py)
- [app/source_handler.py](file://app/source_handler.py)
- [app/webhook_handler.py](file://app/webhook_handler.py)
- [app/report_generator.py](file://app/report_generator.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/policy.py](file://app/policy.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/investigator.py](file://agents/investigator.py)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Component Analysis](#detailed-component-analysis)
6. [Dependency Analysis](#dependency-analysis)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Conclusion](#conclusion)
10. [Appendices](#appendices)

## Introduction
This document describes AutoPoV’s backend services built on FastAPI. It covers the main application entry point, the LangGraph-based agent orchestration system, background scan management, adaptive model policy routing, learning store for performance tracking, configuration management, authentication and authorization, Git repository handling, source code processing, webhook integration, and report generation. It explains the service architecture, API endpoints, real-time streaming capabilities, and inter-service communication patterns. It also includes configuration options, security considerations, and operational procedures.

## Project Structure
The backend is organized into cohesive modules:
- app: FastAPI application, configuration, authentication, Git and source handlers, scan manager, agent graph, webhook handler, report generator, learning store, and policy router
- agents: LangGraph agent components for vulnerability detection and processing
- data: persistent data stores (ChromaDB vector store, SQLite learning store)
- results: persisted scan results, snapshots, and reports
- codeql_queries: local CodeQL query packs for vulnerability detection
- frontend: optional React-based UI (not covered here)

```mermaid
graph TB
subgraph "FastAPI App"
MAIN["app/main.py"]
CFG["app/config.py"]
AUTH["app/auth.py"]
SCAN["app/scan_manager.py"]
GRAPH["app/agent_graph.py"]
GIT["app/git_handler.py"]
SRC["app/source_handler.py"]
WH["app/webhook_handler.py"]
REP["app/report_generator.py"]
POL["app/policy.py"]
LS["app/learning_store.py"]
end
subgraph "Agents"
ING["agents/ingest_codebase.py"]
INV["agents/investigator.py"]
end
subgraph "Data"
CHROMA["./data/chroma (vector store)"]
SQLITE["./data/learning.db (SQLite)"]
end
subgraph "Results"
RUNS["./results/runs (JSON)"]
SNAP["./results/snapshots (codebase snapshots)"]
POV["./results/povs (PoV artifacts)"]
end
MAIN --> AUTH
MAIN --> SCAN
MAIN --> WH
MAIN --> REP
SCAN --> GRAPH
GRAPH --> ING
GRAPH --> INV
GRAPH --> POL
POL --> LS
ING --> CHROMA
SCAN --> RUNS
SCAN --> SNAP
REP --> POV
```

**Diagram sources**
- [app/main.py:1-768](file://app/main.py#L1-L768)
- [app/agent_graph.py:1-800](file://app/agent_graph.py#L1-L800)
- [agents/ingest_codebase.py:1-413](file://agents/ingest_codebase.py#L1-L413)
- [agents/investigator.py:1-519](file://agents/investigator.py#L1-L519)

**Section sources**
- [app/main.py:114-122](file://app/main.py#L114-L122)
- [app/config.py:13-255](file://app/config.py#L13-L255)

## Core Components
- FastAPI application entry point and API surface
- LangGraph agent orchestration for vulnerability detection and PoV validation
- Background scan manager with persistence and metrics
- Adaptive model policy routing backed by a learning store
- Authentication and rate-limiting for API access
- Git and source code ingestion handlers
- Webhook integrations for CI/CD automation
- Report generation (JSON/PDF) with metrics and PoV summaries
- Configuration management for models, tools, and directories

**Section sources**
- [app/main.py:175-768](file://app/main.py#L175-L768)
- [app/agent_graph.py:82-169](file://app/agent_graph.py#L82-L169)
- [app/scan_manager.py:47-663](file://app/scan_manager.py#L47-L663)
- [app/policy.py:12-40](file://app/policy.py#L12-L40)
- [app/auth.py:40-256](file://app/auth.py#L40-L256)
- [app/git_handler.py:20-392](file://app/git_handler.py#L20-L392)
- [app/source_handler.py:18-382](file://app/source_handler.py#L18-L382)
- [app/webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [app/report_generator.py:200-830](file://app/report_generator.py#L200-L830)
- [app/learning_store.py:14-256](file://app/learning_store.py#L14-L256)
- [app/config.py:13-255](file://app/config.py#L13-L255)

## Architecture Overview
AutoPoV’s backend is a FastAPI application that orchestrates vulnerability scans using a LangGraph workflow. Clients submit scans via REST endpoints, which delegate to the scan manager. The scan manager coordinates the agent graph, which performs code ingestion, CodeQL analysis, autonomous discovery, LLM investigation, PoV generation, and validation. Results are persisted and metrics are tracked. Webhooks integrate with Git providers to trigger scans automatically. Reports summarize findings and PoV outcomes.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "FastAPI app/main.py"
participant Auth as "app/auth.py"
participant SM as "app/scan_manager.py"
participant AG as "app/agent_graph.py"
participant GH as "app/git_handler.py"
participant SH as "app/source_handler.py"
participant LG as "agents/ingest_codebase.py"
participant IR as "agents/investigator.py"
Client->>API : POST /api/scan/git
API->>Auth : verify_api_key_with_rate_limit()
API->>GH : check_repo_accessibility()/clone_repository()
GH-->>API : codebase_path
API->>SM : create_scan() + run_scan_async()
SM->>AG : run_scan(codebase_path, model, cwes)
AG->>LG : ingest_directory()
AG->>IR : investigate(findings)
IR-->>AG : verdict, confidence, cost
AG-->>SM : final_state
SM-->>API : ScanResult
API-->>Client : ScanResponse
```

**Diagram sources**
- [app/main.py:204-286](file://app/main.py#L204-L286)
- [app/git_handler.py:155-294](file://app/git_handler.py#L155-L294)
- [app/scan_manager.py:234-366](file://app/scan_manager.py#L234-L366)
- [app/agent_graph.py:241-307](file://app/agent_graph.py#L241-L307)
- [agents/ingest_codebase.py:207-313](file://agents/ingest_codebase.py#L207-L313)
- [agents/investigator.py:270-433](file://agents/investigator.py#L270-L433)

## Detailed Component Analysis

### FastAPI Application and API Endpoints
- Health and configuration endpoints
- Scan initiation for Git, ZIP, and raw code
- Replay scans using prior findings
- Real-time log streaming via Server-Sent Events (SSE)
- History, metrics, and admin operations
- Report generation (JSON/PDF)
- Webhook endpoints for GitHub and GitLab

```mermaid
flowchart TD
Start(["Incoming Request"]) --> Route{"Route"}
Route --> |GET /api/health| Health["HealthResponse"]
Route --> |GET /api/config| Config["Config JSON"]
Route --> |POST /api/scan/git| GitScan["Clone + Background Run"]
Route --> |POST /api/scan/zip| ZipScan["Extract + Background Run"]
Route --> |POST /api/scan/paste| PasteScan["Write + Background Run"]
Route --> |GET /api/scan/{id}| Status["ScanStatusResponse"]
Route --> |GET /api/scan/{id}/stream| SSE["SSE Logs"]
Route --> |POST /api/scan/{id}/replay| Replay["Replay with Preloaded Findings"]
Route --> |GET /api/history| History["History CSV"]
Route --> |GET /api/metrics| Metrics["Metrics JSON"]
Route --> |GET /api/report/{id}?format=json| JSONRep["JSON Report"]
Route --> |GET /api/report/{id}?format=pdf| PDFRep["PDF Report"]
Route --> |POST /api/webhook/github| GHHook["GitHub Webhook"]
Route --> |POST /api/webhook/gitlab| GLHook["GitLab Webhook"]
Route --> |POST /api/keys/generate| GenKey["API Key"]
Route --> |GET /api/keys| ListKeys["API Keys"]
Route --> |DELETE /api/keys/{id}| RevokeKey["Revoke Key"]
Route --> |POST /api/admin/cleanup| Cleanup["Cleanup Old Results"]
Route --> End(["Response"])
```

**Diagram sources**
- [app/main.py:175-768](file://app/main.py#L175-L768)

**Section sources**
- [app/main.py:175-768](file://app/main.py#L175-L768)

### LangGraph-Based Agent Orchestration
The agent graph defines a state machine that orchestrates vulnerability detection:
- Ingest codebase into a vector store
- Run CodeQL queries or autonomous discovery
- Investigate findings with LLMs using policy-driven model selection
- Generate, validate, and run PoVs
- Loop through findings until completion

```mermaid
stateDiagram-v2
[*] --> Ingesting : "ingest_code"
Ingesting --> RunningCodeQL : "run_codeql"
RunningCodeQL --> Investigating : "investigate"
Investigating --> GeneratingPoV : "generate_pov"
GeneratingPoV --> ValidatingPoV : "validate_pov"
ValidatingPoV --> RunningInDocker : "run_in_docker" [success]
ValidatingPoV --> GeneratingPoV : "retry" [failure]
ValidatingPoV --> LoggingFailure : "log_failure" [final]
RunningInDocker --> LoggingConfirmed : "log_confirmed"
LoggingConfirmed --> Investigating : "next finding"
LoggingConfirmed --> [*] : "done"
LoggingFailure --> Investigating : "next finding"
LoggingFailure --> [*] : "done"
LoggingSkip --> Investigating : "next finding"
LoggingSkip --> [*] : "done"
```

**Diagram sources**
- [app/agent_graph.py:82-169](file://app/agent_graph.py#L82-L169)
- [app/agent_graph.py:691-778](file://app/agent_graph.py#L691-L778)

**Section sources**
- [app/agent_graph.py:82-800](file://app/agent_graph.py#L82-L800)

### Background Scan Management
The scan manager coordinates asynchronous scans, persists results, tracks logs, and exposes metrics. It uses a thread pool executor to run scans off the main event loop and maintains a singleton instance for thread safety.

```mermaid
classDiagram
class ScanManager {
+create_scan(codebase_path, model_name, cwes, triggered_by, lite) string
+run_scan_async(scan_id, progress_callback) ScanResult
+run_scan_with_findings_async(scan_id, findings, detected_language) ScanResult
+get_scan(scan_id) dict
+get_scan_result(scan_id) ScanResult
+get_scan_history(limit, offset) list
+get_scan_logs(scan_id) list
+append_log(scan_id, message) bool
+cancel_scan(scan_id) bool
+cleanup_old_results(max_age_days, max_results) (int, int)
+get_metrics() dict
}
class ScanResult {
+scan_id : string
+status : string
+codebase_path : string
+model_name : string
+cwes : list
+total_findings : int
+confirmed_vulns : int
+false_positives : int
+failed : int
+total_cost_usd : float
+duration_s : float
+start_time : string
+end_time : string
+findings : list
+logs : list
}
ScanManager --> ScanResult : "produces"
```

**Diagram sources**
- [app/scan_manager.py:47-663](file://app/scan_manager.py#L47-L663)

**Section sources**
- [app/scan_manager.py:47-663](file://app/scan_manager.py#L47-L663)

### Adaptive Model Policy Routing
The policy router selects models for each stage (investigate, PoV) based on routing mode:
- Fixed: use a configured model
- Auto router: use a configurable router model
- Learning: choose the best-performing model from the learning store

```mermaid
flowchart TD
Start(["Stage Request"]) --> Mode{"ROUTING_MODE"}
Mode --> |fixed| Fixed["Use MODEL_NAME"]
Mode --> |auto| Auto["Use AUTO_ROUTER_MODEL"]
Mode --> |learning| Learn["Query LearningStore.get_model_recommendation()"]
Learn --> Found{"Recommendation?"}
Found --> |Yes| UseRec["Use Recommended Model"]
Found --> |No| Fallback["Fallback to AUTO_ROUTER_MODEL"]
Fixed --> End(["Model Selected"])
Auto --> End
UseRec --> End
Fallback --> End
```

**Diagram sources**
- [app/policy.py:12-40](file://app/policy.py#L12-L40)
- [app/learning_store.py:188-248](file://app/learning_store.py#L188-L248)

**Section sources**
- [app/policy.py:12-40](file://app/policy.py#L12-L40)
- [app/learning_store.py:188-248](file://app/learning_store.py#L188-L248)

### Learning Store for Performance Tracking
The learning store persists investigation outcomes and PoV runs to a SQLite database. It aggregates model performance and recommends models for future scans.

```mermaid
erDiagram
INVESTIGATIONS {
integer id PK
string scan_id
string cwe
string filepath
string language
string source
string verdict
float confidence
string model
float cost_usd
string timestamp
}
POVS {
integer id PK
string scan_id
string cwe
string model
float cost_usd
integer success
string validation_method
string timestamp
}
```

**Diagram sources**
- [app/learning_store.py:25-59](file://app/learning_store.py#L25-L59)

**Section sources**
- [app/learning_store.py:14-256](file://app/learning_store.py#L14-L256)

### Configuration Management System
Settings encapsulate environment-driven configuration for models, tools, directories, and feature flags. It validates model mode, checks tool availability, and ensures required directories exist.

```mermaid
flowchart TD
Load["Load .env"] --> Validate["Validate MODEL_MODE"]
Validate --> Tools["Check Tool Availability<br/>Docker, CodeQL, Joern, Kaitai"]
Tools --> Persist["Ensure Directories Exist"]
Persist --> Ready["Settings Ready"]
```

**Diagram sources**
- [app/config.py:13-255](file://app/config.py#L13-L255)

**Section sources**
- [app/config.py:13-255](file://app/config.py#L13-L255)

### Authentication and Authorization
- Bearer token authentication for API endpoints
- Admin-only endpoints protected by admin key verification
- Per-key rate limiting for scan-triggering endpoints
- API key storage with secure hashing and revocation

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "FastAPI app/main.py"
participant Auth as "app/auth.py"
Client->>API : Request with Authorization : Bearer <key>
API->>Auth : verify_api_key()
Auth-->>API : (token, key_name)
API-->>Client : Authorized Response
Client->>API : Admin Endpoint with Bearer <admin_key>
API->>Auth : verify_admin_key()
Auth-->>API : admin_key
API-->>Client : Admin Response
```

**Diagram sources**
- [app/main.py:188-201](file://app/main.py#L188-L201)
- [app/auth.py:192-251](file://app/auth.py#L192-L251)

**Section sources**
- [app/auth.py:40-256](file://app/auth.py#L40-L256)

### Git Repository Handling
The Git handler manages repository accessibility checks, cloning with credentials injection, branch verification, and cleanup. It supports GitHub, GitLab, and Bitbucket providers.

```mermaid
flowchart TD
Start(["Clone Request"]) --> Detect["Detect Provider"]
Detect --> Inject["Inject Credentials"]
Inject --> Clone["git clone (--single-branch, --depth 1)"]
Clone --> Commit{"Commit Provided?"}
Commit --> |Yes| Checkout["Checkout Specific Commit"]
Commit --> |No| Skip["Skip Checkout"]
Checkout --> Cleanup[".git Removal"]
Skip --> Cleanup
Cleanup --> Done(["Local Path Returned"])
```

**Diagram sources**
- [app/git_handler.py:20-392](file://app/git_handler.py#L20-L392)

**Section sources**
- [app/git_handler.py:20-392](file://app/git_handler.py#L20-L392)

### Source Code Processing
The source handler supports ZIP/TAR extraction, file/folder uploads, and raw code paste. It enforces path traversal protection and preserves structure when requested.

```mermaid
flowchart TD
Start(["Upload/Source Input"]) --> Type{"Type?"}
Type --> |ZIP| Zip["Extract ZIP (path traversal check)"]
Type --> |TAR| Tar["Extract TAR (path traversal check)"]
Type --> |Files| Files["Copy Files (preserve structure)"]
Type --> |Folder| Folder["Copy Folder"]
Type --> |Raw| Raw["Write Source File"]
Zip --> SourceDir["source/ Directory"]
Tar --> SourceDir
Files --> SourceDir
Folder --> SourceDir
Raw --> SourceDir
SourceDir --> Done(["Ready for Scan"])
```

**Diagram sources**
- [app/source_handler.py:18-382](file://app/source_handler.py#L18-L382)

**Section sources**
- [app/source_handler.py:18-382](file://app/source_handler.py#L18-L382)

### Webhook Integration
Webhook handler verifies signatures/tokens and parses provider events to trigger scans. It supports GitHub and GitLab webhooks and returns structured responses.

```mermaid
sequenceDiagram
participant Provider as "Git Provider"
participant WH as "app/webhook_handler.py"
participant API as "app/main.py"
participant SM as "app/scan_manager.py"
Provider->>WH : POST /api/webhook/{provider}
WH->>WH : verify_signature/token()
WH->>WH : parse_event()
WH->>API : register_scan_callback()
API->>SM : trigger_scan_from_webhook()
SM-->>Provider : {"status","message","scan_id"}
```

**Diagram sources**
- [app/webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [app/main.py:134-173](file://app/main.py#L134-L173)

**Section sources**
- [app/webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [app/main.py:134-173](file://app/main.py#L134-L173)

### Report Generation
The report generator creates JSON and PDF reports summarizing findings, PoV outcomes, model usage, and metrics. It optionally integrates with OpenRouter activity for detailed usage attribution.

```mermaid
flowchart TD
Start(["Scan Complete"]) --> JSON["generate_json_report()"]
Start --> PDF["generate_pdf_report()"]
JSON --> Summ["Summarize Findings & PoVs"]
PDF --> Cover["Cover Page & Executive Summary"]
Summ --> Metrics["Compute Detection/FP/PoV Rates"]
Cover --> Sections["Methodology & Details"]
Metrics --> Save["Persist Report Files"]
Sections --> Save
Save --> Done(["Downloadable Report"])
```

**Diagram sources**
- [app/report_generator.py:200-830](file://app/report_generator.py#L200-L830)

**Section sources**
- [app/report_generator.py:200-830](file://app/report_generator.py#L200-L830)

### Real-Time Streaming Capabilities
The SSE endpoint streams scan logs and final results to clients. It polls scan state and yields new log entries until completion.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "app/main.py"
participant SM as "app/scan_manager.py"
Client->>API : GET /api/scan/{id}/stream
loop Until Completed
API->>SM : get_scan(scan_id)
SM-->>API : scan_info
API-->>Client : data : {type : "log", message}
end
API-->>Client : data : {type : "complete", result}
```

**Diagram sources**
- [app/main.py:548-584](file://app/main.py#L548-L584)
- [app/scan_manager.py:419-422](file://app/scan_manager.py#L419-L422)

**Section sources**
- [app/main.py:548-584](file://app/main.py#L548-L584)

## Dependency Analysis
The backend exhibits clear separation of concerns:
- FastAPI app depends on configuration, authentication, scan manager, agent graph, handlers, and report generator
- Agent graph depends on policy router, learning store, and agent components
- Scan manager depends on agent graph and persistence
- Handlers depend on configuration and external tools
- Report generator depends on scan results and optional OpenRouter activity

```mermaid
graph LR
MAIN["app/main.py"] --> AUTH["app/auth.py"]
MAIN --> SCAN["app/scan_manager.py"]
MAIN --> WH["app/webhook_handler.py"]
MAIN --> REP["app/report_generator.py"]
SCAN --> GRAPH["app/agent_graph.py"]
GRAPH --> POL["app/policy.py"]
POL --> LS["app/learning_store.py"]
GRAPH --> ING["agents/ingest_codebase.py"]
GRAPH --> INV["agents/investigator.py"]
MAIN --> CFG["app/config.py"]
MAIN --> GIT["app/git_handler.py"]
MAIN --> SRC["app/source_handler.py"]
```

**Diagram sources**
- [app/main.py:19-28](file://app/main.py#L19-L28)
- [app/agent_graph.py:19-29](file://app/agent_graph.py#L19-L29)
- [app/scan_manager.py:18-21](file://app/scan_manager.py#L18-L21)

**Section sources**
- [app/main.py:19-28](file://app/main.py#L19-L28)
- [app/agent_graph.py:19-29](file://app/agent_graph.py#L19-L29)
- [app/scan_manager.py:18-21](file://app/scan_manager.py#L18-L21)

## Performance Considerations
- Asynchronous execution: Scans run in thread pool executors to avoid blocking the event loop
- Vector store batching: ChromaDB ingestion batches embeddings to reduce overhead
- Tool availability checks: CodeQL, Docker, and other tools are checked before use to avoid retries
- Cost tracking: Token usage and costs are recorded per finding to control spending
- Cleanup: Old results and temporary directories are cleaned up to prevent disk growth

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Authentication failures: Ensure Authorization header includes a valid Bearer token or api_key query param; admin endpoints require ADMIN_API_KEY
- Rate limit exceeded: Exceeded per-key scan rate; wait for the rate limit window to reset
- Repository access denied: Configure provider tokens (GITHUB_TOKEN, GITLAB_TOKEN, BITBUCKET_TOKEN) and verify branch/commit
- CodeQL not available: Install CodeQL CLI and ensure it is on PATH; otherwise, the system falls back to LLM-only analysis
- Docker disabled/unavailable: Some PoV validations may be skipped; enable DOCKER_ENABLED and ensure Docker is installed
- Large repository timeouts: Prefer ZIP upload for very large repositories; shallow clones are used to reduce time
- Report generation errors: Ensure fpdf2 is installed for PDF reports; JSON reports are always available

**Section sources**
- [app/auth.py:192-251](file://app/auth.py#L192-L251)
- [app/git_handler.py:251-294](file://app/git_handler.py#L251-L294)
- [app/config.py:162-211](file://app/config.py#L162-L211)
- [app/report_generator.py:264-268](file://app/report_generator.py#L264-L268)

## Conclusion
AutoPoV’s backend provides a robust, modular, and scalable vulnerability detection platform. It combines FastAPI, LangGraph, and adaptive model routing to deliver accurate and efficient assessments. With comprehensive authentication, real-time streaming, webhook automation, and detailed reporting, it supports both interactive and CI/CD-driven workflows.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### API Endpoints Reference
- GET /api/health: Health status and tool availability
- GET /api/config: System configuration (supported CWEs, routing mode, model settings)
- POST /api/scan/git: Initiate scan from Git repository
- POST /api/scan/zip: Initiate scan from ZIP upload
- POST /api/scan/paste: Initiate scan from raw code paste
- POST /api/scan/{scan_id}/replay: Replay findings with selected models
- POST /api/scan/{scan_id}/cancel: Cancel a running scan
- GET /api/scan/{scan_id}: Get scan status and results
- GET /api/scan/{scan_id}/stream: Stream logs via SSE
- GET /api/history: Scan history
- GET /api/metrics: System metrics
- GET /api/report/{scan_id}?format=json|pdf: Download report
- POST /api/webhook/github: GitHub webhook
- POST /api/webhook/gitlab: GitLab webhook
- POST /api/keys/generate: Generate API key (admin)
- GET /api/keys: List API keys (admin)
- DELETE /api/keys/{id}: Revoke API key (admin)
- POST /api/admin/cleanup: Cleanup old results (admin)

**Section sources**
- [app/main.py:175-768](file://app/main.py#L175-L768)

### Configuration Options
Key environment variables and settings:
- Model selection: MODEL_MODE, MODEL_NAME, OPENROUTER_API_KEY, OLLAMA_BASE_URL
- Routing: ROUTING_MODE, AUTO_ROUTER_MODEL, LEARNING_DB_PATH
- Tools: CODEQL_CLI_PATH, CODEQL_PACKS_BASE, DOCKER_ENABLED, JOERN_CLI_PATH
- Security: ADMIN_API_KEY, WEBHOOK_SECRET, GITHUB_WEBHOOK_SECRET, GITLAB_WEBHOOK_SECRET
- Paths: DATA_DIR, RESULTS_DIR, RUNS_DIR, SNAPSHOT_DIR, CHROMA_PERSIST_DIR
- Limits: MAX_COST_USD, COST_TRACKING_ENABLED, SCOUT_MAX_COST_USD

**Section sources**
- [app/config.py:13-255](file://app/config.py#L13-L255)