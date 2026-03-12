# Scan Management

<cite>
**Referenced Files in This Document**
- [app/scan_manager.py](file://app/scan_manager.py)
- [app/main.py](file://app/main.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/config.py](file://app/config.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [app/webhook_handler.py](file://app/webhook_handler.py)
- [frontend/src/pages/ScanProgress.jsx](file://frontend/src/pages/ScanProgress.jsx)
- [monitor_scan.py](file://monitor_scan.py)
- [check_scan.py](file://check_scan.py)
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
This document explains AutoPoV’s scan management system: how scans are created, scheduled, executed, monitored, and cleaned up; how state is persisted and concurrently managed; and how the system integrates with the agent graph, result aggregation, and error recovery mechanisms. It also covers scheduling examples, progress tracking, resource management, performance optimization, memory management, and scalability for multiple concurrent scans.

## Project Structure
The scan management system spans several modules:
- API entrypoint and orchestration: FastAPI endpoints in the main application
- Scan lifecycle and persistence: ScanManager singleton managing state, logs, and results
- Agent graph workflow: LangGraph-based orchestration of vulnerability detection and PoV generation
- Code ingestion: Vector store ingestion and cleanup
- Configuration: Environment-driven settings and tool availability checks
- Webhooks: Automated triggering of scans from Git providers
- Frontend: Real-time progress and logs via polling and Server-Sent Events (SSE)

```mermaid
graph TB
subgraph "API Layer"
MAIN["FastAPI App<br/>app/main.py"]
WEBHOOK["Webhook Handler<br/>app/webhook_handler.py"]
end
subgraph "Scan Management"
SM["ScanManager<br/>app/scan_manager.py"]
CFG["Settings<br/>app/config.py"]
end
subgraph "Agent Workflow"
AG["AgentGraph<br/>app/agent_graph.py"]
CI["Code Ingester<br/>agents/ingest_codebase.py"]
end
subgraph "Frontend"
UI["ScanProgress Page<br/>frontend/src/pages/ScanProgress.jsx"]
end
MAIN --> SM
MAIN --> AG
MAIN --> WEBHOOK
SM --> AG
AG --> CI
CFG --> SM
CFG --> AG
UI --> MAIN
```

**Diagram sources**
- [app/main.py:114-122](file://app/main.py#L114-L122)
- [app/scan_manager.py:47-72](file://app/scan_manager.py#L47-L72)
- [app/agent_graph.py:82-168](file://app/agent_graph.py#L82-L168)
- [agents/ingest_codebase.py:41-121](file://agents/ingest_codebase.py#L41-L121)
- [app/webhook_handler.py:15-24](file://app/webhook_handler.py#L15-L24)
- [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)

**Section sources**
- [app/main.py:114-122](file://app/main.py#L114-L122)
- [app/scan_manager.py:47-72](file://app/scan_manager.py#L47-L72)
- [app/agent_graph.py:82-168](file://app/agent_graph.py#L82-L168)
- [agents/ingest_codebase.py:41-121](file://agents/ingest_codebase.py#L41-L121)
- [app/webhook_handler.py:15-24](file://app/webhook_handler.py#L15-L24)
- [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)

## Core Components
- ScanManager: Singleton orchestrator for scan lifecycle, concurrency control, persistence, and cleanup. Provides thread-safe log appending and async execution via a thread pool.
- AgentGraph: LangGraph workflow implementing the vulnerability detection pipeline, including code ingestion, CodeQL analysis, investigation, PoV generation/validation, and Docker-based execution.
- CodeIngester: Manages code chunking, embeddings, ChromaDB collections per scan, and cleanup.
- Settings: Centralized configuration for models, tools, directories, and availability checks.
- WebhookHandler: Validates and parses provider webhooks, triggers scans via callback registration.
- Frontend ScanProgress: Real-time monitoring via polling and SSE.

**Section sources**
- [app/scan_manager.py:47-663](file://app/scan_manager.py#L47-L663)
- [app/agent_graph.py:82-1225](file://app/agent_graph.py#L82-L1225)
- [agents/ingest_codebase.py:41-413](file://agents/ingest_codebase.py#L41-L413)
- [app/config.py:13-255](file://app/config.py#L13-L255)
- [app/webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)

## Architecture Overview
The system separates concerns across layers:
- API layer handles requests, schedules background tasks, and streams logs via SSE.
- ScanManager coordinates scan creation, execution, and persistence.
- AgentGraph executes the vulnerability detection workflow and streams logs back to ScanManager.
- CodeIngester manages vector store state per scan and cleans up after completion.
- Frontend consumes status and logs via REST and SSE.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "FastAPI App<br/>app/main.py"
participant SM as "ScanManager<br/>app/scan_manager.py"
participant AG as "AgentGraph<br/>app/agent_graph.py"
participant CI as "CodeIngester<br/>agents/ingest_codebase.py"
Client->>API : "POST /api/scan/git"
API->>SM : "create_scan()"
API->>API : "BackgroundTask : clone + run_scan_async()"
API-->>Client : "ScanResponse"
API->>SM : "run_scan_async(scan_id)"
SM->>AG : "run_scan(codebase_path, model, cwes, scan_id)"
AG->>CI : "ingest_directory(...)"
AG->>AG : "run_codeql / heuristic/LLM scouts"
AG->>AG : "investigate → generate_pov → validate_pov → run_in_docker"
AG-->>SM : "Final ScanState"
SM->>SM : "_save_result()"
SM-->>API : "ScanResult"
API-->>Client : "SSE logs until completion"
```

**Diagram sources**
- [app/main.py:204-285](file://app/main.py#L204-L285)
- [app/scan_manager.py:234-366](file://app/scan_manager.py#L234-L366)
- [app/agent_graph.py:178-1192](file://app/agent_graph.py#L178-L1192)
- [agents/ingest_codebase.py:207-313](file://agents/ingest_codebase.py#L207-L313)

## Detailed Component Analysis

### ScanManager: Lifecycle, Concurrency, Persistence
- Singleton with thread-safe initialization and shared state across threads.
- Active scans tracked in-memory with per-scan locks for safe log updates.
- Async execution via ThreadPoolExecutor to offload blocking operations (CodeQL, LLM calls).
- Two execution modes:
  - run_scan_async: normal scan using AgentGraph.
  - run_scan_with_findings_async: replay mode using preloaded findings.
- Persistence:
  - Saves results as JSON in results/runs.
  - Appends CSV history for metrics and summaries.
  - Optional codebase snapshot for replay support.
- Cleanup:
  - Removes old result files and rebuilds CSV.
  - Cleans up vector store collection for the scan.
- Monitoring:
  - Thread-safe log appending and retrieval.
  - Metrics aggregation across historical runs.

```mermaid
classDiagram
class ScanManager {
-_active_scans : Dict
-_scan_callbacks : Dict
-_executor : ThreadPoolExecutor
-_runs_dir : str
-_scan_locks : Dict
+create_scan(...)
+run_scan_async(scan_id, progress_callback)
+run_scan_with_findings_async(scan_id, findings, detected_language)
+get_scan(scan_id)
+get_scan_result(scan_id)
+get_scan_history(limit, offset)
+get_scan_logs(scan_id)
+append_log(scan_id, message)
+cancel_scan(scan_id)
+cleanup_scan(scan_id)
+cleanup_old_results(max_age_days, max_results)
+get_metrics()
-_run_scan_sync(...)
-_run_replay_sync(...)
-_save_result(result)
-_rebuild_scan_history_csv()
}
class ScanResult {
+scan_id : str
+status : str
+codebase_path : str
+model_name : str
+cwes : List
+total_findings : int
+confirmed_vulns : int
+false_positives : int
+failed : int
+total_cost_usd : float
+duration_s : float
+start_time : str
+end_time : str
+findings : List
+logs : List
}
ScanManager --> ScanResult : "produces"
```

**Diagram sources**
- [app/scan_manager.py:47-663](file://app/scan_manager.py#L47-L663)

**Section sources**
- [app/scan_manager.py:47-114](file://app/scan_manager.py#L47-L114)
- [app/scan_manager.py:234-366](file://app/scan_manager.py#L234-L366)
- [app/scan_manager.py:367-418](file://app/scan_manager.py#L367-L418)
- [app/scan_manager.py:419-494](file://app/scan_manager.py#L419-L494)
- [app/scan_manager.py:495-562](file://app/scan_manager.py#L495-L562)
- [app/scan_manager.py:604-653](file://app/scan_manager.py#L604-L653)

### AgentGraph: Workflow, Integration, and Logging
- Defines ScanState and VulnerabilityState typed dictionaries.
- LangGraph workflow:
  - Ingest codebase into vector store.
  - Run CodeQL queries (or fallback to LLM-only and heuristic scouts).
  - Investigate findings with LLM, generate and validate PoV scripts, optionally run in Docker.
  - Loop through findings and finalize status.
- Real-time logging:
  - Streams logs to ScanManager via thread-safe append_log.
  - Maintains logs in state for retrieval.
- Tool availability:
  - Checks CodeQL, Docker, and other tools via Settings.

```mermaid
flowchart TD
Start(["Start run_scan"]) --> Ingest["Ingest codebase"]
Ingest --> CodeQL{"CodeQL available?"}
CodeQL --> |Yes| RunQL["Run CodeQL queries"]
CodeQL --> |No| HeurLLM["Heuristic + LLM scouts"]
RunQL --> Merge["Merge findings"]
HeurLLM --> Merge
Merge --> Loop{"More findings?"}
Loop --> |Yes| Investigate["Investigate with LLM"]
Investigate --> Verdict{"Verdict == REAL & confidence >= threshold?"}
Verdict --> |Yes| GenPOV["Generate PoV"]
Verdict --> |No| Skip["Skip"]
GenPOV --> Validate["Validate PoV"]
Validate --> Valid{"Valid?"}
Valid --> |Yes| RunDocker["Run PoV in Docker (fallback)"]
Valid --> |No| Retry["Retry generation"]
RunDocker --> Confirm["Confirm"]
Retry --> GenPOV
Skip --> Loop
Confirm --> Loop
Loop --> |No| End(["Set status=completed"])
```

**Diagram sources**
- [app/agent_graph.py:82-168](file://app/agent_graph.py#L82-L168)
- [app/agent_graph.py:178-1192](file://app/agent_graph.py#L178-L1192)

**Section sources**
- [app/agent_graph.py:64-80](file://app/agent_graph.py#L64-L80)
- [app/agent_graph.py:178-307](file://app/agent_graph.py#L178-L307)
- [app/agent_graph.py:691-777](file://app/agent_graph.py#L691-L777)
- [app/agent_graph.py:779-1004](file://app/agent_graph.py#L779-L1004)
- [app/agent_graph.py:1111-1131](file://app/agent_graph.py#L1111-L1131)

### Code Ingester: Vector Store and Cleanup
- Creates per-scan ChromaDB collections and stores embeddings.
- Supports online and offline embeddings based on settings.
- Provides retrieval and file content lookup for context.
- Cleans up per-scan collections upon scan completion.

**Section sources**
- [agents/ingest_codebase.py:41-121](file://agents/ingest_codebase.py#L41-L121)
- [agents/ingest_codebase.py:207-313](file://agents/ingest_codebase.py#L207-L313)
- [agents/ingest_codebase.py:393-404](file://agents/ingest_codebase.py#L393-L404)

### Configuration and Tool Availability
- Centralized settings for models, tools, directories, and availability checks.
- Ensures required directories exist at startup.

**Section sources**
- [app/config.py:13-255](file://app/config.py#L13-L255)

### Webhook Integration
- Validates signatures/tokens and parses provider events.
- Registers a callback to trigger scans automatically from push/PR events.

**Section sources**
- [app/webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [app/main.py:134-172](file://app/main.py#L134-L172)

### Frontend Monitoring
- Polls status and listens to SSE for live logs.
- Supports cancellation and redirects to results on completion.

**Section sources**
- [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)

## Dependency Analysis
- API depends on ScanManager for orchestration and AgentGraph for execution.
- ScanManager depends on AgentGraph and CodeIngester for execution and persistence.
- AgentGraph depends on CodeIngester and policy/router for model selection.
- Settings centralizes tool availability and paths used across modules.
- WebhookHandler registers a callback to trigger scans from provider events.

```mermaid
graph LR
MAIN["app/main.py"] --> SM["app/scan_manager.py"]
MAIN --> AG["app/agent_graph.py"]
MAIN --> WH["app/webhook_handler.py"]
SM --> AG
AG --> CI["agents/ingest_codebase.py"]
SM --> CFG["app/config.py"]
AG --> CFG
WH --> MAIN
```

**Diagram sources**
- [app/main.py:24-25](file://app/main.py#L24-L25)
- [app/scan_manager.py:18-20](file://app/scan_manager.py#L18-L20)
- [app/agent_graph.py:19-28](file://app/agent_graph.py#L19-L28)
- [agents/ingest_codebase.py:33](file://agents/ingest_codebase.py#L33)
- [app/config.py:19-20](file://app/config.py#L19-L20)
- [app/webhook_handler.py:101-105](file://app/webhook_handler.py#L101-L105)

**Section sources**
- [app/main.py:24-25](file://app/main.py#L24-L25)
- [app/scan_manager.py:18-20](file://app/scan_manager.py#L18-L20)
- [app/agent_graph.py:19-28](file://app/agent_graph.py#L19-L28)
- [agents/ingest_codebase.py:33](file://agents/ingest_codebase.py#L33)
- [app/config.py:19-20](file://app/config.py#L19-L20)
- [app/webhook_handler.py:101-105](file://app/webhook_handler.py#L101-L105)

## Performance Considerations
- Concurrency:
  - ThreadPoolExecutor limits concurrent scans to balance throughput and resource usage.
  - Per-scan locks ensure thread-safe log updates without global contention.
- I/O and CPU-bound tasks:
  - CodeQL database creation and query execution are offloaded to threads.
  - Vector store ingestion batches embeddings to reduce overhead.
- Memory management:
  - Code chunks are processed in batches; temporary files are cleaned up after CodeQL runs.
  - Collections are deleted per scan to prevent unbounded memory growth.
- Scalability:
  - Horizontal scaling via multiple workers behind a reverse proxy.
  - Rate limiting and background tasks prevent blocking the API event loop.
- Cost control:
  - Configurable max cost and per-operation cost tracking integrated in findings.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and remedies:
- CodeQL not available:
  - The system falls back to LLM-only and heuristic scouts; ingestion warnings are logged.
- Vector store failures:
  - Code ingestion errors are surfaced; scan continues without vector store context.
- Docker not available:
  - PoV validation may rely on static/unit test results; Docker fallback is attempted when appropriate.
- Long-running scans:
  - Use SSE endpoints to stream logs; poll status for progress.
- Cleanup:
  - Admin endpoint removes old result files and rebuilds CSV.

**Section sources**
- [app/agent_graph.py:199-203](file://app/agent_graph.py#L199-L203)
- [agents/ingest_codebase.py:224-226](file://agents/ingest_codebase.py#L224-L226)
- [app/main.py:726-741](file://app/main.py#L726-L741)

## Conclusion
AutoPoV’s scan management system combines a robust API layer, a thread-safe scan coordinator, and a configurable agent graph workflow. It persists results, streams logs in real time, cleans up resources, and recovers gracefully from tool unavailability. With configurable concurrency, batching, and cleanup policies, it scales to handle multiple concurrent scans efficiently while maintaining observability and reliability.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### Examples

- Scheduling a Git scan:
  - Use the Git scan endpoint to create and schedule a scan; the API clones the repository and runs the scan in the background.
  - Example invocation path: [app/main.py:204-285](file://app/main.py#L204-L285)

- Progress tracking:
  - Poll status endpoint for periodic updates; use SSE endpoint for live logs.
  - Example invocation paths:
    - [app/main.py:511-545](file://app/main.py#L511-L545)
    - [app/main.py:548-583](file://app/main.py#L548-L583)
  - Frontend monitoring:
    - [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)

- Replay a previous scan:
  - Use the replay endpoint to rerun findings with different models; the API constructs replay findings and starts new scans.
  - Example invocation path: [app/main.py:404-490](file://app/main.py#L404-L490)

- Resource management and cleanup:
  - Admin endpoint to remove old result files and rebuild CSV.
  - Example invocation path: [app/main.py:726-741](file://app/main.py#L726-L741)

- Manual monitoring scripts:
  - Status checker: [check_scan.py:1-16](file://check_scan.py#L1-L16)
  - Live monitor: [monitor_scan.py:1-90](file://monitor_scan.py#L1-L90)

**Section sources**
- [app/main.py:204-285](file://app/main.py#L204-L285)
- [app/main.py:404-490](file://app/main.py#L404-L490)
- [app/main.py:511-545](file://app/main.py#L511-L545)
- [app/main.py:548-583](file://app/main.py#L548-L583)
- [app/main.py:726-741](file://app/main.py#L726-L741)
- [frontend/src/pages/ScanProgress.jsx:16-79](file://frontend/src/pages/ScanProgress.jsx#L16-L79)
- [check_scan.py:1-16](file://check_scan.py#L1-L16)
- [monitor_scan.py:1-90](file://monitor_scan.py#L1-L90)