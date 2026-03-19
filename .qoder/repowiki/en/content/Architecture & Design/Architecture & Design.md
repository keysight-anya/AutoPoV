# Architecture & Design

<cite>
**Referenced Files in This Document**
- [README.md](file://README.md)
- [app/main.py](file://app/main.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/scan_manager.py](file://app/scan_manager.py)
- [app/config.py](file://app/config.py)
- [app/learning_store.py](file://app/learning_store.py)
- [agents/__init__.py](file://agents/__init__.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/agentic_discovery.py](file://agents/agentic_discovery.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [Dockerfile.backend](file://Dockerfile.backend)
- [docker-compose.yml](file://docker-compose.yml)
- [requirements.txt](file://requirements.txt)
- [frontend/package.json](file://frontend/package.json)
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
This document describes the high-level architecture and design of AutoPoV, an autonomous, agentic system for discovering, investigating, generating, and validating exploitable vulnerabilities. The system is built around a LangGraph-based agent orchestration engine, stateful workflow management, and conditional routing. It integrates external tools (CodeQL, Docker, ChromaDB, Joern), a learning store for self-improvement, and a FastAPI backend with real-time streaming and robust security controls. The document also covers infrastructure requirements, system context diagrams, cross-cutting concerns (security, monitoring, scalability), and the technology stack.

## Project Structure
AutoPoV is organized into three primary layers:
- Backend API and Orchestration: FastAPI application, agent graph, scan lifecycle, configuration, and learning store.
- Agents: Specialized modules implementing discovery, investigation, exploit generation, validation, and runtime execution.
- Frontend: React-based web UI communicating with the backend via REST and Server-Sent Events (SSE).

```mermaid
graph TB
subgraph "Backend"
API["FastAPI App<br/>app/main.py"]
AG["Agent Graph<br/>app/agent_graph.py"]
SM["Scan Manager<br/>app/scan_manager.py"]
CFG["Settings & Config<br/>app/config.py"]
LS["Learning Store<br/>app/learning_store.py"]
end
subgraph "Agents"
AC["Code Ingestion<br/>agents/ingest_codebase.py"]
AD["Agentic Discovery<br/>agents/agentic_discovery.py"]
INV["Investigator<br/>agents/investigator.py"]
PT["PoV Tester<br/>agents/pov_tester.py"]
end
subgraph "External Systems"
CH["ChromaDB"]
CO["CodeQL CLI"]
DJ["Docker Engine"]
JR["Joern"]
end
FE["React Frontend<br/>frontend/package.json"]
FE --> API
API --> SM
SM --> AG
AG --> AC
AG --> AD
AG --> INV
AG --> PT
AC --> CH
AD --> CO
INV --> CH
PT --> DJ
INV --> JR
API --> LS
```

**Diagram sources**
- [app/main.py:165-212](file://app/main.py#L165-L212)
- [app/agent_graph.py:137-229](file://app/agent_graph.py#L137-L229)
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/config.py:14-342](file://app/config.py#L14-L342)
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)
- [frontend/package.json:1-34](file://frontend/package.json#L1-L34)

**Section sources**
- [README.md:89-124](file://README.md#L89-L124)
- [app/main.py:165-212](file://app/main.py#L165-L212)
- [app/agent_graph.py:137-229](file://app/agent_graph.py#L137-L229)
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/config.py:14-342](file://app/config.py#L14-L342)
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)
- [frontend/package.json:1-34](file://frontend/package.json#L1-L34)

## Core Components
- FastAPI Backend: Provides REST endpoints for scan initiation, status, streaming logs, replay, cancellation, and administrative operations. Implements CORS, CSRF protection, and rate-limited authentication.
- Agent Graph (LangGraph): Defines a stateful workflow with nodes for ingestion, discovery, investigation, exploit generation, validation, and runtime execution. Conditional edges route based on confidence thresholds, validation outcomes, and retry policies.
- Scan Manager: Manages scan lifecycle, persistence, concurrency, and background execution. Maintains active scans, snapshots, and results.
- Configuration: Centralized settings for models, tools, storage, parallelism, and safety controls.
- Learning Store: SQLite-backed persistence for agent outcomes enabling adaptive model routing and self-improvement.
- Agents:
  - Code Ingestion: Chunks code, computes embeddings, and persists to ChromaDB.
  - Agentic Discovery: Integrates CodeQL, Semgrep, LLM scouts, and heuristics with language profiling and triage.
  - Investigator: LLM + RAG analysis to classify findings as REAL or FALSE_POSITIVE with confidence.
  - PoV Tester: Executes generated exploits in targeted harnesses or containers to confirm exploitability.
- Infrastructure: Docker Compose for backend, Ollama, and frontend; Dockerfile.backend installs CodeQL and Docker CLI.

**Section sources**
- [app/main.py:257-286](file://app/main.py#L257-L286)
- [app/agent_graph.py:111-229](file://app/agent_graph.py#L111-L229)
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/config.py:14-342](file://app/config.py#L14-L342)
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)
- [Dockerfile.backend:1-80](file://Dockerfile.backend#L1-L80)
- [docker-compose.yml:1-66](file://docker-compose.yml#L1-L66)

## Architecture Overview
The system follows a stateful, agent-centric architecture:
- Stateful Orchestration: LangGraph maintains ScanState and VulnerabilityState across nodes, enabling persistent context and deterministic routing.
- Conditional Routing: Edges evaluate confidence, validation results, and retry counts to decide next steps.
- Tool Integration: Agents invoke CodeQL, ChromaDB, Docker, and Joern depending on language and exploitability.
- Persistence and Adaptation: Learning Store records outcomes to improve model selection and routing over time.

```mermaid
graph TB
A["FastAPI Endpoint"] --> B["ScanManager.create_scan"]
B --> C["AgentGraph.compile()"]
C --> D["Ingest Codebase"]
D --> E["Run CodeQL/Semgrep/LangSmith"]
E --> F["Investigate (LLM+RAG)"]
F --> G{"Confidence ≥ threshold?"}
G -- "Yes" --> H["Generate PoV Script"]
G -- "No" --> I["Skip Finding"]
H --> J["Validate (Static → Unit → Docker)"]
J --> K{"Confirmed?"}
K -- "Yes" --> L["Record in Learning Store"]
K -- "No" --> M["Refine or Retry"]
L --> N["Next Finding or End"]
M --> J
I --> N
```

**Diagram sources**
- [app/agent_graph.py:137-229](file://app/agent_graph.py#L137-L229)
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)

## Detailed Component Analysis

### LangGraph-Based Agent Orchestration
- State Types: ScanState and VulnerabilityState encapsulate scan-wide and per-finding context, including tokens, costs, logs, and validation history.
- Nodes: Ingestion, discovery, investigation, PoV generation, validation, refinement, runtime execution, and logging nodes.
- Conditional Edges: Route based on confidence thresholds, validation outcomes, and retry limits.
- Parallel Investigation: Optional batch processing of findings to accelerate throughput.

```mermaid
classDiagram
class ScanState {
+string scan_id
+string status
+string codebase_path
+string model_name
+string model_mode
+string[] cwes
+VulnerabilityState[] findings
+Optional~VulnerabilityState[]~ preloaded_findings
+Optional~string~ detected_language
+int current_finding_idx
+string start_time
+Optional~string~ end_time
+float total_cost_usd
+int total_tokens
+Dict~string, Dict~string,int~~ tokens_by_model
+string[] logs
+Optional~string~ error
+int proofs_attempted
+int confirmed_count
+Optional~string~ openrouter_api_key
+bool rag_ready
+Optional~Dict~string,Any~~ rag_stats
+Dict[]string,Any~~ scan_openrouter_usage
}
class VulnerabilityState {
+Optional~string~ cve_id
+string filepath
+int line_number
+string cwe_type
+string code_chunk
+string llm_verdict
+string llm_explanation
+float confidence
+Optional~string~ pov_script
+Optional~string~ pov_path
+Optional~Dict~string,Any~~ pov_result
+int retry_count
+float inference_time_s
+float cost_usd
+Optional~string~ final_status
+Optional~string~ detected_language
+Optional~string~ source
+Optional~string~ model_used
+int prompt_tokens
+int completion_tokens
+int total_tokens
+Optional~string~ sifter_model
+Optional~Dict~string,int~~ sifter_tokens
+Optional~string~ architect_model
+Optional~Dict~string,int~~ architect_tokens
+Optional~Dict~string,Any~~ validation_result
+Optional~Dict[]string,Any~~ refinement_history
+Optional~Dict~string,Any~~ exploit_contract
+Optional~string~ execution_profile
}
class AgentGraph {
+set_scan_manager(scan_manager)
+_build_graph() StateGraph
+_node_ingest_code(state) ScanState
+_node_run_codeql(state) ScanState
+_node_investigate(state) ScanState
+_node_investigate_parallel(state) ScanState
+_should_generate_pov(state) str
+_should_run_pov(state) str
+_after_runtime_proof(state) str
+_has_more_findings(state) str
}
AgentGraph --> ScanState : "manages"
AgentGraph --> VulnerabilityState : "updates"
```

**Diagram sources**
- [app/agent_graph.py:45-110](file://app/agent_graph.py#L45-L110)
- [app/agent_graph.py:111-229](file://app/agent_graph.py#L111-L229)

**Section sources**
- [app/agent_graph.py:45-110](file://app/agent_graph.py#L45-L110)
- [app/agent_graph.py:111-229](file://app/agent_graph.py#L111-L229)

### Stateful Workflow Management
- Scan Lifecycle: Creation, persistence, background execution, cancellation, and result serialization.
- Concurrency: Thread-safe logs and locks per scan; background tasks for long-running operations.
- Snapshots: Active scans persisted to disk to recover from backend restarts.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "FastAPI"
participant SM as "ScanManager"
participant AG as "AgentGraph"
Client->>API : "POST /api/scan/git"
API->>SM : "create_scan()"
SM-->>API : "scan_id"
API-->>Client : "ScanResponse"
API->>SM : "run_scan_async(scan_id)"
SM->>AG : "compile() and invoke()"
AG-->>SM : "state updates (logs, findings)"
SM-->>API : "status updates"
API-->>Client : "SSE stream"
```

**Diagram sources**
- [app/main.py:289-371](file://app/main.py#L289-L371)
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/agent_graph.py:137-229](file://app/agent_graph.py#L137-L229)

**Section sources**
- [app/scan_manager.py:58-133](file://app/scan_manager.py#L58-L133)
- [app/main.py:289-371](file://app/main.py#L289-L371)

### Conditional Routing Mechanisms
- Confidence Threshold: Findings below a configurable threshold are skipped.
- Validation Outcomes: Confirmed vs. failed/expired findings drive routing to refinement or termination.
- Retry Policy: Controlled retries with refinement loops.

```mermaid
flowchart TD
Start(["Investigate Node"]) --> CheckConf["Confidence ≥ MIN_CONFIDENCE_FOR_POV?"]
CheckConf --> |No| Skip["Log Skip"]
CheckConf --> |Yes| Gen["Generate PoV"]
Gen --> Validate["Validate (Static → Unit → Docker)"]
Validate --> Confirmed{"Confirmed?"}
Confirmed --> |Yes| Record["Record in Learning Store"]
Confirmed --> |No| Refine["Refine/Retry"]
Refine --> Validate
Record --> Next{"More Findings?"}
Skip --> Next
Next --> |Yes| Investigate["Investigate Next Finding"]
Next --> |No| End(["End"])
```

**Diagram sources**
- [app/agent_graph.py:164-227](file://app/agent_graph.py#L164-L227)
- [app/config.py:134-139](file://app/config.py#L134-L139)

**Section sources**
- [app/agent_graph.py:164-227](file://app/agent_graph.py#L164-L227)
- [app/config.py:134-139](file://app/config.py#L134-L139)

### External Tool Integration
- CodeQL: Discovery and analysis orchestrated via agentic discovery with language-specific suites and fallbacks.
- ChromaDB: Persistent vector store for semantic search; ingestion supports online and offline embeddings.
- Docker: Sandboxed execution of PoV scripts; configurable timeouts and resource limits.
- Joern: Optional CPG analysis for native memory safety issues.

```mermaid
graph LR
AD["Agentic Discovery"] --> CO["CodeQL CLI"]
AC["Code Ingestion"] --> CH["ChromaDB"]
INV["Investigator"] --> CH
PT["PoV Tester"] --> DJ["Docker Engine"]
INV --> JR["Joern"]
```

**Diagram sources**
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)

**Section sources**
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)

### Learning Store and Adaptive Routing
- Persistence: Records investigation outcomes and PoV runs with timestamps and costs.
- Analytics: Aggregates model performance and suggests model recommendations per stage and context.
- Feedback Loop: Improves routing decisions over time.

```mermaid
classDiagram
class LearningStore {
+record_investigation(...)
+record_pov(...)
+get_summary() dict
+get_model_stats() dict
+get_model_recommendation(stage, cwe, language) Optional~string~
}
```

**Diagram sources**
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)

**Section sources**
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)

### Frontend and Real-Time Streaming
- Technology Stack: React, Vite, Tailwind, Axios, Recharts.
- Communication: REST APIs and SSE for live logs and progress updates.
- Pages: Dashboard, scan management, metrics, settings, and results.

```mermaid
graph TB
FE["React Frontend"] --> API["FastAPI Backend"]
API --> SSE["SSE Stream Logs"]
FE --> SSE
```

**Diagram sources**
- [frontend/package.json:1-34](file://frontend/package.json#L1-L34)
- [app/main.py:769-806](file://app/main.py#L769-L806)

**Section sources**
- [frontend/package.json:1-34](file://frontend/package.json#L1-L34)
- [app/main.py:769-806](file://app/main.py#L769-L806)

## Dependency Analysis
- Backend Dependencies: FastAPI, LangChain, LangGraph, ChromaDB, Docker SDK, GitPython, OpenRouter client, and others.
- Containerization: Docker Compose provisions backend, Ollama, and frontend; volumes persist ChromaDB and results.
- Tool Availability: Runtime checks for Docker, CodeQL, and Joern; environment-driven configuration.

```mermaid
graph TB
REQ["requirements.txt"] --> FA["FastAPI"]
REQ --> LC["LangChain"]
REQ --> LG["LangGraph"]
REQ --> CD["ChromaDB"]
REQ --> DK["Docker SDK"]
REQ --> GP["GitPython"]
DC["docker-compose.yml"] --> BE["backend"]
DC --> OL["ollama"]
DC --> FE["frontend"]
BE --> DF["Dockerfile.backend"]
```

**Diagram sources**
- [requirements.txt:1-47](file://requirements.txt#L1-L47)
- [docker-compose.yml:1-66](file://docker-compose.yml#L1-L66)
- [Dockerfile.backend:1-80](file://Dockerfile.backend#L1-L80)

**Section sources**
- [requirements.txt:1-47](file://requirements.txt#L1-L47)
- [docker-compose.yml:1-66](file://docker-compose.yml#L1-L66)
- [Dockerfile.backend:1-80](file://Dockerfile.backend#L1-L80)

## Performance Considerations
- Parallel Processing: Batch findings for investigation to reduce latency; tune worker count and rate limits.
- Early Termination: Stop after a configurable number of confirmed findings to cap cost and time.
- Chunking and Embeddings: Tune chunk size and overlap; prefer local embeddings for offline resilience.
- Resource Limits: Configure Docker CPU/memory limits and timeouts; enforce per-request LLM timeouts.
- Caching: Utilize analysis cache and prompt cache to reduce repeated work.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
- Health Checks: Use the health endpoint to verify Docker, CodeQL, and Joern availability.
- Authentication: Ensure admin and API keys are configured; verify rate-limiting behavior.
- Logs: Subscribe to SSE streams for real-time diagnostics; inspect persisted scan snapshots.
- Tool Availability: Confirm Docker, CodeQL, and Joern binaries; adjust paths and timeouts in settings.
- Storage: Verify persistent volumes for ChromaDB and results; ensure adequate disk space.

**Section sources**
- [app/main.py:257-267](file://app/main.py#L257-L267)
- [app/config.py:201-249](file://app/config.py#L201-L249)
- [app/scan_manager.py:175-197](file://app/scan_manager.py#L175-L197)

## Conclusion
AutoPoV’s architecture centers on a stateful, conditional agent graph orchestrated by LangGraph, integrated with external tools and a learning store for continuous improvement. The FastAPI backend provides secure, scalable APIs with real-time streaming and robust lifecycle management. Infrastructure is containerized for ease of deployment, while configuration enables flexible model and tool choices. Together, these design choices enable autonomous, reproducible, and benchmarkable vulnerability research.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### System Context Diagram: From Code Ingestion to Exploit Validation
```mermaid
graph TB
CI["Code Input<br/>Git/ZIP/Paste"] --> IG["Ingestion Agent"]
IG --> CH["ChromaDB"]
IG --> AD["Agentic Discovery"]
AD --> CO["CodeQL CLI"]
AD --> SG["Semgrep"]
AD --> SC["LLM Scout"]
AD --> HS["Heuristic Scout"]
AD --> MR["Merge & Dedupe"]
MR --> INV["Investigator Agent"]
INV --> CH
INV --> JR["Joern"]
INV --> VR["Validation Agent"]
VR --> ST["Static Validator"]
VR --> UT["Unit Test Runner"]
VR --> DR["Docker Runner"]
DR --> PT["PoV Tester"]
PT --> OUT["Confirmed Vulns"]
INV --> LS["Learning Store"]
PT --> LS
```

**Diagram sources**
- [README.md:34-69](file://README.md#L34-L69)
- [agents/agentic_discovery.py:50-200](file://agents/agentic_discovery.py#L50-L200)
- [agents/ingest_codebase.py:107-200](file://agents/ingest_codebase.py#L107-L200)
- [agents/investigator.py:38-200](file://agents/investigator.py#L38-L200)
- [agents/pov_tester.py:18-200](file://agents/pov_tester.py#L18-L200)
- [app/learning_store.py:14-200](file://app/learning_store.py#L14-L200)

### Infrastructure Requirements
- Backend: Python 3.11+, FastAPI, LangChain, LangGraph, ChromaDB, Docker SDK, GitPython.
- Tools: Docker Desktop, CodeQL CLI, optional Joern.
- Frontend: Node.js 20+, Vite, React, Tailwind.
- Deployment: Docker Compose with persistent volumes for ChromaDB and results.

**Section sources**
- [README.md:130-140](file://README.md#L130-L140)
- [requirements.txt:1-47](file://requirements.txt#L1-L47)
- [docker-compose.yml:1-66](file://docker-compose.yml#L1-L66)
- [Dockerfile.backend:1-80](file://Dockerfile.backend#L1-L80)

### Cross-Cutting Concerns
- Security: Two-tier authentication (Admin Key, API Key), rate limiting, CSRF protection, and optional sandboxing via Docker.
- Monitoring: Real-time SSE logs, LangSmith tracing, and metrics endpoints.
- Scalability: Parallel investigation, early termination, and configurable resource limits.

**Section sources**
- [app/main.py:196-212](file://app/main.py#L196-L212)
- [app/config.py:127-131](file://app/config.py#L127-L131)
- [app/config.py:133-139](file://app/config.py#L133-L139)