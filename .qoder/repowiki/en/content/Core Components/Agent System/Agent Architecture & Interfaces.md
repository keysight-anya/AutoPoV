# Agent Architecture & Interfaces

<cite>
**Referenced Files in This Document**
- [agents/__init__.py](file://agents/__init__.py)
- [agents/app_runner.py](file://agents/app_runner.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [agents/verifier.py](file://agents/verifier.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/config.py](file://app/config.py)
- [app/main.py](file://app/main.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [prompts.py](file://prompts.py)
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

## Introduction
This document explains AutoPoV’s agent architecture and interface design with a focus on LangGraph integration, agent lifecycle management, and state machine patterns. It covers the common agent interface, base classes, shared utilities, dependency injection patterns, and communication protocols between agents. Architectural diagrams illustrate agent relationships, data flow, and state transitions. The document also addresses agent factory patterns, dynamic instantiation, configuration-driven agent selection, agent isolation, error handling, and graceful degradation mechanisms.

## Project Structure
AutoPoV organizes its agent system under the agents/ package and orchestrates workflows via app/agent_graph.py using LangGraph. The FastAPI application in app/main.py exposes endpoints that trigger scans and manage agent lifecycles. Configuration and policy routing are centralized in app/config.py and app/policy.py, respectively. Prompts for LLM interactions live in prompts.py.

```mermaid
graph TB
subgraph "API Layer"
Main["FastAPI App<br/>app/main.py"]
end
subgraph "Orchestration"
AgentGraph["Agent Graph<br/>app/agent_graph.py"]
end
subgraph "Agents"
HeuristicScout["Heuristic Scout<br/>agents/heuristic_scout.py"]
LLMScout["LLM Scout (via policy)<br/>agents/investigator.py"]
CodeIngester["Code Ingester<br/>agents/ingest_codebase.py"]
Investigator["Vulnerability Investigator<br/>agents/investigator.py"]
Verifier["Vulnerability Verifier<br/>agents/verifier.py"]
DockerRunner["Docker Runner<br/>agents/docker_runner.py"]
AppRunner["Application Runner<br/>agents/app_runner.py"]
PoVTester["PoV Tester<br/>agents/pov_tester.py"]
StaticValidator["Static Validator<br/>agents/static_validator.py"]
UnitTestRunner["Unit Test Runner<br/>agents/unit_test_runner.py"]
end
subgraph "Support"
Config["Settings<br/>app/config.py"]
Policy["Policy Router<br/>app/policy.py"]
Learning["Learning Store<br/>app/learning_store.py"]
Prompts["Prompts<br/>prompts.py"]
end
Main --> AgentGraph
AgentGraph --> HeuristicScout
AgentGraph --> LLMScout
AgentGraph --> CodeIngester
AgentGraph --> Investigator
AgentGraph --> Verifier
AgentGraph --> DockerRunner
AgentGraph --> PoVTester
AgentGraph --> AppRunner
AgentGraph --> StaticValidator
AgentGraph --> UnitTestRunner
AgentGraph --> Policy
AgentGraph --> Learning
Investigator --> Prompts
Verifier --> Prompts
HeuristicScout --> Config
CodeIngester --> Config
DockerRunner --> Config
AppRunner --> Config
Policy --> Learning
Policy --> Config
```

**Diagram sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [agents/app_runner.py](file://agents/app_runner.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)
- [prompts.py](file://prompts.py)

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/main.py](file://app/main.py)
- [app/config.py](file://app/config.py)
- [app/policy.py](file://app/policy.py)
- [prompts.py](file://prompts.py)

## Core Components
- Agent Graph: Orchestrates vulnerability detection workflow using LangGraph nodes and conditional edges. Manages state transitions, error handling, and fallbacks.
- Agent Registry: Central exports in agents/__init__.py expose agent constructors and global instances for dependency injection.
- Agent Base Classes: Each agent encapsulates a focused responsibility (scouting, ingestion, investigation, verification, validation, execution).
- Policy Router: Selects models per stage using fixed, learning-based, or auto-router modes.
- Learning Store: Persists outcomes to inform model selection and improve routing.
- Configuration: Centralized settings for models, tools, limits, and environment.

**Section sources**
- [agents/__init__.py](file://agents/__init__.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)

## Architecture Overview
AutoPoV uses a LangGraph StateGraph to define a vulnerability detection pipeline. The graph maintains a ScanState that tracks scan metadata, findings, and logs. Nodes represent stages like code ingestion, CodeQL analysis, investigation, PoV generation, validation, and execution. Conditional edges route control flow based on outcomes (e.g., whether to generate PoV, skip, or fail). Agents are resolved via dependency injection using global getters (get_* functions) and policy routing.

```mermaid
sequenceDiagram
participant Client as "Client"
participant API as "FastAPI App<br/>app/main.py"
participant Graph as "Agent Graph<br/>app/agent_graph.py"
participant Policy as "Policy Router<br/>app/policy.py"
participant Store as "Learning Store<br/>app/learning_store.py"
participant Scout as "Heuristic Scout<br/>agents/heuristic_scout.py"
participant LLMScout as "LLM Scout (via policy)"
participant Ingester as "Code Ingester<br/>agents/ingest_codebase.py"
participant Investigator as "Investigator<br/>agents/investigator.py"
participant Verifier as "Verifier<br/>agents/verifier.py"
participant Docker as "Docker Runner<br/>agents/docker_runner.py"
Client->>API : POST /api/scan/*
API->>Graph : Start scan workflow
Graph->>Ingester : Ingest codebase (vector store)
Graph->>Graph : Detect language and create CodeQL DB
Graph->>Graph : Run CodeQL queries (SARIF)
Graph->>Scout : Autonomous discovery (heuristic)
Graph->>LLMScout : Autonomous discovery (LLM)
Graph->>Policy : Select model for investigation
Policy->>Store : Query historical performance
Graph->>Investigator : Analyze finding (RAG + LLM)
Investigator-->>Graph : Verdict + confidence
Graph->>Policy : Select model for PoV
Policy-->>Graph : Model recommendation
Graph->>Verifier : Generate PoV script
Verifier-->>Graph : PoV script + metadata
Graph->>Verifier : Validate PoV (static/unit/LLM)
Graph->>Docker : Run PoV in container (isolated)
Docker-->>Graph : Execution result
Graph-->>API : Final scan status and findings
API-->>Client : Scan status/logs/results
```

**Diagram sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/main.py](file://app/main.py)

## Detailed Component Analysis

### Agent Graph and State Machine
The Agent Graph defines a typed state (ScanState) and nodes representing workflow stages. It implements:
- State transitions: entry point to ingestion, then CodeQL analysis, investigation, PoV generation/validation, and execution.
- Conditional edges: branching based on investigation verdict and validation outcomes.
- Fallbacks: graceful degradation when CodeQL or vector store are unavailable.
- Logging and progress tracking: centralized via internal logging method.

```mermaid
stateDiagram-v2
[*] --> Ingesting
Ingesting --> RunningCodeQL : "ingest_code"
RunningCodeQL --> Investigating : "run_codeql"
Investigating --> GeneratingPoV : "verdict == REAL"
Investigating --> Skipped : "verdict != REAL"
GeneratingPoV --> ValidatingPoV : "generate_pov"
ValidatingPoV --> RunningPoV : "validated"
ValidatingPoV --> GeneratingPoV : "retry"
ValidatingPoV --> Failed : "validation failed"
RunningPoV --> Investigating : "more findings"
RunningPoV --> Completed : "done"
Skipped --> Investigating : "more findings"
Skipped --> Completed : "done"
Failed --> Investigating : "more findings"
Failed --> Completed : "done"
```

**Diagram sources**
- [app/agent_graph.py](file://app/agent_graph.py)

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)

### Agent Registration and Dependency Injection
AutoPoV uses a consistent pattern:
- Each agent module exports a class (e.g., VulnerabilityInvestigator) and a global instance (investigator).
- A getter function (e.g., get_investigator()) returns the global instance.
- The agent registry (agents/__init__.py) re-exports these constructors and getters for easy imports.

```mermaid
classDiagram
class VulnerabilityInvestigator {
+investigate(...)
+batch_investigate(...)
-_get_llm(model_name)
-_run_joern_analysis(...)
-_get_code_context(...)
-_get_rag_context(...)
}
class VulnerabilityVerifier {
+generate_pov(...)
+validate_pov(...)
+analyze_failure(...)
-_get_llm(model_name)
-_llm_validate_pov(...)
}
class CodeIngester {
+ingest_directory(...)
+retrieve_context(...)
+get_file_content(...)
-_get_embeddings()
-_get_chroma_client()
-_get_collection(scan_id)
}
class DockerRunner {
+run_pov(...)
+run_with_input(...)
+run_binary_pov(...)
+batch_run(...)
+get_stats()
-is_available()
}
class PoVTester {
+test_pov_against_app(...)
+test_with_app_lifecycle(...)
-_patch_pov_url(...)
-_run_python_pov(...)
-_run_javascript_pov(...)
}
class StaticValidator {
+validate(...)
+quick_validate(...)
-_calculate_confidence(...)
-_check_code_relevance(...)
}
class UnitTestRunner {
+test_vulnerable_function(...)
+test_with_mock_data(...)
+validate_syntax(...)
-_extract_function(...)
-_create_test_harness(...)
-_run_isolated_test(...)
}
class ApplicationRunner {
+start_nodejs_app(...)
+stop_app(scan_id)
+get_app_url(scan_id)
+is_app_running(scan_id)
+cleanup_all()
}
class HeuristicScout {
+scan_directory(codebase_path, cwes)
-_detect_language(filepath)
-_is_code_file(filepath)
}
VulnerabilityInvestigator --> CodeIngester : "uses"
VulnerabilityVerifier --> StaticValidator : "uses"
VulnerabilityVerifier --> UnitTestRunner : "uses"
PoVTester --> ApplicationRunner : "uses"
DockerRunner ..> Config : "reads settings"
HeuristicScout ..> Config : "reads settings"
CodeIngester ..> Config : "reads settings"
```

**Diagram sources**
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [agents/app_runner.py](file://agents/app_runner.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)
- [app/config.py](file://app/config.py)

**Section sources**
- [agents/__init__.py](file://agents/__init__.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [agents/app_runner.py](file://agents/app_runner.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)

### Policy Routing and Model Selection
The Policy Router selects models per stage based on configuration:
- Fixed mode: always uses a configured model.
- Learning mode: queries the Learning Store for performance signals.
- Auto mode: uses an auto-router model.

```mermaid
flowchart TD
Start(["Select Model"]) --> Mode{"Routing Mode"}
Mode --> |Fixed| UseFixed["Use configured model"]
Mode --> |Learning| QueryStore["Query Learning Store"]
QueryStore --> HasRec{"Recommendation exists?"}
HasRec --> |Yes| UseRec["Use recommended model"]
HasRec --> |No| UseAuto["Use auto-router model"]
Mode --> |Auto| UseAuto
UseFixed --> End(["Return model"])
UseRec --> End
UseAuto --> End
```

**Diagram sources**
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)

**Section sources**
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)

### Agent Factory Pattern and Dynamic Instantiation
- Global instances: Each agent module defines a global instance (e.g., investigator, verifier) and a getter (e.g., get_investigator()).
- Factory-like behavior: The Agent Graph resolves agents via get_* functions, enabling dynamic selection and reuse.
- Configuration-driven: Agents read settings from app/config.py to adapt behavior (e.g., embedding providers, tool availability).

**Section sources**
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/config.py](file://app/config.py)

### Communication Protocols Between Agents
- Shared state: ScanState carries findings, metadata, and logs across nodes.
- Inter-agent calls: The Agent Graph invokes agent getters and passes structured arguments (e.g., scan_id, filepath, line_number, model_name).
- Prompt orchestration: Prompts.py centralizes LLM prompts consumed by Investigator and Verifier.
- Tool integration: Agents call external tools (CodeQL, Docker, Joern) and handle timeouts and failures gracefully.

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [prompts.py](file://prompts.py)

### Agent Isolation and Safety
- Docker isolation: DockerRunner executes PoV scripts in containers with restricted CPU/memory and no network access.
- Unit test harness: UnitTestRunner creates isolated Python environments to validate PoV logic without external dependencies.
- Static validation: StaticValidator enforces safe patterns (standard library only) and CWE-specific checks.
- Process isolation: ApplicationRunner manages app lifecycle with timeouts and cleanup.

**Section sources**
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/app_runner.py](file://agents/app_runner.py)

### Error Handling and Graceful Degradation
- CodeQL fallback: If CodeQL is unavailable or fails, the workflow falls back to heuristic and LLM-only analysis.
- Vector store fallback: Ingestion failures do not block the scan; warnings are logged and the scan proceeds.
- Validation tiers: Verifier uses static validation first, then unit tests, then LLM analysis as fallback.
- Edge-case handling: The Agent Graph handles missing findings, invalid states, and partial results.

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [agents/verifier.py](file://agents/verifier.py)

## Dependency Analysis
The following diagram highlights key dependencies among agents, configuration, and supporting modules.

```mermaid
graph TB
AgentGraph["Agent Graph<br/>app/agent_graph.py"] --> HeuristicScout["Heuristic Scout<br/>agents/heuristic_scout.py"]
AgentGraph --> CodeIngester["Code Ingester<br/>agents/ingest_codebase.py"]
AgentGraph --> Investigator["Investigator<br/>agents/investigator.py"]
AgentGraph --> Verifier["Verifier<br/>agents/verifier.py"]
AgentGraph --> DockerRunner["Docker Runner<br/>agents/docker_runner.py"]
AgentGraph --> PoVTester["PoV Tester<br/>agents/pov_tester.py"]
AgentGraph --> AppRunner["Application Runner<br/>agents/app_runner.py"]
AgentGraph --> StaticValidator["Static Validator<br/>agents/static_validator.py"]
AgentGraph --> UnitTestRunner["Unit Test Runner<br/>agents/unit_test_runner.py"]
AgentGraph --> Policy["Policy Router<br/>app/policy.py"]
AgentGraph --> Learning["Learning Store<br/>app/learning_store.py"]
Investigator --> Prompts["Prompts<br/>prompts.py"]
Verifier --> Prompts
HeuristicScout --> Config["Settings<br/>app/config.py"]
CodeIngester --> Config
DockerRunner --> Config
AppRunner --> Config
Policy --> Config
Policy --> Learning
```

**Diagram sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [agents/heuristic_scout.py](file://agents/heuristic_scout.py)
- [agents/ingest_codebase.py](file://agents/ingest_codebase.py)
- [agents/investigator.py](file://agents/investigator.py)
- [agents/verifier.py](file://agents/verifier.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/pov_tester.py](file://agents/pov_tester.py)
- [agents/app_runner.py](file://agents/app_runner.py)
- [agents/static_validator.py](file://agents/static_validator.py)
- [agents/unit_test_runner.py](file://agents/unit_test_runner.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)
- [prompts.py](file://prompts.py)

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [app/policy.py](file://app/policy.py)
- [app/learning_store.py](file://app/learning_store.py)
- [app/config.py](file://app/config.py)
- [prompts.py](file://prompts.py)

## Performance Considerations
- Cost control: Settings include MAX_COST_USD and COST_TRACKING_ENABLED to cap spending. Investigator and Verifier extract token usage to compute costs.
- Chunking and batching: CodeIngester splits code into chunks and batches embeddings to optimize vector store throughput.
- Tool availability checks: Config provides is_codeql_available(), is_docker_available(), and is_joern_available() to avoid unnecessary waits.
- Parallelism: The Agent Graph processes findings sequentially per scan; parallelization can be introduced at higher levels (e.g., multiple scans).
- Caching and reuse: Global agent instances reduce initialization overhead.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and remedies:
- CodeQL not available: The Agent Graph falls back to heuristic and LLM-only analysis. Verify CODEQL_CLI_PATH and CODEQL_PACKS_BASE.
- Docker not available: DockerRunner returns a non-success result with stderr indicating “Docker not available.” Disable Docker-dependent steps or install Docker.
- Vector store ingestion errors: Ingestion failures are logged as warnings; the scan continues without RAG context.
- Model selection problems: Policy Router defaults to AUTO_ROUTER_MODEL if learning has no recommendation.
- Validation failures: Use Verifier.analyze_failure to get suggestions for improving PoV scripts.

**Section sources**
- [app/agent_graph.py](file://app/agent_graph.py)
- [agents/docker_runner.py](file://agents/docker_runner.py)
- [agents/verifier.py](file://agents/verifier.py)
- [app/policy.py](file://app/policy.py)
- [app/config.py](file://app/config.py)

## Conclusion
AutoPoV’s agent architecture integrates LangGraph for robust workflow orchestration, with clear separation of concerns across agents. The system employs dependency injection via global getters, policy-based model selection, and layered validation to ensure safety and reliability. Graceful degradation and isolation mechanisms protect against tool unavailability and unsafe execution. Together, these patterns enable scalable, configurable, and maintainable vulnerability detection and PoV generation.