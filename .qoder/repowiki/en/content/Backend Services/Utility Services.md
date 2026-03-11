# Utility Services

<cite>
**Referenced Files in This Document**
- [git_handler.py](file://app/git_handler.py)
- [source_handler.py](file://app/source_handler.py)
- [webhook_handler.py](file://app/webhook_handler.py)
- [report_generator.py](file://app/report_generator.py)
- [config.py](file://app/config.py)
- [main.py](file://app/main.py)
- [scan_manager.py](file://app/scan_manager.py)
- [test_git_handler.py](file://tests/test_git_handler.py)
- [test_source_handler.py](file://tests/test_source_handler.py)
- [test_webhook_handler.py](file://tests/test_webhook_handler.py)
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
This document provides comprehensive documentation for AutoPoV’s utility services and helper modules that power the codebase ingestion pipeline, external integrations, and reporting capabilities. It covers:
- Git handler for repository cloning, branch management, and commit tracking
- Source handler for file ingestion, preprocessing, and format conversion
- Webhook handler for external system integration, event processing, and callback management
- Report generator for PDF/JSON output, template rendering, and data export

It includes usage examples, error handling strategies, integration patterns, performance considerations, caching strategies, and operational monitoring guidance for each utility service.

## Project Structure
The utility services are implemented as cohesive modules within the application layer and integrate with configuration, scanning orchestration, and reporting systems.

```mermaid
graph TB
subgraph "App Layer"
GH["GitHandler<br/>app/git_handler.py"]
SH["SourceHandler<br/>app/source_handler.py"]
WH["WebhookHandler<br/>app/webhook_handler.py"]
RG["ReportGenerator<br/>app/report_generator.py"]
CFG["Settings<br/>app/config.py"]
SM["ScanManager<br/>app/scan_manager.py"]
MAIN["FastAPI App<br/>app/main.py"]
end
subgraph "External Integrations"
GHAPI["GitHub API"]
GLAPI["GitLab API"]
FPDF["FPDF Library"]
end
MAIN --> GH
MAIN --> SH
MAIN --> WH
MAIN --> RG
MAIN --> SM
GH --> CFG
SH --> CFG
WH --> CFG
RG --> CFG
RG --> FPDF
GH --> GHAPI
GH --> GLAPI
```

**Diagram sources**
- [git_handler.py:1-392](file://app/git_handler.py#L1-L392)
- [source_handler.py:1-382](file://app/source_handler.py#L1-L382)
- [webhook_handler.py:1-363](file://app/webhook_handler.py#L1-L363)
- [report_generator.py:1-830](file://app/report_generator.py#L1-L830)
- [config.py:1-255](file://app/config.py#L1-L255)
- [main.py:1-768](file://app/main.py#L1-L768)
- [scan_manager.py:1-663](file://app/scan_manager.py#L1-L663)

**Section sources**
- [git_handler.py:1-392](file://app/git_handler.py#L1-L392)
- [source_handler.py:1-382](file://app/source_handler.py#L1-L382)
- [webhook_handler.py:1-363](file://app/webhook_handler.py#L1-L363)
- [report_generator.py:1-830](file://app/report_generator.py#L1-L830)
- [config.py:1-255](file://app/config.py#L1-L255)
- [main.py:1-768](file://app/main.py#L1-L768)
- [scan_manager.py:1-663](file://app/scan_manager.py#L1-L663)

## Core Components
- GitHandler: Clones repositories from GitHub, GitLab, and Bitbucket; injects credentials; verifies accessibility; checks branches; tracks repository metadata; cleans up temporary clones.
- SourceHandler: Handles ZIP/TAR uploads, file/folder uploads, and raw code paste; performs path traversal checks; preserves or flattens directory structure; detects binary files.
- WebhookHandler: Verifies GitHub/GitLab signatures/tokens; parses push/PR/MR events; triggers scans via callback; creates structured callback payloads.
- ReportGenerator: Generates JSON and PDF reports; renders professional templates; aggregates metrics; integrates OpenRouter usage tracking; exports PoV scripts.

**Section sources**
- [git_handler.py:20-392](file://app/git_handler.py#L20-L392)
- [source_handler.py:18-382](file://app/source_handler.py#L18-L382)
- [webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [report_generator.py:200-830](file://app/report_generator.py#L200-L830)

## Architecture Overview
The utility services integrate with the main FastAPI application and the scanning orchestrator. Webhooks trigger asynchronous scans that clone codebases, run analysis, and produce reports.

```mermaid
sequenceDiagram
participant Client as "External System"
participant API as "FastAPI App"
participant WH as "WebhookHandler"
participant GH as "GitHandler"
participant SM as "ScanManager"
participant RG as "ReportGenerator"
Client->>API : "POST /api/webhook/github"
API->>WH : "handle_github_webhook(signature, event_type, payload)"
WH->>WH : "verify signature"
WH->>WH : "parse event"
WH->>API : "callback(scan_id, source_url, branch, commit)"
API->>GH : "clone_repository(url, scan_id, branch, commit)"
GH-->>API : "path, provider"
API->>SM : "run_scan_async(scan_id)"
SM-->>API : "ScanResult"
API->>RG : "generate_json_report / generate_pdf_report"
RG-->>API : "report_path"
API-->>Client : "WebhookResponse"
```

**Diagram sources**
- [main.py:134-173](file://app/main.py#L134-L173)
- [webhook_handler.py:196-266](file://app/webhook_handler.py#L196-L266)
- [git_handler.py:199-294](file://app/git_handler.py#L199-L294)
- [scan_manager.py:117-200](file://app/scan_manager.py#L117-L200)
- [report_generator.py:209-262](file://app/report_generator.py#L209-L262)

## Detailed Component Analysis

### Git Handler
The GitHandler manages repository ingestion from multiple providers, handles authentication, and prepares codebases for scanning.

- Provider detection and credential injection
- Pre-checks for repository accessibility and branch existence
- Shallow cloning with timeouts and cleanup
- Repository metadata extraction and language statistics

```mermaid
classDiagram
class GitHandler {
+__init__()
+_inject_credentials(url, provider) str
+_detect_provider(url) str
+_sanitize_scan_id(scan_id) str
+_parse_github_url(url) Tuple~str,str~
+get_github_repo_info(url) Dict
+check_branch_exists(url, branch) Tuple~bool,str~
+check_repo_accessibility(url, branch) Tuple~bool,str,Dict~
+clone_repository(url, scan_id, branch, commit, depth) Tuple~str,str~
+cleanup(scan_id) void
+get_repo_info(path) dict
-_is_binary(file_path, chunk_size) bool
-_get_language_from_ext(ext) Optional~str~
}
```

**Diagram sources**
- [git_handler.py:20-392](file://app/git_handler.py#L20-L392)

Key behaviors:
- Credentials are injected into URLs for GitHub, GitLab, and Bitbucket when configured.
- Accessibility checks include size limits and branch verification for GitHub.
- Cloning uses subprocess with timeouts and removes .git metadata to save space.
- Repository info aggregation counts files, lines, and languages.

Usage example paths:
- [git_handler.py:199-294](file://app/git_handler.py#L199-L294)
- [git_handler.py:303-336](file://app/git_handler.py#L303-L336)

Error handling:
- GitCommandError raised for authentication failures, not found, network errors, and timeouts.
- Cleanup removes partial clones on failure.

Integration patterns:
- Called by the webhook flow to clone repositories before scanning.
- Provides repository metadata for pre-scan validation.

**Section sources**
- [git_handler.py:20-392](file://app/git_handler.py#L20-L392)
- [test_git_handler.py:1-63](file://tests/test_git_handler.py#L1-L63)

### Source Handler
The SourceHandler ingests code from multiple input formats, enforces security against path traversal, and prepares source trees for analysis.

- ZIP/TAR extraction with path traversal checks
- File/folder upload handling with optional structure preservation
- Raw code paste with language-aware filename inference
- Binary file detection for specialized parsing

```mermaid
classDiagram
class SourceHandler {
+__init__()
+_get_scan_dir(scan_id) str
+handle_zip_upload(zip_path, scan_id) str
+handle_tar_upload(tar_path, scan_id, compression) str
+handle_file_upload(file_paths, scan_id, preserve_structure) str
+handle_folder_upload(folder_path, scan_id) str
+handle_raw_code(code, scan_id, language, filename) str
+cleanup(scan_id) void
+get_source_info(source_dir) dict
-_is_binary(file_path, chunk_size) bool
-_get_language_from_ext(ext) Optional~str~
-get_extension_from_language(language) Optional~str~
}
```

**Diagram sources**
- [source_handler.py:18-382](file://app/source_handler.py#L18-L382)

Key behaviors:
- Path traversal checks ensure extracted members stay within the destination directory.
- Raw code writes with inferred extensions based on language names.
- Binary detection supports later parsing with specialized tools.

Usage example paths:
- [source_handler.py:31-78](file://app/source_handler.py#L31-L78)
- [source_handler.py:126-164](file://app/source_handler.py#L126-L164)
- [source_handler.py:193-232](file://app/source_handler.py#L193-L232)

Error handling:
- Raises ValueError on detected path traversal attempts.
- Cleans up scan directories on completion.

Integration patterns:
- Used by the main application for non-Git ingestion flows.
- Supplies source metadata for scan configuration.

**Section sources**
- [source_handler.py:18-382](file://app/source_handler.py#L18-L382)
- [test_source_handler.py:1-79](file://tests/test_source_handler.py#L1-L79)

### Webhook Handler
The WebhookHandler validates and parses events from GitHub and GitLab, triggering scans asynchronously and managing callback payloads.

- Signature/token verification for GitHub/GitLab
- Event parsing for push and pull/merge request events
- Callback registration to trigger scans from external systems
- Structured callback payloads for downstream reporting

```mermaid
classDiagram
class WebhookHandler {
+__init__()
+register_scan_callback(callback) void
+verify_github_signature(payload, signature) bool
+verify_gitlab_token(token) bool
+parse_github_event(event_type, payload) Optional~Dict~
+parse_gitlab_event(event_type, payload) Optional~Dict~
+handle_github_webhook(signature, event_type, payload) Dict
+handle_gitlab_webhook(token, event_type, payload) Dict
+create_callback_payload(scan_id, status, findings, metrics) Dict
}
```

**Diagram sources**
- [webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)

Key behaviors:
- HMAC verification for GitHub and GitLab tokens.
- Parses event payloads to extract repository, branch, commit, and author information.
- Triggers scans asynchronously via registered callback.

Usage example paths:
- [webhook_handler.py:196-266](file://app/webhook_handler.py#L196-L266)
- [webhook_handler.py:267-336](file://app/webhook_handler.py#L267-L336)
- [webhook_handler.py:338-353](file://app/webhook_handler.py#L338-L353)

Error handling:
- Returns structured responses for invalid signatures, malformed JSON, ignored events, and missing callbacks.

Integration patterns:
- Registered in the FastAPI lifespan to trigger scans from external systems.
- Used by the main application to orchestrate webhook-driven scans.

**Section sources**
- [webhook_handler.py:15-363](file://app/webhook_handler.py#L15-L363)
- [test_webhook_handler.py:1-166](file://tests/test_webhook_handler.py#L1-L166)
- [main.py:94-111](file://app/main.py#L94-L111)
- [main.py:134-173](file://app/main.py#L134-L173)

### Report Generator
The ReportGenerator produces JSON and PDF reports from scan results, including metrics, findings, and PoV validation outcomes. It integrates with OpenRouter for usage tracking.

- JSON report generation with comprehensive metadata and metrics
- Professional PDF report with sections for executive summary, findings, methodology, and appendices
- OpenRouter activity tracking for model usage attribution
- PoV script export and summary aggregation

```mermaid
classDiagram
class ReportGenerator {
+__init__()
+generate_json_report(result) str
+generate_pdf_report(result) str
-_generate_methodology(result) Dict
-_get_openrouter_activity(result) List
-_collect_models_used(result) List
-_summarize_pov(result) Dict
-_calculate_detection_rate(result) float
-_calculate_fp_rate(result) float
-_calculate_pov_success_rate(result) float
-_calculate_cost_per_confirmed(result) float
-_format_findings(findings) List
+save_pov_scripts(result) List
}
class ProfessionalPDFReport {
+header() void
+footer() void
+section_header(title, icon) void
+subsection_header(title) void
+body_text(text, bold) void
+metric_card(label, value, color) void
+table_header(headers, widths) void
+table_row(cells, widths, alternate) void
+code_block(code, max_lines) void
+info_box(title, content, border_color) void
}
class OpenRouterActivityTracker {
+__init__(api_key)
+get_activity(date) List
+get_activity_for_scan(start_time, end_time) List
}
ReportGenerator --> ProfessionalPDFReport : "renders"
ReportGenerator --> OpenRouterActivityTracker : "uses"
```

**Diagram sources**
- [report_generator.py:200-830](file://app/report_generator.py#L200-L830)

Key behaviors:
- JSON report includes scan metadata, model usage, metrics, findings, and methodology.
- PDF report uses a custom ProfessionalPDFReport class with branded sections and tables.
- OpenRouter activity is fetched for usage attribution when online mode is enabled.
- PoV scripts are summarized and exported for confirmed vulnerabilities.

Usage example paths:
- [report_generator.py:209-262](file://app/report_generator.py#L209-L262)
- [report_generator.py:264-610](file://app/report_generator.py#L264-L610)
- [report_generator.py:800-830](file://app/report_generator.py#L800-L830)

Error handling:
- Raises ReportGeneratorError when PDF generation is attempted without the required library.
- Gracefully falls back to JSON when external APIs are unavailable.

Integration patterns:
- Consumed by the main application after scans complete.
- Works with ScanResult objects produced by ScanManager.

**Section sources**
- [report_generator.py:200-830](file://app/report_generator.py#L200-L830)
- [config.py:136-149](file://app/config.py#L136-L149)
- [scan_manager.py:23-45](file://app/scan_manager.py#L23-L45)

## Dependency Analysis
The utility services depend on configuration settings and integrate with the scanning orchestrator and FastAPI application.

```mermaid
graph TB
GH["GitHandler"]
SH["SourceHandler"]
WH["WebhookHandler"]
RG["ReportGenerator"]
CFG["Settings"]
SM["ScanManager"]
MAIN["FastAPI App"]
GH --> CFG
SH --> CFG
WH --> CFG
RG --> CFG
MAIN --> GH
MAIN --> SH
MAIN --> WH
MAIN --> RG
MAIN --> SM
```

**Diagram sources**
- [git_handler.py:17-25](file://app/git_handler.py#L17-L25)
- [source_handler.py:15-23](file://app/source_handler.py#L15-L23)
- [webhook_handler.py:12-20](file://app/webhook_handler.py#L12-L20)
- [report_generator.py:13-14](file://app/report_generator.py#L13-L14)
- [config.py:248-254](file://app/config.py#L248-L254)
- [main.py:21-27](file://app/main.py#L21-L27)
- [scan_manager.py:18-20](file://app/scan_manager.py#L18-L20)

**Section sources**
- [config.py:136-149](file://app/config.py#L136-L149)
- [main.py:21-27](file://app/main.py#L21-L27)
- [scan_manager.py:18-20](file://app/scan_manager.py#L18-L20)

## Performance Considerations
- Git cloning
  - Use shallow clones and branch-specific checkout to reduce bandwidth and storage.
  - Apply timeouts to prevent long-running operations on large repositories.
  - Remove .git metadata after cloning to minimize disk usage.
  - Validate repository size and branch availability before cloning to avoid wasted resources.

- Source ingestion
  - Enforce path traversal checks to avoid malicious archives.
  - Prefer streaming extraction for large archives when feasible.
  - Skip binary files during preprocessing to reduce I/O overhead.

- Webhook processing
  - Verify signatures/tokens early to fail fast on invalid requests.
  - Asynchronously trigger scans to keep webhook responses quick.
  - Limit event parsing to scan-relevant actions to reduce processing.

- Reporting
  - PDF generation depends on an external library; guard with availability checks.
  - Limit table rows and code block truncation to manage PDF size.
  - Aggregate metrics and summaries to minimize report payload sizes.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- GitHandler
  - Authentication failures: Ensure provider tokens are configured and valid.
  - Network errors: Verify connectivity and consider shallow clones for large repos.
  - Timeout errors: Reduce clone depth or use ZIP upload for very large repositories.

- SourceHandler
  - Path traversal errors: Validate archive contents and reject suspicious entries.
  - Permission errors: Ensure write permissions to temporary directories.

- WebhookHandler
  - Invalid signatures/tokens: Confirm secrets match provider configurations.
  - Unsupported events: Only push and pull/merge request events trigger scans.

- ReportGenerator
  - PDF generation failures: Install the required library or fall back to JSON.
  - Missing OpenRouter data: Confirm API key and online mode configuration.

Operational monitoring:
- Track scan durations and costs via ScanResult metrics.
- Monitor webhook event processing success rates and error messages.
- Observe repository size and branch availability checks to preempt failures.

**Section sources**
- [git_handler.py:243-294](file://app/git_handler.py#L243-L294)
- [source_handler.py:56-63](file://app/source_handler.py#L56-L63)
- [webhook_handler.py:213-265](file://app/webhook_handler.py#L213-L265)
- [report_generator.py:266-267](file://app/report_generator.py#L266-L267)

## Conclusion
AutoPoV’s utility services provide robust, secure, and scalable foundations for codebase ingestion, external integration, and reporting. By leveraging provider-specific authentication, strict security checks, asynchronous processing, and comprehensive reporting, the system supports efficient vulnerability discovery and validation workflows. Proper configuration, monitoring, and error handling ensure reliable operation across diverse environments.