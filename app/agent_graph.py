"""
AutoPoV Agent Graph Module
LangGraph-based agentic workflow for vulnerability detection
"""

import os
import json
import uuid
import shutil
from typing import Dict, Any, List, Optional, TypedDict, Annotated
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

import subprocess

from app.config import settings
from agents.llm_scout import get_llm_scout
from agents.ingest_codebase import get_code_ingester
from agents.investigator import get_investigator
from agents.verifier import get_verifier
from agents.docker_runner import get_docker_runner
from agents.pov_tester import get_pov_tester


class ScanStatus(str, Enum):
    """Scan status enum"""
    PENDING = "pending"
    INGESTING = "ingesting"
    RUNNING_CODEQL = "running_codeql"
    INVESTIGATING = "investigating"
    GENERATING_POV = "generating_pov"
    VALIDATING_POV = "validating_pov"
    RUNNING_POV = "running_pov"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class VulnerabilityState(TypedDict):
    """State for a single vulnerability finding"""
    cve_id: Optional[str]
    filepath: str
    line_number: int
    cwe_type: str
    code_chunk: str
    llm_verdict: str
    llm_explanation: str
    confidence: float
    pov_script: Optional[str]
    pov_path: Optional[str]
    pov_result: Optional[Dict[str, Any]]
    retry_count: int
    inference_time_s: float
    cost_usd: float
    final_status: Optional[str]
    # Language tracking
    detected_language: Optional[str]  # Language of the file
    source: Optional[str]  # How the finding was detected (codeql, llm, heuristic)
    # Token tracking per model
    model_used: Optional[str]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    # Hierarchical LLM tracking
    sifter_model: Optional[str]
    sifter_tokens: Optional[Dict[str, int]]  # {prompt, completion, total}
    architect_model: Optional[str]
    architect_tokens: Optional[Dict[str, int]]  # {prompt, completion, total}
    # Validation and refinement tracking
    validation_result: Optional[Dict[str, Any]]
    refinement_history: Optional[List[Dict[str, Any]]]
    exploit_contract: Optional[Dict[str, Any]]
    execution_profile: Optional[str]


class ScanState(TypedDict):
    """Overall scan state"""
    scan_id: str
    status: str
    codebase_path: str
    model_name: str
    model_mode: str
    cwes: List[str]
    findings: List[VulnerabilityState]
    preloaded_findings: Optional[List[VulnerabilityState]]
    detected_language: Optional[str]
    current_finding_idx: int
    start_time: str
    end_time: Optional[str]
    total_cost_usd: float
    # Token tracking per model
    total_tokens: int
    tokens_by_model: Dict[str, Dict[str, int]]  # {model_name: {prompt, completion, total}}
    logs: List[str]
    error: Optional[str]

    proofs_attempted: int
    confirmed_count: int  # Track confirmed findings for early termination
    openrouter_api_key: Optional[str]
    rag_ready: bool
    rag_stats: Optional[Dict[str, Any]]
    scan_openrouter_usage: List[Dict[str, Any]]


class AgentGraph:
    """LangGraph agent for vulnerability detection workflow"""
    
    def __init__(self):
        self.graph = self._build_graph()
        self._scan_manager = None  # Reference to scan manager for cancellation checks
    
    def set_scan_manager(self, scan_manager):
        """Set reference to scan manager for cancellation checks"""
        self._scan_manager = scan_manager
    
    def _check_cancelled(self, state: ScanState) -> bool:
        """Check if scan has been cancelled"""
        if self._scan_manager and state.get("scan_id"):
            scan_info = self._scan_manager._active_scans.get(state["scan_id"])
            if scan_info and scan_info.get("status") == "cancelled":
                return True
        return False

    def _get_selected_model(self, state: ScanState) -> str:
        model_name = (state.get("model_name") or "").strip()
        if not model_name:
            raise ValueError("Scan has no selected model. Choose one in Settings or pass an explicit CLI override.")
        settings.resolve_model_mode(model_name)
        return model_name
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Define the state graph
        workflow = StateGraph(ScanState)
        
        # Add nodes
        workflow.add_node("ingest_code", self._node_ingest_code)
        workflow.add_node("run_codeql", self._node_run_codeql)
        workflow.add_node("investigate", self._node_investigate)
        workflow.add_node("generate_pov", self._node_generate_pov)
        workflow.add_node("validate_pov", self._node_validate_pov)
        workflow.add_node("refine_pov", self._node_refine_pov)  # Self-healing refiner
        workflow.add_node("run_in_docker", self._node_run_in_docker)
        workflow.add_node("log_confirmed", self._node_log_confirmed)
        workflow.add_node("log_skip", self._node_log_skip)
        workflow.add_node("log_failure", self._node_log_failure)
        
        # Define edges
        workflow.set_entry_point("ingest_code")
        workflow.add_edge("ingest_code", "run_codeql")
        
        # Add a node to log the number of findings before investigation
        workflow.add_node("log_findings_count", self._node_log_findings_count)
        workflow.add_edge("run_codeql", "log_findings_count")
        workflow.add_edge("log_findings_count", "investigate")
        
        # Conditional edges from investigate
        workflow.add_conditional_edges(
            "investigate",
            self._should_generate_pov,
            {
                "generate_pov": "generate_pov",
                "log_skip": "log_skip"
            }
        )
        
        workflow.add_edge("generate_pov", "validate_pov")
        
        # Conditional edges from validate_pov
        workflow.add_conditional_edges(
            "validate_pov",
            self._should_run_pov,
            {
                "run_in_docker": "run_in_docker",
                "refine_pov": "refine_pov",  # Self-healing refinement
                "log_failure": "log_failure"
            }
        )
        
        # Refiner loop: refinement goes back to validation
        workflow.add_edge("refine_pov", "validate_pov")
        
        workflow.add_conditional_edges(
            "run_in_docker",
            self._after_runtime_proof,
            {
                "log_confirmed": "log_confirmed",
                "log_failure": "log_failure"
            }
        )
        
        # After logging, check if there are more findings to process
        # Loop back to investigate to process the next finding
        workflow.add_conditional_edges(
            "log_confirmed",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        workflow.add_conditional_edges(
            "log_skip",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        workflow.add_conditional_edges(
            "log_failure",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        return workflow.compile()
    
    def _node_log_findings_count(self, state: ScanState) -> ScanState:
        """Log the number of findings found before investigation"""
        findings_count = len(state.get("findings", []))
        self._update_scan_runtime(state, status=ScanStatus.INVESTIGATING, progress=45, findings=state.get("findings", []))
        self._log(state, f"Discovery found {findings_count} potential vulnerabilities to investigate")
        if findings_count == 0:
            self._log(state, "No findings to investigate, scan will complete")
        return state
    
    def _node_ingest_code(self, state: ScanState) -> ScanState:
        """Ingest the codebase into the vector store and require it for downstream RAG."""
        if settings.SKIP_CHROMADB and settings.RAG_REQUIRED:
            self._log(state, "RAG_REQUIRED=true overrides SKIP_CHROMADB; vector ingestion is mandatory for this scan")

        self._log(state, "Ingesting codebase into vector store...")
        state["status"] = ScanStatus.INGESTING
        self._update_scan_runtime(state, status=ScanStatus.INGESTING, progress=25, rag_ready=False)

        try:
            ingester = get_code_ingester()
            stats = ingester.ingest_directory(
                state["codebase_path"],
                state["scan_id"],
                progress_callback=lambda count, path: self._log(
                    state, f"  Processed {count} files: {path}"
                )
            )

            if stats.get("files_processed", 0) <= 0 or stats.get("chunks_created", 0) <= 0:
                raise RuntimeError("RAG ingestion completed without indexing any source chunks")

            state["rag_ready"] = True
            state["rag_stats"] = stats
            self._log(state, f"Ingested {stats['chunks_created']} chunks from {stats['files_processed']} files")
            self._update_scan_runtime(state, progress=35, rag_ready=True, rag_stats=stats)

            if stats["errors"]:
                for error in stats["errors"][:5]:
                    self._log(state, f"  Warning: {error}")

        except Exception as e:
            state["rag_ready"] = False
            state["rag_stats"] = {"error": str(e)}
            self._update_scan_runtime(state, rag_ready=False, rag_stats=state["rag_stats"])
            self._log(state, f"ERROR: Mandatory code ingestion failed: {e}")
            raise RuntimeError(f"Mandatory code ingestion failed: {e}") from e

        return state
    
    def _merge_findings(self, base: List[VulnerabilityState], extra: List[VulnerabilityState]) -> List[VulnerabilityState]:
        """Merge findings and deduplicate by (filepath, line, cwe)."""
        merged: List[VulnerabilityState] = []
        seen = set()
        for item in base + extra:
            key = (item.get("filepath"), item.get("line_number"), item.get("cwe_type"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged
    
    def _is_security_finding(self, finding: VulnerabilityState) -> bool:
        """
        Filter out obvious non-security findings (code quality, style issues).
        
        IMPORTANT: We do NOT filter based on CWE classification. 
        A vulnerability is defined by exploitability, not by its CWE label.
        All findings deserve investigation - the PoV process will determine exploitability.
        """
        code_chunk = finding.get("code_chunk", "").lower()
        
        # Only filter out obvious code quality/style issues from static analyzers
        # These are clearly not security issues
        non_security_patterns = [
            "empty block",
            "switch has at least one case that is too long",
            "multiple forward and backward goto",
            "code quality",
            "style",
            "comment",
            "readability",
            "complexity",
            "maintainability",
            "duplicate code",
            "unused variable",
            "naming convention",
            "magic number",
            "todo",
            "fixme",
            "indentation",
            "whitespace",
            "line length",
        ]
        
        # Skip if code_chunk matches non-security patterns
        for pattern in non_security_patterns:
            if pattern in code_chunk:
                return False
        
        # Keep ALL other findings for investigation
        # The PoV generation and validation process will determine exploitability
        return True

    def _node_run_codeql(self, state: ScanState) -> ScanState:
        """
        Run agentic discovery with resilient decision-tree:
        1. Language Profiling
        2. CodeQL Pre-Flight (with Semgrep fallback)
        3. Hybrid Enforcement for high-risk languages
        4. Cost-Benefit Triage with LLM Scout
        """
        self._log(state, "Running agentic discovery...")
        state["status"] = ScanStatus.RUNNING_CODEQL
        self._update_scan_runtime(state, status=ScanStatus.RUNNING_CODEQL, progress=40)
        
        if state.get("preloaded_findings"):
            self._log(state, f"Using preloaded findings: {len(state['preloaded_findings'])}")
            state["findings"] = state["preloaded_findings"]
            return state
        
        try:
            # Import agentic discovery
            from agents.agentic_discovery import get_agentic_discovery
            
            # Run agentic discovery
            discovery_results = get_agentic_discovery().discover(
                codebase_path=state["codebase_path"],
                cwes=state["cwes"],
                scan_id=state["scan_id"],
                state=state
            )
            
            # Merge all findings from different strategies
            all_findings: List[VulnerabilityState] = []
            for result in discovery_results:
                if result.success:
                    self._log(state, f"{result.strategy.value}: Found {len(result.findings)} findings")
                    for finding_data in result.findings:
                        # Convert to VulnerabilityState
                        finding = VulnerabilityState(
                            cve_id=None,
                            filepath=finding_data.get("filepath", ""),
                            line_number=finding_data.get("line_number", 0),
                            cwe_type=finding_data.get("cwe_type", "UNKNOWN"),
                            code_chunk=finding_data.get("code_chunk", ""),
                            llm_verdict="",
                            llm_explanation="",
                            confidence=finding_data.get("confidence", 0.7),
                            pov_script=None,
                            pov_path=None,
                            pov_result=None,
                            retry_count=0,
                            inference_time_s=0.0,
                            cost_usd=0.0,
                            final_status="",
                            detected_language=finding_data.get("detected_language", state.get("detected_language", "unknown")),
                            source=finding_data.get("source", "unknown"),
                            model_used=None,
                            prompt_tokens=0,
                            completion_tokens=0,
                            total_tokens=0,
                            sifter_model=None,
                            sifter_tokens=None,
                            architect_model=None,
                            architect_tokens=None,
                            validation_result=None,
                            refinement_history=[],
                            exploit_contract=None,
                            execution_profile=None
                        )
                        all_findings.append(finding)
                else:
                    self._log(state, f"{result.strategy.value}: Failed - {result.error}")
            
            # Deduplicate findings
            deduped = self._merge_findings([], all_findings)
            
            # Filter out non-security findings (code quality, style issues)
            security_findings = [f for f in deduped if self._is_security_finding(f)]
            filtered_count = len(deduped) - len(security_findings)
            if filtered_count > 0:
                self._log(state, f"Filtered out {filtered_count} non-security findings (code quality/style issues)")
            
            # Sort by confidence descending
            security_findings.sort(key=lambda item: item.get("confidence", 0.0), reverse=True)
            
            if len(security_findings) > settings.DISCOVERY_MAX_FINDINGS:
                self._log(state, f"Capping discovery set from {len(security_findings)} to {settings.DISCOVERY_MAX_FINDINGS} findings for stable downstream processing")
                security_findings = security_findings[:settings.DISCOVERY_MAX_FINDINGS]
            state["findings"] = security_findings
            for finding in state["findings"]:
                self._append_scan_openrouter_usage(state, finding.get("scout_openrouter_usage"), "llm_scout", finding=finding)
            self._update_scan_runtime(state, progress=45, findings=state["findings"])
            self._log(state, f"Agentic discovery completed: {len(state['findings'])} total unique findings")
            
        except Exception as e:
            self._log(state, f"Agentic discovery error: {e}")
            import traceback
            self._log(state, f"Traceback: {traceback.format_exc()}")
            # Fallback to traditional methods
            findings = self._run_llm_only_analysis(state)
            auto_findings = self._run_autonomous_discovery(state)
            merged = self._merge_findings(findings, auto_findings)
            merged.sort(key=lambda item: item.get("confidence", 0.0), reverse=True)
            state["findings"] = merged[:settings.DISCOVERY_MAX_FINDINGS]
            for finding in state["findings"]:
                self._append_scan_openrouter_usage(state, finding.get("scout_openrouter_usage"), "llm_scout", finding=finding)
            self._update_scan_runtime(state, progress=45, findings=state["findings"])

        return state

    def _run_llm_only_analysis(self, state: ScanState) -> List[VulnerabilityState]:
        """
        Run LLM-only analysis when CodeQL is not available.

        Walks code files in the codebase, splits them into chunks, and uses
        the LLM scout to propose candidate vulnerabilities.  This mirrors what
        the heuristic scout does but leverages the LLM for richer detection.
        Falls back gracefully if the LLM is unavailable.
        """
        self._log(state, "Running LLM-only analysis (CodeQL unavailable)...")

        findings: List[VulnerabilityState] = []

        # Collect code files
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java',
            '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.rb', '.php', '.cs'
        }
        code_files: List[str] = []
        for root, dirs, files in os.walk(state["codebase_path"]):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
                'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'
            )]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in code_extensions:
                    code_files.append(os.path.join(root, fname))

        if not code_files:
            self._log(state, "No code files found for LLM-only analysis")
            return findings

        # Limit to first 20 files to control cost
        max_files = min(len(code_files), 20)
        code_files = code_files[:max_files]
        self._log(state, f"LLM-only analysis: scanning {len(code_files)} files for {len(state['cwes'])} CWEs")

        for filepath in code_files:
            rel_path = os.path.relpath(filepath, state["codebase_path"])
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(settings.MAX_CHUNK_SIZE * 2)
            except Exception:
                continue

            if not content.strip():
                continue

            # Use simple pattern matching as a pre-filter to avoid LLM calls on clean files
            # Basic dangerous function patterns
            dangerous_patterns = [
                r'eval\s*\(', r'exec\s*\(', r'system\s*\(', r'popen\s*\(',
                r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\(',
                r'malloc\s*\([^)]*\)\s*;',  # malloc without size check
                r'sqlite3_exec\s*\(', r'mysql_query\s*\(',
                r'innerHTML\s*=', r'document\.write\s*\(',
            ]
            import re
            heuristic_hits = []
            try:
                lines = content.split('\n')
                for line_idx, line in enumerate(lines, start=1):
                    for pattern_str in dangerous_patterns:
                        if re.search(pattern_str, line):
                            heuristic_hits.append({
                                "cwe_type": "UNCLASSIFIED",
                                "filepath": rel_path,
                                "line_number": line_idx,
                                "code_chunk": line.strip(),
                                "llm_verdict": "",
                                "llm_explanation": "",
                                "confidence": 0.35,
                                "pov_script": None,
                                "pov_path": None,
                                "pov_result": None,
                                "retry_count": 0,
                                "inference_time_s": 0.0,
                                "cost_usd": 0.0,
                                "final_status": "",
                                "alert_message": "LLM-only pattern match",
                                "source": "llm_only",
                                "language": state.get("detected_language", "unknown")
                            })
                            break  # Only add each line once
            except Exception as e:
                self._log(state, f"Pattern pre-filter error on {rel_path}: {e}")

            findings.extend(heuristic_hits)

        self._log(state, f"LLM-only analysis produced {len(findings)} candidate findings")
        return findings
    
    def _node_investigate(self, state: ScanState) -> ScanState:
        """Investigate ONE finding with LLM (at current_finding_idx) or ALL in parallel"""
        # Check for cancellation
        if self._check_cancelled(state):
            self._log(state, "Scan cancelled by user")
            state["status"] = ScanStatus.CANCELLED
            return state
        
        # Use parallel processing if enabled and this is the first finding
        # But only if there are pending findings that haven't been investigated yet
        if settings.PARALLEL_PROCESSING_ENABLED and state.get("current_finding_idx", 0) == 0:
            pending_findings = [f for f in state["findings"] if not f.get("llm_verdict")]
            if pending_findings:
                return self._node_investigate_parallel(state)
            # If all findings already have llm_verdict, skip parallel and let routing handle it
        
        state["status"] = ScanStatus.INVESTIGATING
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            self._log(state, "No more findings to investigate")
            return state
        
        finding = state["findings"][idx]
        
        # Skip if already investigated
        if finding.get("llm_verdict"):
            self._log(state, f"Finding {idx} already investigated, skipping")
            return state
        
        self._log(state, f"Investigating {finding['cwe_type']} at {finding['filepath']}:{finding['line_number']}")
        model_to_use = self._get_selected_model(state)
        self._log(state, f"Using selected model: {model_to_use}")
        investigator = get_investigator()

        # Pass the model name and optional per-request API key from scan state
        try:
            result = investigator.investigate(
                scan_id=state["scan_id"],
                codebase_path=state["codebase_path"],
                cwe_type=finding["cwe_type"],
                filepath=finding["filepath"],
                line_number=finding["line_number"],
                alert_message=finding.get("alert_message", ""),
                model_name=model_to_use,
                api_key_override=state.get("openrouter_api_key")
            )
            self._log(state, f"Investigation completed with verdict: {result.get('verdict', 'UNKNOWN')}")
        except Exception as e:
            self._log(state, f"ERROR during investigation: {str(e)}")
            import traceback
            self._log(state, f"Traceback: {traceback.format_exc()}")
            # Create a default result to prevent crash
            result = {
                "verdict": "UNKNOWN",
                "explanation": f"Investigation failed: {str(e)}",
                "confidence": 0.0,
                "inference_time_s": 0.0,
                "vulnerable_code": ""
            }
        
        finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
        finding["llm_explanation"] = result.get("explanation", "")
        finding["confidence"] = result.get("confidence", 0.0)
        finding["inference_time_s"] = result.get("inference_time_s", 0.0)
        finding["code_chunk"] = result.get("vulnerable_code", "") or finding.get("code_chunk", "")
        finding["cwe_type"] = result.get("cwe_type") or finding.get("cwe_type") or "UNCLASSIFIED"
        finding["cve_id"] = result.get("cve_id")
        
        # Track tokens per model
        token_usage = result.get("token_usage", {})
        model_used = result.get("model_used", model_to_use)
        
        finding["model_used"] = model_used
        finding["openrouter_usage"] = result.get("openrouter_usage", {})
        self._append_scan_openrouter_usage(state, finding["openrouter_usage"], "investigator", finding=finding)
        finding["prompt_tokens"] = token_usage.get("prompt_tokens", 0)
        finding["completion_tokens"] = token_usage.get("completion_tokens", 0)
        finding["total_tokens"] = token_usage.get("total_tokens", 0)
        
        # Update scan-level token tracking
        if finding["total_tokens"] > 0:
            state["total_tokens"] = state.get("total_tokens", 0) + finding["total_tokens"]
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += finding["prompt_tokens"]
            state["tokens_by_model"][model_used]["completion"] += finding["completion_tokens"]
            state["tokens_by_model"][model_used]["total"] += finding["total_tokens"]
        
        # Track cost (optional, for backward compatibility)
        actual_cost = result.get("cost_usd", 0.0)
        if actual_cost > 0:
            finding["cost_usd"] = actual_cost
        else:
            finding["cost_usd"] = 0.0
        
        state["total_cost_usd"] += finding["cost_usd"]
        
        state["findings"][idx] = finding
        
        self._log(state, f"  Verdict: {finding['llm_verdict']} (confidence: {finding['confidence']:.2f})")
        if finding["total_tokens"] > 0:
            self._log(state, f"  Tokens: {finding['total_tokens']} (prompt: {finding['prompt_tokens']}, completion: {finding['completion_tokens']})")

        return state
    
    def _investigate_finding_batch(self, findings_batch: List[Dict[str, Any]], state: ScanState, model_name: str) -> List[Dict[str, Any]]:
        """Investigate a batch of findings in parallel. Thread-safe."""
        investigator = get_investigator()
        results = []
        
        for finding in findings_batch:
            try:
                result = investigator.investigate(
                    scan_id=state["scan_id"],
                    codebase_path=state["codebase_path"],
                    cwe_type=finding["cwe_type"],
                    filepath=finding["filepath"],
                    line_number=finding["line_number"],
                    alert_message=finding.get("alert_message", ""),
                    model_name=model_name,
                    api_key_override=state.get("openrouter_api_key")
                )
                
                finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
                finding["llm_explanation"] = result.get("explanation", "")
                finding["confidence"] = result.get("confidence", 0.0)
                finding["inference_time_s"] = result.get("inference_time_s", 0.0)
                finding["code_chunk"] = result.get("vulnerable_code", "") or finding.get("code_chunk", "")
                finding["cwe_type"] = result.get("cwe_type") or finding.get("cwe_type") or "UNCLASSIFIED"
                finding["cve_id"] = result.get("cve_id")
                
                # Track tokens
                token_usage = result.get("token_usage", {})
                model_used = result.get("model_used", model_name)
                finding["model_used"] = model_used
                finding["openrouter_usage"] = result.get("openrouter_usage", {})
                finding["prompt_tokens"] = token_usage.get("prompt_tokens", 0)
                finding["completion_tokens"] = token_usage.get("completion_tokens", 0)
                finding["total_tokens"] = token_usage.get("total_tokens", 0)
                finding["cost_usd"] = result.get("cost_usd", 0.0)
                
            except Exception as e:
                finding["llm_verdict"] = "UNKNOWN"
                finding["llm_explanation"] = f"Investigation failed: {str(e)}"
                finding["confidence"] = 0.0
            
            results.append(finding)
        
        return results
    
    def _node_investigate_parallel(self, state: ScanState) -> ScanState:
        """Investigate ALL findings in parallel batches for faster processing"""
        if not settings.PARALLEL_PROCESSING_ENABLED:
            return self._node_investigate(state)
        
        state["status"] = ScanStatus.INVESTIGATING
        
        # Get findings that haven't been investigated yet
        pending_findings = [f for f in state["findings"] if not f.get("llm_verdict")]
        
        if not pending_findings:
            self._log(state, "No pending findings to investigate")
            return state
        
        self._log(state, f"Starting parallel investigation of {len(pending_findings)} findings with {settings.PARALLEL_MAX_WORKERS} workers")
        
        model_to_use = self._get_selected_model(state)
        
        # Split findings into batches for parallel processing
        batch_size = max(1, len(pending_findings) // settings.PARALLEL_MAX_WORKERS)
        batches = [pending_findings[i:i + batch_size] for i in range(0, len(pending_findings), batch_size)]
        
        all_results = []
        total_tokens = 0
        total_cost = 0.0
        
        with ThreadPoolExecutor(max_workers=settings.PARALLEL_MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._investigate_finding_batch, batch, state, model_to_use): i
                for i, batch in enumerate(batches)
            }
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                    self._log(state, f"Completed batch {batch_idx + 1}/{len(batches)}")
                except Exception as e:
                    self._log(state, f"Batch {batch_idx} failed: {e}")
        
        # Update state with results
        for result in all_results:
            # Find and update the corresponding finding in state
            for i, f in enumerate(state["findings"]):
                if (f["filepath"] == result["filepath"] and 
                    f["line_number"] == result["line_number"]):
                    state["findings"][i] = result
                    self._append_scan_openrouter_usage(state, result.get("openrouter_usage"), "investigator", finding=result)
                    total_tokens += result.get("total_tokens", 0)
                    total_cost += result.get("cost_usd", 0.0)
                    break
        
        state["total_tokens"] = state.get("total_tokens", 0) + total_tokens
        state["total_cost_usd"] = state.get("total_cost_usd", 0.0) + total_cost
        
        # Keep current_finding_idx at 0 to start routing through decision logic
        # All findings now have llm_verdict, so the workflow will route each through _should_generate_pov
        state["current_finding_idx"] = 0
        
        self._log(state, f"Parallel investigation complete. Total tokens: {total_tokens}, Cost: ${total_cost:.4f}")
        
        return state
    
    def _build_pov_context(self, finding: Dict[str, Any], code_context: str, state: ScanState) -> str:
        if not code_context:
            return ''
        vulnerable = str(finding.get('code_chunk') or '').strip()
        if not vulnerable:
            return code_context[:2400]
        idx = code_context.find(vulnerable)
        if idx == -1:
            return code_context[:2400]
        offline = state.get('model_mode') == 'offline'
        window = 1200 if offline else 3000
        start = max(0, idx - window)
        end = min(len(code_context), idx + len(vulnerable) + window)
        return code_context[start:end]


    def _infer_runtime_profile(self, finding: Dict[str, Any], state: ScanState) -> str:
        """Infer the best runtime harness from exploit contract, explicit profile, and file language."""
        exploit_contract = finding.get('exploit_contract') or {}
        explicit = str(finding.get('execution_profile') or exploit_contract.get('runtime_profile') or '').strip().lower()
        if explicit:
            return explicit

        target_entrypoint = str(exploit_contract.get('target_entrypoint') or '').strip().lower()
        target_url = str(exploit_contract.get('target_url') or exploit_contract.get('base_url') or '').strip().lower()
        if target_url.startswith('http://') or target_url.startswith('https://') or target_entrypoint.startswith('/') or target_entrypoint.startswith('http'):
            return 'web'

        filepath = str(finding.get('filepath') or '').lower()
        _, ext = os.path.splitext(filepath)
        if ext in {'.c', '.h'}:
            return 'c'
        if ext in {'.cc', '.cpp', '.cxx', '.hpp'}:
            return 'cpp'
        if ext in {'.js', '.jsx'}:
            return 'javascript'
        if ext in {'.ts', '.tsx'}:
            return 'node'
        if ext == '.py':
            return 'python'

        detected = str(finding.get('detected_language') or state.get('detected_language') or '').strip().lower()
        if detected in {'c', 'cpp', 'python', 'javascript', 'typescript', 'node'}:
            return 'node' if detected == 'typescript' else detected

        return 'python'

    def _infer_runtime_profile(self, finding: Dict[str, Any], state: ScanState) -> str:
        """Infer the best runtime harness from the exploit contract, file path, and detected language."""
        exploit_contract = finding.get('exploit_contract') or {}
        explicit = str(finding.get('execution_profile') or exploit_contract.get('runtime_profile') or '').strip().lower()
        if explicit:
            return explicit

        target_entrypoint = str(exploit_contract.get('target_entrypoint') or '').strip().lower()
        target_url = str(exploit_contract.get('target_url') or exploit_contract.get('base_url') or '').strip().lower()
        if target_url.startswith('http://') or target_url.startswith('https://') or target_entrypoint.startswith('/') or target_entrypoint.startswith('http'):
            return 'web'

        filepath = str(finding.get('filepath') or '').lower()
        _, ext = os.path.splitext(filepath)
        if ext in {'.c', '.h'}:
            return 'c'
        if ext in {'.cc', '.cpp', '.cxx', '.hpp'}:
            return 'cpp'
        if ext in {'.js', '.jsx'}:
            return 'javascript'
        if ext in {'.ts', '.tsx'}:
            return 'node'
        if ext == '.py':
            return 'python'

        detected = str(finding.get('detected_language') or state.get('detected_language') or '').strip().lower()
        if detected in {'c', 'cpp', 'python', 'javascript', 'node'}:
            return detected
        if detected == 'typescript':
            return 'node'

        return 'python'

    def _node_generate_pov(self, state: ScanState) -> ScanState:
        """Generate PoV script for a finding"""
        # Check for cancellation
        if self._check_cancelled(state):
            self._log(state, "Scan cancelled by user")
            state["status"] = ScanStatus.CANCELLED
            return state
        
        state["status"] = ScanStatus.GENERATING_POV
        
        # Get current finding being processed
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if finding["llm_verdict"] != "REAL":
            return state
        confidence = float(finding.get("confidence", 0.0) or 0.0)
        if confidence < settings.MIN_CONFIDENCE_FOR_POV:
            self._log(state, f"Skipping PoV generation because confidence {confidence:.2f} is below the proof threshold {settings.MIN_CONFIDENCE_FOR_POV:.2f}")
            finding["final_status"] = "unproven_low_confidence"
            state["findings"][idx] = finding
            return state
        
        self._log(state, f"Generating PoV for {finding['cwe_type']}...")

        model_to_use = self._get_selected_model(state)
        self._log(state, f"Using selected model for PoV: {model_to_use}")
        
        verifier = get_verifier()
        
        # Get code context - try ChromaDB first, then fall back to disk
        full_code_context = None
        try:
            full_code_context = get_code_ingester().get_file_content(
                finding["filepath"], state["scan_id"]
            )
        except Exception:
            pass
        
        # Fallback: read directly from disk
        if not full_code_context:
            try:
                abs_path = os.path.join(state["codebase_path"], finding["filepath"]) if not os.path.isabs(finding["filepath"]) else finding["filepath"]
                if os.path.isfile(abs_path):
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        full_code_context = f.read()
            except Exception:
                pass
        
        full_code_context = full_code_context or ""
        code_context = self._build_pov_context(finding, full_code_context, state)
        self._log(state, f"Using PoV context window: {len(code_context)} chars")
        
        # Get target language for language-aware PoV generation
        target_language = state.get("detected_language", "python")
        
        # Pass model name from scan state
        result = verifier.generate_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding["code_chunk"],
            explanation=finding["llm_explanation"],
            code_context=code_context,
            target_language=target_language,
            model_name=model_to_use,
            exploit_contract=finding.get("exploit_contract") or {}
        )
        
        # Log model and token info
        model_used = result.get("model_used", model_to_use)
        token_usage = result.get("token_usage", {})
        
        if model_used:
            self._log(state, f"  Model: {model_used}")
        
        # Track tokens
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        total_tokens = token_usage.get("total_tokens", 0)
        
        if total_tokens > 0:
            self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
            state["total_tokens"] = state.get("total_tokens", 0) + total_tokens
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += prompt_tokens
            state["tokens_by_model"][model_used]["completion"] += completion_tokens
            state["tokens_by_model"][model_used]["total"] += total_tokens
        
        # Track cost for backward compatibility
        if result.get("cost_usd", 0) > 0:
            state["total_cost_usd"] += result["cost_usd"]
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
            finding["execution_profile"] = ((result.get("exploit_contract") or {}).get("runtime_profile") or finding.get("execution_profile"))
            finding["exploit_contract"] = result.get("exploit_contract")
            finding["pov_model_used"] = model_used
            finding["pov_openrouter_usage"] = result.get("openrouter_usage", {})
            self._append_scan_openrouter_usage(state, finding["pov_openrouter_usage"], "pov_generation", finding=finding)
            finding["pov_prompt_tokens"] = prompt_tokens
            finding["pov_completion_tokens"] = completion_tokens
            finding["pov_total_tokens"] = total_tokens
            # Cost already added above, just store it in finding
            if "cost_usd" not in finding:
                finding["cost_usd"] = result.get("cost_usd", 0)
            self._log(state, "  PoV generated successfully")
        else:
            finding["final_status"] = "pov_generation_failed"
            self._log(state, f"  PoV generation failed: {result.get('error')}")
        
        state["findings"][idx] = finding
        return state
    
    def _node_validate_pov(self, state: ScanState) -> ScanState:
        """Validate PoV script using hybrid approach"""
        state["status"] = ScanStatus.VALIDATING_POV
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            self._log(state, "No PoV script available for validation")
            finding["validation_result"] = {
                "is_valid": False,
                "issues": ["No PoV script generated"],
                "suggestions": [],
                "will_trigger": "NO",
                "validation_method": "missing_pov",
                "static_result": None,
                "unit_test_result": None,
            }
            state["findings"][idx] = finding
            return state
        
        self._log(state, "Validating PoV script...")
        
        verifier = get_verifier()
        
        # Get vulnerable code for unit test validation
        vulnerable_code = finding.get("code_chunk", "")
        
        model_to_use = self._get_selected_model(state)
        result = verifier.validate_pov(
            pov_script=finding["pov_script"],
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=vulnerable_code,
            exploit_contract=finding.get("exploit_contract") or {},
            model_name=model_to_use
        )
        
        # Log validation method used
        validation_method = result.get("validation_method", "unknown")
        self._log(state, f"  Validation method: {validation_method}")
        
        # Log static analysis results if available
        if result.get("static_result"):
            static = result["static_result"]
            self._log(state, f"  Static analysis confidence: {static['confidence']:.0%}")
            if static["matched_patterns"]:
                self._log(state, f"  Matched patterns: {len(static['matched_patterns'])}")
        
        # Log unit test results if available
        if result.get("unit_test_result"):
            unit_test = result["unit_test_result"]
            if unit_test.get("vulnerability_triggered"):
                self._log(state, "  ✓ Unit test confirmed vulnerability trigger!")
            elif unit_test.get("success"):
                self._log(state, "  Unit test executed (vulnerability not triggered)")
            else:
                self._log(state, f"  Unit test failed: {unit_test.get('stderr', 'Unknown error')[:100]}")
        
        if result["is_valid"]:
            will_trigger = result.get("will_trigger", "MAYBE")
            self._log(state, f"  PoV validation passed (will trigger: {will_trigger})")
        else:
            issues = result.get("issues", [])
            self._log(state, f"  PoV validation failed: {issues[:2]}")  # Log first 2 issues
            finding["retry_count"] += 1
        
        # Store validation result in finding
        finding["validation_result"] = result
        self._append_scan_openrouter_usage(state, result.get("openrouter_usage"), "llm_validation", finding=finding)
        
        state["findings"][idx] = finding
        return state

    def _node_refine_pov(self, state: ScanState) -> ScanState:
        """Refine PoV script based on validation errors (Self-Healing)"""
        state["status"] = ScanStatus.GENERATING_POV  # Still generating
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            return state
        
        # Get validation errors
        validation_result = finding.get("validation_result", {})
        validation_errors = validation_result.get("issues", [])
        
        if not validation_errors:
            self._log(state, "No validation errors to refine, skipping refinement")
            return state
        
        self._log(state, f"Refining PoV for {finding['cwe_type']} (attempt {finding['retry_count'] + 1})...")
        self._log(state, f"  Errors: {validation_errors[:2]}")
        
        # Get code context
        full_code_context = ""
        try:
            full_code_context = get_code_ingester().get_file_content(
                finding["filepath"], state["scan_id"]
            ) or ""
        except Exception:
            full_code_context = ""

        if not full_code_context:
            try:
                candidate_path = finding["filepath"]
                abs_path = candidate_path if os.path.isabs(candidate_path) else os.path.join(state["codebase_path"], candidate_path)
                if os.path.isfile(abs_path):
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        full_code_context = f.read()
            except Exception:
                full_code_context = full_code_context or ""

        code_context = self._build_pov_context(finding, full_code_context, state)
        self._log(state, f"Using PoV context window: {len(code_context)} chars")
        
        # Get target language
        target_language = state.get("detected_language", "python")
        
        model_to_use = self._get_selected_model(state)
        
        # Initialize refinement history
        if not isinstance(finding.get("refinement_history"), list):
            finding["refinement_history"] = []
        
        # Call verifier to refine the PoV
        verifier = get_verifier()
        result = verifier.refine_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding.get("code_chunk", ""),
            explanation=finding["llm_explanation"],
            code_context=code_context,
            failed_pov=finding["pov_script"],
            validation_errors=validation_errors,
            attempt_number=finding["retry_count"] + 1,
            target_language=target_language,
            model_name=model_to_use,
            exploit_contract=finding.get("exploit_contract") or {}
        )
        
        # Track refinement in history with tokens
        model_used = result.get("model_used", model_to_use)
        token_usage = result.get("token_usage", {})
        
        self._append_scan_openrouter_usage(state, result.get("openrouter_usage"), "pov_refinement", finding=finding, attempt=finding["retry_count"] + 1)
        finding["refinement_history"].append({
            "attempt": finding["retry_count"] + 1,
            "errors": validation_errors,
            "success": result.get("success", False),
            "timestamp": result.get("timestamp", ""),
            "model_used": model_used,
            "tokens": token_usage,
            "cost_usd": result.get("cost_usd", 0.0),
            "openrouter_usage": result.get("openrouter_usage", {})
        })
        
        # Track tokens
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        total_tokens = token_usage.get("total_tokens", 0)
        
        if total_tokens > 0:
            state["total_tokens"] = state.get("total_tokens", 0) + total_tokens
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += prompt_tokens
            state["tokens_by_model"][model_used]["completion"] += completion_tokens
            state["tokens_by_model"][model_used]["total"] += total_tokens
        
        # Update cost tracking (for backward compatibility)
        if result.get("cost_usd", 0) > 0:
            state["total_cost_usd"] += result["cost_usd"]
            finding["cost_usd"] = finding.get("cost_usd", 0) + result["cost_usd"]
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
            finding["execution_profile"] = ((result.get("exploit_contract") or {}).get("runtime_profile") or finding.get("execution_profile"))
            finding["exploit_contract"] = result.get("exploit_contract") or finding.get("exploit_contract")
            finding["retry_count"] += 1
            self._log(state, f"  PoV refined successfully (attempt {finding['retry_count']})")
            if total_tokens > 0:
                self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
        else:
            self._log(state, f"  PoV refinement failed: {result.get('error')}")
            finding["retry_count"] += 1
        
        state["findings"][idx] = finding
        return state

    def _node_run_in_docker(self, state: ScanState) -> ScanState:
        """Run PoV proof and only confirm findings when exploit evidence is observed."""
        state["status"] = ScanStatus.RUNNING_POV

        idx = state.get("current_finding_idx", 0)
        self._update_scan_runtime(state, status=ScanStatus.RUNNING_POV, progress=min(97, 65 + idx * 3))
        if idx >= len(state["findings"]):
            return state

        self._update_scan_runtime(state, status=ScanStatus.VALIDATING_POV, progress=min(95, 55 + idx * 3))
        finding = state["findings"][idx]

        if not finding.get("pov_script"):
            return state

        # Check if we already have validation results
        validation_result = finding.get("validation_result") or {}
        unit_test_result = validation_result.get("unit_test_result") or {}

        # If unit test already confirmed vulnerability, use that result
        if unit_test_result.get("vulnerability_triggered"):
            self._log(state, "Using unit test confirmation (vulnerability triggered)")
            finding["pov_result"] = {
                "success": True,
                "vulnerability_triggered": True,
                "validation_method": "unit_test",
                "stdout": unit_test_result.get("stdout", ""),
                "stderr": unit_test_result.get("stderr", ""),
                "execution_time_s": unit_test_result.get("execution_time_s", 0)
            }
            self._log(state, "VULNERABILITY CONFIRMED")
            state["findings"][idx] = finding
            return state

        # Static validation is advisory only; runtime evidence is still required
        static_result = validation_result.get("static_result", {})
        if static_result.get("is_valid") and static_result.get("confidence", 0) >= 0.8:
            self._log(state, "Static validation looks strong, but runtime exploit evidence is still required before confirmation")

        # Fall back to runtime execution for cases where validation was inconclusive
        if not finding.get("pov_script"):
            self._log(state, "No PoV script available, skipping runtime proof")
            finding["pov_result"] = {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": "No PoV script generated",
                "exit_code": -1,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
            state["findings"][idx] = finding
            return state

        execution_profile = self._infer_runtime_profile(finding, state)
        target_language = execution_profile if execution_profile in {"c", "cpp", "python", "javascript", "typescript", "node"} else (finding.get("detected_language") or state.get("detected_language") or "python")
        self._log(state, f"Using execution profile: {execution_profile}")

        specialized_result = get_pov_tester().test_with_contract(
            pov_script=finding["pov_script"],
            scan_id=state["scan_id"],
            cwe_type=finding.get("cwe_type", ""),
            codebase_path=state["codebase_path"],
            exploit_contract=finding.get("exploit_contract") or {},
            target_language=target_language,
            vulnerable_code=finding.get("code_chunk", ""),
            filepath=finding.get("filepath", "")
        )

        if specialized_result.get("success"):
            self._log(state, f"Specialized runtime harness used: {specialized_result.get('validation_method', 'runtime_harness')}")
            finding["pov_result"] = specialized_result
            result = specialized_result
        elif specialized_result.get("proof_infrastructure_error"):
            self._log(state, f"Native/runtime proof harness failed: {specialized_result.get('stderr', 'unknown error')}")
            result = specialized_result
            finding["pov_result"] = result
        else:
            self._log(state, f"Specialized runtime harness unavailable: {specialized_result.get('stderr', 'unknown error')}")
            self._log(state, "Running PoV in Docker (generic fallback)...")
            runner = get_docker_runner()
            result = runner.run_pov(
                pov_script=finding["pov_script"],
                scan_id=state["scan_id"],
                pov_id=str(idx),
                execution_profile=execution_profile,
                target_language=target_language,
                exploit_contract=finding.get("exploit_contract") or {}
            )
            finding["pov_result"] = result

        finding["pov_result"] = result

        if result["vulnerability_triggered"]:
            self._log(state, "VULNERABILITY TRIGGERED")
        else:
            self._log(state, f"  PoV did not trigger vulnerability (exit code: {result['exit_code']})")


        state["findings"][idx] = finding
        return state

    def _node_log_confirmed(self, state: ScanState) -> ScanState:
        """Log confirmed vulnerability"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "confirmed"
            # Track confirmed count for early termination
            state["confirmed_count"] = state.get("confirmed_count", 0) + 1
            self._log(state, f"Confirmed vulnerability #{state['confirmed_count']}: {state['findings'][idx].get('cwe_type', 'UNCLASSIFIED')}")
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        # Check if there are more findings to process
        if state["current_finding_idx"] < len(state["findings"]):
            # Continue with next finding
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _node_log_skip(self, state: ScanState) -> ScanState:
        """Log skipped finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            if not state["findings"][idx].get("final_status"):
                state["findings"][idx]["final_status"] = "skipped"
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _node_log_failure(self, state: ScanState) -> ScanState:
        """Log failed finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "failed"
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _should_generate_pov(self, state: ScanState) -> str:
        """Determine if we should generate PoV for current finding"""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            self._log(state, "No findings to process, ending workflow")
            return "log_skip"
        
        # Early termination: Stop after N confirmed findings
        confirmed_count = state.get("confirmed_count", 0)
        if settings.EARLY_STOP_AFTER_CONFIRMED > 0 and confirmed_count >= settings.EARLY_STOP_AFTER_CONFIRMED:
            self._log(state, f"Early termination: {confirmed_count} confirmed findings reached (limit: {settings.EARLY_STOP_AFTER_CONFIRMED})")
            # Mark remaining findings as skipped
            for i in range(idx, len(state["findings"])):
                state["findings"][i]["final_status"] = "skipped_early_stop"
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
            return "log_skip"
        
        # Lite mode: Skip PoV generation entirely, just report findings
        if settings.LITE_MODE:
            finding = state["findings"][idx]
            verdict = finding.get("llm_verdict", "UNKNOWN")
            confidence = finding.get("confidence", 0.0)
            if verdict == "REAL" or confidence >= settings.MIN_CONFIDENCE_FOR_POV:
                finding["final_status"] = "unproven_lite"
            else:
                finding["final_status"] = "skipped_lite"
            self._log(state, f"LITE MODE: Finding {idx} status={finding['final_status']} (no exploit proof attempted)")
            return "log_skip"
        
        finding = state["findings"][idx]
        verdict = finding.get("llm_verdict", "UNKNOWN")
        confidence = finding.get("confidence", 0.0)
        source = finding.get("source", "unknown")
        
        self._log(state, f"Decision for finding {idx}: verdict={verdict}, confidence={confidence:.2f}, source={source}")
        
        # Trust high-confidence findings from static analyzers (CodeQL, Semgrep)
        # Skip re-investigation if confidence >= 0.8 and source is a trusted static analyzer
        trusted_sources = {"codeql", "semgrep"}
        if source in trusted_sources and confidence >= 0.8 and verdict in ["UNKNOWN", ""]:
            self._log(state, f"Finding {idx} from {source} has high confidence ({confidence:.2f}), trusting static analysis result")
            # Mark as REAL to proceed to PoV generation
            finding["llm_verdict"] = "REAL"
            finding["llm_explanation"] = f"Trusted finding from {source} static analysis with {confidence:.0%} confidence"
            state["findings"][idx] = finding
            verdict = "REAL"
        
        # Only generate PoV for findings that meet minimum confidence threshold
        if verdict == "REAL" and confidence >= settings.MIN_CONFIDENCE_FOR_POV:
            if state.get("proofs_attempted", 0) >= settings.PROOF_MAX_FINDINGS:
                finding["final_status"] = "unproven_budget_exhausted"
                self._log(state, f"Proof budget reached ({settings.PROOF_MAX_FINDINGS}); recording finding without runtime proof")
                return "log_skip"
            state["proofs_attempted"] = state.get("proofs_attempted", 0) + 1
            self._log(state, f"Finding {idx} is REAL with high confidence, generating PoV")
            self._update_scan_runtime(state, status=ScanStatus.GENERATING_POV, progress=min(92, 50 + idx * 3))
            return "generate_pov"
        else:
            if verdict == "REAL":
                finding["final_status"] = "unproven_low_confidence"
            self._log(state, f"Finding {idx} skipped (verdict={verdict}, confidence={confidence:.2f})")
            return "log_skip"
    
    def _should_run_pov(self, state: ScanState) -> str:
        """Determine if we should run PoV, refine, or fail"""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return "log_failure"
        
        finding = state["findings"][idx]
        validation_result = finding.get("validation_result") or {}
        if not isinstance(validation_result, dict):
            validation_result = {}

        pov_script = (finding.get("pov_script") or "").strip()
        if not pov_script:
            self._log(state, "No PoV script available after generation/validation; marking finding as failed")
            return "log_failure"
        
        # Check if validation passed
        if validation_result.get("is_valid"):
            return "run_in_docker"
        
        # Check if we can retry with refinement
        if finding["retry_count"] < settings.MAX_RETRIES:
            self._log(state, f"PoV validation failed, attempting refinement (attempt {finding['retry_count'] + 1}/{settings.MAX_RETRIES})")
            return "refine_pov"
        else:
            self._log(state, f"PoV validation failed after {settings.MAX_RETRIES} attempts")
            return "log_failure"
    
    def _after_runtime_proof(self, state: ScanState) -> str:
        """Route based on whether runtime proof actually triggered the vulnerability."""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state.get("findings", [])):
            return "log_failure"
        finding = state["findings"][idx]
        pov_result = finding.get("pov_result") or {}
        if isinstance(pov_result, dict) and pov_result.get("vulnerability_triggered"):
            return "log_confirmed"
        self._log(state, "Runtime proof did not trigger the vulnerability")
        return "log_failure"

    def _has_more_findings(self, state: ScanState) -> str:
        """Check if there are more findings to process after logging"""
        idx = state.get("current_finding_idx", 0)
        total = len(state["findings"])
        
        self._log(state, f"Checking for more findings: current={idx}, total={total}")
        
        # Safety check: prevent infinite loop if idx is not advancing
        if idx >= total:
            # All findings processed, mark as completed
            self._log(state, f"All {total} findings processed, completing scan")
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
            return "end"
        
        # Check if current finding has already been processed (has final_status or was investigated in parallel)
        finding = state["findings"][idx]
        if finding.get("final_status"):
            self._log(state, f"Finding {idx} already processed with status={finding['final_status']}, advancing index")
            state["current_finding_idx"] = idx + 1
            # Recursively check again after advancing
            return self._has_more_findings(state)
        
        # Check if finding was already investigated (e.g., via parallel processing) but doesn't have final_status yet
        # In this case, we need to route it through the decision logic to set final_status
        if finding.get("llm_verdict") and not finding.get("final_status"):
            self._log(state, f"Finding {idx} was investigated (verdict={finding['llm_verdict']}), routing to decision")
            return "investigate"  # Route through investigate -> should_generate_pov -> log_skip to set final_status
        
        self._log(state, f"Processing next finding ({idx + 1}/{total})")
        return "investigate"  # More findings to process
    
    def _update_scan_runtime(self, state: Optional[ScanState], **updates):
        if state is None or not state.get("scan_id"):
            return
        try:
            from app.scan_manager import get_scan_manager
            serializable = {}
            for key, value in updates.items():
                if key == "status" and hasattr(value, "value"):
                    serializable[key] = value.value
                elif key == "findings" and value is not None:
                    serializable[key] = [dict(f) if isinstance(f, dict) else f for f in value]
                else:
                    serializable[key] = value
            get_scan_manager().update_scan(state["scan_id"], **serializable)
        except Exception as e:
            print(f"[AgentGraph] Failed to update scan runtime: {e}")

    def _log(self, state: Optional[ScanState], message: str):
        """Add log message to state and stream to scan manager in real-time"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}"
        
        # Only append to state if state is not None
        if state is not None:
            state["logs"].append(log_entry)
        
        # Also log to scan manager for real-time streaming using thread-safe method
        if state is not None:
            try:
                from app.scan_manager import get_scan_manager
                scan_manager = get_scan_manager()
                # Use the thread-safe append_log method
                scan_manager.append_log(state["scan_id"], log_entry)
            except Exception as e:
                # Log error for debugging but don't break the scan
                print(f"[AgentGraph] Failed to log to scan manager: {e}")
                pass
    
    def _append_scan_openrouter_usage(self, state: Optional[ScanState], usage: Any, agent_role: str, finding: Optional[Dict[str, Any]] = None, attempt: Optional[int] = None):
        if state is None:
            return
        if "scan_openrouter_usage" not in state or state["scan_openrouter_usage"] is None:
            state["scan_openrouter_usage"] = []

        entries: List[Dict[str, Any]] = []
        if isinstance(usage, dict) and usage:
            entries = [dict(usage)]
        elif isinstance(usage, list):
            entries = [dict(item) for item in usage if isinstance(item, dict) and item]
        elif isinstance(usage, str) and usage.strip():
            try:
                parsed = json.loads(usage)
                if isinstance(parsed, dict):
                    entries = [dict(parsed)]
                elif isinstance(parsed, list):
                    entries = [dict(item) for item in parsed if isinstance(item, dict) and item]
            except Exception:
                entries = []

        if not entries:
            return

        existing_generation_ids = {
            str(item.get("generation_id")) for item in (state.get("scan_openrouter_usage") or [])
            if isinstance(item, dict) and item.get("generation_id")
        }

        for entry in entries:
            generation_id = str(entry.get("generation_id") or "").strip()
            if generation_id and generation_id in existing_generation_ids:
                continue
            entry.setdefault("agent_role", agent_role)
            if finding:
                entry.setdefault("filepath", finding.get("filepath", ""))
                entry.setdefault("line_number", finding.get("line_number", 0))
                entry.setdefault("cwe_type", finding.get("cwe_type", "UNCLASSIFIED"))
            if attempt is not None:
                entry.setdefault("attempt", attempt)
            state["scan_openrouter_usage"].append(entry)
            if generation_id:
                existing_generation_ids.add(generation_id)

    def _estimate_cost(self, inference_time_s: float) -> float:
        """
        DEPRECATED: Use actual token-based cost calculation instead.
        This method is kept for fallback only.
        """
        # This is a rough estimate - actual costs should be calculated from token usage
        # For academic accuracy, we should never rely on this estimation
        if settings.MODEL_MODE == "online":
            # Very rough estimate - should not be used for actual cost tracking
            return inference_time_s * 0.001  # Reduced from 0.01 to be more realistic
        else:
            # Offline: no cost
            return 0.0
    
    def run_scan(
        self,
        codebase_path: str,
        model_name: str,
        cwes: List[str],
        scan_id: Optional[str] = None,
        preloaded_findings: Optional[List[VulnerabilityState]] = None,
        detected_language: Optional[str] = None,
        model_mode: Optional[str] = None,
        openrouter_api_key: Optional[str] = None
    ) -> ScanState:
        """
        Run a complete vulnerability scan
        
        Args:
            codebase_path: Path to codebase
            model_name: LLM model name
            cwes: List of CWEs to check
            scan_id: Optional scan ID
            preloaded_findings: Optional preloaded findings for replay
            detected_language: Optional detected language
        
        Returns:
            Final scan state
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())
        
        initial_state = ScanState(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            codebase_path=codebase_path,
            model_name=model_name,
            model_mode=model_mode or settings.resolve_model_mode(model_name),
            cwes=cwes,
            findings=[],
            preloaded_findings=preloaded_findings,
            detected_language=detected_language,
            current_finding_idx=0,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            total_cost_usd=0.0,
            total_tokens=0,
            tokens_by_model={},
            logs=[],
            error=None,
            proofs_attempted=0,
            confirmed_count=0,
            openrouter_api_key=openrouter_api_key,
            rag_ready=False,
            rag_stats=None,
            scan_openrouter_usage=[]
        )
        
        # Run the graph with recursion limit
        from langchain_core.runnables import RunnableConfig
        config = RunnableConfig(recursion_limit=500)
        final_state = self.graph.invoke(initial_state, config=config)
        
        return final_state


# Global agent graph instance
agent_graph = AgentGraph()


def get_agent_graph() -> AgentGraph:
    """Get the global agent graph instance"""
    return agent_graph
























