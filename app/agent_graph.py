"""
AutoPoV Agent Graph Module
LangGraph-based agentic workflow for vulnerability detection
"""

import os
import json
import uuid
import shutil
from typing import Dict, Any, List, Optional, TypedDict, Annotated
from datetime import datetime, timezone
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

import subprocess

from app.config import settings
from app.target_metadata import merge_contract_hints, path_hints_for, resolve_curated_target_metadata
from agents.llm_scout import get_llm_scout
from agents.ingest_codebase import get_code_ingester
from agents.investigator import get_investigator
from agents.verifier import get_verifier
from agents.docker_runner import get_docker_runner
from agents.pov_tester import get_pov_tester
from agents.pov_sanitizer import sanitize_pov_script
from agents.oracle_policy import classify_signal_detailed
from agents.probe_runner import run_probe, format_probe_context
from agents.trace_agent import run_trace, format_trace_context
from agents.pov_coordinator import decide as coordinator_decide, format_constraints_for_prompt
from agents.recon_agent import run_recon, ReconReport


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
    target_type: str
    target_label: Optional[str]
    benchmark_metadata: Optional[Dict[str, Any]]
    repo_url: Optional[str]
    target_metadata: Optional[Dict[str, Any]]
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
    probe_result: Optional[Dict[str, Any]]  # Preflight probe results (ProbeResult.to_dict())
    repo_surface_class: Optional[str]  # e.g. 'cli_tool_c', 'library_c', 'python_module', ...
    library_api_context: Optional[str]  # Extracted public API for library_c repos
    trace_result: Optional[Dict[str, Any]]  # Dynamic trace results (TraceResult.to_dict())
    recon_report: Optional[Dict[str, Any]]  # Reconnaissance report (ReconReport.to_dict())
    recon_high_value_files: Optional[List[Dict[str, Any]]]
    recon_historical_vuln_types: Optional[List[str]]
    recon_repo_activity: Optional[Dict[str, Any]]

def _auto_populate_oracle_from_probe(contract: dict, probe_result: dict) -> None:
    """Fill success_indicators from probe data when investigation didn't set them.

    This prevents the contract gate from blocking findings that have probe-resolved
    surface but no explicit success_indicators from the investigation LLM.
    """
    if contract.get('success_indicators') or contract.get('expected_outcome'):
        return  # already populated by investigation
    indicators = []
    surface = str(probe_result.get('probe_surface_type') or '').lower()
    family = str(contract.get('runtime_family') or contract.get('runtime_profile') or '').lower()

    if family in ('c', 'cpp', 'native', 'binary'):
        indicators.append('AddressSanitizer or UndefinedBehaviorSanitizer error output')
        indicators.append('Non-zero exit code indicating crash (SIGSEGV, SIGABRT)')
    elif family in ('python',):
        indicators.append('Unhandled exception traceback demonstrating the vulnerability')
        indicators.append('Non-zero exit code')
    elif family in ('node', 'javascript'):
        indicators.append('Unhandled exception or rejection demonstrating the vulnerability')
        indicators.append('Process crash with non-zero exit code')
    elif family in ('java',):
        indicators.append('Java exception stack trace demonstrating the vulnerability')
        indicators.append('JVM crash or non-zero exit code')

    if surface == 'web_service':
        indicators.append('HTTP response demonstrating unauthorized data access or server error')

    if indicators:
        contract['success_indicators'] = indicators


# ── CVE finding injection helpers (used by _node_recon) ──────────────────────

def _infer_cve_harness_type(proof_type: str, runtime: str) -> str:
    """Select the correct harness type for a CVE based on proof type and runtime."""
    if proof_type == 'crash_signal':
        return 'subprocess_binary'
    if proof_type == 'state_change':
        return 'direct_import' if runtime in ('python', 'node', 'java') \
               else 'subprocess_binary'
    if proof_type == 'information_disclosure':
        return 'http_request' if runtime in ('python', 'node', 'java') \
               else 'direct_import'
    if proof_type == 'observable_output':
        return 'http_request' if runtime in ('python', 'node', 'java') \
               else 'subprocess_binary'
    if proof_type in ('behavioral_deviation', 'resource_exhaustion'):
        return 'direct_import' if runtime in ('python', 'node', 'java') \
               else 'subprocess_binary'
    return 'subprocess_binary'


def _infer_cve_execution_strategy(proof_type: str) -> str:
    """Select execution strategy from proof type."""
    return {
        'crash_signal':           'single_call',
        'state_change':           'single_call',
        'information_disclosure': 'single_call',
        'observable_output':      'single_call',
        'behavioral_deviation':   'single_call',
        'resource_exhaustion':    'repeated_execution',
    }.get(proof_type, 'single_call')


def _build_cve_observable_evidence(
        proof_type: str, hint: str, desc: str) -> list:
    """Build observable evidence list from proof type and hint."""
    base = [hint] if hint else ([desc[:120]] if desc else [])
    extras = {
        'crash_signal':           ['AddressSanitizer', 'heap-buffer-overflow',
                                   'SIGSEGV', 'exit code 134'],
        'state_change':           ['/tmp/autopov_rce.txt exists',
                                   'command output in stdout'],
        'information_disclosure': ['sensitive data in response',
                                   'internal path disclosed'],
        'observable_output':      ['error message in response',
                                   'injected content reflected'],
        'resource_exhaustion':    ['memory usage increased', 'exit code 23',
                                   'process killed OOM'],
        'behavioral_deviation':   ['actual output differs from expected',
                                   'Object.prototype mutated'],
    }.get(proof_type, [])
    return base + [e for e in extras if e not in base]


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

    def _get_model_max_retries(self, state: ScanState) -> int:
        """Return the max refinement retries for the model selected in this scan.

        Uses the per-model capability profile so offline small models get more
        retries (they need it) while large online models use a tighter budget.
        Falls back to settings.MAX_RETRIES when no model is set.
        """
        try:
            model_name = self._get_selected_model(state)
            profile = settings.resolve_model_capability_profile(model_name=model_name)
            return int(profile.get('max_retries') or settings.MAX_RETRIES)
        except Exception:
            return settings.MAX_RETRIES
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Define the state graph
        workflow = StateGraph(ScanState)
        
        # Add nodes
        workflow.add_node("ingest_code", self._node_ingest_code)
        workflow.add_node("run_codeql", self._node_run_codeql)
        workflow.add_node("investigate", self._node_investigate)
        workflow.add_node("probe_target", self._node_probe_target)  # Preflight probe
        workflow.add_node("trace_target", self._node_trace_target)  # Dynamic trace (strace+valgrind)
        workflow.add_node("generate_pov", self._node_generate_pov)
        workflow.add_node("proof_strategy", self._node_proof_strategy)  # v2: proof strategy phase
        workflow.add_node("validate_pov", self._node_validate_pov)
        workflow.add_node("refine_pov", self._node_refine_pov)  # Self-healing refiner
        workflow.add_node("run_in_docker", self._node_run_in_docker)
        workflow.add_node("log_confirmed", self._node_log_confirmed)
        workflow.add_node("log_skip", self._node_log_skip)
        workflow.add_node("log_failure", self._node_log_failure)
        
        # Define edges — recon runs BEFORE discovery so agentic_discovery
        # can use ReconReport's build_system, runtime_family, and attack_surfaces.
        workflow.set_entry_point("ingest_code")
        
        # Add recon node (runs once, before discovery)
        workflow.add_node("recon", self._node_recon)
        # Add a node to log the number of findings before investigation
        workflow.add_node("log_findings_count", self._node_log_findings_count)
        workflow.add_edge("ingest_code", "recon")
        workflow.add_edge("recon", "run_codeql")
        workflow.add_edge("run_codeql", "log_findings_count")
        workflow.add_edge("log_findings_count", "investigate")
        
        # Conditional edges from investigate — route through probe_target before PoV gen
        workflow.add_conditional_edges(
            "investigate",
            self._should_generate_pov,
            {
                "generate_pov": "probe_target",  # probe runs before first PoV generation
                "log_skip": "log_skip"
            }
        )
        workflow.add_edge("probe_target", "trace_target")  # trace runs after probe
        workflow.add_edge("trace_target", "proof_strategy")  # proof strategy runs after trace
        workflow.add_edge("proof_strategy", "generate_pov")
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
                "refine_pov": "refine_pov",
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

    def _summarize_output(self, value: Any, limit: int = 600) -> str:
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[:limit].rstrip() + "\n...[truncated]"

    def _build_runtime_feedback_payload(
        self,
        validation_result: Optional[Dict[str, Any]] = None,
        runtime_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        validation = validation_result or {}
        runtime = runtime_result or {}

        if validation:
            payload["validation"] = {
                "is_valid": bool(validation.get("is_valid")),
                "issues": list(validation.get("issues") or []),
                "suggestions": list(validation.get("suggestions") or []),
                "will_trigger": validation.get("will_trigger"),
                "validation_method": validation.get("validation_method"),
                "static_result": validation.get("static_result"),
                "unit_test_result": validation.get("unit_test_result"),
            }

        if runtime:
            payload["runtime"] = {
                "failure_category": runtime.get("failure_category"),
                "validation_method": runtime.get("validation_method"),
                "proof_infrastructure_error": bool(runtime.get("proof_infrastructure_error")),
                "oracle_result": runtime.get("oracle_result") or {},
                "preflight": runtime.get("preflight") or {},
                "surface": runtime.get("surface") or {},
                "selected_variant": runtime.get("selected_variant"),
                "recommended_input_mode": runtime.get("recommended_input_mode"),
                "supported_input_modes": runtime.get("supported_input_modes") or [],
                "path_exercised": bool(runtime.get("path_exercised")),
                "target_binary": runtime.get("target_binary"),
                "target_url": runtime.get("target_url"),
                "exit_code": runtime.get("exit_code"),
                "stdout_excerpt": self._summarize_output(runtime.get("stdout", "")),
                "stderr_excerpt": self._summarize_output(runtime.get("stderr", "")),
                "build_status": runtime.get("build_status"),
                "build_log": (runtime.get("build_log") or "").strip()[-600:] or None,
            }

            runtime_details = payload["runtime"]
            oracle = runtime_details.get("oracle_result") or {}
            if isinstance(runtime_details.get("preflight"), dict):
                runtime_details["preflight_issues"] = list(runtime_details["preflight"].get("issues") or [])
            if isinstance(runtime_details.get("surface"), dict):
                runtime_details["observed_surface"] = {
                    "options": list(runtime_details["surface"].get("options") or []),
                    "supports_positional_file": runtime_details["surface"].get("supports_positional_file"),
                    "eval_option": runtime_details["surface"].get("eval_option"),
                    "include_option": runtime_details["surface"].get("include_option"),
                    # Preserve help_text so _extract_subcommands_from_surface can parse
                    # CLI subcommands on subsequent generation/refinement calls.
                    "help_text": runtime_details["surface"].get("help_text") or "",
                }
            # When Docker ran the PoV, the preflight --help output is stored directly
            # on the pov_result as 'preflight_help_text' (captured by docker_runner).
            # Promote it into observed_surface so _extract_subcommands_from_surface
            # can parse the Commands: block and populate known_subcommands.
            docker_help = str(runtime.get("preflight_help_text") or "").strip()
            if docker_help:
                obs = runtime_details.setdefault("observed_surface", {})
                if not obs.get("help_text"):
                    obs["help_text"] = docker_help
            if oracle:
                runtime_details["oracle_reason"] = oracle.get("reason")
                runtime_details["matched_markers"] = list(oracle.get("matched_markers") or [])
                runtime_details["self_report_only"] = bool(oracle.get("self_report_only"))

            # FIX-5: Include enriched signal_detail so the refinement prompt can
            # give the LLM precise, actionable crash-type hints instead of raw stdout.
            _sig_detail = runtime.get('signal_detail')
            if _sig_detail and isinstance(_sig_detail, dict):
                runtime_details['signal_detail'] = _sig_detail

        return payload

    def _attach_feedback_to_contract(
        self,
        finding: VulnerabilityState,
        validation_result: Optional[Dict[str, Any]] = None,
        runtime_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        contract = dict(finding.get("exploit_contract") or {})
        runtime_feedback = dict(contract.get("runtime_feedback") or {})
        new_feedback = self._build_runtime_feedback_payload(validation_result=validation_result, runtime_result=runtime_result)
        for key, value in new_feedback.items():
            if value not in (None, "", [], {}):
                runtime_feedback[key] = value
        if runtime_feedback:
            contract["runtime_feedback"] = runtime_feedback
        finding["exploit_contract"] = contract
        return contract

    def _derive_refinement_errors(
        self,
        validation_result: Optional[Dict[str, Any]] = None,
        runtime_result: Optional[Dict[str, Any]] = None,
        finding: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        issues = list((validation_result or {}).get("issues") or [])
        runtime = runtime_result or {}

        # Detect identical refinement outputs — the LLM repeated the same buggy code
        if finding:
            _history = finding.get("refinement_history") or []
            if _history:
                _last_original = _history[-1].get("pov_script") or ""
                _current = finding.get("pov_script") or ""
                if _last_original and _current and _last_original.strip() == _current.strip():
                    issues.append(
                        "CRITICAL: Your previous fix attempt produced IDENTICAL code. "
                        "You are repeating the same bug instead of fixing it. "
                        "You MUST modify the script — do not copy-paste the failed version. "
                        "Review the error message above and change the specific lines that cause the failure."
                    )

        if issues:
            return issues

        failure_category = str(runtime.get("failure_category") or "").strip()
        oracle = runtime.get("oracle_result") or {}
        oracle_reason = str(oracle.get("reason") or "").strip()
        stderr_text = str(runtime.get("stderr") or "").strip()
        stdout_text = str(runtime.get("stdout") or "").strip()
        exit_code = int(runtime.get("exit_code") or -1)

        # ─── Step -1: Detect container timeout (exit_code 124) ───
        if exit_code == 124:
            issues.append(
                "Container timed out: the PoV script or build took too long and was killed. "
                "Simplify the exploit: reduce payload size, avoid unnecessary compilation steps, "
                "and ensure the binary invocation completes within the timeout window."
            )
            return issues

        # ─── Step 0: Inject verbatim Python traceback FIRST so the LLM sees the exact error ───
        # This must appear BEFORE heuristic hints so the model knows precisely what failed.
        _stderr_lower = stderr_text.lower()
        if 'traceback (most recent call last)' in _stderr_lower or 'syntaxerror' in _stderr_lower:
            _tb_snippet = stderr_text[:800].strip()
            issues.append(f"Python traceback from last run:\n{_tb_snippet}")

        # ─── Step 1: Specific pattern detections (highest priority, exact fixes) ───

        # bytes + text=True subprocess bug
        if "'bytes' object has no attribute 'encode'" in stderr_text or "bytes' object has no attribute 'encode'" in stderr_text:
            issues.append(
                "CRITICAL: You passed bytes to subprocess.run() with text=True. "
                "Fix: either decode the payload first (input=payload.decode('latin-1', errors='replace')) "
                "or remove text=True and pass bytes directly (input=payload, capture_output=True). "
                "Do NOT mix bytes payloads with text=True."
            )
            return issues

        # Wrong binary name — TARGET_BINARY doesn't match probe-discovered binary
        _probe_bin_name = str(((finding or {}).get('exploit_contract') or {}).get('probe_binary_name') or '').strip()
        if _probe_bin_name and ('[autopov] binary not found:' in _stderr_lower):
            # Extract what name was used
            _bn_match = re.search(r'\[autopov\] binary not found: ([\w.-]+)', stderr_text)
            _wrong_name = _bn_match.group(1) if _bn_match else 'unknown'
            if _wrong_name != _probe_bin_name:
                issues.append(
                    f"CRITICAL: Wrong binary name. "
                    f"The script searched for '{_wrong_name}' but the probe discovered the actual binary is "
                    f"'{_probe_bin_name}'. Use os.environ.get('TARGET_BINARY') to get the correct path. "
                    f"The harness sets TARGET_BINARY to '{_probe_bin_name}'."
                )
                return issues

        # Wrong input surface — stdin used when binary needs a file argument
        _probe_input_surface = str(((finding or {}).get('exploit_contract') or {}).get('probe_input_surface') or '').strip()
        if (oracle_reason == 'no_oracle_match' and _probe_input_surface == 'file_argument'
                and any(kw in (runtime_result or {}).get('stderr', '') + (runtime_result or {}).get('stdout', '')
                        for kw in ('no files to process', 'no input file', 'missing file', 'expected file'))):
            issues.append(
                f"CRITICAL: This binary ({_probe_bin_name or 'target'}) reads from a FILE ARGUMENT, not stdin. "
                "Create a crafted file and pass its path as a CLI argument. "
                "Do NOT use subprocess.run(argv, input=payload, ...). "
                "Instead: write payload to a temp file, then call [binary, '/tmp/crafted_input.ext']."
            )
            return issues

        if issues:
            return issues

        # --- Enrich with classify_signal_detailed actionable hint ---
        # This gives the model a precise, human-readable explanation of WHY the
        # previous run failed and WHAT to do about it, before more specific checks.
        try:
            sig_detail = classify_signal_detailed(stdout_text, stderr_text, exit_code)
            # Only inject hint when it adds new information (not 'success')
            if sig_detail.recovery_strategy != 'success' and sig_detail.actionable_hint:
                issues.append(f"Signal analysis ({sig_detail.crash_type}): {sig_detail.reason}")
                issues.append(f"Recovery hint: {sig_detail.actionable_hint}")
                # For exec_failed with check_build, also expose the build log
                if sig_detail.crash_type == 'exec_failed' and sig_detail.recovery_strategy == 'check_build':
                    build_log = (runtime.get("build_log") or "").strip()
                    if build_log:
                        issues.append(f"Build log (last lines):\n{build_log[-800:]}")
            # Store structured signal_detail on finding for injection into refinement prompt
            if finding is not None and sig_detail.recovery_strategy != 'success':
                finding['_signal_detail'] = {
                    'crash_type': sig_detail.crash_type,
                    'reason': sig_detail.reason,
                    'actionable_hint': sig_detail.actionable_hint,
                    'recovery_strategy': sig_detail.recovery_strategy,
                }
        except Exception:
            pass

        # ── Issue #13: Enrich refinement with actual output + actionable hints ──
        # When there's a strong sanitizer crash but the path relevance check failed,
        # extract the ASan crash details so the LLM knows WHAT crashed and can
        # redirect to the correct binary.
        if oracle_reason == 'strong_signal+path_not_relevant':
            _asan_match = re.search(r'ERROR: AddressSanitizer[^\n]*\n[^\n]*\n[^\n]*', stderr_text)
            if not _asan_match:
                _asan_match = re.search(r'ERROR: AddressSanitizer[^\n]*\n[^\n]*\n[^\n]*', stdout_text)
            _crash_summary = _asan_match.group(0).strip()[:400] if _asan_match else ''
            _target_bin = str(((finding or {}).get('exploit_contract') or {}).get('probe_binary_name') or '').strip()
            issues.append(
                f"STRONG CRASH DETECTED but in a different binary/code path than the target. "
                f"The exploit IS triggering a real vulnerability — just not in the target binary. "
                f"You MUST redirect the exploit to target the correct binary. "
                f"Use os.environ.get('TARGET_BINARY') for the correct path"
                f"{f' (binary name: {_target_bin})' if _target_bin else ''}. "
                f"Ensure you are running the TARGET BINARY, not a different executable."
            )
            if _crash_summary:
                issues.append(f"ASan crash details:\n{_crash_summary}")
            if stderr_text:
                issues.append(f"Runtime stderr (last 400 chars): {self._summarize_output(stderr_text, limit=400)}")

        # ── Issue #13: When ASan crash IS captured but oracle didn't confirm, show details ──
        # Even when the oracle result is no_oracle_match, if ASan output exists, the LLM
        # benefits from seeing the exact crash location so it can refine the payload.
        elif oracle_reason == 'no_oracle_match' and 'AddressSanitizer' in stderr_text:
            _asan_match2 = re.search(r'ERROR: AddressSanitizer[^\n]*\n[^\n]*\n[^\n]*', stderr_text)
            if _asan_match2:
                issues.append(f"ASan crash was captured but oracle didn't confirm the vulnerability. Details:\n{_asan_match2.group(0).strip()[:400]}")

        # ——— New pattern detections: linker errors, harness not found, crash w/o ASan, tempfile misuse ———
        if 'undefined reference' in stderr_text:
            issues.append(
                'Linker error: missing source files. Compile all relevant *.c/*.cpp files '
                'using glob (e.g. glob.glob(\'/workspace/codebase/src/*.c\')). Or link against '
                'the library with -l flags from AUTOPOV_LIB_NAMES.'
            )
        if 'No such file or directory' in stderr_text and 'harness' in stderr_text.lower():
            issues.append(
                'Harness file not found. Write harness source to /tmp/harness.c and compile '
                'with full -I/-L flags from AUTOPOV_LIB_INCLUDE_DIRS and AUTOPOV_LIB_LINK_DIRS env vars.'
            )
        if exit_code in (134, 139) and 'AddressSanitizer' not in stderr_text and 'UndefinedBehaviorSanitizer' not in stderr_text:
            issues.append(
                'Crash detected (signal) but no ASan/UBSan output captured. Ensure the binary '
                'was compiled with -fsanitize=address,undefined. Print stderr BEFORE any '
                '"VULNERABILITY TRIGGERED" message.'
            )
        if 'tempfile.tempdir' in stderr_text:
            issues.append(
                'tempfile.tempdir() is not a function. Use tempfile.NamedTemporaryFile() '
                'or tempfile.mkdtemp() to create temporary files/directories.'
            )

        # ——— Specific Python runtime error detections (highest priority for env failures) ———
        # These give the LLM exact fixes instead of generic "environment failure" hints.
        _stderr_lower = stderr_text.lower()

        if "attributeerror: 'str' object has no attribute 'decode'" in _stderr_lower:
            issues.append(
                "CRITICAL BUG: You used subprocess.run(..., text=True) AND called .decode() on the result. "
                "When text=True is set, result.stdout/result.stderr are already strings — .decode() crashes. "
                "FIX: Remove ALL .decode() calls. Use: stdout = result.stdout or ''  (no .decode())."
            )
            return issues

        if "nameerror: name" in _stderr_lower and "is not defined" in _stderr_lower:
            _name_match = re.search(r"NameError: name '([a-zA-Z0-9_]+)' is not defined", stderr_text)
            _bad_name = _name_match.group(1) if _name_match else 'a variable'
            issues.append(
                f"CRITICAL BUG: NameError — {_bad_name} is not defined. "
                f"Make sure {_bad_name} is defined before use, or use the correct variable name. "
                f"If you meant the target binary, use TARGET_BINARY (set at module level)."
            )
            return issues

        if "modulenotfounderror: no module named 'requests'" in _stderr_lower:
            issues.append(
                "CRITICAL BUG: The 'requests' library is not installed in the proof container. "
                "FIX: Use urllib.request from the Python standard library instead of 'requests'."
            )
            return issues

        if "filenotfounderror: [errno 2] no such file or directory" in _stderr_lower:
            _fnf_match = re.search(r"No such file or directory: '([^']+)'", stderr_text)
            _missing_path = _fnf_match.group(1) if _fnf_match else 'the target file'
            issues.append(
                f"CRITICAL BUG: FileNotFoundError — {_missing_path} does not exist. "
                f"If this is the target binary, use os.environ.get('TARGET_BINARY') instead of a hardcoded path. "
                f"If this is a source file for compilation, the binary is ALREADY BUILT — do NOT recompile."
            )
            return issues

        if "typeerror: a bytes-like object is required, not 'str'" in _stderr_lower:
            issues.append(
                "CRITICAL BUG: You passed bytes to subprocess.run() with text=True. "
                "FIX: Either (a) remove text=True and keep bytes input, or "
                "(b) decode the payload first: input=payload.decode('latin-1', errors='replace'). "
                "Do NOT mix bytes payloads with text=True."
            )
            return issues

        # ——— Detect key-file-not-found: binary ran but couldn't open its key material ———
        # Pattern: "failed to open key file" / path to .sec/.pub not found.
        # This means bootstrap (keygen) didn't run, or ran with the wrong HOME.
        # Must be checked BEFORE the generic binary_not_found block (which also
        # fires on "No such file or directory" and would give a misleading hint).
        _key_file_patterns = (
            'failed to open key file',
            'failed to open secret key',
            'failed to open public key',
        )
        _key_path_patterns = ('.sec', '.pub', '.seckey', '.pubkey', 'secret key', 'key file')
        _stderr_lower = stderr_text.lower()
        _is_key_missing = (
            any(p in _stderr_lower for p in _key_file_patterns)
            or (
                'no such file or directory' in _stderr_lower
                and any(p in _stderr_lower for p in _key_path_patterns)
            )
        ) and not runtime.get('proof_infrastructure_error')
        if _is_key_missing:
            # Find the bootstrap subcommand from the contract (keygen, init, etc.)
            _BOOTSTRAP_HINTS_SET = {'keygen', 'init', 'setup', 'configure', 'genkey', 'gen-key', 'generate-key'}
            _known_subs = [
                str(x).strip().lower()
                for x in (
                    (finding.get('exploit_contract') or {}).get('known_subcommands')
                    or (finding.get('exploit_contract') or {}).get('proof_plan', {}).get('observed_subcommands')
                    or []
                )
                if str(x).strip()
            ]
            _boot_sub = next((s for s in _known_subs if s in _BOOTSTRAP_HINTS_SET), 'keygen')
            issues.append(
                f"Key material missing: the binary could not open its secret key file. "
                f"You MUST generate key material BEFORE calling extract/archive. "
                f"Step 1: run `{_boot_sub}` with a passphrase piped to stdin (e.g. via pty or stdin pipe). "
                f"Step 2: set HOME env var to a writable temp directory before running keygen. "
                f"Step 3: call the trigger subcommand with the SAME HOME so it finds the keys. "
                f"AUTOPOV_BOOTSTRAP_HOME env var is already set — use it as the HOME path."
            )
            if stderr_text:
                issues.append(f"Runtime stderr: {self._summarize_output(stderr_text, limit=240)}")
            return issues

        # ——— Detect binary-not-found by name (hardcoded bare name in script) ———
        # This is distinct from environment_failure (binary not built at all).
        # It means the binary was built but the script used a bare name on $PATH
        # instead of the absolute path from os.environ['TARGET_BINARY'].
        binary_not_found = (
            'no such file or directory' in stderr_text.lower()
            or 'command not found' in stderr_text.lower()
            or 'errno 2' in stderr_text.lower()
            or 'filenotfounderror' in stderr_text.lower()
        ) and not runtime.get("proof_infrastructure_error")
        if binary_not_found:
            _target_bin = (
                runtime.get('selected_binary')
                or runtime.get('target_binary')
                or 'the-binary'
            )
            _bin_name = os.path.basename(str(_target_bin)).strip() or 'the-binary'
            issues.append(
                f"Binary not found: the PoV script used a hardcoded binary name that does not exist "
                f"on $PATH inside the container. Fix: replace any hardcoded name like "
                f"subprocess.run(['{_bin_name}', ...]) with "
                f"TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN'). "
                f"The container always sets TARGET_BINARY to the full absolute path of the built binary."
            )
            if _target_bin and _target_bin != 'the-binary':
                issues.append(
                    f"Correct binary path (set by container): use os.environ['TARGET_BINARY'] — "
                    f"it resolves to the absolute path (e.g. {_target_bin})"
                )
            if stderr_text:
                issues.append(f"Runtime stderr: {self._summarize_output(stderr_text, limit=300)}")
            return issues

        # ——— Actionable guidance for environment / infrastructure failures ———
        # These are the most common cause of oracle_not_observed for native targets.
        # Give the model explicit instructions instead of opaque category codes.
        env_failure = (
            oracle_reason == 'environment_failure'
            or failure_category == 'environment_failure'
            or 'target binary not found' in stderr_text.lower()
            or 'awaiting native harness fallback' in stderr_text.lower()
            or runtime.get("proof_infrastructure_error")
        )
        if env_failure:
            issues.append(
                "Environment failure: the target binary could not be located or executed. "
                "The pov_script MUST build the binary itself (e.g. using subprocess to run make/cmake) "
                "or use the pre-built binary path from the TARGET_BINARY env var. "
                "Do NOT assume the binary already exists — compile it explicitly in the PoV."
            )
            if stderr_text:
                issues.append(f"Runtime stderr: {self._summarize_output(stderr_text, limit=240)}")
            return issues

        if failure_category:
            issues.append(f"Runtime failure category: {failure_category}")

        # ——— Task 4b: binary_ignored_input — the binary ran but ignored the PoV input entirely ———
        # This fires when the oracle detects stdout == preflight baseline (binary just printed help/usage).
        # The model must switch to a completely different delivery strategy.
        if oracle_reason == 'binary_ignored_input':
            _probe_bin = str(((finding or {}).get('exploit_contract') or {}).get('probe_binary_name') or '').strip()
            _known_subs = [
                str(s).strip()
                for s in ((finding or {}).get('exploit_contract') or {}).get('known_subcommands', [])
                if str(s).strip()
            ]
            _subs_str = ', '.join(_known_subs) if _known_subs else 'unknown'
            issues.append(
                f"CRITICAL: The target binary '{_probe_bin or 'TARGET_BINARY'}' COMPLETELY IGNORED your input. "
                f"Its stdout is identical to its baseline help output — your payload never reached "
                f"the vulnerable code path. You MUST change your exploitation strategy:\n"
                f"  1. If you passed input via stdin, try passing it as a FILE ARGUMENT instead.\n"
                f"  2. If you used a bare invocation, add a SUBCOMMAND first: {_subs_str}.\n"
                f"  3. If this binary is a TEST RUNNER (ignores external input), write a C harness "
                f"that #includes the library headers and calls the vulnerable function directly "
                f"with crafted data. Compile it with: gcc -fsanitize=address,undefined -g -O1 harness.c "
                f"-I/workspace/codebase -L/workspace/codebase -o harness\n"
                f"  4. Write the crafted input to a temporary file and pass its path as an argument."
            )
            if stderr_text:
                issues.append(f"Runtime stderr: {self._summarize_output(stderr_text, limit=240)}")
            return issues

        # ——— Actionable guidance for oracle_not_observed / non_evidence ———
        # The binary ran but produced no crash/sanitizer signal.
        # Give the model concrete direction on what the PoV must produce.
        if oracle_reason in {'oracle_not_observed', 'non_evidence'} or failure_category == 'oracle_not_observed':
            # Distinguish: is this a self-compile attempt that failed (model tried to
            # recompile the pre-built binary but got a compiler error), a genuine
            # inline-harness target (model correctly compiles a C test), or a plain
            # pre-built binary invocation that produced no oracle signal.
            _stderr_lower = stderr_text.lower()
            _is_self_compile_failure = (
                # Direct compiler invocation failed
                (
                    ('clang' in _stderr_lower or 'gcc' in _stderr_lower)
                    and any(sig in _stderr_lower for sig in (
                        'no input files', 'no such file or directory',
                        'undefined reference', 'cannot find', 'linker input',
                        'traceback', 'calledprocesserror',
                    ))
                )
                # C file-dropper variant: autopov harness tried to compile a .c file the PoV wrote
                or '[autopov] compilation failed' in _stderr_lower
                or '[autopov] no c source files found' in _stderr_lower
                or '[autopov] no c files found' in _stderr_lower
            )
            is_inline_harness = (
                not _is_self_compile_failure
                and (
                    'compile' in _stderr_lower
                    or 'gcc' in _stderr_lower
                    or 'clang' in _stderr_lower
                    or 'undefined reference' in _stderr_lower
                )
            )
            if _is_self_compile_failure:
                issues.append(
                    "Self-compile failed: the PoV tried to recompile the target with clang/gcc "
                    "but the compiler could not find the source files or encountered linker errors. "
                    "The binary is ALREADY BUILT with ASan by the build harness and is available "
                    "via TARGET_BINARY env var. "
                    "Do NOT include any compilation steps in the PoV script. "
                    "Simply invoke TARGET_BINARY with the correct subcommand and crafted input data "
                    "that exercises the vulnerable code path."
                )
            elif is_inline_harness:
                issues.append(
                    "Oracle not observed (inline harness): the PoV ran but produced no crash signal. "
                    "Rewrite the harness so it: (1) compiles the target WITH -fsanitize=address,undefined -g -O1 "
                    "(add these flags to your gcc/clang compile command), "
                    "(2) passes input that overflows or corrupts memory at the vulnerable function, "
                    "(3) does NOT just run with --help or benign input. "
                    "The oracle requires ASan/UBSan output, SIGSEGV, or exit code 134/139."
                )
            else:
                issues.append(
                    "Oracle not observed: the PoV ran the pre-built binary but produced no crash signal. "
                    "The binary is already compiled by the build harness — do NOT try to recompile it. "
                    "Instead: (1) use the TARGET_BINARY env var to invoke the binary, "
                    "(2) call a known subcommand (from known_subcommands) as the first positional argument, "
                    "(3) pass input that triggers the vulnerable path (overflow, corrupt filename, etc.). "
                    "The oracle requires ASan/UBSan output, SIGSEGV, or exit code 134/139."
                )
        elif oracle_reason:
            issues.append(f"Runtime oracle reason: {oracle_reason}")

        # ── Detect help-probe failure: binary called with usage/help flags, no crash possible ──
        # This is model-agnostic — fires for any model that generates a --help-style invocation.
        # Inject a hard-blocking hint so the next PoV attempt uses real crashing input.
        _combined_output = (stderr_text + ' ' + stdout_text).lower()
        if oracle_reason == 'no_oracle_match' and any(
            kw in _combined_output
            for kw in ('invalid option', 'usage:', 'usage\n', '--help', 'synopsis', 'try \'')
        ):
            issues.append(
                "PoV invoked the binary with help/usage flags or invalid options — "
                "this never produces a crash. You MUST provide REAL CRASHING INPUT: "
                "supply a crafted file, oversized buffer, or argument that exercises "
                "the vulnerable code path. Do NOT use --help, --version, or bare probes."
            )

        if oracle.get("self_report_only"):
            issues.append(
                "PoV self-reported success (printed 'VULNERABILITY TRIGGERED') without "
                "corroborating crash/sanitizer evidence. Remove the unconditional print and "
                "let a real crash or ASan report confirm the vulnerability."
            )

        recommended_input_mode = str(runtime.get("recommended_input_mode") or "").strip()
        supported_input_modes = [str(x) for x in (runtime.get("supported_input_modes") or []) if str(x).strip()]
        if recommended_input_mode:
            issues.append(f"Observed runtime surface recommends input mode: {recommended_input_mode}")
        if supported_input_modes:
            issues.append("Observed runtime surface supports input modes: " + ", ".join(supported_input_modes))

        selected_variant = str(runtime.get("selected_variant") or "").strip()
        if selected_variant:
            issues.append(f"Failed runtime variant: {selected_variant}")

        preflight = runtime.get("preflight") or {}
        for item in (preflight.get("issues") or [])[:3]:
            issues.append(f"Preflight issue: {item}")

        surface = runtime.get("surface") or {}
        options = [str(x) for x in (surface.get("options") or []) if str(x).strip()]
        if options:
            issues.append("Observed target surface options: " + ", ".join(options[:8]))

        if stderr_text:
            issues.append(f"Runtime stderr: {self._summarize_output(stderr_text, limit=240)}")

        if stdout_text and not issues:
            issues.append(f"Runtime stdout: {self._summarize_output(stdout_text, limit=240)}")

        return issues
    

    def _resolve_target_metadata(self, state: ScanState) -> Dict[str, Any]:
        metadata = state.get('target_metadata') or {}
        if metadata:
            return metadata
        metadata = resolve_curated_target_metadata(
            target_type=state.get('target_type', 'repo'),
            target_label=state.get('target_label'),
            repo_url=state.get('repo_url'),
            benchmark_metadata=state.get('benchmark_metadata'),
            codebase_path=state.get('codebase_path'),
        )
        if metadata:
            state['target_metadata'] = metadata
            self._log(state, f"Resolved curated target metadata: {metadata.get('id')} (matched by {metadata.get('matched_by')})")
        return metadata

    def _proof_threshold_for_finding(self, finding: VulnerabilityState, state: ScanState) -> float:
        # Use the configured threshold directly — no hard-floor override.
        # MIN_CONFIDENCE_FOR_POV=0.50 means any REAL finding the model considers
        # at least 50% likely to be real will get a proof attempt.
        threshold = settings.MIN_CONFIDENCE_FOR_POV
        runtime_profile = self._infer_runtime_profile(finding, state)
        if runtime_profile in {'c', 'cpp', 'binary', 'native'}:
            # Native findings are the easiest to prove (harness execution);
            # apply the same floor so behaviour is consistent across families.
            threshold = min(threshold, 0.50)
        return threshold

    def _augment_contract_with_target_metadata(self, state: ScanState, finding: VulnerabilityState) -> Dict[str, Any]:
        metadata = self._resolve_target_metadata(state)
        if not metadata:
            return finding.get('exploit_contract') or {}
        repo_hints = metadata.get('repo_hints') or {}
        file_hints = path_hints_for(metadata, finding.get('filepath', ''))
        contract = merge_contract_hints(finding.get('exploit_contract') or {}, repo_hints, file_hints)
        if contract != (finding.get('exploit_contract') or {}):
            contract['target_metadata'] = {'id': metadata.get('id'), 'matched_by': metadata.get('matched_by')}
            finding['exploit_contract'] = contract
        return finding.get('exploit_contract') or {}

    def _audit_finding_handoff(
        self,
        state: ScanState,
        finding: VulnerabilityState,
        phase: str,
        runtime_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        verifier = get_verifier()
        self._augment_contract_with_target_metadata(state, finding)
        audit = verifier.audit_handoff(
            finding.get('exploit_contract') or {},
            finding.get('cwe_type', ''),
            finding.get('llm_explanation', '') or finding.get('code_chunk', ''),
            finding.get('code_chunk', ''),
            filepath=finding.get('filepath', ''),
            runtime_feedback=runtime_result or ((finding.get('exploit_contract') or {}).get('runtime_feedback') or {}),
            phase=phase,
        )
        # Update exploit_contract with normalized version, but avoid recursive bloat
        _normalized = audit.get('normalized_contract') or {}
        # Strip any nested contract_audit or handoff_payload that may have accumulated
        _normalized.pop('contract_audit', None)
        _normalized.pop('handoff_payload', None)
        finding['exploit_contract'] = _normalized or (finding.get('exploit_contract') or {})
        # Store only a lightweight audit summary — full payload is redundant with exploit_contract
        _payload = audit.get('handoff_payload') or {}
        finding['contract_audit'] = {
            'phase': audit.get('phase'),
            'is_ready': audit.get('is_ready'),
            'issues': list(audit.get('issues') or [])[:10],
            'warnings': list(audit.get('warnings') or [])[:5],
            'handoff_summary': {
                'keys': list(_payload.keys()) if isinstance(_payload, dict) else [],
                'locator_keys': list(_payload.get('target_locator', {}).keys()) if isinstance(_payload, dict) else [],
                'requirements_keys': list(_payload.get('execution_requirements', {}).keys()) if isinstance(_payload, dict) else [],
            },
        }
        for warning in (audit.get('warnings') or [])[:2]:
            self._log(state, f"Contract audit warning: {warning}")
        return audit

    def _node_log_findings_count(self, state: ScanState) -> ScanState:
        """Log the number of findings found before investigation"""
        findings_count = len(state.get("findings", []))
        self._update_scan_runtime(state, status=ScanStatus.INVESTIGATING, progress=45, findings=state.get("findings", []))
        self._log(state, f"Discovery found {findings_count} potential vulnerabilities to investigate")
        if findings_count == 0:
            self._log(state, "No findings to investigate, scan will complete")
        return state

    def _node_recon(self, state: ScanState) -> ScanState:
        """Run LLM-driven reconnaissance on the codebase.

        Produces a ReconReport that guides all downstream decisions:
        proof strategy, Docker image selection, oracle evaluation, and PoV generation.
        Runs ONCE per scan, before discovery begins.
        """
        if self._check_cancelled(state):
            return state

        # Skip recon when preloaded findings are provided (benchmark replay).
        # Recon is unnecessary — the findings already contain all needed context.
        if state.get('preloaded_findings'):
            self._log(state, '[recon] Skipping — preloaded findings provided')
            return state

        self._log(state, "[recon] Running reconnaissance on codebase...")
        self._update_scan_runtime(state, status=ScanStatus.INGESTING, progress=30)

        # Authoritative repo surface classification — runs here (before discovery)
        # so that all downstream nodes (discovery, investigation, probe, etc.) see it.
        if not state.get('repo_surface_class'):
            try:
                repo_cls = self._classify_repo_surface(state['codebase_path'])
                state['repo_surface_class'] = repo_cls
                self._log(state, f"Repo surface class: {repo_cls}")
            except Exception as cls_err:
                state['repo_surface_class'] = 'unknown'
                self._log(state, f"  Warning: repo surface classification failed (non-fatal): {cls_err}")

        try:
            model_name = state.get('model_name') or ''
            api_key = state.get('openrouter_api_key') or None
            report = run_recon(
                codebase_path=state['codebase_path'],
                model_name=model_name or None,
                api_key_override=api_key,
                repo_url=state.get('repo_url') or '',
            )
            state['recon_report'] = report.to_dict()

            # Wire docker_extra_deps from recon into top-level state so it can
            # be injected into every finding's exploit_contract later.
            if report.docker_extra_deps:
                state['recon_docker_extra_deps'] = report.docker_extra_deps
            # Wire DB substitution env vars from recon
            if report.db_substitution_env:
                state['recon_db_substitution_env'] = report.db_substitution_env
            if report.detected_databases:
                state['recon_detected_databases'] = [d for d in report.detected_databases]

            # Back-propagate enriched recon fields into top-level state
            # so downstream nodes can access them without digging into the dict.
            if report.entry_point_candidates and not state.get('entry_point_candidates'):
                state['entry_point_candidates'] = report.entry_point_candidates
            if report.input_format_hints and not state.get('input_format_hints'):
                state['input_format_hints'] = report.input_format_hints
            if report.sample_input_files and not state.get('sample_input_files'):
                state['sample_input_files'] = report.sample_input_files
            if report.has_web_surface:
                state['repo_web_capable'] = True
            if report.web_frameworks:
                state['web_frameworks'] = report.web_frameworks
            if report.repo_surface_class and report.repo_surface_class != 'unknown':
                state['repo_surface_class'] = report.repo_surface_class

            # Back-propagate git intelligence for use by discovery and investigation
            if report.high_value_files:
                state['recon_high_value_files'] = report.high_value_files
                self._log(state,
                    f"[recon] {len(report.high_value_files)} high-value files from git history: "
                    + ', '.join(f['file'] for f in report.high_value_files[:5]))
            if report.historical_vuln_types:
                state['recon_historical_vuln_types'] = report.historical_vuln_types
                self._log(state,
                    f"[recon] Historical vulnerability types: "
                    + ', '.join(report.historical_vuln_types))
            if report.repo_activity:
                state['recon_repo_activity'] = report.repo_activity
                _activity = report.repo_activity
                self._log(state,
                    f"[recon] Repo activity: last_commit={_activity.get('last_commit_date')}, "
                    f"active={_activity.get('is_active')}, "
                    f"total_commits={_activity.get('total_commits')}")
            if report.security_policy:
                self._log(state, "[recon] SECURITY.md found and read")
            if report.github_security_findings:
                self._log(state,
                    f"[recon] {len(report.github_security_findings)} findings from GitHub security APIs")

            self._log(
                state,
                f"[recon] Complete: project_type={report.project_type}, "
                f"runtime={report.runtime_family}, default_proof={report.default_proof_type}, "
                f"surfaces={len(report.attack_surfaces)}, "
                f"frameworks={report.framework_hints[:3]}"
            )
        except Exception as exc:
            self._log(state, f"[recon] Failed ({exc}), using minimal defaults")
            # Provide a minimal report so downstream doesn't crash
            from agents.recon_agent import ReconReport as _RR
            state['recon_report'] = _RR().to_dict()

        # Inject known-CVE findings from dependency scanning (pre-confirmed)
        _recon_dict = state.get('recon_report') or {}
        _cve_findings = _recon_dict.get('known_cve_findings') or []
        if _cve_findings:
            self._log(state, f"[recon] Injecting {len(_cve_findings)} known CVE findings from dependency scan")
            _surface = state.get('repo_surface_class', 'unknown')
            _runtime = _recon_dict.get('runtime_family', 'native')
            if 'findings' not in state or state['findings'] is None:
                state['findings'] = []
            for _cve in _cve_findings:
                _cve_id = _cve.get('cve', '')
                _pkg = _cve.get('package', '')
                _desc = _cve.get('description', '')
                _hint = _cve.get('proof_hint', '')
                _cwe = _cve.get('cwe', 'CWE-1035')  # CWE-1035 = using known-vulnerable component
                # Use proof_type and harness_type derived from OSV description
                _proof_type = _cve.get('proof_type', 'observable_output')
                _cvss = float(_cve.get('cvss') or 0)
                _fix_ver = _cve.get('fix_version', '')
                _harness = _infer_cve_harness_type(_proof_type, _runtime)
                state['findings'].append({
                    'cve_id': _cve_id,
                    'filepath': f'dependency:{_pkg}',
                    'line_number': 0,
                    'cwe_type': _cwe,
                    'code_chunk': f'{_pkg} {_cve.get("installed_version", "unknown")} ({_cve.get("vulnerable_versions", _cve.get("fix_version", ""))})',
                    'llm_verdict': 'REAL',
                    'llm_explanation': f'Known vulnerability {_cve_id} in {_pkg}: {_desc}',
                    'confidence': 1.0,
                    'pov_script': None,
                    'pov_path': None,
                    'pov_result': None,
                    'retry_count': 0,
                    'inference_time_s': 0,
                    'cost_usd': 0,
                    'final_status': None,
                    'detected_language': _runtime,
                    'source': 'dependency_cve',
                    'model_used': '',
                    'prompt_tokens': 0,
                    'completion_tokens': 0,
                    'total_tokens': 0,
                    'sifter_model': None,
                    'sifter_tokens': None,
                    'architect_model': None,
                    'architect_tokens': None,
                    'validation_result': None,
                    'execution_profile': None,
                    'exploit_contract': {
                        'target_entrypoint': _hint or _pkg,
                        'runtime_profile': _runtime,
                        'repo_surface_class': _surface,
                        'docker_extra_deps': (_recon_dict.get('docker_extra_deps') or []),
                        'db_substitution_env': (state.get('recon_db_substitution_env') or {}),
                        'cve_fix_version': _fix_ver,
                        'cve_cvss': _cvss,
                        'cve_osv_id': _cve.get('osv_id', ''),
                        'proof_strategy': {
                            'proof_type': _proof_type,
                            'observable_evidence': _build_cve_observable_evidence(
                                _proof_type, _hint, _desc),
                            'harness_type': _harness,
                            'execution_strategy': _infer_cve_execution_strategy(_proof_type),
                            'verification_method': f'Demonstrate {_hint}',
                            'negative_control': f'Run with benign input, confirm no {_proof_type} evidence',
                            'estimated_difficulty': 'low' if _cvss >= 9.0 else 'medium',
                            'cve_proof_hint': _hint,
                            'why_this_works': f'Known CVE {_cve_id} with published exploitation path',
                        },
                    },
                    'refinement_history': [],
                })
            self._log(state, f"[recon] Total findings after CVE injection: {len(state['findings'])}")

        return state
    
    def _node_ingest_code(self, state: ScanState) -> ScanState:
        """Ingest the codebase into the vector store and require it for downstream RAG."""
        # Task 7: Record scan start timestamp for scan-level timeout enforcement
        import time as _time_ingest
        if '_scan_start_ts' not in state:
            state['_scan_start_ts'] = _time_ingest.time()

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

            # Collect repo-derived input hints (test fixtures, sample files, expected
            # input extensions) and store on state for downstream PoV generation.
            # This is repo-generic: we scan the cloned repo, not any hardcoded paths.
            try:
                hints = self._collect_repo_input_hints(state["codebase_path"])
                if hints:
                    state["repo_input_hints"] = hints
                    self._log(state, f"Repo input hints collected: {len(hints.get('sample_files', []))} sample files, extensions: {hints.get('input_extensions', [])}")
            except Exception as hint_err:
                self._log(state, f"  Warning: repo input hint collection failed (non-fatal): {hint_err}")

            # Detect whether the repo has web-serving capability.
            # Result stored as state["repo_web_capable"] (bool) and used downstream
            # to avoid false-positive downgrading of web CWEs for C-based web servers.
            try:
                state["repo_web_capable"] = self._detect_web_capability(state["codebase_path"])
                self._log(state, f"Web-serving capability detected: {state['repo_web_capable']}")
            except Exception as web_err:
                state["repo_web_capable"] = False  # safe default
                self._log(state, f"  Warning: web capability detection failed (non-fatal): {web_err}")

            # Classify the repo surface as a fallback — recon is the authoritative
            # source after the graph reorder (recon runs before discovery).  This
            # block only fires when recon hasn't populated it yet (e.g. replay).
            if not state.get('repo_surface_class'):
                try:
                    repo_cls = self._classify_repo_surface(state["codebase_path"])
                    state["repo_surface_class"] = repo_cls
                    self._log(state, f"Repo surface class (ingest fallback): {repo_cls}")
                except Exception as cls_err:
                    state["repo_surface_class"] = 'unknown'
                    self._log(state, f"  Warning: repo surface classification failed (non-fatal): {cls_err}")

            # Task 2A: For C library repos extract public API from headers so the
            # model can write function-harness PoVs rather than file-fuzzers.
            if state.get("repo_surface_class") in ('library_c', 'library_c_with_cli'):
                try:
                    api_ctx = self._extract_c_library_api(state["codebase_path"])
                    if api_ctx:
                        state["library_api_context"] = api_ctx
                        self._log(state, f"C library API context extracted: {len(api_ctx)} chars")
                except Exception as api_err:
                    self._log(state, f"  Warning: C library API extraction failed (non-fatal): {api_err}")

        except Exception as e:
            state["rag_ready"] = False
            state["rag_stats"] = {"error": str(e)}
            self._update_scan_runtime(state, rag_ready=False, rag_stats=state["rag_stats"])
            self._log(state, f"ERROR: Mandatory code ingestion failed: {e}")
            raise RuntimeError(f"Mandatory code ingestion failed: {e}") from e

        return state

    def _classify_repo_surface(self, codebase_path: str) -> str:
        """Classify the repo into a surface class for downstream routing.

        Delegates to the standalone function in recon_agent.py so that
        other modules (probe_runner, docker_runner) can import it without
        circular dependencies.
        """
        from agents.recon_agent import classify_repo_surface
        return classify_repo_surface(codebase_path)

    def _extract_c_library_api(self, codebase_path: str, max_chars: int = 3000) -> str:
        """Extract public function signatures from the primary header of a C library.

        Walks the codebase for .h files at depth ≤ 2, preferring the header whose
        basename matches the repo directory name (e.g. cJSON.h for DaveGamble/cJSON).
        Returns a string of function signatures, capped at max_chars.
        """
        import re as _re
        import os as _os
        from pathlib import Path as _Path

        cb = _Path(codebase_path)
        repo_name = cb.name.lower()

        # Collect .h files at depth ≤ 3 (handles subdirectory repos like libexpat/expat/lib/)
        headers: list = []  # list of (priority, path)
        for _root, _dirs, _files in _os.walk(str(cb)):
            _rel = _os.path.relpath(_root, str(cb))
            _depth = 0 if _rel == '.' else _rel.count(_os.sep) + 1
            if _depth > 3:
                _dirs[:] = []
                continue
            _dirs[:] = [d for d in _dirs if d not in {'.git', 'CMakeFiles', '_codeql_build_dir', '.autopov-cmake-build', '.autopov-probe-build'}]
            for _fname in _files:
                if not _fname.endswith('.h'):
                    continue
                _stem = _Path(_fname).stem.lower()
                # Priority 0: exact repo name match (e.g. cJSON.h)
                _prio = 0 if _stem == repo_name else (1 if _depth == 0 else 2)
                headers.append((_prio, _os.path.join(_root, _fname)))

        headers.sort(key=lambda x: x[0])

        # Function signature regex for C declarations
        # Matches standard C function declarations, including those with library-specific
        # export macros like XMLPARSEAPI, CJSON_PUBLIC, etc.
        _SIG_RE = _re.compile(
            r'^\s*(?:(?:extern|static|inline|const|unsigned|signed|void|int|char|long|short|float|double|'
            r'size_t|uint\w*|int\w*|\w+_t|XMLPARSEAPI|CJSON_PUBLIC|XML_\w+)\s*[\(\)]*\s*)*'
            r'(?:\*+\s*)?(\w+)\s*\([^)]*\)\s*;',
            _re.MULTILINE,
        )

        sigs: list = []
        total_chars = 0
        for _, hpath in headers:
            try:
                content = _Path(hpath).read_text(encoding='utf-8', errors='ignore')
            except OSError:
                continue
            for m in _SIG_RE.finditer(content):
                line = m.group(0).strip()
                if total_chars + len(line) + 1 > max_chars:
                    break
                sigs.append(line)
                total_chars += len(line) + 1
            if total_chars >= max_chars:
                break

        return '\n'.join(sigs) if sigs else ''

    def _second_chance_discovery(self, state: ScanState) -> list:
        """Task 3: LLM-guided deep vulnerability discovery for library repos.

        Called when ALL static analysis findings were dismissed as FALSE_POSITIVE.
        Reads the core library source files and asks the LLM to identify real
        exploitable code paths (buffer overflows, use-after-free, etc.).

        Returns a list of new finding dicts ready for investigation.
        """
        import os as _os
        from pathlib import Path as _Path

        codebase_path = state.get('codebase_path', '')
        if not codebase_path or not _os.path.isdir(codebase_path):
            return []

        self._log(state, "Running second-chance LLM-guided discovery on core library source...")

        # Determine language-specific settings based on surface class
        _surface = state.get('repo_surface_class', '')
        _LANG_CONFIG = {
            'library_c': {
                'extensions': ('.c', '.cpp', '.cc', '.cxx'),
                'lang_label': 'C/C++', 'detected_language': 'c',
                'runtime_profile': 'c', 'execution_surface': 'c_library_harness',
                'vuln_types': 'memory-safety vulnerabilities (buffer overflow, heap overflow, use-after-free, integer overflow leading to buffer overrun, etc.)',
            },
            'library_c_with_cli': {
                'extensions': ('.c', '.cpp', '.cc', '.cxx'),
                'lang_label': 'C/C++', 'detected_language': 'c',
                'runtime_profile': 'c', 'execution_surface': 'c_library_harness',
                'vuln_types': 'memory-safety vulnerabilities (buffer overflow, heap overflow, use-after-free, integer overflow leading to buffer overrun, etc.)',
            },
            'python_module': {
                'extensions': ('.py',),
                'lang_label': 'Python', 'detected_language': 'python',
                'runtime_profile': 'python', 'execution_surface': 'python_module_harness',
                'vuln_types': 'security vulnerabilities (code injection, deserialization flaws, path traversal, SSRF, command injection, unsafe eval/exec, etc.)',
            },
            'node_module': {
                'extensions': ('.js', '.ts', '.mjs'),
                'lang_label': 'JavaScript/TypeScript', 'detected_language': 'javascript',
                'runtime_profile': 'node', 'execution_surface': 'node_module_harness',
                'vuln_types': 'security vulnerabilities (prototype pollution, command injection, path traversal, ReDoS, deserialization flaws, etc.)',
            },
            'java_lib': {
                'extensions': ('.java',),
                'lang_label': 'Java', 'detected_language': 'java',
                'runtime_profile': 'java', 'execution_surface': 'java_library_harness',
                'vuln_types': 'security vulnerabilities (deserialization flaws, XML external entity injection, JNDI injection, path traversal, SQL injection, etc.)',
            },
        }
        _lconf = _LANG_CONFIG.get(_surface, _LANG_CONFIG['library_c'])
        # Find core source files (largest, excluding test/tool dirs)
        _SKIP_DIRS = {'test', 'tests', 'xmlwf', 'examples', 'sample', 'samples',
                      'bench', 'fuzz', 'tools', 'cmd', 'app', 'bin', 'demo',
                      '.git', 'CMakeFiles', '_codeql_build_dir', '.autopov-cmake-build',
                      'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
        _exts = _lconf['extensions']
        _src_files: list = []  # (size, rel_path, full_path)
        for _root, _dirs, _files in _os.walk(codebase_path):
            _dirs[:] = [d for d in _dirs if d.lower() not in _SKIP_DIRS]
            for _fname in _files:
                if any(_fname.endswith(ext) for ext in _exts):
                    _fpath = _os.path.join(_root, _fname)
                    try:
                        _sz = _os.path.getsize(_fpath)
                        _rel = _os.path.relpath(_fpath, codebase_path)
                        _src_files.append((_sz, _rel, _fpath))
                    except OSError:
                        pass

        # Take the top 3 largest source files (most likely to contain parser/processing logic)
        _src_files.sort(key=lambda x: x[0], reverse=True)
        _top_files = _src_files[:3]
        if not _top_files:
            return []

        # Read code chunks from top files (first 6000 chars each)
        _code_chunks = []
        for _sz, _rel, _fpath in _top_files:
            try:
                _content = _Path(_fpath).read_text(encoding='utf-8', errors='ignore')[:6000]
                _code_chunks.append(f"--- {_rel} ({_sz} bytes) ---\n{_content}")
            except OSError:
                pass

        if not _code_chunks:
            return []

        # Build the discovery prompt — language-aware
        _lib_api = state.get('library_api_context', '')
        _lang_label = _lconf['lang_label']
        _vuln_types = _lconf['vuln_types']
        _prompt = (
            f"You are a security researcher. The following code is from a {_lang_label} library. "
            f"Static analysis found NO exploitable vulnerabilities, but this library has known CVEs. "
            f"Identify up to 3 REAL {_vuln_types} in this code.\n\n"
            "For each vulnerability, respond with a JSON array of objects:\n"
            '[{"filepath": "relative/path", "line_number": NNN, "cwe_type": "CWE-XXX", '
            '"description": "brief explanation of the bug and how to trigger it", '
            '"vulnerable_function": "function_name"}]\n\n'
        )
        if _lib_api:
            _prompt += f"Library public API:\n{_lib_api[:1500]}\n\n"
        _prompt += "\n\n".join(_code_chunks)

        # Invoke the LLM
        try:
            from agents.investigator import get_investigator
            investigator = get_investigator()
            model_name = state.get('model_name') or ''
            llm = investigator._get_llm(model_name=model_name or None)

            from langchain_core.messages import HumanMessage
            response = llm.invoke([HumanMessage(content=_prompt)])
            raw_text = response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            self._log(state, f"  Second-chance LLM call failed: {e}")
            return []

        # Parse the response as JSON array
        import json as _json
        import re as _re
        try:
            # Extract JSON from response (may be wrapped in markdown code block)
            _json_match = _re.search(r'\[\s*\{.*?\}\s*\]', raw_text, _re.DOTALL)
            if not _json_match:
                self._log(state, "  Second-chance: no JSON array found in LLM response")
                return []
            findings_data = _json.loads(_json_match.group(0))
        except (_json.JSONDecodeError, ValueError) as e:
            self._log(state, f"  Second-chance: JSON parse error: {e}")
            return []

        # Convert to finding dicts
        new_findings = []
        for item in findings_data[:3]:  # Cap at 3
            filepath = item.get('filepath', '')
            line_number = int(item.get('line_number', 0) or 0)
            cwe_type = item.get('cwe_type', 'CWE-787')
            description = item.get('description', '')
            vuln_func = item.get('vulnerable_function', '')

            # Read the actual code chunk around the line
            code_chunk = ''
            if filepath and line_number:
                try:
                    _full_path = _os.path.join(codebase_path, filepath)
                    _lines = _Path(_full_path).read_text(encoding='utf-8', errors='ignore').splitlines()
                    _start = max(0, line_number - 5)
                    _end = min(len(_lines), line_number + 10)
                    code_chunk = '\n'.join(_lines[_start:_end])
                except (OSError, IndexError):
                    pass

            new_findings.append({
                'cve_id': None,
                'filepath': filepath,
                'line_number': line_number,
                'cwe_type': cwe_type,
                'code_chunk': code_chunk or description,
                'llm_verdict': 'REAL',  # Force as REAL — this is the second chance
                'llm_explanation': f'Second-chance discovery: {description}',
                'confidence': 0.75,  # High enough to trigger PoV generation
                'pov_script': None,
                'pov_path': None,
                'pov_result': None,
                'retry_count': 0,
                'inference_time_s': 0,
                'cost_usd': 0,
                'final_status': None,
                'detected_language': _lconf['detected_language'],
                'source': 'llm_second_chance',
                'model_used': state.get('model_name', ''),
                'exploit_contract': {
                    'target_entrypoint': vuln_func or 'main',
                    'runtime_profile': _lconf['runtime_profile'],
                    'repo_surface_class': state.get('repo_surface_class', ''),
                    'library_api_context': state.get('library_api_context', ''),
                    'execution_surface': _lconf['execution_surface'],
                },
                'refinement_history': [],
            })

        self._log(state, f"  Second-chance produced {len(new_findings)} findings: "
                  + ', '.join(f.get('filepath', '?') for f in new_findings))
        return new_findings

    def _collect_repo_input_hints(self, codebase_path: str) -> dict:
        """Scan the cloned repo for test fixtures and expected input format hints.

        Returns a dict with:
          - sample_files: relative paths to files inside known test/fixture dirs
          - input_extensions: file extensions seen in test dirs (signals expected formats)
          - has_test_fixtures: bool

        This is entirely repo-derived (no hardcoded file names or extensions).
        The result is stored on state["repo_input_hints"] and injected into the
        PoV generation prompt so models use the repo's own test data rather than
        guessing at input formats.
        """
        import os as _os
        from pathlib import Path as _Path

        # Directories that conventionally contain test inputs / fixtures
        FIXTURE_DIRS = {
            'test', 'tests', 'test-data', 'testdata', 'test_data',
            'fixtures', 'fixture', 'samples', 'sample', 'examples',
            'example', 'data', 'resources', 'testfiles', 'testcases',
        }
        # File extensions that represent binary/structured inputs (not source code)
        INPUT_EXTENSIONS = {
            '.bin', '.dat', '.raw', '.enc', '.zip', '.tar', '.gz', '.bz2',
            '.xml', '.json', '.yaml', '.yml', '.csv', '.txt', '.pcap',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.html', '.htm',
        }
        # Limit to avoid huge lists in the prompt
        MAX_SAMPLE_FILES = 10

        sample_files: list = []
        input_extensions: set = set()

        for root, dirs, files in _os.walk(codebase_path):
            # Prune hidden dirs and build output dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('build', 'dist', 'obj', '__pycache__')]
            rel_root = _os.path.relpath(root, codebase_path)
            parts = set(_Path(rel_root).parts)
            # Only scan inside known fixture dirs
            if not (parts & FIXTURE_DIRS):
                continue
            for filename in files:
                ext = _Path(filename).suffix.lower()
                if ext in INPUT_EXTENSIONS:
                    rel_path = _os.path.join(rel_root, filename)
                    input_extensions.add(ext)
                    if len(sample_files) < MAX_SAMPLE_FILES:
                        sample_files.append(rel_path)

        return {
            'sample_files': sample_files,
            'input_extensions': sorted(input_extensions),
            'has_test_fixtures': bool(sample_files),
        }

    def _detect_web_capability(self, codebase_path: str) -> bool:
        """Scan the codebase for evidence of HTTP/web-serving capability.

        Returns True when the repo appears to be a web server or web application
        that handles HTTP traffic.  Used to avoid false-positive downgrading of
        web-only CWEs (XSS, SQLi, CSRF) for native-language web servers (e.g. nginx,
        mongoose-based C servers, cpp-httplib apps).

        Checks (returns True on first match):
        1. Known web framework headers in C/C++ source files
        2. HTTP response string literals in source
        3. Web handler function name patterns
        4. Build file linking to known web libraries
        """
        import re as _re
        import os as _os

        _WEB_HEADERS = {
            'microhttpd.h', 'mongoose.h', 'civetweb.h', 'onion.h',
            'httplib.h', 'crow.h', 'uwebsockets', 'http_parser.h',
            'libevent/http.h', 'event2/http.h',
        }
        _HTTP_STRINGS = ['HTTP/1.', 'Content-Type:', '200 OK', '404 Not Found']
        _BUILD_PATTERNS = [
            r'-lmicrohttpd', r'-lmongoose', r'find_package.*[Hh]ttp',
            r'pkg_check_modules.*microhttpd', r'target_link_libraries.*mongoose',
        ]
        _HANDLER_RE = _re.compile(
            r'\b(handle_request|http_handler|send_response|route_\w+|on_request|'
            r'ngx_http_\w+|mg_serve|mhd_\w+)\b'
        )
        for root, dirs, files in _os.walk(codebase_path):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__'}]
            for fname in files:
                fpath = _os.path.join(root, fname)
                ext = _os.path.splitext(fname)[1].lower()
                if ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}:
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read(32768)  # first 32 KB
                        for hdr in _WEB_HEADERS:
                            if hdr in content:
                                return True
                        for pat in _HTTP_STRINGS:
                            if pat in content:
                                return True
                        if _HANDLER_RE.search(content):
                            return True
                    except OSError:
                        continue
                elif fname.lower() in {'makefile', 'cmakelists.txt', 'configure.ac', 'meson.build'}:
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            content = f.read(16384)
                        for pat in _BUILD_PATTERNS:
                            if _re.search(pat, content, _re.IGNORECASE):
                                return True
                    except OSError:
                        continue
        return False
    
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
        Filter out obvious non-security findings (code quality, style issues)
        and findings in test/spec files.

        IMPORTANT: We do NOT filter based on CWE classification.
        A vulnerability is defined by exploitability, not by its CWE label.
        """
        # Drop findings from test files — they are not exploitable in production
        filepath = finding.get("filepath", "").replace("\\", "/").lower()
        test_markers = ["/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
                        "test_", "_test.", ".spec.", ".test.", "/src/test/"]
        if any(m in filepath for m in test_markers):
            return False

        code_chunk = finding.get("code_chunk", "").lower()

        # Filter out well-known non-security Semgrep / CodeQL rule message patterns
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
        for pattern in non_security_patterns:
            if pattern in code_chunk:
                return False

        # Drop Semgrep findings whose code_chunk is a login-wall placeholder.
        # Semgrep Cloud returns "requires login" when the matched line cannot be
        # fetched without authentication.  This placeholder produces truncated /
        # invalid LLM responses and adds no exploitability signal.
        _raw_chunk = finding.get("code_chunk", "")
        _placeholder_chunks = {"requires login", "requires login\n"}
        if str(_raw_chunk).strip().lower() in _placeholder_chunks:
            return False

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
                    # FIX-11: Extract build_profile from discovery metadata so it
                    # can be seeded into each finding's exploit_contract later.
                    _disc_build_profile = (result.metadata or {}).get('build_profile')
                    for finding_data in result.findings:
                        # Convert to VulnerabilityState
                        # FIX-11: Seed exploit_contract with build_profile from
                        # discovery so docker_runner can skip wrong strategies.
                        _seed_ec = None
                        if _disc_build_profile:
                            _seed_ec = {'build_profile': _disc_build_profile}
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
                            exploit_contract=_seed_ec,
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

            # Task 6: Warn when discovery returns 0 findings for Go/JS languages
            # where CodeQL autobuild may have silently failed
            if len(security_findings) == 0:
                _detected_lang = str(state.get('detected_language') or '').lower()
                if _detected_lang in {'go', 'golang'}:
                    self._log(state, "WARNING: 0 findings for Go target — CodeQL autobuild may have failed. "
                              "Ensure GOFLAGS='' and go.sum exists in the repository.")
                elif _detected_lang in {'javascript', 'typescript'}:
                    self._log(state, "WARNING: 0 findings for JS/TS target — Semgrep rules may have been over-filtered.")
            
            # Task 7: Downgrade confidence for findings in fuzzer/harness scaffolding files.
            # CodeQL sometimes reports CWE-120 on fread() inside *_fuzzer.c or fuzz_*.c
            # files — these are intentional scaffolding, not real product bugs.
            _FUZZER_PATH_RE = __import__('re').compile(
                r'(fuzz_|_fuzzer|_harness|fuzzing[/\\]|harness[/\\])',
                __import__('re').IGNORECASE,
            )
            for _f in security_findings:
                _fpath = str(_f.get('filepath') or '')
                if _FUZZER_PATH_RE.search(_fpath):
                    _f['confidence'] = min(_f.get('confidence', 0.7), 0.2)
                    _ec = dict(_f.get('exploit_contract') or {})
                    _ec['likely_fuzzer_scaffolding'] = True
                    _f['exploit_contract'] = _ec

            # Task 10: CWE-79 noise reduction for non-web languages.
            # XSS findings in C/C++/Go/Rust are almost always false positives.
            _NON_WEB_LANGS = {'c', 'cpp', 'c++', 'go', 'rust'}
            _xss_filtered = 0
            for _f in security_findings:
                _cwe = str(_f.get('cwe_type') or '').upper()
                _lang = str(_f.get('detected_language') or '').lower()
                if _cwe in ('CWE-79', 'CWE-079') and _lang in _NON_WEB_LANGS and _f.get('confidence', 0.7) < 0.6:
                    _f['confidence'] = min(_f.get('confidence', 0.7), 0.15)
                    _f['llm_verdict'] = 'FALSE_POSITIVE'
                    _f['llm_explanation'] = 'XSS (CWE-79) is irrelevant for non-web language: ' + _lang
                    _xss_filtered += 1
            if _xss_filtered:
                self._log(state, f"Task 10: Downgraded {_xss_filtered} CWE-79 findings for non-web languages")

            # ── Recon priority boost: findings in high-value files get +0.15 confidence ──
            _hv_files = state.get('recon_high_value_files') or []
            _hv_hist_types = set(state.get('recon_historical_vuln_types') or [])
            if _hv_files or _hv_hist_types:
                _hv_paths = {str(f.get('file', '')) for f in _hv_files if f.get('file')}
                _boosted = 0
                for _f in security_findings:
                    _fp = str(_f.get('filepath', ''))
                    _cwe = str(_f.get('cwe_type', '')).upper()
                    boost = 0.0
                    if _fp in _hv_paths:
                        boost += 0.10
                    if _cwe in _hv_hist_types:
                        boost += 0.05
                    if boost > 0:
                        _f['confidence'] = min(1.0, _f.get('confidence', 0.5) + boost)
                        _boosted += 1
                if _boosted:
                    self._log(state, f'Recon priority boost: boosted {_boosted} findings in high-value files / historical vuln types')

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
            # Fallback: LLM-only analysis (no heuristics)
            findings = self._run_llm_only_analysis(state)
            findings.sort(key=lambda item: item.get("confidence", 0.0), reverse=True)
            state["findings"] = findings[:settings.DISCOVERY_MAX_FINDINGS]
            for finding in state["findings"]:
                self._append_scan_openrouter_usage(state, finding.get("scout_openrouter_usage"), "llm_scout", finding=finding)
            self._update_scan_runtime(state, progress=45, findings=state["findings"])

        return state

    def _run_autonomous_discovery(self, state: ScanState) -> List[VulnerabilityState]:
        """Deprecated: kept only to avoid import errors if called from old code paths.
        Returns empty list — heuristic pattern matching has been removed.
        Use _run_llm_only_analysis instead."""
        self._log(state, "_run_autonomous_discovery called — no-op (heuristic discovery removed)")
        return []

    def _run_llm_only_analysis(self, state: ScanState) -> List[VulnerabilityState]:
        """
        LLM-only analysis used when CodeQL/Semgrep are unavailable.

        Walks code files, splits them into chunks, and uses the LLM scout to
        propose candidate vulnerabilities.  No heuristic pre-filters are applied
        so the LLM receives the full file context and is not artificially biased
        toward any particular sink pattern.
        """
        self._log(state, "Running LLM-only analysis (CodeQL unavailable)...")

        findings: List[VulnerabilityState] = []

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

        # Limit files to control cost
        max_files = min(len(code_files), 20)
        code_files = code_files[:max_files]
        self._log(state, f"LLM-only analysis: scanning {len(code_files)} files")

        from agents.llm_scout import LLMScout
        from prompts import format_scout_prompt
        scout = LLMScout()

        for filepath in code_files:
            rel_path = os.path.relpath(filepath, state["codebase_path"])
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(settings.MAX_CHUNK_SIZE * 2)
            except Exception:
                continue

            if not content.strip():
                continue

            lang = state.get("detected_language", "unknown")
            try:
                raw_findings = scout.scan_snippets(
                    [{"filepath": rel_path, "language": lang, "code": content}],
                    cwes=[]
                )
                for rf in (raw_findings or []):
                    findings.append(VulnerabilityState(
                        cve_id=rf.get("cve_id"),
                        filepath=rf.get("filepath", rel_path),
                        line_number=int(rf.get("line") or 0),
                        cwe_type=rf.get("cwe") or "UNCLASSIFIED",
                        code_chunk=rf.get("snippet") or "",
                        llm_verdict="",
                        llm_explanation=rf.get("reason") or "",
                        confidence=float(rf.get("confidence") or 0.4),
                        pov_script=None,
                        pov_path=None,
                        pov_result=None,
                        retry_count=0,
                        inference_time_s=0.0,
                        cost_usd=0.0,
                        final_status="",
                        alert_message=rf.get("reason") or "LLM scout finding",
                        source="llm_only",
                        detected_language=lang,
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
                        execution_profile=None,
                    ))
            except Exception as ex:
                self._log(state, f"LLM scout error on {rel_path}: {ex}")

        self._log(state, f"LLM-only analysis produced {len(findings)} candidate findings")
        return findings
    
    def _node_investigate(self, state: ScanState) -> ScanState:
        """Investigate ONE finding with LLM (at current_finding_idx) or ALL in parallel"""
        # Check for cancellation
        if self._check_cancelled(state):
            self._log(state, "Scan cancelled by user")
            state["status"] = ScanStatus.CANCELLED
            return state

        # Stage-skip: CVE dependency findings are pre-confirmed and need no investigation
        idx = state.get("current_finding_idx", 0)
        if idx < len(state.get("findings", [])):
            _f = state["findings"][idx]
            if _f.get('source') == 'dependency_cve' and _f.get('llm_verdict') == 'REAL':
                self._log(state, f"Skipping investigation for pre-confirmed CVE finding {idx}: {_f.get('cve_id', '')}")
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
                api_key_override=state.get("openrouter_api_key"),
                repo_web_capable=state.get("repo_web_capable", False),
                recon_report=state.get('recon_report'),
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

        # Task 1: CWE data flow — preserve tool-provided CWE classifications.
        # Only allow the investigator to *refine* (e.g. CWE-120 → CWE-787) when
        # the original was from CodeQL/Semgrep.  Never overwrite a tool CWE with
        # a completely different one unless the investigator is highly confident.
        _original_cwe = finding.get("cwe_type") or "UNCLASSIFIED"
        _original_source = finding.get("cwe_source", "pending")
        _inv_cwe = str(result.get("cwe_type") or "").strip()
        _inv_confidence = float(result.get("confidence", 0) or 0)

        if _original_source == 'tool' and _original_cwe != 'UNCLASSIFIED':
            # Tool already classified — only accept investigator refinement if
            # it's a genuine refinement (same family) or high-confidence override
            if _inv_cwe and _inv_cwe != 'UNCLASSIFIED' and _inv_cwe != _original_cwe:
                # Check if it's a CWE family refinement (same first 2 digits)
                import re as _re_cwe_check
                _orig_num = _re_cwe_check.search(r'(\d+)', _original_cwe)
                _inv_num = _re_cwe_check.search(r'(\d+)', _inv_cwe)
                _is_refinement = (
                    _orig_num and _inv_num
                    and str(_orig_num.group(1))[:2] == str(_inv_num.group(1))[:2]
                )
                if _is_refinement or _inv_confidence >= 0.9:
                    finding["cwe_type"] = _inv_cwe
                    finding["cwe_source"] = "tool_refined"
                else:
                    # Keep the tool's classification — investigator disagrees but
                    # isn't confident enough to override
                    finding["cwe_type"] = _original_cwe
            else:
                # Investigator agrees or returned UNCLASSIFIED — keep tool CWE
                finding["cwe_type"] = _original_cwe
        else:
            # No tool classification — use investigator's result
            finding["cwe_type"] = _inv_cwe or _original_cwe or "UNCLASSIFIED"
            if finding["cwe_type"] == "UNCLASSIFIED":
                finding["cwe_type"] = self._infer_cwe_from_text(finding) or "UNCLASSIFIED"
            if finding["cwe_type"] != "UNCLASSIFIED":
                finding["cwe_source"] = "llm_inferred"

        finding["cve_id"] = result.get("cve_id")
        # 2c: carry joern taint context forward to PoV generation
        if result.get("joern_context"):
            finding["joern_context"] = result["joern_context"]

        # Task 8: Forward-pass investigation intel for downstream prompts.
        # root_cause and impact are surfaced in PRIORITY 1 of the restructured prompt.
        _inv_root_cause = str(result.get('root_cause') or '').strip()
        if _inv_root_cause:
            finding['root_cause'] = _inv_root_cause
            # Also inject into exploit_contract so prompts can access it
            _ec_fwd = dict(finding.get('exploit_contract') or {})
            _ec_fwd['root_cause'] = _inv_root_cause
            finding['exploit_contract'] = _ec_fwd
        _inv_impact = str(result.get('impact') or '').strip()
        if _inv_impact:
            finding['impact'] = _inv_impact
            _ec_fwd = dict(finding.get('exploit_contract') or {})
            _ec_fwd['impact'] = _inv_impact
            finding['exploit_contract'] = _ec_fwd
        # Forward taxonomy_refs (tool-identified references) into contract
        _tax_refs = finding.get('taxonomy_refs') or []
        if _tax_refs:
            _ec_fwd = dict(finding.get('exploit_contract') or {})
            _ec_fwd['taxonomy_refs'] = _tax_refs
            finding['exploit_contract'] = _ec_fwd
        # Task 4: tag joern_reachable on the finding for use by the contract gate
        _jc = result.get('joern_context', '')
        finding['joern_reachable'] = (
            bool(_jc)
            and 'no taint path' not in _jc.lower()
            and 'not found' not in _jc.lower()
            and 'not available' not in _jc.lower()
            and 'timed out' not in _jc.lower()
        )

        # Carry investigator-resolved entrypoint into exploit contract so contract gate can pass
        inv_entrypoint = str(result.get("target_entrypoint") or "").strip()
        if inv_entrypoint and inv_entrypoint.lower() not in {'unknown', 'none', 'n/a', ''}:
            contract = dict(finding.get("exploit_contract") or {})
            if not contract.get("target_entrypoint") or str(contract.get("target_entrypoint", "")).strip().lower() in {'unknown', 'none', 'n/a', ''}:
                contract["target_entrypoint"] = inv_entrypoint
                finding["exploit_contract"] = contract
        # Ensure runtime_profile is set from file extension when the investigator didn't set it.
        # This prevents JS/TS/Python findings from defaulting to an empty runtime_profile,
        # which would cause _contract_gate to emit no gate_family and block PoV generation.
        _contract_after = dict(finding.get("exploit_contract") or {})
        if not _contract_after.get("runtime_profile"):
            _fp = str(finding.get("filepath") or "")
            _, _ext = os.path.splitext(_fp.lower())
            _inferred = {
                '.js': 'javascript', '.jsx': 'javascript',
                '.ts': 'node', '.tsx': 'node',
                '.py': 'python',
                '.java': 'java',
                '.c': 'c', '.h': 'c',
                '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
            }.get(_ext, '')
            if _inferred:
                _contract_after["runtime_profile"] = _inferred
                finding["exploit_contract"] = _contract_after
        # T4 — execution_surface consistency: if runtime_profile is Python/Java/JS but
        # execution_surface='native' (LLM mistake), correct it so docker_runner routes correctly.
        _contract_after2 = dict(finding.get("exploit_contract") or {})
        _rt_profile2 = str(_contract_after2.get('runtime_profile') or '').strip().lower()
        _exec_surf2 = str(_contract_after2.get('execution_surface') or '').strip().lower()
        _NON_NATIVE2 = {'python', 'java', 'javascript', 'node', 'typescript'}
        if _rt_profile2 in _NON_NATIVE2 and _exec_surf2 == 'native':
            _surf_fix = {
                'java': 'function_call',
                'python': 'repo_script',
                'javascript': 'function_call',
                'node': 'function_call',
                'typescript': 'function_call',
            }.get(_rt_profile2, 'repo_script')
            _contract_after2['execution_surface'] = _surf_fix
            finding['exploit_contract'] = _contract_after2

        # ── Seed PoC: fetch existing exploit from CVE references (cached) ──
        _cve_for_poc = str(
            finding.get('cve_id')
            or (finding.get('exploit_contract') or {}).get('cve_id')
            or ''
        ).strip()
        if _cve_for_poc and _cve_for_poc.startswith('CVE-'):
            try:
                from agents.cve_enricher import fetch_existing_poc
                _seed = fetch_existing_poc(_cve_for_poc)
                if _seed:
                    _ec_seed = dict(finding.get('exploit_contract') or {})
                    _ec_seed['seed_poc'] = _seed
                    finding['exploit_contract'] = _ec_seed
                    self._log(state, f'[investigate] Fetched seed PoC for {_cve_for_poc} ({len(_seed)} chars)')
            except Exception as _e_poc:
                logger.debug('seed_poc fetch failed: %s', _e_poc)
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
        # Prefer top-level cost_usd, fall back to cost embedded in openrouter_usage
        # (online models store the exact billed cost there when the LangChain wrapper
        # does not propagate it up to the result dict directly).
        actual_cost = result.get("cost_usd", 0.0)
        if not actual_cost:
            actual_cost = float((result.get("openrouter_usage") or {}).get("cost_usd", 0.0) or 0.0)
        if actual_cost > 0:
            finding["cost_usd"] = actual_cost
        else:
            finding["cost_usd"] = 0.0
        
        state["total_cost_usd"] += finding["cost_usd"]
        
        state["findings"][idx] = finding
        self._sync_findings_runtime(state, include_status=True)
        
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
                    api_key_override=state.get("openrouter_api_key"),
                    repo_web_capable=state.get("repo_web_capable", False),
                    recon_report=state.get('recon_report'),
                )
                
                finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
                finding["llm_explanation"] = result.get("explanation", "")
                finding["confidence"] = result.get("confidence", 0.0)
                finding["inference_time_s"] = result.get("inference_time_s", 0.0)
                finding["code_chunk"] = result.get("vulnerable_code", "") or finding.get("code_chunk", "")
                finding["cwe_type"] = result.get("cwe_type") or finding.get("cwe_type") or "UNCLASSIFIED"
                if finding["cwe_type"] == "UNCLASSIFIED":
                    finding["cwe_type"] = self._infer_cwe_from_text(finding) or "UNCLASSIFIED"
                finding["cve_id"] = result.get("cve_id")
                # 2c: carry joern taint context forward to PoV generation
                if result.get("joern_context"):
                    finding["joern_context"] = result["joern_context"]
                # Task 4: tag joern_reachable
                _jc = result.get('joern_context', '')
                finding['joern_reachable'] = (
                    bool(_jc)
                    and 'no taint path' not in _jc.lower()
                    and 'not found' not in _jc.lower()
                    and 'not available' not in _jc.lower()
                    and 'timed out' not in _jc.lower()
                )
                inv_entrypoint = str(result.get("target_entrypoint") or "").strip()
                if inv_entrypoint and inv_entrypoint.lower() not in {'unknown', 'none', 'n/a', ''}:
                    contract = dict(finding.get("exploit_contract") or {})
                    if not contract.get("target_entrypoint") or str(contract.get("target_entrypoint", "")).strip().lower() in {'unknown', 'none', 'n/a', ''}:
                        contract["target_entrypoint"] = inv_entrypoint
                        finding["exploit_contract"] = contract
                # Ensure runtime_profile is set from file extension when the investigator didn't set it.
                _pbatch_contract = dict(finding.get("exploit_contract") or {})
                if not _pbatch_contract.get("runtime_profile"):
                    _fp2 = str(finding.get("filepath") or "")
                    _, _ext2 = os.path.splitext(_fp2.lower())
                    _inferred2 = {
                        '.js': 'javascript', '.jsx': 'javascript',
                        '.ts': 'node', '.tsx': 'node',
                        '.py': 'python',
                        '.java': 'java',
                        '.c': 'c', '.h': 'c',
                        '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
                    }.get(_ext2, '')
                    if _inferred2:
                        _pbatch_contract["runtime_profile"] = _inferred2
                        finding["exploit_contract"] = _pbatch_contract
                # T4 — execution_surface consistency (batch path)
                _pbatch_contract3 = dict(finding.get('exploit_contract') or {})
                _rt_p3 = str(_pbatch_contract3.get('runtime_profile') or '').strip().lower()
                _ex_s3 = str(_pbatch_contract3.get('execution_surface') or '').strip().lower()
                _NON_NATIVE3 = {'python', 'java', 'javascript', 'node', 'typescript'}
                if _rt_p3 in _NON_NATIVE3 and _ex_s3 == 'native':
                    _s3 = {'java': 'function_call', 'python': 'repo_script',
                           'javascript': 'function_call', 'node': 'function_call',
                           'typescript': 'function_call'}.get(_rt_p3, 'repo_script')
                    _pbatch_contract3['execution_surface'] = _s3
                    finding['exploit_contract'] = _pbatch_contract3
                token_usage = result.get("token_usage", {})
                model_used = result.get("model_used", model_name)
                finding["model_used"] = model_used
                finding["openrouter_usage"] = result.get("openrouter_usage", {})
                finding["prompt_tokens"] = token_usage.get("prompt_tokens", 0)
                finding["completion_tokens"] = token_usage.get("completion_tokens", 0)
                finding["total_tokens"] = token_usage.get("total_tokens", 0)
                # Prefer top-level cost; fall back to cost nested in openrouter_usage
                batch_cost = result.get("cost_usd", 0.0)
                if not batch_cost:
                    batch_cost = float((result.get("openrouter_usage") or {}).get("cost_usd", 0.0) or 0.0)
                finding["cost_usd"] = batch_cost
                
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
            completed_batches = 0
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                    completed_batches += 1
                    self._log(state, f"Completed investigation batch {completed_batches}/{len(batches)} (worker batch {batch_idx + 1})")
                except Exception as e:
                    completed_batches += 1
                    self._log(state, f"Investigation batch {completed_batches}/{len(batches)} failed (worker batch {batch_idx + 1}): {e}")
        
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
        self._sync_findings_runtime(state, include_status=True, progress=45)
        
        return state
    
    def _build_pov_context(self, finding: Dict[str, Any], code_context: str, state: ScanState) -> str:
        """Build context window for PoV generation.

        Both online and offline models receive the same window and fallback sizes
        (3000-char surround window, 8000-char fallback) so that benchmark results
        are not skewed by an infrastructure-level context asymmetry.
        """
        if not code_context:
            return ''
        vulnerable = str(finding.get('code_chunk') or '').strip()
        # Unified sizes — same for online and offline to ensure fair benchmarking.
        window = 3000
        fallback_size = 8000
        if not vulnerable:
            return code_context[:fallback_size]
        idx = code_context.find(vulnerable)
        if idx == -1:
            # code_chunk may have ellipsis or trimmed lines — search for first non-trivial line
            first_line = next(
                (ln.strip() for ln in vulnerable.splitlines()
                 if ln.strip() and not ln.strip().startswith('//') and '...' not in ln),
                None
            )
            if first_line and len(first_line) > 10:
                idx = code_context.find(first_line)
            if idx == -1:
                return code_context[:fallback_size]
        start = max(0, idx - window)
        end = min(len(code_context), idx + len(vulnerable) + window)
        return code_context[start:end]


    def _infer_cwe_from_text(self, finding: dict) -> str:
        """Attempt to extract a CWE ID from finding text fields when investigator
        returned UNCLASSIFIED.  Scans alert_message, llm_explanation, and code_chunk
        for patterns like CWE-416, CWE-120, etc."""
        import re as _re_cwe
        for field in ('alert_message', 'llm_explanation', 'code_chunk'):
            text = str(finding.get(field) or '')
            m = _re_cwe.search(r'CWE-?(\d+)', text, _re_cwe.IGNORECASE)
            if m:
                return f'CWE-{m.group(1)}'
        return ''


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
        # HTML files with embedded JS are treated as JavaScript runtime
        if ext in {'.html', '.htm'}:
            return 'javascript'

        detected = str(finding.get('detected_language') or state.get('detected_language') or '').strip().lower()
        _lang_map = {
            'c': 'c', 'cpp': 'cpp', 'c++': 'cpp',
            'java': 'java',
            'javascript': 'javascript',
            'typescript': 'node',
            'python': 'python',
            'node': 'node',
        }
        if detected in _lang_map:
            return _lang_map[detected]

        return 'python'

    def _node_probe_target(self, state: ScanState) -> ScanState:
        """Preflight probe node: run a lightweight Docker probe against the codebase
        BEFORE PoV generation so the LLM gets real runtime data (binary path, accepted
        CLI flags, crash behaviour, missing shared libs) instead of guessing.

        Results are stored in state['probe_result'] and injected as
        exploit_contract['probe_context'] for every finding processed in this scan.
        The probe only runs once per scan (not once per finding).
        """
        # Skip if already probed this scan (probe is per-scan, not per-finding)
        if state.get('probe_result') is not None:
            return state

        # Stage-skip: CVE dependency findings already have full exploit_contract
        # from the advisory database — running a build probe is wasted time.
        # EXCEPTION: native CVE findings still need probe to discover binary paths.
        idx = state.get('current_finding_idx', 0)
        _findings = state.get('findings', [])
        if idx < len(_findings) and _findings[idx].get('source') == 'dependency_cve':
            _cve_runtime = (_findings[idx].get('exploit_contract') or {}).get('runtime_profile', '')
            if _cve_runtime != 'native':
                self._log(state, f'Probe: skipping for non-native CVE dependency finding {idx} (runtime={_cve_runtime})')
                return state
            else:
                self._log(state, f'Probe: running for native CVE finding {idx} (binary path discovery needed)')

        codebase_path = state.get('codebase_path', '')
        scan_id = state.get('scan_id', 'unknown')
        self._log(state, f'Probe: running preflight probe against {codebase_path}')

        # Detect the dominant language profile for probe image selection.
        # Use the most common language across findings, defaulting to 'native'.
        _lang_votes: Dict[str, int] = {}
        for _f in state.get('findings', []):
            _lang = str((_f.get('exploit_contract') or {}).get('runtime_profile') or _f.get('detected_language') or '').strip().lower()
            if _lang:
                _lang_votes[_lang] = _lang_votes.get(_lang, 0) + 1
        _probe_profile = max(_lang_votes, key=_lang_votes.get) if _lang_votes else 'native'

        # Attempt the probe; always succeeds (errors are captured inside ProbeResult)
        probe = run_probe(
            codebase_path=codebase_path,
            scan_id=scan_id,
            exploit_contract=None,
            timeout=300,  # allow time for build inside probe container
            runtime_profile=_probe_profile,
        )
        probe_dict = probe.to_dict()
        state['probe_result'] = probe_dict

        # Synthesize repo intelligence profile from recon + probe data
        try:
            from agents.repo_intelligence import synthesize_repo_profile, inject_protocol_into_contract
            _repo_profile = synthesize_repo_profile(
                recon_report=state.get('recon_report'),
                probe_result=probe_dict,
                findings=state.get('findings'),
                codebase_path=codebase_path,
            )
            state['repo_profile'] = _repo_profile.to_dict()
            self._log(state, f'RepoProfile: type={_repo_profile.project_type}, '
                             f'format={_repo_profile.input_format}, '
                             f'protocol={" → ".join(_repo_profile.multi_step_protocol) or "none"}')
            # Persist repo profile to memory for future scans
            try:
                from agents.repo_memory import get_repo_memory
                _mem = get_repo_memory()
                _mem.store_repo_profile(_repo_profile.repo_name, _repo_profile.to_dict(), scan_id=scan_id)
                # Recall previous winning strategies
                _prev_winners = _mem.get_winning_strategies(_repo_profile.repo_name)
                if _prev_winners:
                    state['repo_profile']['previous_winning_strategies'] = _prev_winners
                    self._log(state, f'RepoMemory: recalled {len(_prev_winners)} winning strategies from previous scans')
                    # Inject winning strategies into every finding's exploit_contract
                    # so PoV generation and refinement prompts can use them.
                    for _f_ws in state.get('findings', []):
                        _ec_ws = dict(_f_ws.get('exploit_contract') or {})
                        if not _ec_ws.get('previous_winning_strategies'):
                            _ec_ws['previous_winning_strategies'] = _prev_winners
                        _f_ws['exploit_contract'] = _ec_ws
            except Exception as _mem_err:
                logger.debug('RepoMemory persistence failed (non-fatal): %s', _mem_err)
        except Exception as _rp_err:
            logger.warning('RepoProfile synthesis failed: %s', _rp_err)
            state['repo_profile'] = {}

        if probe.probe_skipped:
            self._log(state, f'Probe skipped: {probe.probe_skip_reason}')
        else:
            self._log(state, f'Probe complete in {probe.probe_duration_s:.1f}s: '
                             f'binary={probe.probe_binary_path or "not_found"}, '
                             f'crash={probe.probe_crash_observed}, '
                             f'ldd_missing={probe.probe_ldd_missing}')
            # Inject all probe discoveries into every finding's exploit_contract.
            # Binary path/name and input surface only when a binary was found;
            # baseline exit code + stderr always (needed for asan_disabled oracle
            # even on non-native repos where no ELF binary is discovered).
            _probe_binary_name = os.path.basename(probe.probe_binary_path) if probe.probe_binary_path else ''
            _probe_input_surface = probe.probe_input_surface or 'unknown'
            for finding in state.get('findings', []):
                ec = dict(finding.get('exploit_contract') or {})
                if probe.probe_binary_path:
                    if not ec.get('probe_binary_path'):
                        ec['probe_binary_path'] = probe.probe_binary_path
                    if not ec.get('probe_binary_name'):
                        ec['probe_binary_name'] = _probe_binary_name
                if _probe_input_surface != 'unknown' and not ec.get('probe_input_surface'):
                    ec['probe_input_surface'] = _probe_input_surface
                # Propagate baseline exit code + stderr so docker_runner can pass
                # them to oracle_policy for the asan_disabled fallback oracle.
                if probe.probe_baseline_exit_code != -1 and not ec.get('probe_baseline_exit_code'):
                    ec['probe_baseline_exit_code'] = probe.probe_baseline_exit_code
                if probe.probe_baseline_stderr and not ec.get('probe_baseline_stderr'):
                    ec['probe_baseline_stderr'] = probe.probe_baseline_stderr
                # 2b: Enrich target_binary and proof_plan.input_mode from probe data
                # so PoV generation has concrete runtime anchors even when static analysis
                # could not resolve the binary name or input surface.
                _weak = {'', 'unknown', 'none', 'n/a'}
                if probe.probe_binary_path and str(ec.get('target_binary') or '').strip().lower() in _weak:
                    # Use basename only — full paths like /workspace/codebase/enchive
                    # confuse downstream contract matching and PoV generation.
                    import os as _os
                    ec['target_binary'] = _os.path.basename(probe.probe_binary_path)
                if _probe_input_surface != 'unknown':
                    _input_mode_map = {
                        'file_argument': 'file',
                        'stdin': 'stdin',
                        'argv_only': 'argv',
                        'network': 'request',
                    }
                    _mapped_mode = _input_mode_map.get(_probe_input_surface, '')
                    if _mapped_mode:
                        plan = ec.setdefault('proof_plan', {})
                        if not plan.get('input_mode'):
                            plan['input_mode'] = _mapped_mode
                # Task 5b: propagate probe help_text into observed_surface so
                # _build_binary_surface_block() can emit it in the generation prompt.
                if probe.probe_help_text:
                    obs = ec.setdefault('observed_surface', {})
                    if not obs.get('help_text'):
                        obs['help_text'] = probe.probe_help_text
                    # Also surface the classified input surface within observed_surface
                    if _probe_input_surface != 'unknown' and not obs.get('input_surface'):
                        obs['input_surface'] = _probe_input_surface
                # Task 2: propagate surface-adaptive probe fields so contract gate
                # can route to the correct execution surface without pre-filled fields.
                if probe.probe_surface_type and not ec.get('probe_surface_type'):
                    ec['probe_surface_type'] = probe.probe_surface_type
                if probe.probe_entry_command and not ec.get('probe_entry_command'):
                    ec['probe_entry_command'] = probe.probe_entry_command
                if probe.probe_base_url and not ec.get('probe_base_url'):
                    ec['probe_base_url'] = probe.probe_base_url
                # T3: propagate format hint so _build_binary_surface_block() in prompts.py
                # can inject the correct format guidance into the PoV generation prompt.
                if probe_dict.get('probe_format_hint') and not ec.get('probe_format_hint'):
                    ec['probe_format_hint'] = probe_dict['probe_format_hint']
                # Adaptive intelligence: forward probe-derived subcommands, extensions,
                # rejection patterns, and bootstrap subcommand so downstream consumers
                # (docker_runner, pov_tester, prompts) use runtime-discovered data
                # instead of hardcoded maps.
                if probe.probe_discovered_subcommands and not ec.get('probe_discovered_subcommands'):
                    ec['probe_discovered_subcommands'] = probe.probe_discovered_subcommands
                if probe.probe_inferred_extensions and not ec.get('probe_inferred_extensions'):
                    ec['probe_inferred_extensions'] = probe.probe_inferred_extensions
                if probe.probe_rejection_patterns and not ec.get('probe_rejection_patterns'):
                    ec['probe_rejection_patterns'] = probe.probe_rejection_patterns
                if probe.probe_bootstrap_subcommand and not ec.get('probe_bootstrap_subcommand'):
                    ec['probe_bootstrap_subcommand'] = probe.probe_bootstrap_subcommand
                # Task 3: propagate probe_binary_is_test flag so env_kind routing
                # can switch to c_library_harness when only a test binary was found.
                if probe.probe_binary_is_test:
                    ec['probe_binary_is_test'] = '1'
                # Task 1/2A: Propagate repo_surface_class and library_api_context so
                # PoV generation and guardrails can route without re-reading state.
                _repo_cls = state.get('repo_surface_class') or ''
                if _repo_cls and not ec.get('repo_surface_class'):
                    ec['repo_surface_class'] = _repo_cls
                _lib_api = state.get('library_api_context') or ''
                if _lib_api and not ec.get('library_api_context'):
                    ec['library_api_context'] = _lib_api
                # Fix: Force c_library_harness for library_c_with_cli when binary
                # is in a wrapper/example directory (not a primary CLI tool).
                if _repo_cls == 'library_c_with_cli' and probe.probe_binary_path:
                    import re as _re_wrapper
                    _WRAPPER_PATH_RE = _re_wrapper.compile(
                        r'[\/](examples?|samples?|demos?|tools?|wf|xmlwf|cmd|cli|bin|contrib|tests?|bench|fuzz|readme)[\/]',
                        _re_wrapper.IGNORECASE
                    )
                    _WRAPPER_NAME_RE = _re_wrapper.compile(
                        r'^(?:readme[_-]?|example[_-]?|sample[_-]?|demo[_-]?|test[_-]?|bench[_-]?)',
                        _re_wrapper.IGNORECASE
                    )
                    _bin_basename = _os.path.basename(probe.probe_binary_path)
                    if _WRAPPER_PATH_RE.search(probe.probe_binary_path) or _WRAPPER_NAME_RE.match(_bin_basename):
                        ec['probe_binary_is_test'] = '1'
                # Clear conflicting binary fields when routing to c_library_harness
                # so the model doesn't get confused by having both a target_binary
                # AND c_library_harness instructions.
                if ec.get('probe_binary_is_test') == '1' and _repo_cls in ('library_c_with_cli', 'library_c'):
                    ec.pop('target_binary', None)
                    ec.pop('probe_binary_name', None)
                    ec.pop('probe_binary_path', None)  # prevent native prelude from finding wrapper binary
                    ec['probe_binary_is_example'] = '1'
                    # Explicitly set execution_surface so docker_runner routes
                    # to c_library_harness and prompts inject harness template
                    ec['execution_surface'] = 'c_library_harness'
                # Task 5: if probe input surface was detected as test_harness_output,
                # clear the probe binary path (it's a test runner) and set surface type.
                if _probe_input_surface == 'test_harness_output':
                    ec.pop('probe_binary_path', None)
                    ec.pop('probe_binary_name', None)
                    ec.pop('target_binary', None)
                    if not ec.get('probe_surface_type'):
                        ec['probe_surface_type'] = 'c_library'
                    # Ensure library API is exposed for this finding
                    if _lib_api:
                        obs = ec.setdefault('observed_surface', {})
                        if not obs.get('library_api'):
                            obs['library_api'] = _lib_api
                # Library harness quality boost: inject the vulnerable function's
                # actual source code into the contract so the LLM can write a
                # harness that calls the real API with correct argument types.
                if _repo_cls in ('library_c', 'library_c_with_cli') and not ec.get('vulnerable_function_source'):
                    _vuln_src = self._extract_vulnerable_function_source(
                        state.get('codebase_path', ''),
                        finding.get('filepath', ''),
                        finding.get('line_number', 0),
                        finding.get('exploit_contract', {}).get('target_entrypoint', ''),
                    )
                    if _vuln_src:
                        ec['vulnerable_function_source'] = _vuln_src
                # Auto-populate success_indicators from probe when investigation didn't set them
                _auto_populate_oracle_from_probe(ec, state.get('probe_result') or {})

                # Inject repo protocol intelligence from RepoProfile
                _rp = state.get('repo_profile')
                if _rp:
                    try:
                        from agents.repo_intelligence import inject_protocol_into_contract, RepoProfile
                        _rp_obj = RepoProfile(**{k: v for k, v in _rp.items() if hasattr(RepoProfile, k)})
                        ec = inject_protocol_into_contract(_rp_obj, ec)
                    except Exception:
                        pass  # non-fatal
                    # Wire repo profile fields into contract for docker_runner routing
                    if not ec.get('repo_runtime_family'):
                        ec['repo_runtime_family'] = _rp.get('runtime_family', '')
                    if not ec.get('repo_build_system'):
                        ec['repo_build_system'] = _rp.get('build_system', '')
                    if not ec.get('repo_default_proof_type'):
                        ec['repo_default_proof_type'] = _rp.get('default_proof_type', '')
                finding['exploit_contract'] = ec

            # ── Inject recon intelligence into every finding's exploit_contract ──
            # Recon data was previously only stored in state['recon_report'] and
            # never reached the exploit_contract — the vehicle that carries data
            # to PoV generation.  Now we inject key recon fields so downstream
            # consumers (proof strategy, PoV gen, investigation) see them.
            _recon_data = state.get('recon_report') or {}
            if _recon_data:
                for finding in state.get('findings', []):
                    ec = dict(finding.get('exploit_contract') or {})
                    if not ec.get('recon_attack_surfaces'):
                        ec['recon_attack_surfaces'] = _recon_data.get('attack_surfaces', [])
                    if not ec.get('recon_proof_strategies'):
                        ec['recon_proof_strategies'] = _recon_data.get('proof_strategies', {})
                    if not ec.get('recon_entry_points'):
                        ec['recon_entry_points'] = _recon_data.get('entrypoints', [])
                    # Extract subcommand names from recon entrypoints
                    if not ec.get('recon_subcommands'):
                        _r_subs = [ep.get('name', '') for ep in _recon_data.get('entrypoints', []) if ep.get('name')]
                        if _r_subs:
                            ec['recon_subcommands'] = _r_subs
                    if not ec.get('recon_input_format_hints'):
                        ec['recon_input_format_hints'] = _recon_data.get('input_format_hints', [])
                    if not ec.get('recon_sample_inputs'):
                        ec['recon_sample_inputs'] = _recon_data.get('sample_input_files', [])
                    if not ec.get('recon_default_proof_type'):
                        ec['recon_default_proof_type'] = _recon_data.get('default_proof_type', '')
                    if not ec.get('recon_default_harness_type'):
                        ec['recon_default_harness_type'] = _recon_data.get('default_harness_type', '')
                    # Merge recon subcommands into known_subcommands if probe didn't find any
                    _existing_subs = ec.get('known_subcommands') or []
                    _recon_subs = ec.get('recon_subcommands') or []
                    if _recon_subs and not _existing_subs:
                        ec['known_subcommands'] = _recon_subs
                    elif _recon_subs and _existing_subs:
                        # Merge, deduplicate, preserve order
                        _merged = list(_existing_subs)
                        for s in _recon_subs:
                            if s not in _merged:
                                _merged.append(s)
                        ec['known_subcommands'] = _merged
                    finding['exploit_contract'] = ec
                self._log(state, f'[probe] Injected recon intelligence into {len(state.get("findings", []))} findings\' exploit_contracts')

            # Task 9: Detect library-only repos (no CLI binary, no web server)
            # and set execution_surface to function_call so PoV gen uses import+call.
            if not probe.probe_binary_path and not probe.probe_surface_type:
                _det_lang = str(state.get('detected_language') or '').lower()
                if _det_lang in {'javascript', 'typescript'}:
                    self._log(state, 'Probe: No binary or server found for JS/TS repo — routing as library (function_call)')
                    for finding in state.get('findings', []):
                        ec = dict(finding.get('exploit_contract') or {})
                        if not ec.get('execution_surface'):
                            ec['execution_surface'] = 'function_call'
                            ec['runtime_profile'] = 'node'
                        finding['exploit_contract'] = ec
                elif _det_lang == 'python':
                    self._log(state, 'Probe: No binary or server found for Python repo — routing as library (function_call)')
                    for finding in state.get('findings', []):
                        ec = dict(finding.get('exploit_contract') or {})
                        if not ec.get('execution_surface'):
                            ec['execution_surface'] = 'function_call'
                            ec['runtime_profile'] = 'python'
                        finding['exploit_contract'] = ec

        return state

    def _extract_vulnerable_function_source(
        self, codebase_path: str, filepath: str, line_number: int, entrypoint: str,
    ) -> str:
        """Extract the full C/C++ function body surrounding a vulnerability.

        Reads the source file and finds the function containing `line_number`,
        or the function named `entrypoint`. Returns up to 120 lines of the
        function body so the LLM can write an accurate harness.
        """
        import os as _os
        import re as _re
        from pathlib import Path as _Path

        if not codebase_path or not filepath:
            return ''

        # Resolve the file path relative to codebase
        src_path = _Path(codebase_path) / filepath
        if not src_path.is_file():
            # Try without leading directory components (scanner paths may differ)
            for root, _dirs, files in _os.walk(codebase_path):
                for f in files:
                    if f == _Path(filepath).name:
                        src_path = _Path(root) / f
                        break
                if src_path.is_file():
                    break
        if not src_path.is_file():
            return ''

        try:
            lines = src_path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError:
            return ''

        if not lines:
            return ''

        # Strategy 1: Find the function containing the vulnerable line
        target_line = max(0, (line_number or 1) - 1)  # 0-indexed

        # Walk backwards from target_line to find function start
        func_start = None
        # C function declaration pattern: return_type [*] func_name(...) {
        _FUNC_DECL = _re.compile(
            r'^\s*(?:static\s+|inline\s+|extern\s+|const\s+|unsigned\s+|void\s+|'
            r'\w+\s+)*(?:\*\s*)*\w+\s*\([^;]*\)\s*\{?\s*$'
        )
        for i in range(min(target_line, len(lines) - 1), max(target_line - 80, -1), -1):
            if i < 0:
                break
            if _FUNC_DECL.match(lines[i]):
                func_start = i
                break

        if func_start is None and entrypoint and entrypoint.lower() not in {'', 'unknown', 'none', 'main'}:
            # Strategy 2: Search for the named entrypoint function
            _ep_re = _re.compile(r'\b' + _re.escape(entrypoint) + r'\s*\(')
            for i, line in enumerate(lines):
                if _ep_re.search(line) and '{' in line or (i + 1 < len(lines) and '{' in lines[i + 1]):
                    func_start = i
                    break

        if func_start is None:
            # Fallback: return context around the vulnerable line (40 lines)
            start = max(0, target_line - 10)
            end = min(len(lines), target_line + 30)
            return '\n'.join(lines[start:end])

        # Find function end by matching braces
        brace_depth = 0
        func_end = func_start
        found_open = False
        for i in range(func_start, min(len(lines), func_start + 200)):
            for ch in lines[i]:
                if ch == '{':
                    brace_depth += 1
                    found_open = True
                elif ch == '}':
                    brace_depth -= 1
            if found_open and brace_depth <= 0:
                func_end = i
                break
        else:
            func_end = min(len(lines) - 1, func_start + 120)

        # Also include any preceding function signature / comment (up to 5 lines)
        sig_start = max(0, func_start - 5)
        # Cap at 120 lines total
        end = min(func_end + 1, sig_start + 120)

        return '\n'.join(lines[sig_start:end])

    def _node_trace_target(self, state: ScanState) -> ScanState:
        """Dynamic trace node: runs strace + valgrind after the probe and before PoV generation.

        Runs once per scan (like probe_target). Results are stored in state['trace_result']
        and injected as exploit_contract['trace_context'] for every finding.
        Only runs for native C/C++ targets; skips silently for other languages.
        """
        # Skip if already traced this scan
        if state.get('trace_result') is not None:
            return state

        # Stage-skip: CVE dependency findings already have the exploit path from
        # the advisory DB — strace/valgrind trace discovers nothing useful.
        # EXCEPTION: native CVE findings benefit from strace/valgrind for surface confirmation.
        idx = state.get('current_finding_idx', 0)
        _findings = state.get('findings', [])
        if idx < len(_findings) and _findings[idx].get('source') == 'dependency_cve':
            _cve_runtime = (_findings[idx].get('exploit_contract') or {}).get('runtime_profile', '')
            if _cve_runtime != 'native':
                self._log(state, f'Trace: skipping for non-native CVE dependency finding {idx} (runtime={_cve_runtime})')
                return state
            else:
                self._log(state, f'Trace: running for native CVE finding {idx} (surface confirmation needed)')

        codebase_path = state.get('codebase_path', '')
        scan_id = state.get('scan_id', 'unknown')
        repo_surface_class = state.get('repo_surface_class') or ''

        # Determine probe_binary_path from the first finding that has it
        _probe_contract: Dict[str, Any] = {}
        for _f in state.get('findings', []):
            _ec = _f.get('exploit_contract') or {}
            if _ec.get('probe_binary_path'):
                _probe_contract = _ec
                break

        self._log(state, f'Trace: running dynamic trace for surface={repo_surface_class}')

        try:
            trace = run_trace(
                codebase_path=codebase_path,
                scan_id=scan_id,
                exploit_contract=_probe_contract,
                repo_surface_class=repo_surface_class,
            )
            trace_dict = trace.to_dict()
            state['trace_result'] = trace_dict

            if trace.trace_skipped:
                self._log(state, f'Trace skipped: {trace.trace_skip_reason}')
            else:
                self._log(state,
                    f'Trace complete in {trace.trace_duration_s:.1f}s: '
                    f'surface={trace.trace_input_surface}, '
                    f'valgrind_errors={trace.trace_valgrind_errors}')

            # Inject trace_context into every finding's exploit_contract
            trace_ctx_str = format_trace_context(trace)
            # FIX-14: Also store structured JSON trace for the coordinator so it
            # can parse fields programmatically instead of regex-scraping text.
            _trace_json_str = trace.to_json() if hasattr(trace, 'to_json') else ''
            if trace_ctx_str:
                for finding in state.get('findings', []):
                    ec = dict(finding.get('exploit_contract') or {})
                    if not ec.get('trace_context'):
                        ec['trace_context'] = trace_ctx_str
                    if _trace_json_str and not ec.get('trace_json'):
                        ec['trace_json'] = _trace_json_str
                    # Also propagate detected input surface if stronger than probe's
                    if trace.trace_input_surface and trace.trace_input_surface != 'unknown':
                        if not ec.get('trace_input_surface'):
                            ec['trace_input_surface'] = trace.trace_input_surface
                    finding['exploit_contract'] = ec
        except Exception as exc:
            self._log(state, f'Trace node error (non-fatal): {exc}')
            state['trace_result'] = {'trace_skipped': True, 'trace_skip_reason': f'exception:{exc}'}

        return state

    def _get_recon_default_proof_strategy(self, state: ScanState) -> Dict[str, Any]:
        """Get the default proof strategy from the recon report.

        Instead of always defaulting to crash_signal, this uses the
        reconnaissance report to pick the right proof type for the project.
        """
        recon_data = state.get('recon_report') or {}
        if recon_data:
            recon = ReconReport.from_dict(recon_data)
            return recon.get_default_proof_strategy()
        # Ultimate fallback if no recon report exists
        return {'proof_type': 'crash_signal', 'observable_evidence': [], 'harness_type': 'subprocess_binary'}

    def _node_proof_strategy(self, state: ScanState) -> ScanState:
        """Determine proof strategy for each confirmed finding before PoV generation.

        This v2 phase asks the LLM what kind of runtime evidence proves the vulnerability
        is real, and what harness approach is needed. The result is stored in
        finding['exploit_contract']['proof_strategy'] for downstream use by the
        PoV generator, oracle, and coordinator.
        """
        if self._check_cancelled(state):
            return state

        from prompts import format_proof_strategy_prompt

        idx = state.get('current_finding_idx', 0)
        if idx >= len(state['findings']):
            return state

        finding = state['findings'][idx]
        verdict = finding.get('llm_verdict', '')
        if verdict != 'REAL':
            return state

        ec = finding.get('exploit_contract') or {}
        # Skip if proof_strategy already set
        if ec.get('proof_strategy'):
            return state

        self._log(state, f"[proof_strategy] Determining proof strategy for finding {idx}")

        # ── Infer proof_category dynamically (CWE-agnostic) ──────────────
        try:
            from agents.finding_context import _infer_proof_category, FindingContext as _FC
            _inv = finding.get('investigation') or {}
            _mini_ctx = _FC(
                root_cause=str(_inv.get('explanation') or finding.get('llm_explanation') or ''),
                impact=str(ec.get('impact') or ''),
                vulnerable_code=str(_inv.get('vulnerable_code') or finding.get('code_chunk') or ''),
                code_context=str(_inv.get('code_context') or ''),
                trigger_steps=list(ec.get('trigger_steps') or []),
                runtime_family=str(ec.get('runtime_family') or state.get('target_language') or 'native'),
            )
            _proof_category = _infer_proof_category(_mini_ctx)
        except Exception:
            _proof_category = 'crash'
        ec['proof_category'] = _proof_category
        self._log(state, f"[proof_strategy] inferred proof_category={_proof_category}")

        try:
            investigation = finding.get('investigation') or {}
            prompt = format_proof_strategy_prompt(
                cwe_type=investigation.get('cwe_type', finding.get('cwe_type', '')),
                filepath=investigation.get('filepath', finding.get('filepath', '')),
                target_language=ec.get('runtime_family', state.get('target_language', '')),
                explanation=investigation.get('explanation', finding.get('llm_explanation', '')),
                vulnerable_code=investigation.get('vulnerable_code', finding.get('code_chunk', '')),
                exploit_contract=ec,
                recon_report=state.get('recon_report'),
                probe_result=state.get('probe_result'),
                proof_category=_proof_category,
            )

            # Use the same LLM as investigation
            from agents.investigator import get_investigator
            _investigator = get_investigator()
            model_name = state.get('model_name') or ''
            llm = _investigator._get_llm(model_name=model_name or None)
            import json as _json
            from langchain_core.messages import HumanMessage
            response = llm.invoke([HumanMessage(content=prompt)])
            content = response.content if hasattr(response, 'content') else str(response)

            # Parse JSON from response
            _clean = content.strip()
            if '```' in _clean:
                _clean = _clean.split('```json')[-1].split('```')[0].strip() if '```json' in _clean else _clean.split('```')[1].split('```')[0].strip()
            proof_strategy = _json.loads(_clean)

            # Validate required fields
            _required = ('proof_type', 'observable_evidence', 'harness_type')
            if all(k in proof_strategy for k in _required):
                # ── Override: if proof_category=behavioral but LLM chose crash_signal, force behavioral_deviation
                # EXCEPTION: for native C/C++ targets with crash-prone CWEs, the LLM's crash_signal
                # choice is authoritative — ASan will catch buffer overflows, use-after-free, etc.
                # even when the abstract vulnerability class is "behavioral" (path traversal, info leak).
                # Overriding crash_signal to behavioral_deviation on these targets causes the oracle
                # to look for observable_evidence markers instead of sanitizer/crash signals, which
                # almost never matches and produces 0 confirmations.
                _runtime_family = str(ec.get('runtime_family') or state.get('target_language') or '').lower()
                _is_native = _runtime_family in ('c', 'cpp', 'native', 'binary') or str(ec.get('runtime_profile') or '').lower() in ('c', 'cpp', 'native', 'binary')
                _crash_cwes = {'CWE-120', 'CWE-125', 'CWE-121', 'CWE-122', 'CWE-124', 'CWE-126',
                               'CWE-127', 'CWE-787', 'CWE-788', 'CWE-415', 'CWE-416',
                               'CWE-190', 'CWE-191', 'CWE-476', 'CWE-680',
                               'CWE-022', 'CWE-073', 'CWE-078', 'CWE-077'}
                _cwe_id = str(finding.get('cwe_type') or '').strip().upper()
                _is_crash_cwe = _cwe_id in _crash_cwes
                if _proof_category == 'behavioral' and proof_strategy.get('proof_type') == 'crash_signal':
                    if _is_native and _is_crash_cwe:
                        self._log(state, f"[proof_strategy] NATIVE CRASH CWE OVERRIDE: keeping crash_signal for {_cwe_id} on native target "
                                  f"(proof_category was {_proof_category} but ASan will catch this)")
                    else:
                        self._log(state, f"[proof_strategy] OVERRIDE: proof_category=behavioral but LLM chose crash_signal → forcing behavioral_deviation")
                        proof_strategy['proof_type'] = 'behavioral_deviation'
                # ── Reverse override: for native crash-prone CWEs, force crash_signal even when
                # LLM chose behavioral_deviation.  The behavioral oracle almost never confirms
                # native C targets — it looks for observable_evidence markers in output instead
                # of sanitizer/crash signals.  For buffer overflows, path traversal, command
                # injection etc. in native code, ASan/SIGSEGV is the correct proof path.
                if _is_native and _is_crash_cwe and proof_strategy.get('proof_type') != 'crash_signal':
                    self._log(state, f"[proof_strategy] NATIVE CRASH CWE FORCE: overriding proof_type={proof_strategy.get('proof_type')} "
                              f"→ crash_signal for {_cwe_id} on native target")
                    proof_strategy['proof_type'] = 'crash_signal'
                    # Also add crash-relevant observable evidence so the oracle can match
                    _obs = proof_strategy.get('observable_evidence') or []
                    _crash_markers = ['AddressSanitizer', 'heap-buffer-overflow', 'stack-buffer-overflow',
                                      'use-after-free', 'double-free', 'SEGV', 'SIGABRT']
                    for _cm in _crash_markers:
                        if _cm not in _obs:
                            _obs.append(_cm)
                    proof_strategy['observable_evidence'] = _obs
                # ── Sanitize observable_evidence: ensure behavioral findings have behavioral markers
                if _proof_category == 'behavioral':
                    _obs = proof_strategy.get('observable_evidence', [])
                    _crash_kw = ('asan', 'sigsegv', 'sigabrt', 'addresssanitizer', 'segmentation',
                                 'core dump', 'crash', 'heap-buffer', 'stack-buffer',
                                 'use-after-free', 'double-free', 'signal 11', 'signal 6')
                    _has_behavioral = any(
                        m for m in _obs
                        if not any(ck in m.lower() for ck in _crash_kw)
                    )
                    if not _has_behavioral:
                        # Task 6: Derive evidence dynamically from exploitation approach
                        try:
                            from agents.finding_context import _derive_observable_evidence_from_approach, _infer_exploitation_approach
                            _approach_text = _infer_exploitation_approach(_mini_ctx)
                            _cwe_for_derive = str(finding.get('cwe_type') or '').strip()
                            _derived = _derive_observable_evidence_from_approach(_approach_text, cwe=_cwe_for_derive)
                            if _derived:
                                proof_strategy['observable_evidence'] = _derived
                                self._log(state, f'[proof_strategy] Derived observable_evidence from approach: {_derived}')
                            else:
                                _behavioral_defaults = ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'INSECURE_PERMISSION', 'SENSITIVE_DATA_LEAKED']
                                proof_strategy['observable_evidence'] = _behavioral_defaults
                                self._log(state, f'[proof_strategy] Replaced crash-only evidence with behavioral defaults')
                        except Exception:
                            _behavioral_defaults = ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'INSECURE_PERMISSION', 'SENSITIVE_DATA_LEAKED']
                            proof_strategy['observable_evidence'] = _behavioral_defaults
                            self._log(state, f'[proof_strategy] Replaced crash-only evidence with behavioral defaults (fallback)')

                # Task 6: Use OSV proof_type/hint as ground truth signal
                _osv_findings = (state.get('recon_report') or {}).get('osv_findings') or []
                if _osv_findings:
                    for _osv_f in _osv_findings:
                        _osv_pt = str(_osv_f.get('proof_type') or '').strip().lower()
                        _osv_hint = str(_osv_f.get('proof_hint') or '').strip()
                        if _osv_pt and _osv_pt != 'crash_signal' and proof_strategy.get('proof_type') == 'crash_signal':
                            self._log(state, f'[proof_strategy] OSV override: proof_type={_osv_pt} (was crash_signal)')
                            proof_strategy['proof_type'] = _osv_pt
                        if _osv_hint and not proof_strategy.get('exploitation_approach'):
                            proof_strategy['exploitation_approach'] = _osv_hint
                ec['proof_strategy'] = proof_strategy
                finding['exploit_contract'] = ec
                self._log(state, f"[proof_strategy] proof_type={proof_strategy.get('proof_type')}, "
                          f"harness_type={proof_strategy.get('harness_type')}")
            else:
                self._log(state, '[proof_strategy] Response missing required fields, using recon default')
                ec['proof_strategy'] = self._get_recon_default_proof_strategy(state)
                finding['exploit_contract'] = ec

        except Exception as exc:
            self._log(state, f'[proof_strategy] LLM call failed ({exc}), using recon default')
            ec['proof_strategy'] = self._get_recon_default_proof_strategy(state)
            finding['exploit_contract'] = ec

        # Inject recon-derived docker_extra_deps into exploit_contract
        # so docker_runner can install them before build/PoV execution.
        _recon_deps = state.get('recon_docker_extra_deps') or []
        if _recon_deps and not ec.get('docker_extra_deps'):
            ec['docker_extra_deps'] = _recon_deps
            finding['exploit_contract'] = ec

        # Inject DB substitution env vars for web service targets
        _db_env = state.get('recon_db_substitution_env') or {}
        if _db_env and not ec.get('db_substitution_env'):
            ec['db_substitution_env'] = _db_env
            finding['exploit_contract'] = ec

        return state

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
        proof_threshold = self._proof_threshold_for_finding(finding, state)
        if confidence < proof_threshold:
            self._log(state, f"Skipping PoV generation because confidence {confidence:.2f} is below the proof threshold {proof_threshold:.2f}")
            finding["final_status"] = "unproven_low_confidence"
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
            return state
        
        self._log(state, f"Generating PoV for {finding['cwe_type']}...")

        # Fast-fail for native targets when the build failed and no binary exists.
        # This avoids wasting LLM tokens + docker cycles on findings that can never
        # be confirmed because there is no ASan binary to drive.
        _ec_gen = finding.get('exploit_contract') or {}
        _runtime_gen = str(_ec_gen.get('runtime_profile') or self._infer_runtime_profile(finding, state) or '').lower()
        if _runtime_gen in ('c', 'cpp', 'native', 'binary'):
            _has_binary = bool(
                str(_ec_gen.get('probe_binary_path') or '').strip()
                or str(_ec_gen.get('target_binary') or '').strip()
            )
            _exec_surface = str(_ec_gen.get('execution_surface') or '').lower()
            _is_library = _exec_surface == 'c_library_harness' or str(_ec_gen.get('repo_surface_class') or '').lower() in ('library_c', 'library_c_with_cli')
            # Check if the Docker container's build prelude could still succeed
            # (the probe might have failed for transient reasons like missing deps
            # that the PoV script or the container's build commands can install).
            _codebase_exists = bool(state.get('codebase_path') and os.path.isdir(state['codebase_path']))
            _has_makefile = False
            _has_cmake = False
            if _codebase_exists:
                _cb = state['codebase_path']
                _has_makefile = any(os.path.isfile(os.path.join(_cb, mf)) for mf in ('Makefile', 'makefile', 'GNUmakefile'))
                _has_cmake = os.path.isfile(os.path.join(_cb, 'CMakeLists.txt'))
            # Task 3: Only fast-fail when there is truly no binary AND no library path.
            # If a binary was found (probe_binary_path), proceed even with unknown entrypoint —
            # the PoV can still exercise the binary with crafted input and the oracle
            # can confirm via crash/ASan/behavioral evidence or contract-driven markers.
            if not _has_binary and not _is_library:
                if _codebase_exists and (_has_makefile or _has_cmake):
                    # The codebase has a build system — the Docker container's build
                    # prelude may succeed where the probe failed.  Allow PoV generation
                    # to proceed; if the Docker build also fails, the finding will fail
                    # at runtime (same outcome as not trying).
                    self._log(state, f"  Warning: no binary found but build system detected — "
                                     f"allowing PoV generation (Docker build may succeed)")
                    finding.setdefault('failure_log', []).append({
                        'stage': 'generation',
                        'reason': 'No binary from probe but build system exists in codebase — '
                                  'proceeding with PoV generation for Docker build attempt.',
                    })
                else:
                    self._log(state, f"  Fast-fail: native target but no binary found (build failed). Skipping PoV generation.")
                    finding['final_status'] = 'failed'
                    finding['failure_reason'] = 'build_failed'
                    finding.setdefault('failure_log', []).append({
                        'stage': 'generation',
                        'reason': 'Native target build failed — no binary available for PoV execution. '
                                  'TARGET_BINARY would be empty, so all PoV attempts would fail.',
                    })
                    state['findings'][idx] = finding
                    self._sync_findings_runtime(state, include_status=True)
                    return state

        # ── Issue 7: Clean skip for browser/DOM findings in non-web library repos ──
        # Findings that require a browser or DOM environment (e.g. XSS in KaTeX,
        # prototype pollution in a utility library) cannot be confirmed when the
        # repo is a library with no running web server.  Skip them early with a
        # descriptive status instead of letting them burn LLM tokens and fail.
        _exec_surface_dom = str(_ec_gen.get('execution_surface') or '').lower()
        _runtime_dom = _runtime_gen  # already lowered above
        _repo_class = str(_ec_gen.get('repo_surface_class') or '').lower()
        _cwe_id_dom = str(finding.get('cwe_id') or '')
        _is_dom_surface = any(kw in _exec_surface_dom for kw in ('browser', 'dom', 'client_side', 'html'))
        _is_xss_like = _cwe_id_dom in ('CWE-79', 'CWE-80', 'CWE-116')
        _is_library_repo = 'library' in _repo_class or _repo_class in ('npm_package', 'pypi_package', 'crate')
        _has_live_url = bool(str(_ec_gen.get('target_url') or '').strip())
        if (_is_dom_surface or (_is_xss_like and _runtime_dom in ('javascript', 'node', 'typescript'))) \
                and _is_library_repo and not _has_live_url:
            # For XSS/prototype-pollution in library repos, the vulnerability is in the
            # library code itself and can be triggered by importing the module and calling
            # the vulnerable function directly.  Downgrade the surface to repo_script
            # instead of blocking completely.
            _cwe_num = _cwe_id_dom.replace('CWE-', '') if _cwe_id_dom.startswith('CWE-') else _cwe_id_dom
            _is_exercisable_as_module = _cwe_num in ('79', '80', '116', '020', '1321', '400')
            if _is_exercisable_as_module:
                self._log(state, f"  Downgrade: browser/DOM finding in library repo — "
                                 f"downgrading surface={_exec_surface_dom} to repo_script (cwe={_cwe_id_dom})")
                # Downgrade the surface so PoV can use module-level execution
                _ec_gen['execution_surface'] = 'repo_script'
                _ec_gen.setdefault('proof_plan', {})['execution_surface'] = 'repo_script'
                finding['exploit_contract'] = _ec_gen
            else:
                self._log(state, f"  Skip: browser/DOM finding in library repo with no live server. "
                                 f"surface={_exec_surface_dom} cwe={_cwe_id_dom}")
                finding['final_status'] = 'not_applicable'
                finding['failure_reason'] = 'browser_dom_no_server'
                finding.setdefault('failure_log', []).append({
                    'stage': 'generation',
                    'reason': 'Finding requires a browser/DOM environment but the repo is a '
                              'library with no running web server. PoV cannot be confirmed.',
                })
                state['findings'][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
                return state

        model_to_use = self._get_selected_model(state)
        self._log(state, f"Using selected model for PoV: {model_to_use}")
        
        verifier = get_verifier()
        audit = self._audit_finding_handoff(state, finding, phase='generation')
        if not audit.get('is_ready'):
            _finding_id = finding.get('id', 'unknown')
            _finding_cwe = finding.get('cwe_id', 'unknown')
            import logging as _gate_logger
            _gate_logger.getLogger('autopov.gate').warning(
                f"[GATE_BLOCK] scan={state.get('scan_id')} finding={_finding_id} "
                f"cwe={_finding_cwe} issues={audit.get('issues')}"
            )
            self._log(state, f"[GATE_BLOCK] finding={_finding_id} cwe={_finding_cwe} "
                      f"blocked: {(audit.get('issues') or [])[:3]}")
            finding.setdefault('failure_log', []).append({
                'stage': 'contract_gate',
                'reason': list(audit.get('issues') or []),
                'warnings': list(audit.get('warnings') or []),
            })
            finding['validation_result'] = {
                'is_valid': False,
                'issues': list(audit.get('issues') or []),
                'suggestions': list(audit.get('warnings') or []),
                'will_trigger': 'NO',
                'validation_method': 'contract_gate',
                'static_result': None,
                'unit_test_result': None,
            }
            finding['final_status'] = 'unproven_contract_gate'
            finding['failure_reason'] = 'contract_gate'
            finding['contract_gate_reasons'] = list(audit.get('issues') or [])
            state['findings'][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
            return state
        
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
        target_language = finding.get("detected_language") or self._infer_runtime_profile(finding, state) or state.get("detected_language", "python")
        if target_language == "binary":
            target_language = "c"
        
        # Pass model name from scan state
        # Seed runtime_feedback with surface data from a prior execution so that
        # _extract_subcommands_from_surface can populate known_subcommands even on
        # the first retry attempt (where exploit_contract.runtime_feedback is still {}).
        base_runtime_feedback = dict((finding.get("exploit_contract") or {}).get("runtime_feedback") or {})
        if not base_runtime_feedback.get("observed_surface"):
            prior_pov = finding.get("pov_result") or {}
            # Try multiple sources for surface data:
            # 1. Direct 'surface' key (from pov_tester)
            # 2. Nested 'preflight.surface' key
            # 3. Top-level 'preflight_subcommands' / 'preflight_help_text' (from docker_runner)
            surface_candidate = prior_pov.get("surface")
            if not surface_candidate:
                preflight = prior_pov.get("preflight") or {}
                surface_candidate = preflight.get("surface")
            if not surface_candidate:
                # Construct observed_surface from docker_runner's top-level fields
                preflight_subcommands = prior_pov.get("preflight_subcommands")
                preflight_help_text = prior_pov.get("preflight_help_text")
                if preflight_subcommands or preflight_help_text:
                    surface_candidate = {
                        "subcommands": preflight_subcommands or [],
                        "help_text": preflight_help_text or "",
                    }
            if surface_candidate:
                base_runtime_feedback["observed_surface"] = surface_candidate

        # Build probe_context from the scan-level ProbeResult (set by _node_probe_target)
        probe_context_str = ''
        probe_dict = state.get('probe_result') or {}
        if probe_dict and not probe_dict.get('probe_skipped'):
            try:
                from agents.probe_runner import ProbeResult, format_probe_context
                pr = ProbeResult()
                pr.__dict__.update(probe_dict)
                probe_context_str = format_probe_context(pr)
            except Exception:
                pass

        # Inject probe-discovered help text into observed_surface so _build_binary_surface_block
        # can feed the model real subcommands instead of letting it guess.
        probe_help_text = probe_dict.get('probe_help_text') or ''
        probe_cli_flags = probe_dict.get('probe_cli_flags') or []
        probe_input_surface = probe_dict.get('probe_input_surface') or ''
        if probe_help_text or probe_cli_flags or probe_input_surface:
            if 'observed_surface' not in base_runtime_feedback:
                base_runtime_feedback['observed_surface'] = {}
            obs = base_runtime_feedback['observed_surface']
            if not obs.get('help_text') and probe_help_text:
                obs['help_text'] = probe_help_text
            if not obs.get('cli_flags') and probe_cli_flags:
                obs['cli_flags'] = probe_cli_flags
            if not obs.get('input_surface') and probe_input_surface and probe_input_surface != 'unknown':
                obs['input_surface'] = probe_input_surface
        # Inject contract setup_requirements so _build_binary_surface_block can emit
        # the keygen bootstrap hint on the very first generation attempt.
        _contract_setup_reqs = (
            (finding.get('exploit_contract') or {}).get('setup_requirements') or []
        )
        if _contract_setup_reqs:
            if 'observed_surface' not in base_runtime_feedback:
                base_runtime_feedback['observed_surface'] = {}
            _obs_gen = base_runtime_feedback['observed_surface']
            if not _obs_gen.get('setup_requirements'):
                _obs_gen['setup_requirements'] = _contract_setup_reqs
        # Inject entrypoint_candidates so the generation prompt lists all known anchors.
        # This helps the model pick the right TARGET_BINARY from the first attempt.
        _ec_for_gen = finding.get('exploit_contract') or {}
        _ep_candidates = [str(c).strip() for c in (_ec_for_gen.get('entrypoint_candidates') or []) if str(c).strip()]
        if _ep_candidates:
            if 'observed_surface' not in base_runtime_feedback:
                base_runtime_feedback['observed_surface'] = {}
            if not base_runtime_feedback['observed_surface'].get('entrypoint_candidates'):
                base_runtime_feedback['observed_surface']['entrypoint_candidates'] = _ep_candidates
        # Also inject AUTOPOV_PROBE_BINARY via environment if probe found the binary
        probe_binary = probe_dict.get('probe_binary_path') or ''

        result = verifier.generate_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding["code_chunk"],
            explanation=finding["llm_explanation"],
            code_context=code_context,
            target_language=target_language,
            model_name=model_to_use,
            exploit_contract=finding.get("exploit_contract") or {},
            runtime_feedback=base_runtime_feedback,
            codebase_path=state.get("codebase_path", ""),
            source=finding.get("source", ""),
            probe_context=probe_context_str,
            repo_input_hints=state.get("repo_input_hints") or {},
            joern_context=finding.get("joern_context") or '',
            recon_report=state.get('recon_report'),
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
        # Prefer top-level cost_usd; fall back to cost nested in openrouter_usage
        pov_cost = result.get("cost_usd", 0)
        if not pov_cost:
            pov_cost = float((result.get("openrouter_usage") or {}).get("cost_usd", 0.0) or 0.0)
        if pov_cost > 0:
            state["total_cost_usd"] += pov_cost

        generated_script = sanitize_pov_script(result.get("pov_script") or "")
        generation_succeeded = bool(result.get("success") and generated_script)
        
        if generation_succeeded:
            finding["pov_script"] = generated_script
            finding["execution_profile"] = ((result.get("exploit_contract") or {}).get("runtime_profile") or finding.get("execution_profile"))
            # Store the PoV language selected by _select_pov_language() so the
            # execution node can pass it to run_pov() and _detect_script_runtime()
            # uses it as an authoritative hint (separate from the target language).
            if result.get("pov_language"):
                finding["pov_language"] = result["pov_language"]
            # Preserve proof_strategy from v2 pipeline before overwriting contract
            _prev_proof_strategy = (finding.get("exploit_contract") or {}).get("proof_strategy")
            finding["exploit_contract"] = result.get("exploit_contract")
            if _prev_proof_strategy and isinstance(finding.get("exploit_contract"), dict):
                finding["exploit_contract"]["proof_strategy"] = _prev_proof_strategy
            finding["pov_model_used"] = model_used
            finding["pov_model_mode"] = result.get("model_mode") or "unknown"
            finding["pov_context_window_chars"] = len(code_context)
            finding["pov_openrouter_usage"] = result.get("openrouter_usage", {})
            self._append_scan_openrouter_usage(state, finding["pov_openrouter_usage"], "pov_generation", finding=finding)
            finding["pov_prompt_tokens"] = prompt_tokens
            finding["pov_completion_tokens"] = completion_tokens
            finding["pov_total_tokens"] = total_tokens
            # Cost already added above, just store it in finding
            if "cost_usd" not in finding:
                finding["cost_usd"] = result.get("cost_usd", 0)
            self._log(state, "  PoV generated successfully")
            self._log_proof_plan_summary(state, finding)
        elif result.get("status") == "contract_gate_failed":
            # Contract gate blocked generation before the model was called.
            # Tag the finding distinctly so it can be tracked separately from
            # ordinary generation failures in benchmark stratification.
            finding["final_status"] = "contract_gate_failed"
            finding["contract_gate_blocked"] = True
            finding["contract_gate_reasons"] = result.get("suggestions", [])
            finding["resolution_status"] = result.get("resolution_status", "unresolved")
            finding["pov_model_mode"] = result.get("model_mode") or "unknown"
            self._log(state, f"  PoV generation blocked by contract gate: {result.get('suggestions', [])}")
        else:
            # --- NO_POV_GENERATED salvage pass ---
            # The model produced output but JSON/parse failed.  Try to extract
            # any ```python ... ``` block from the raw response before giving up.
            raw_resp = result.get("raw_response") or ""
            salvaged = ""
            if raw_resp:
                import re as _re
                m = _re.search(r'```python\s*(.+?)```', raw_resp, _re.DOTALL)
                if not m:
                    m = _re.search(r'```\s*(?:python)?\s*(.+?)```', raw_resp, _re.DOTALL)
                if m:
                    candidate = m.group(1).strip()
                    # Minimal sanity: must define a main() and have at least 5 lines
                    if 'def main' in candidate and len(candidate.splitlines()) >= 5:
                        salvaged = candidate
            if salvaged:
                from agents.pov_sanitizer import sanitize_pov_script as _sanitize
                salvaged = _sanitize(salvaged)
                finding["pov_script"] = salvaged
                finding["pov_model_used"] = result.get("model_used", model_to_use)
                finding["pov_model_mode"] = result.get("model_mode") or "unknown"
                finding["pov_context_window_chars"] = len(code_context)
                finding["pov_salvaged_from_raw"] = True
                self._log(state, f"  PoV salvaged from raw model response ({len(salvaged)} chars)")
            else:
                finding["final_status"] = "pov_generation_failed"
                finding["failure_reason"] = (
                    f"no_pov_generated: {(result.get('error') or 'model output unparseable')[:200]}"
                )
                self._log(state, f"  PoV generation failed: {result.get('error')}")
        
        state["findings"][idx] = finding
        self._sync_findings_runtime(state, include_status=True)
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
            self._sync_findings_runtime(state, include_status=True)
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
            finding.setdefault('failure_log', []).append({
                'stage': 'static_validation',
                'reason': issues[:5],
                'attempt': finding.get('retry_count', 0),
            })
            finding["retry_count"] += 1
        
        # Store validation result in finding and carry it forward as structured proof feedback
        finding["validation_result"] = result
        self._attach_feedback_to_contract(finding, validation_result=result)
        self._append_scan_openrouter_usage(state, result.get("openrouter_usage"), "llm_validation", finding=finding)
        
        state["findings"][idx] = finding
        self._sync_findings_runtime(state, include_status=True)
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
        
        # Derive refinement feedback from validation first, then runtime if validation was inconclusive
        validation_result = finding.get("validation_result", {})
        runtime_result = finding.get("pov_result", {})
        validation_errors = self._derive_refinement_errors(validation_result, runtime_result, finding=finding)
        self._attach_feedback_to_contract(finding, validation_result=validation_result, runtime_result=runtime_result)
        audit = self._audit_finding_handoff(state, finding, phase='refinement', runtime_result=runtime_result)
        for issue in (audit.get('issues') or []):
            if issue not in validation_errors:
                validation_errors.append(issue)

        # ── Entrypoint candidate promotion ─────────────────────────────────────
        # When the previous attempt got no oracle signal (no_oracle_match or
        # path_not_relevant), the current target_entrypoint is not working as
        # a relevance anchor.  Promote the next candidate from the ranked list
        # so the oracle has a fresh anchor to match against.
        _oracle_result = (runtime_result or {}).get('oracle_result') or {}
        _oracle_reason = str(_oracle_result.get('reason') or '').strip()
        _retry_count = int(finding.get('retry_count') or 0)
        if _retry_count > 0 and _oracle_reason in {'no_oracle_match', 'path_not_relevant', 'ambiguous_signal', 'strong_signal+path_not_relevant'}:
            _ec = dict(finding.get('exploit_contract') or {})
            _candidates = [str(c).strip() for c in (_ec.get('entrypoint_candidates') or []) if str(c).strip()]
            _current_ep = str(_ec.get('target_entrypoint') or '').strip()
            if _candidates and len(_candidates) > 1:
                # Find the current EP in the list and promote to the next one
                try:
                    _cur_idx = _candidates.index(_current_ep)
                    _next_idx = _cur_idx + 1
                except ValueError:
                    _next_idx = 1  # current EP not in list — jump to index 1
                if _next_idx < len(_candidates):
                    _next_ep = _candidates[_next_idx]
                    _ec['target_entrypoint'] = _next_ep
                    finding['exploit_contract'] = _ec
                    _ep_hint = (
                        f"ENTRYPOINT PROMOTION: previous target_entrypoint '{_current_ep}' produced no "
                        f"oracle match. Switching to next candidate: '{_next_ep}'. "
                        f"The harness now sets TARGET_BINARY to the path of '{_next_ep}'. "
                        f"All candidates (ranked): {_candidates}."
                    )
                    if not any('entrypoint promotion' in e.lower() for e in validation_errors):
                        validation_errors.insert(0, _ep_hint)
                    self._log(state, f'  Entrypoint promoted: {_current_ep!r} -> {_next_ep!r} '
                              f'(oracle_reason={_oracle_reason})')

        # Inject subcommand enforcement into the errors list so the model sees
        # the correct subcommands regardless of which prompt path is taken.
        _known_subs = [
            str(s).strip()
            for s in ((finding.get("exploit_contract") or {}).get("known_subcommands") or [])
            if str(s).strip()
        ]
        if _known_subs:
            _subcmd_hint = (
                f"Subcommand enforcement: the binary requires a known subcommand as the FIRST "
                f"positional argument. Use one of: {', '.join(_known_subs)}. "
                f"Do NOT use a C function name (e.g. command_extract) as the subcommand."
            )
            if not any("subcommand" in e.lower() for e in validation_errors):
                validation_errors.append(_subcmd_hint)
        
        if not validation_errors:
            self._log(state, "No structured refinement feedback available, skipping refinement")
            return state

        # ── Diversity forcing: detect repeated identical PoV output ────────────
        # Uses a STRUCTURAL hash that extracts only exploit-significant patterns
        # (subprocess calls, payloads, target binary refs, compile commands, imports)
        # so that two scripts using the same broken approach but with different
        # comments or variable names are correctly detected as duplicates.
        import hashlib as _hashlib
        import re as _struct_re

        def _structural_hash(script: str) -> str:
            """Hash only exploit-significant patterns from a PoV script."""
            if not script:
                return _hashlib.md5(b'').hexdigest()
            # Extract exploit-significant lines/patterns
            _patterns = []
            for line in script.splitlines():
                stripped = line.strip()
                # Skip empty lines and comments
                if not stripped or stripped.startswith('#'):
                    continue
                # subprocess.run / Popen calls and arguments
                if _struct_re.search(r'subprocess\.(run|Popen|call|check_output|check_call)', stripped):
                    _patterns.append(stripped)
                # payload / buffer assignments
                elif _struct_re.search(r'(payload|buffer|exploit|shellcode|PAYLOAD|BUFFER)\s*=', stripped):
                    _patterns.append(stripped)
                # TARGET_BINARY / TARGET_BIN references
                elif _struct_re.search(r'TARGET_(BINARY|BIN|PROGRAM|EXE)', stripped):
                    _patterns.append(stripped)
                # compile commands (gcc, clang, cc invocations)
                elif _struct_re.search(r'\b(gcc|g\+\+|clang|clang\+\+|cc)\b.*-o\b', stripped):
                    _patterns.append(stripped)
                # import statements
                elif stripped.startswith('import ') or stripped.startswith('from '):
                    _patterns.append(stripped)
                # os.system / os.popen calls
                elif _struct_re.search(r'os\.(system|popen|exec)', stripped):
                    _patterns.append(stripped)
            # Normalise whitespace and hash the structural skeleton
            skeleton = '\n'.join(_patterns)
            return _hashlib.md5(skeleton.encode()).hexdigest()

        _current_pov_hash = _structural_hash(str(finding.get('pov_script') or ''))
        _prior_hashes = set()
        # Issue #14: Also track payload hashes to detect same-approach-with-different-variable-names
        _current_payload_hash = _hashlib.md5(
            ''.join(
                _struct_re.findall(r'(?:payload|buffer|exploit|data|content|input)\s*=\s*["\'](.{8,}?)["\']',
                                   str(finding.get('pov_script') or ''), _struct_re.IGNORECASE)
            ).encode()
        ).hexdigest() if finding.get('pov_script') else ''
        _prior_payload_hashes = set()
        for _hist_entry in (finding.get('refinement_history') or []):
            _hist_pov = str(_hist_entry.get('pov_script') or '')
            if _hist_pov:
                _prior_hashes.add(_structural_hash(_hist_pov))
                # Issue #14: Also hash the payloads from the history
                _hist_payload_hash = _hashlib.md5(
                    ''.join(
                        _struct_re.findall(r'(?:payload|buffer|exploit|data|content|input)\s*=\s*["\'](.{8,}?)["\']',
                                           _hist_pov, _struct_re.IGNORECASE)
                    ).encode()
                ).hexdigest() if _hist_pov else ''
                if _hist_payload_hash:
                    _prior_payload_hashes.add(_hist_payload_hash)

        # Check structural hash duplication
        _is_duplicate = _current_pov_hash in _prior_hashes
        # Issue #14: Also check payload hash duplication (same exploit data, different wrapper)
        _is_same_payload = _current_payload_hash and _current_payload_hash in _prior_payload_hashes

        if _is_duplicate or _is_same_payload:
            _subcmds_str = ', '.join(_known_subs) if _known_subs else 'the available subcommands'
            _diversity_hint = (
                "CRITICAL: Your last attempt produced structurally identical output to a previous attempt"
                + (" (same exploit payload)" if _is_same_payload else "") + ". "
                "You MUST use a completely different exploitation approach. "
                "If the previous approach used argv/CLI flags, try stdin or file input instead. "
                f"If the previous approach used one subcommand, try a different one from: {_subcmds_str}. "
                "Change the payload type, input format, or entire exploit strategy. "
                "Specific suggestions: (1) use a different input method (stdin vs file vs env var), "
                "(2) try a different subcommand or command path, "
                "(3) change the payload structure (e.g. longer/shorter data, different file format), "
                "(4) if the binary reads config files, try poisoning a config file instead of direct input."
            )
            if not any('identical' in e.lower() or 'different approach' in e.lower() for e in validation_errors):
                validation_errors = [_diversity_hint] + list(validation_errors)
            self._log(state, "  Identical PoV detected — injecting diversity hint")

        # Issue #14: Force strategy change when the same oracle_reason repeats 3+ times
        # This catches cases where the script changes slightly each time but hits the
        # same failure mode (e.g. binary_ignored_input 3 times in a row).
        _oracle_reasons_history = [
            str((_h.get('oracle_reason') or '')).strip()
            for _h in (finding.get('refinement_history') or [])
        ]
        if runtime_result:
            _oracle_reasons_history.append(str((runtime_result.get('oracle_result') or {}).get('reason') or ''))
        _recent_reasons = [r for r in _oracle_reasons_history[-4:] if r]
        if len(_recent_reasons) >= 3:
            _most_common = max(set(_recent_reasons), key=_recent_reasons.count)
            if _recent_reasons.count(_most_common) >= 3:
                _strategy_hint = (
                    f"CRITICAL: The same failure reason '{_most_common}' has occurred 3+ times. "
                    f"Your current approach is fundamentally flawed. You MUST change strategy entirely: "
                    f"(1) if you've been using CLI arguments, switch to file-based input, "
                    f"(2) if you've been using file input, try stdin, "
                    f"(3) if the binary ignores your input, try a different subcommand, "
                    f"(4) if you're targeting a library function, write a C harness that calls it directly, "
                    f"(5) if you're getting format rejection, try a completely different payload format."
                )
                if not any('3+' in e or 'fundamentally flawed' in e.lower() for e in validation_errors):
                    validation_errors = [_strategy_hint] + list(validation_errors)
                self._log(state, f"  Repeated oracle reason '{_most_common}' 3+ times — forcing strategy change")
        # ─────────────────────────────────────────────────────────────────────

        # ── PoV Coordinator: stateful attempt-log analysis ───────────────────────────
        # Build attempt_log from refinement_history + current runtime_result so
        # the coordinator sees the full picture across all retries.
        _coord_attempt_log: List[Dict[str, Any]] = []
        for _hist in (finding.get('refinement_history') or []):
            _coord_attempt_log.append({
                'pov_script': _hist.get('pov_script') or finding.get('pov_script') or '',
                'oracle_reason': _hist.get('oracle_reason') or '',
                'exit_code': _hist.get('exit_code') or -1,
                'stdout': _hist.get('stdout') or '',
                'stderr': _hist.get('stderr') or '',
            })
        # Add the most-recent runtime result too
        if runtime_result:
            _coord_attempt_log.append({
                'pov_script': finding.get('pov_script') or '',
                'oracle_reason': str((runtime_result.get('oracle_result') or {}).get('reason') or ''),
                'exit_code': int(runtime_result.get('exit_code') or -1),
                'stdout': str(runtime_result.get('stdout') or '')[:1200],
                'stderr': str(runtime_result.get('stderr') or '')[:1200],
            })

        _coord_trace_ctx = str((finding.get('exploit_contract') or {}).get('trace_context') or '')
        _coord_contract = finding.get('exploit_contract') or {}
        model_to_use = self._get_selected_model(state)

        # ── Strategy pivot: force different approach when stuck on same failure ───
        # If the current attempt AND any previous attempt have the same oracle_reason,
        # the model is repeating the same broken approach. Inject a strong pivot directive.
        # Trigger earlier (after 1st repeat) to leave more retries for the new strategy.
        _current_reason = str((runtime_result.get('oracle_result') or {}).get('reason') or '') if runtime_result else ''
        if _current_reason and finding.get('retry_count', 0) >= 1:
            _prev_reasons = [a.get('oracle_reason', '') for a in _coord_attempt_log[:-1]] if len(_coord_attempt_log) > 1 else []
            if _current_reason in _prev_reasons:
                _stuck_reason = _current_reason
                _repeat_count = _prev_reasons.count(_stuck_reason) + 1
                _pivot_hint = (
                    f"CRITICAL: The last {_repeat_count} attempt(s) all failed with "
                    f"'{_stuck_reason}'. You MUST use a completely different attack approach. "
                    f"Change the execution surface, input method, or trigger mechanism entirely. "
                    f"Do NOT make minor variations on the same strategy."
                )
                if not any('completely different attack' in e for e in validation_errors):
                    validation_errors.insert(0, _pivot_hint)
                self._log(state, f'  Strategy pivot triggered: stuck on {_stuck_reason} ({_repeat_count}x)')
            # Also check the original condition (2+ in coord_attempt_log) for backward compat
            elif len(_coord_attempt_log) >= 2:
                _recent_reasons = [a.get('oracle_reason', '') for a in _coord_attempt_log[-2:]]
                if _recent_reasons[0] and len(set(_recent_reasons)) == 1:
                    _stuck_reason = _recent_reasons[0]
                    _pivot_hint = (
                        f"CRITICAL: The last {len(_recent_reasons)} attempts all failed with "
                        f"'{_stuck_reason}'. You MUST use a completely different attack approach. "
                        f"Change the execution surface, input method, or trigger mechanism entirely. "
                        f"Do NOT make minor variations on the same strategy."
                    )
                    if not any('completely different attack' in e for e in validation_errors):
                        validation_errors.insert(0, _pivot_hint)
                    self._log(state, f'  Strategy pivot triggered: stuck on {_stuck_reason}')

        try:
            _coord_llm = get_verifier()._get_llm(model_to_use, purpose="general")
            _coord_decision = coordinator_decide(
                attempt_log=_coord_attempt_log,
                exploit_contract=_coord_contract,
                trace_context=_coord_trace_ctx,
                model_name=model_to_use,
                openrouter_client=_coord_llm,
            )
            _coord_errors = format_constraints_for_prompt(_coord_decision)
            if _coord_errors:
                # Prepend coordinator guidance ahead of existing errors
                for _ce in reversed(_coord_errors):
                    if not any(_ce[:40] in e for e in validation_errors):
                        validation_errors.insert(0, _ce)
            self._log(state,
                f'  Coordinator: action={_coord_decision.action}, '
                f'abandon={_coord_decision.abandon}, '
                f'rationale={_coord_decision.rationale[:80]}')

            # Coordinator says abandon — skip remaining retries
            if _coord_decision.abandon:
                self._log(state, '  Coordinator abandoned this finding — skipping remaining retries')
                finding['final_status'] = 'unproven'
                finding['pov_result'] = dict(finding.get('pov_result') or {})
                finding['pov_result']['failure_category'] = 'coordinator_abandoned'
                finding['pov_result']['oracle_reason'] = 'coordinator_abandoned'
                # Clear pov_script so _should_run_pov routes to log_failure
                finding['last_pov_script'] = finding.get('pov_script') or ''
                finding['pov_script'] = ''
                # Set retry_count to max so validate_pov also routes to log_failure
                finding['retry_count'] = self._get_model_max_retries(state)
                state['findings'][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
                return state
        except Exception as _coord_exc:
            self._log(state, f'  Coordinator error (non-fatal): {_coord_exc}')
        # ─────────────────────────────────────────────────────────────────────
        
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
        
        # model_to_use was set above in the coordinator block (uses _get_selected_model)
        
        # Initialize refinement history
        if not isinstance(finding.get("refinement_history"), list):
            finding["refinement_history"] = []
        
        # Build probe_context from the scan-level ProbeResult (set by _node_probe_target)
        probe_context_str = ''
        _probe_dict = state.get('probe_result')
        if _probe_dict:
            try:
                from agents.probe_runner import ProbeResult, format_probe_context
                pr = ProbeResult()
                pr.__dict__.update(_probe_dict)
                probe_context_str = format_probe_context(pr)
            except Exception:
                pass

        # Backfill observed_surface with probe help text for the refinement runtime_feedback
        # so _build_binary_surface_block can inject real subcommands on all retry attempts.
        _refine_feedback = self._build_refinement_feedback(finding)
        _probe_help = (_probe_dict or {}).get('probe_help_text') or ''
        _probe_flags = (_probe_dict or {}).get('probe_cli_flags') or []
        _probe_surface = (_probe_dict or {}).get('probe_input_surface') or ''
        if _probe_help or _probe_flags or _probe_surface:
            _obs = _refine_feedback.setdefault('observed_surface', {})
            if not _obs.get('help_text') and _probe_help:
                _obs['help_text'] = _probe_help
            if not _obs.get('cli_flags') and _probe_flags:
                _obs['cli_flags'] = _probe_flags
            if not _obs.get('input_surface') and _probe_surface and _probe_surface != 'unknown':
                _obs['input_surface'] = _probe_surface
        # Also inject contract setup_requirements for the refinement path so the
        # keygen bootstrap hint appears on every retry, not just the initial generation.
        _refine_contract_setup_reqs = (
            (finding.get('exploit_contract') or {}).get('setup_requirements') or []
        )
        if _refine_contract_setup_reqs:
            _obs_refine = _refine_feedback.setdefault('observed_surface', {})
            if not _obs_refine.get('setup_requirements'):
                _obs_refine['setup_requirements'] = _refine_contract_setup_reqs
        # Inject entrypoint_candidates (including any promoted EP) into the refinement
        # prompt so the model knows the full ranked list and which one is now active.
        _ec_for_refine = finding.get('exploit_contract') or {}
        _refine_ep_candidates = [str(c).strip() for c in (_ec_for_refine.get('entrypoint_candidates') or []) if str(c).strip()]
        if _refine_ep_candidates:
            _obs_ep = _refine_feedback.setdefault('observed_surface', {})
            _obs_ep['entrypoint_candidates'] = _refine_ep_candidates
            _obs_ep['active_entrypoint'] = str(_ec_for_refine.get('target_entrypoint') or '').strip()

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
            exploit_contract=finding.get("exploit_contract") or {},
            runtime_feedback=_refine_feedback,
            probe_context=probe_context_str,
            recon_report=state.get('recon_report'),
        )

        # Track refinement in history with tokens
        model_used = result.get("model_used", model_to_use)
        token_usage = result.get("token_usage", {})
        refined_script = sanitize_pov_script(result.get("pov_script") or "")
        refinement_succeeded = bool(result.get("success") and refined_script)
        
        self._append_scan_openrouter_usage(state, result.get("openrouter_usage"), "pov_refinement", finding=finding, attempt=finding["retry_count"] + 1)
        finding["refinement_history"].append({
            "attempt": finding["retry_count"] + 1,
            "errors": validation_errors,
            "success": refinement_succeeded,
            "timestamp": result.get("timestamp", ""),
            "model_used": model_used,
            "tokens": token_usage,
            "cost_usd": result.get("cost_usd", 0.0),
            "openrouter_usage": result.get("openrouter_usage", {}),
            # Store the PoV that was passed IN (the failed PoV being refined).
            # Used by diversity-forcing logic to detect repeated identical outputs.
            "pov_script": finding.get("pov_script") or "",
            # Store runtime output so coordinator can analyze them on next retry
            "oracle_reason": str((runtime_result.get('oracle_result') or {}).get('reason') or '') if runtime_result else '',
            "exit_code": int(runtime_result.get('exit_code') or -1) if runtime_result else -1,
            "stdout": str(runtime_result.get('stdout') or '')[:400] if runtime_result else '',
            "stderr": str(runtime_result.get('stderr') or '')[:400] if runtime_result else '',
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
        
        if result.get("success"):
            finding["pov_script"] = sanitize_pov_script(result["pov_script"])
            finding["execution_profile"] = ((result.get("exploit_contract") or {}).get("runtime_profile") or finding.get("execution_profile"))
            # Carry forward pov_language from refinement result (if present) or keep existing
            if result.get("pov_language"):
                finding["pov_language"] = result["pov_language"]
            # Preserve proof_strategy from v2 pipeline before overwriting contract
            _prev_ps = (finding.get("exploit_contract") or {}).get("proof_strategy")
            finding["exploit_contract"] = result.get("exploit_contract") or finding.get("exploit_contract")
            if _prev_ps and isinstance(finding.get("exploit_contract"), dict):
                finding["exploit_contract"]["proof_strategy"] = _prev_ps
            finding["refinement_model_mode"] = result.get("model_mode", "unknown")
            finding["retry_count"] += 1
            self._log(state, f"  PoV refined successfully (attempt {finding['retry_count']})")
            if total_tokens > 0:
                self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
        else:
            error_text = result.get('error') or 'Model did not return executable PoV code'
            self._log(state, f"  PoV refinement failed: {error_text}")
            _tb_text = result.get('traceback') or ''
            if _tb_text:
                self._log(state, f"  Traceback: {_tb_text[:500]}")
            # Issue #15: Don't increment retry_count for infrastructure errors.
            # Timeouts, Docker failures, and build failures are not the PoV script's
            # fault — retrying the same (or slightly modified) script may succeed
            # when the infrastructure issue is transient (e.g. container start race).
            _prev_runtime = finding.get('pov_result') or {}
            _is_infra_error = (
                bool(_prev_runtime.get('proof_infrastructure_error'))
                or str(_prev_runtime.get('failure_reason') or '').strip() in {
                    'timeout', 'infrastructure_failure', 'docker-unavailable',
                    'docker-image-prep-failed', 'archive-upload-failed', 'build_failed',
                }
            )
            if _is_infra_error:
                self._log(state, "  Infrastructure error detected — not incrementing retry_count")
            else:
                finding["retry_count"] += 1
        
        state["findings"][idx] = finding
        self._sync_findings_runtime(state, include_status=True)
        return state

    def _ensure_staged_runtime_result(self, result: Dict[str, Any], finding: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        staged = dict(result or {})
        tester = get_pov_tester()
        target_binary = staged.get("target_binary") or (finding or {}).get("exploit_contract", {}).get("target_binary")
        target_url = staged.get("target_url") or (finding or {}).get("target_url")
        oracle = dict(staged.get("oracle_result") or {})
        if not oracle:
            oracle = {
                "triggered": bool(staged.get("vulnerability_triggered")),
                "reason": staged.get("failure_reason") or staged.get("failure_category") or ("oracle_matched" if staged.get("vulnerability_triggered") else "no_oracle_match"),
                "matched_evidence_markers": [],
                "path_relevant": bool(staged.get("vulnerability_triggered")),
            }
        oracle.setdefault("execution_stage", staged.get("execution_stage") or "trigger")
        oracle.setdefault("proof_verdict", staged.get("proof_verdict") or ("proven" if oracle.get("triggered") else "failed"))
        staged.setdefault("execution_stage", oracle.get("execution_stage", "trigger"))
        staged.setdefault("proof_verdict", oracle.get("proof_verdict", "failed"))
        staged["oracle_result"] = oracle
        if not staged.get("setup_result"):
            setup_notes = []
            runtime_image = staged.get("runtime_image")
            if runtime_image:
                setup_notes.append(f"runtime image prepared: {runtime_image}")
            validation_method = staged.get("validation_method") or "runtime"
            if not setup_notes:
                setup_notes.append(f"runtime prepared for {validation_method}")
            setup_stderr = ""
            if staged.get("failure_category") in {"setup_failed", "infrastructure", "infrastructure_failure"}:
                setup_stderr = str(staged.get("stderr") or staged.get("failure_reason") or "")
            setup_artifacts = [item for item in [runtime_image, target_binary, target_url] if item]
            staged["setup_result"] = tester._build_setup_result(
                stage='setup',
                success=not bool(staged.get("proof_infrastructure_error")) and staged.get("failure_category") != "setup_failed",
                stderr=setup_stderr,
                artifacts=setup_artifacts,
                notes=setup_notes,
            )
        if not staged.get("trigger_result"):
            staged["trigger_result"] = tester._build_trigger_result(
                oracle=oracle,
                stdout=str(staged.get("stdout", "") or ""),
                stderr=str(staged.get("stderr", "") or ""),
                exit_code=int(staged.get("exit_code", -1) if staged.get("exit_code") is not None else -1),
            )
        return staged

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

        # Only auto-confirm from unit tests when the harness itself completed successfully.
        if unit_test_result.get("vulnerability_triggered") and unit_test_result.get("success"):
            # 1d: Run oracle_policy on unit-test stdout/stderr instead of blindly confirming.
            # This prevents a harness that unconditionally prints "VULNERABILITY TRIGGERED"
            # from auto-confirming without real crash evidence.
            import agents.oracle_policy as _oracle_policy
            _ut_stdout = unit_test_result.get("stdout", "")
            _ut_stderr = unit_test_result.get("stderr", "")
            _ut_exit = int(unit_test_result.get("exit_code", 0) or 0)
            _ut_contract = finding.get("exploit_contract") or {}
            _ut_anchors = [str(x).strip() for x in (_ut_contract.get('relevance_anchors') or []) if str(x).strip()]
            _probe_bin = str(_ut_contract.get('probe_binary_name') or '').strip()
            if _probe_bin and _probe_bin not in _ut_anchors:
                _ut_anchors = list(_ut_anchors) + [_probe_bin]
            _ut_oracle = _oracle_policy.evaluate_proof_outcome(
                stdout=_ut_stdout,
                stderr=_ut_stderr,
                exit_code=_ut_exit,
                target_entrypoint=str(_ut_contract.get('target_entrypoint') or '').strip(),
                filepath=str(_ut_contract.get('filepath') or finding.get('filepath') or '').strip(),
                pov_script=finding.get('pov_script') or '',
                target_binary=str(_ut_contract.get('target_binary') or '').strip(),
                stage='trigger',
                relevance_anchors=_ut_anchors,
                execution_surface=str(_ut_contract.get('execution_surface') or '').lower(),
            )
            _ut_confirmed = _ut_oracle.get('triggered', False)
            if not _ut_confirmed:
                self._log(state, f"Unit test heuristic trigger rejected by oracle policy: {_ut_oracle.get('reason')}")
            else:
                self._log(state, "Using unit test confirmation (vulnerability triggered)")
                finding["pov_result"] = {
                    "success": True,
                    "vulnerability_triggered": True,
                    "validation_method": "unit_test",
                    "stdout": _ut_stdout,
                    "stderr": _ut_stderr,
                    "execution_time_s": unit_test_result.get("execution_time_s", 0),
                    "oracle_result": _ut_oracle,
                }
                self._log(state, "VULNERABILITY CONFIRMED")
                self._attach_feedback_to_contract(finding, validation_result=validation_result, runtime_result=finding["pov_result"])
                state["findings"][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
                return state
        elif unit_test_result.get("vulnerability_triggered"):
            self._log(state, "Unit test observed a heuristic trigger, but the harness failed; requiring runtime proof before confirmation")

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
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
            return state

        execution_profile = self._infer_runtime_profile(finding, state)
        target_language = execution_profile if execution_profile in {"c", "cpp", "python", "javascript", "typescript", "node", "java"} else (finding.get("detected_language") or state.get("detected_language") or "python")
        self._log(state, f"Using execution profile: {execution_profile}")

        # Docker proof containers are the primary execution path for all 5 supported
        # languages (C/C++, Python, JavaScript/Node, Java, browser).  Each language
        # maps to a dedicated autopov/proof-* image with the correct toolchain and
        # isolation.  The in-process pov_tester path is kept only as an emergency
        # fallback when Docker is unavailable (e.g. unit-test environments).
        runner = get_docker_runner()
        if runner.is_available():
            self._log(state, f"Running PoV in Docker proof container (image: {execution_profile})...")
            # Inject repo name into contract so the binary locator inside the container
            # can score binaries named after the repo (e.g. 'kore') higher than helpers
            _ec = dict(finding.get("exploit_contract") or {})
            if not _ec.get("repo_name"):
                _repo_url = state.get("repo_url") or ""
                _ec["repo_name"] = _repo_url.rstrip("/").split("/")[-1].lower()
            # Inject recon-derived Docker/runtime hints so docker_runner can make
            # intelligent decisions without hardcoding
            _recon = state.get('recon_report') or {}
            if _recon and not _ec.get('recon_docker_image'):
                _ec['recon_docker_image'] = _recon.get('docker_image', '')
                _ec['recon_runtime_family'] = _recon.get('runtime_family', '')
                _ec['recon_build_commands'] = _recon.get('build_commands', [])
            result = runner.run_pov(
                pov_script=finding["pov_script"],
                scan_id=state["scan_id"],
                pov_id=str(idx),
                execution_profile=execution_profile,
                target_language=target_language,
                exploit_contract=_ec,
                codebase_path=state.get("codebase_path"),
                pov_language=finding.get("pov_language"),
            )
            finding["pov_result"] = result

            # If Docker's preflight captured subcommands from the binary's help output,
            # push them into the exploit_contract immediately so the refinement pass
            # (and any subsequent generation) sees the correct subcommands on the
            # very next attempt — not just after a second full Docker run.
            _preflight_subs = result.get('preflight_subcommands') or []
            if _preflight_subs:
                _contract = dict(finding.get('exploit_contract') or {})
                if not _contract.get('known_subcommands'):
                    _contract['known_subcommands'] = _preflight_subs
                    finding['exploit_contract'] = _contract
                    self._log(state, f"Preflight discovered subcommands: {_preflight_subs}")

            # If Docker resolved the binary path, propagate it into exploit_contract so
            # the refinement prompt has the canonical binary name (not a model guess).
            _tb_path = result.get('target_binary_path') or ''
            if _tb_path:
                _contract = dict(finding.get('exploit_contract') or {})
                if not _contract.get('target_binary'):
                    import os as _os
                    _contract['target_binary'] = _os.path.basename(_tb_path)
                    finding['exploit_contract'] = _contract
                    self._log(state, f"Propagated resolved binary name into contract: {_contract['target_binary']}")

            # ── Back-propagate runtime binary discovery into scan-level probe_result ──
            # This enriches ALL subsequent findings in this scan: if the probe ran before
            # the build (common for CMake/autoconf repos), probe_binary_path is empty.
            # The first docker_runner execution tells us the real binary path; write it
            # back so every future generate_pov/refine_pov prompt gets correct surface info.
            _probe_state = state.get('probe_result')
            if isinstance(_probe_state, dict):
                _enriched = False
                if _tb_path and not _probe_state.get('probe_binary_path'):
                    import os as _os2
                    _probe_state['probe_binary_path'] = _tb_path
                    _probe_state['probe_binary_name'] = _os2.path.basename(_tb_path)
                    _probe_state['probe_build_succeeded'] = True
                    _enriched = True
                _rt_help = result.get('preflight_help_text') or ''
                if _rt_help and not _probe_state.get('probe_help_text'):
                    _probe_state['probe_help_text'] = _rt_help
                    # Re-classify input surface with the real help text
                    from agents.probe_runner import _classify_input_surface as _cls_surf
                    _new_surf = _cls_surf(_rt_help, _tb_path or '')
                    if _new_surf != 'unknown':
                        _probe_state['probe_input_surface'] = _new_surf
                    _enriched = True
                _rt_subs = result.get('preflight_subcommands') or []
                if _rt_subs and not _probe_state.get('probe_cli_flags'):
                    _probe_state['probe_cli_flags'] = _rt_subs
                    _enriched = True
                if _enriched:
                    state['probe_result'] = _probe_state
                    self._log(state, f'Probe result enriched from docker runtime: binary={_probe_state.get("probe_binary_path")}')
                    # Also push the enriched surface data into all remaining (unprocessed) findings
                    _enriched_bin_name = _probe_state.get('probe_binary_name') or ''
                    _enriched_surface = _probe_state.get('probe_input_surface') or ''
                    for _fi, _fd in enumerate(state.get('findings', [])):
                        if _fi <= idx:
                            continue  # skip already-processed findings
                        _fec = dict(_fd.get('exploit_contract') or {})
                        _changed = False
                        if _enriched_bin_name and not _fec.get('probe_binary_name'):
                            _fec['probe_binary_name'] = _enriched_bin_name
                            _fec['probe_binary_path'] = _tb_path
                            _changed = True
                        if _enriched_surface not in ('', 'unknown') and not _fec.get('probe_input_surface'):
                            _fec['probe_input_surface'] = _enriched_surface
                            _changed = True
                        if _changed:
                            _fd['exploit_contract'] = _fec
                            state['findings'][_fi] = _fd
        else:
            # Emergency fallback: Docker unavailable (unit tests, dev without Docker)
            self._log(state, "Docker unavailable — falling back to in-process harness (emergency mode)")
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
            result = specialized_result
            finding["pov_result"] = result

        result = self._ensure_staged_runtime_result(result, finding)
        finding["pov_result"] = result
        # Tag pov_result with model_mode + context size for benchmark stratification
        if isinstance(finding.get("pov_result"), dict):
            # model_mode: derive from finding (set during generate_pov) — fallback to
            # result.get('model_mode') so the tag is always present, never 'unknown'
            finding["pov_result"]["pov_model_mode"] = (
                finding.get("pov_model_mode")
                or result.get("model_mode")
                or "unknown"
            )
            finding["pov_result"]["pov_context_window_chars"] = finding.get("pov_context_window_chars", 0)
            # Distinguish contract-gate failures from ordinary validation failures
            if result.get("failure_category") == "contract_gate_failed" or finding.get("contract_gate_blocked"):
                finding["pov_result"]["failure_category"] = "contract_gate_failed"
        self._attach_feedback_to_contract(finding, validation_result=validation_result, runtime_result=result)

        self._log_runtime_result_details(state, result)

        if result["vulnerability_triggered"]:
            self._log(state, "VULNERABILITY TRIGGERED")
        elif result.get("proof_infrastructure_error"):
            self._log(state, f"  PoV runtime infrastructure error ({result.get('validation_method', 'runtime')}): {result.get('failure_reason') or result.get('stderr', 'unknown error')}")
        else:
            self._log(state, f"  PoV did not trigger vulnerability (exit code: {result['exit_code']})")


        state["findings"][idx] = finding
        self._sync_findings_runtime(state, include_status=True)
        return state

    def _node_log_confirmed(self, state: ScanState) -> ScanState:
        """Log confirmed vulnerability"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "confirmed"
            state["findings"][idx]["confirmed"] = True
            # Clear contradictory failure metadata from pov_result
            _pr = state["findings"][idx].get("pov_result")
            if isinstance(_pr, dict) and _pr.get("vulnerability_triggered"):
                _pr.pop("failure_reason", None)
                _pr.pop("failure_category", None)
                _pr["proof_verdict"] = "proven"
            state["findings"][idx].pop("failure_reason", None)
            # ── Generate post-confirmation proof narrative ──
            # Uses the LLM to write a dense, evidence-based paragraph describing
            # what was identified, how it was exploited, and the observed outcome.
            try:
                from agents.investigator import get_investigator
                _inv = get_investigator()
                _narrative = _inv.generate_proof_narrative(
                    finding=state["findings"][idx],
                    model_name=self._get_selected_model(state),
                    api_key_override=state.get("openrouter_api_key"),
                )
                if _narrative:
                    state["findings"][idx]["proof_narrative"] = _narrative
                    self._log(state, f"Generated proof narrative for finding {idx} ({len(_narrative)} chars)")
            except Exception as _narr_err:
                self._log(state, f"Proof narrative generation failed (non-critical): {_narr_err}")
            self._sync_findings_runtime(state, include_status=True)
            # Track confirmed count for early termination
            state["confirmed_count"] = state.get("confirmed_count", 0) + 1
            self._log(state, f"Confirmed vulnerability #{state['confirmed_count']}: {state['findings'][idx].get('cwe_type', 'UNCLASSIFIED')}")
            # ── Record strategy outcome to learning stores ──
            self._record_outcome_to_stores(state, state["findings"][idx], success=True)
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        # Check if there are more findings to process
        if state["current_finding_idx"] < len(state["findings"]):
            # Continue with next finding
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.now(timezone.utc).isoformat()
        
        return state
    
    def _node_log_skip(self, state: ScanState) -> ScanState:
        """Log skipped finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            if not state["findings"][idx].get("final_status"):
                state["findings"][idx]["final_status"] = "skipped"
                self._sync_findings_runtime(state, include_status=True)
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.now(timezone.utc).isoformat()
        
        return state
    
    def _node_log_failure(self, state: ScanState) -> ScanState:
        """Log failed finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            finding = state["findings"][idx]
            # Distinguish validation-blocked from execution-failed
            pov_result = finding.get("pov_result") or {}
            had_pov = bool((finding.get("pov_script") or "").strip() or finding.get("last_pov_script"))
            reached_docker = bool(pov_result.get("execution_time_s") or pov_result.get("exit_code") is not None)
            if finding.get("final_status") in ("unproven", "unproven_timeout"):
                pass  # already set by coordinator/timeout
            elif not had_pov:
                finding["final_status"] = "failed_no_pov"
            elif not reached_docker:
                finding["final_status"] = "failed_validation"
            else:
                finding["final_status"] = "failed"
            # Stamp a human-readable failure_reason so analysis scripts and the
            # frontend can surface why every failed finding didn't get proved.
            if not finding.get("failure_reason"):
                pov_result = finding.get("pov_result") or {}
                stderr = str(pov_result.get("stderr") or "").strip()
                stdout = str(pov_result.get("stdout") or "").strip()
                failure_cat = pov_result.get("failure_category") or ""
                oracle_reason = (
                    pov_result.get("oracle_reason")
                    or (pov_result.get("oracle_result") or {}).get("reason")
                    or ""
                )
                if not finding.get("pov_script"):
                    finding["failure_reason"] = "no_pov_generated"
                elif failure_cat:
                    finding["failure_reason"] = failure_cat
                elif oracle_reason and oracle_reason != "oracle_matched":
                    finding["failure_reason"] = oracle_reason
                elif stderr:
                    finding["failure_reason"] = f"runtime_stderr: {stderr[:300]}"
                elif stdout:
                    finding["failure_reason"] = f"runtime_stdout_only: {stdout[:200]}"
                else:
                    # PoV ran but produced no observable crash output.
                    # Distinguish sub-cases to give better feedback and help
                    # the refinement loop understand what went wrong.
                    _exit_code = pov_result.get('exit_code')
                    _exec_time = pov_result.get('execution_time_s') or 0
                    _env_kind = (pov_result.get('metadata') or {}).get('environment_kind') or (pov_result.get('oracle_result') or {}).get('environment_kind') or ''
                    if _exit_code is not None and _exit_code == 0 and _exec_time < 2:
                        # Script exited cleanly almost instantly — likely a guard/bail
                        # (e.g. "binary not found") or the exploit logic was a no-op.
                        finding["failure_reason"] = "pov_exited_cleanly_no_output"
                    elif _exit_code is not None and _exit_code not in (0, -1, 124):
                        # Non-zero exit but no captured output — Docker may have lost
                        # the stderr (known issue with container.logs() on crash).
                        finding["failure_reason"] = f"pov_crash_no_output(exit={_exit_code})"
                    elif _exit_code == 124 or (_exec_time and _exec_time > 55):
                        # Timeout — script ran for the full container timeout without
                        # producing observable output. Common with server-type PoVs.
                        finding["failure_reason"] = "pov_timeout_no_output"
                    elif _env_kind in ('node', 'python') and _exit_code == 0:
                        # Non-native target: PoV ran the HTTP/module logic but the
                        # oracle didn't observe behavioral evidence. This is different
                        # from a native crash — the PoV needs a better observable.
                        finding["failure_reason"] = f"pov_no_observable_evidence(env={_env_kind})"
                    else:
                        finding["failure_reason"] = "pov_ran_no_crash_detected"
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
            # ── Record failure outcome to learning stores ──
            self._record_outcome_to_stores(state, finding, success=False)
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.now(timezone.utc).isoformat()
        
        return state
    
    # ------------------------------------------------------------------
    # Outcome recording — closes the learning feedback loop
    # ------------------------------------------------------------------
    def _record_outcome_to_stores(self, state: ScanState, finding: dict, success: bool) -> None:
        """Record exploit outcome to RepoMemory and LearningStore (non-fatal)."""
        try:
            _ec = finding.get('exploit_contract') or {}
            _cwe = finding.get('cwe_type', 'UNCLASSIFIED')
            _model = finding.get('pov_model') or state.get('model_name', '')
            _scan_id = state.get('scan_id', '')
            _cost = 0.0
            for u in (state.get('scan_openrouter_usage') or []):
                _cost += float(u.get('cost', 0) or 0)
            # LearningStore — track PoV outcome per model/CWE
            try:
                from app.learning_store import LearningStore
                _ls = LearningStore()
                _validation_method = _ec.get('proof_strategy', {}).get('proof_type', 'crash_signal') if isinstance(_ec.get('proof_strategy'), dict) else str(_ec.get('proof_strategy', 'crash_signal'))
                _ls.record_pov(
                    scan_id=_scan_id,
                    cwe=_cwe,
                    model=_model,
                    cost_usd=_cost,
                    success=success,
                    validation_method=_validation_method,
                )
            except Exception as _ls_err:
                logger.debug('LearningStore.record_pov failed (non-fatal): %s', _ls_err)
            # RepoMemory — record strategy outcome for cross-scan learning
            try:
                from agents.repo_memory import get_repo_memory
                _mem = get_repo_memory()
                _repo_name = (state.get('repo_profile') or {}).get('repo_name', '')
                if not _repo_name:
                    _repo_name = state.get('repo_name', '') or state.get('scan_id', '')
                _strategy_name = ''
                _ps = _ec.get('proof_strategy') or {}
                if isinstance(_ps, dict):
                    _strategy_name = f"{_ps.get('proof_type', 'crash_signal')}|{_ps.get('harness_type', 'subprocess_binary')}"
                else:
                    _strategy_name = str(_ps)
                _mem.record_strategy_outcome(
                    repo_name=_repo_name,
                    strategy_name=_strategy_name,
                    outcome='success' if success else 'failure',
                    finding_cwe=_cwe,
                    details=finding.get('failure_reason', '') if not success else 'confirmed',
                    scan_id=_scan_id,
                )
            except Exception as _mem_err:
                logger.debug('RepoMemory.record_strategy_outcome failed (non-fatal): %s', _mem_err)
        except Exception as _outer_err:
            logger.debug('_record_outcome_to_stores failed (non-fatal): %s', _outer_err)

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
            state["end_time"] = datetime.now(timezone.utc).isoformat()
            self._update_scan_runtime(state,
                status=ScanStatus.COMPLETED,
                end_time=state["end_time"],
                findings=state.get("findings", []),
                progress=100,
            )
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
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
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
        if source in trusted_sources and confidence >= 0.8 and verdict in ["UNKNOWN", "", "FALSE_POSITIVE"]:
            self._log(state, f"Finding {idx} from {source} has high confidence ({confidence:.2f}), overriding verdict={verdict} → REAL")
            # Mark as REAL to proceed to PoV generation
            finding["llm_verdict"] = "REAL"
            finding["llm_explanation"] = f"Trusted finding from {source} static analysis with {confidence:.0%} confidence"
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
            verdict = "REAL"
        
        proof_threshold = self._proof_threshold_for_finding(finding, state)
        # Generate PoV for all REAL findings that meet the exploit-attempt threshold.
        if verdict == "REAL" and confidence >= proof_threshold:
            if state.get("proofs_attempted", 0) >= settings.PROOF_MAX_FINDINGS:
                finding["final_status"] = "unproven_budget_exhausted"
                state["findings"][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
                self._log(state, f"Proof budget reached ({settings.PROOF_MAX_FINDINGS}); recording finding without runtime proof")
                return "log_skip"
            state["proofs_attempted"] = state.get("proofs_attempted", 0) + 1
            # T6: Record per-finding start timestamp on first attempt so the
            # per-finding timeout can be enforced across all retries.
            import time as _time_t6
            if not finding.get('_finding_start_ts'):
                finding['_finding_start_ts'] = _time_t6.time()
                state['findings'][idx] = finding
            self._log(state, f"Finding {idx} is REAL and above proof threshold ({confidence:.2f} >= {proof_threshold:.2f}); generating PoV")
            self._update_scan_runtime(state, status=ScanStatus.GENERATING_POV, progress=min(92, 50 + idx * 3))
            return "generate_pov"
        else:
            if verdict == "REAL":
                finding["final_status"] = "unproven_low_confidence"
                state["findings"][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
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

        # T6 — Per-finding timeout: if elapsed time across all retries exceeds
        # FINDING_TIMEOUT_MINUTES, abandon this finding and move to the next one.
        import time as _time_pov
        _finding_timeout_m = int(settings.FINDING_TIMEOUT_MINUTES or 0)
        if _finding_timeout_m > 0:
            _fstart = finding.get('_finding_start_ts')
            if _fstart and (_time_pov.time() - float(_fstart)) > _finding_timeout_m * 60:
                _elapsed_m = (_time_pov.time() - float(_fstart)) / 60
                self._log(state, f"Finding {idx} exceeded per-finding timeout ({_elapsed_m:.1f}/{_finding_timeout_m} min); marking unproven_timeout")
                finding['final_status'] = 'unproven_timeout'
                state['findings'][idx] = finding
                self._sync_findings_runtime(state, include_status=True)
                return 'log_failure'
        
        # Check if validation passed
        if validation_result.get("is_valid"):
            return "run_in_docker"
        
        # Check if we can retry with refinement
        if finding["retry_count"] < self._get_model_max_retries(state):
            self._log(state, f"PoV validation failed, attempting refinement (attempt {finding['retry_count'] + 1}/{self._get_model_max_retries(state)})")
            return "refine_pov"
        else:
            self._log(state, f"PoV validation failed after {self._get_model_max_retries(state)} attempts")
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
        failure_category = str((pov_result or {}).get("failure_category") or "")
        oracle_reason = str((pov_result or {}).get("oracle_reason") or "")
        # Record oracle/runtime failure in unified failure_log
        finding.setdefault('failure_log', []).append({
            'stage': 'oracle',
            'failure_category': failure_category,
            'oracle_reason': oracle_reason,
            'exit_code': (pov_result or {}).get('exit_code'),
            'attempt': finding.get('retry_count', 0),
        })
        state['findings'][idx] = finding
        retryable_failures = {
            "guardrail_rejected", "path_exercised_no_oracle", "oracle_not_observed",
            "execution_error", "environment_failure",
        }
        # Guard: if the oracle explicitly says path_relevant=False, the executed binary
        # does not contain the vulnerable code. Refinement will never fix this — skip retry.
        # EXCEPTION (Issue #5): when the signal is strong (real ASan crash) but the path
        # anchor didn't match, the crash IS real — just hitting a different code path.
        # Allow retry in this case so the PoV can be refined to target the correct binary.
        _oracle_result_dict = (pov_result or {}).get('oracle_result') or {}
        _oracle_reason_str = str(_oracle_result_dict.get('reason') or '')
        if _oracle_result_dict.get('path_relevant') is False:
            if _oracle_reason_str == 'strong_signal+path_not_relevant':
                # Strong crash detected but wrong binary/path — allow retry with
                # entrypoint promotion so the refiner can target the right binary.
                self._log(state, f"Runtime proof path_relevant=False but strong sanitizer crash — allowing retry for binary redirection.")
            elif _oracle_result_dict.get('signal_class') == 'strong':
                # Strong crash evidence (sanitizer/crash signals in output) but no path anchor.
                # This commonly happens with stripped binaries where the crash output doesn't
                # contain source file paths.  Allow a "probable confirmation" with a caveat.
                # The guard no longer requires matched_evidence_markers because stripped
                # binaries and monolithic builds often don't produce extractable markers
                # even when ASan/UBSan reports a genuine crash.
                _has_crash_output = bool(
                    _oracle_result_dict.get('matched_evidence_markers')
                    or 'addresssanitizer' in str((pov_result or {}).get('stderr', '')).lower()
                    or 'undefinedbehaviorsanitizer' in str((pov_result or {}).get('stderr', '')).lower()
                    or 'segmentation fault' in str((pov_result or {}).get('stderr', '')).lower()
                    or 'runtime error:' in str((pov_result or {}).get('stderr', '')).lower()
                    or 'error: addresssanitizer' in str((pov_result or {}).get('stdout', '')).lower()
                )
                if _has_crash_output:
                    self._log(state, f"Runtime proof path_relevant=False but strong crash evidence — probable confirmation (stripped binary?)")
                    finding['final_status'] = 'confirmed_path_unknown'
                    finding['pov_result'] = dict(finding.get('pov_result') or {})
                    finding['pov_result']['vulnerability_triggered'] = True
                    finding['pov_result']['oracle_reason'] = 'strong_evidence_no_path_anchor'
                    finding['pov_result']['path_relevant'] = False
                    state['findings'][idx] = finding
                    self._sync_findings_runtime(state, include_status=True)
                    return "log_confirmed"
                else:
                    # Strong signal_class but no actual crash output captured —
                    # the signal may have been misclassified. Allow retry.
                    self._log(state, f"Runtime proof path_relevant=False, signal_class=strong but no crash output captured — allowing retry.")
            else:
                self._log(state, f"Runtime proof path_relevant=False — target binary does not contain vulnerable code. Skipping retry.")
                finding['failure_reason'] = 'Target binary does not contain the vulnerable code path (path_relevant=False)'
                state['findings'][idx] = finding
                return "log_failure"
        # Also retry 'exploit' failures when the oracle saw nothing or produced a
        # retryable reason.  After expanding _normalize_oracle_reason (Task 1),
        # these specific reasons flow through instead of being collapsed to
        # no_oracle_match, so each must be listed explicitly.
        if failure_category == "exploit" and oracle_reason in {
            "no_oracle_match", "self_report_only",
            "path_not_relevant", "strong_signal_no_target",
            "strong_signal+path_not_relevant",  # Issue #5: real crash, wrong binary — retry with different binary
            "binary_ignored_input", "setup_stage_only",
            "no_behavioral_evidence",  # behavioral findings should get refinement
            "self_reported_marker_without_crash_evidence",  # PoV was close — ran binary, checked for crash, but binary exited cleanly
            "contract_matched+no_anchor",  # contract markers found but binary name not in output — refinement can add it
        }:
            retryable_failures = retryable_failures | {"exploit"}
        # Also retry 'exploit' failures when oracle_reason='non_evidence' — this happens when the
        # PoV ran the wrong executable (e.g. 'make' instead of the target binary) and stdout was
        # irrelevant build output rather than crash evidence.  A refinement with the corrected
        # TARGET_BINARY will produce real oracle signal.
        if failure_category == "exploit" and oracle_reason == "non_evidence":
            retryable_failures = retryable_failures | {"exploit"}
        # Also retry when oracle_reason='ambiguous_signal' — the PoV ran something related
        # but got parser error output (wrong format/payload), not a crash.  Refinement with
        # the correct format hint (XML for xmlwf, JSON for cjson, etc.) may trigger the vuln.
        if failure_category == "exploit" and oracle_reason == "ambiguous_signal":
            retryable_failures = retryable_failures | {"exploit"}
        # T2 — Retry when PoV self-compiled the binary: the refinement will get an explicit
        # hint to use TARGET_BINARY directly instead of rebuilding.
        _oracle_result_dict = (pov_result or {}).get('oracle_result') or {}
        if _oracle_result_dict.get('reason') == 'self_compile_blocked' or oracle_reason == 'self_compile_blocked':
            retryable_failures = retryable_failures | {"exploit"}
        # T3 — Retry when the PoV exited cleanly with no output or produced no
        # observable evidence for non-native targets.  The refinement loop can
        # add explicit print/assert statements or better oracle observables.
        _failure_reason = str(finding.get('failure_reason') or '')
        if _failure_reason in ('pov_exited_cleanly_no_output', 'pov_timeout_no_output') \
                or _failure_reason.startswith('pov_no_observable_evidence'):
            retryable_failures = retryable_failures | {"exploit"}
        if failure_category in retryable_failures and finding.get("retry_count", 0) < self._get_model_max_retries(state):
            # T6 — Per-finding timeout check before scheduling another retry
            import time as _time_refine
            _ft_m = int(settings.FINDING_TIMEOUT_MINUTES or 0)
            if _ft_m > 0:
                _fst = finding.get('_finding_start_ts')
                if _fst and (_time_refine.time() - float(_fst)) > _ft_m * 60:
                    _el = (_time_refine.time() - float(_fst)) / 60
                    self._log(state, f"Finding {idx} per-finding timeout ({_el:.1f}/{_ft_m} min) before retry; marking unproven_timeout")
                    finding['final_status'] = 'unproven_timeout'
                    state['findings'][idx] = finding
                    self._sync_findings_runtime(state, include_status=True)
                    return 'log_failure'
            self._log(state, f"Runtime proof failed with {failure_category}; attempting refinement ({finding.get('retry_count', 0) + 1}/{self._get_model_max_retries(state)})")
            return "refine_pov"
        self._log(state, "Runtime proof did not trigger the vulnerability")
        return "log_failure"

    def _has_more_findings(self, state: ScanState) -> str:
        """Check if there are more findings to process after logging"""
        idx = state.get("current_finding_idx", 0)
        total = len(state["findings"])
        
        self._log(state, f"Checking for more findings: current={idx}, total={total}")

        # Task 7: Scan-level timeout check
        import time as _time_scan
        _scan_timeout_s = int(settings.SCAN_TIMEOUT_S or 0)
        _scan_start = state.get('_scan_start_ts')
        if _scan_timeout_s > 0 and _scan_start:
            _elapsed = _time_scan.time() - float(_scan_start)
            if _elapsed > _scan_timeout_s:
                _processed = sum(1 for f in state.get('findings', []) if f.get('final_status'))
                self._log(state, f"SCAN TIMEOUT: {_elapsed:.0f}s > {_scan_timeout_s}s limit. "
                          f"Processed {_processed}/{total} findings. Completing scan gracefully.")
                state['timeout_note'] = f'Scan timed out after {_elapsed:.0f}s with {_processed}/{total} findings processed'
                return "end"
        
        # Safety check: prevent infinite loop if idx is not advancing
        if idx >= total:
            # ── Task 3: Second-chance LLM-guided discovery ──────────────────────
            # When ALL findings were dismissed OR all attempted findings failed
            # (none confirmed) AND this is a library repo, run a targeted LLM
            # query to find real vulnerabilities in the core library code.
            _any_confirmed = any(
                f.get('final_status') == 'confirmed'
                for f in state.get('findings', [])
            )
            _any_attempted_not_failed = any(
                f.get('pov_script') and f.get('final_status') not in (
                    'failed', 'non_evidence', 'contract_gate_failed',
                    'unproven_contract_gate', 'unproven_low_confidence',
                )
                for f in state.get('findings', [])
            )
            _surface = state.get('repo_surface_class', '')
            _already_ran_second_chance = state.get('_second_chance_ran', False)
            if (not _any_confirmed
                    and not _any_attempted_not_failed
                    and _surface in ('library_c', 'library_c_with_cli', 'python_module', 'node_module', 'java_lib')
                    and not _already_ran_second_chance
                    and state.get('codebase_path')):
                state['_second_chance_ran'] = True
                new_findings = self._second_chance_discovery(state)
                if new_findings:
                    self._log(state, f"Second-chance discovery found {len(new_findings)} additional findings")
                    state['findings'].extend(new_findings)
                    # Don't advance idx — let the loop process these new findings
                    return "investigate"
            # ── End Task 3 ─────────────────────────────────────────────────────

            # All findings processed, mark as completed
            self._log(state, f"All {total} findings processed, completing scan")
            # FIX-4: Clean up shared build volume created by probe
            _scan_id = state.get('scan_id', '')
            if _scan_id:
                try:
                    import docker as _docker_cleanup
                    _dc = _docker_cleanup.from_env(timeout=10)
                    _dc.volumes.get(f'autopov_build_{_scan_id}').remove(force=True)
                except Exception:
                    pass
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.now(timezone.utc).isoformat()
            self._update_scan_runtime(state,
                status=ScanStatus.COMPLETED,
                end_time=state["end_time"],
                findings=state.get("findings", []),
                progress=100,
            )
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

    def _sync_findings_runtime(self, state: Optional[ScanState], *, include_status: bool = False, progress: Optional[int] = None):
        if state is None or not state.get("scan_id"):
            return
        updates = {
            "findings": state.get("findings", []),
            "current_finding_idx": state.get("current_finding_idx", 0),
            "total_tokens": state.get("total_tokens", 0),
            "total_cost_usd": state.get("total_cost_usd", 0.0),
        }
        if include_status and state.get("status") is not None:
            updates["status"] = state.get("status")
        if progress is not None:
            updates["progress"] = progress
        self._update_scan_runtime(state, **updates)

    def _log_proof_plan_summary(self, state: Optional[ScanState], finding: Dict[str, Any]):
        plan = ((finding.get("exploit_contract") or {}).get("proof_plan") or {}) if isinstance(finding, dict) else {}
        if not isinstance(plan, dict) or not plan:
            return
        runtime_family = plan.get("runtime_family") or "unknown"
        execution_surface = plan.get("execution_surface") or "unknown"
        input_mode = plan.get("input_mode") or "unknown"
        input_format = plan.get("input_format") or "unknown"
        oracles = ', '.join((plan.get("oracle") or [])[:3]) or 'none'
        self._log(state, f"  Proof plan: runtime={runtime_family}, surface={execution_surface}, input={input_mode}/{input_format}")
        self._log(state, f"  Oracle targets: {oracles}")

    def _log_runtime_result_details(self, state: Optional[ScanState], result: Dict[str, Any]):
        if not isinstance(result, dict):
            return
        preflight = result.get("preflight") or {}
        if isinstance(preflight, dict) and preflight:
            checks = preflight.get("checks") or []
            ok_checks = sum(1 for check in checks if isinstance(check, dict) and check.get("ok"))
            self._log(state, f"  Preflight: {ok_checks}/{len(checks)} checks passed")
            issues = preflight.get("issues") or []
            if issues:
                self._log(state, f"  Preflight issues: {issues[:2]}")
            surface = preflight.get("surface") or result.get("surface") or {}
        else:
            surface = result.get("surface") or {}

        if isinstance(surface, dict) and surface:
            observed = []
            if surface.get("supports_positional_file"):
                observed.append("positional-file")
            if surface.get("eval_option"):
                observed.append(f"eval={surface.get('eval_option')}")
            if surface.get("include_option"):
                observed.append(f"include={surface.get('include_option')}")
            if observed:
                self._log(state, f"  Observed target surface: {', '.join(observed)}")

        if result.get("selected_variant"):
            self._log(state, f"  Selected runtime variant: {result.get('selected_variant')}")

        baseline = result.get("baseline_result") or {}
        if isinstance(baseline, dict) and baseline:
            self._log(state, f"  Baseline execution exit code: {baseline.get('exit_code', -1)}")

        oracle = result.get("oracle_result") or {}
        if isinstance(oracle, dict) and oracle:
            matched = oracle.get("matched_markers") or []
            reason = oracle.get("reason") or "unknown"
            if matched:
                self._log(state, f"  Oracle matched: {matched[:3]}")
            else:
                self._log(state, f"  Oracle result: {reason}")

        if result.get("path_exercised") and not result.get("vulnerability_triggered"):
            self._log(state, "  Target path changed between baseline and exploit, but no proof oracle fired")

        failure_category = result.get("failure_category")
        if failure_category:
            self._log(state, f"  Failure category: {failure_category}")

    def _build_refinement_feedback(self, finding: VulnerabilityState) -> Dict[str, Any]:
        pov_result = finding.get("pov_result") or {}
        validation_result = finding.get("validation_result") or {}
            
        # Build observed_surface from multiple sources:
        # 1. Direct 'surface' key (from pov_tester)
        # 2. Nested 'preflight.surface' key
        # 3. Top-level 'preflight_subcommands' / 'preflight_help_text' (from docker_runner)
        observed_surface = (
            pov_result.get("surface")
            or (pov_result.get("preflight") or {}).get("surface")
            or {}
        )
        # If observed_surface is empty but docker_runner stored preflight data, construct it
        if not observed_surface:
            preflight_subcommands = pov_result.get("preflight_subcommands")
            preflight_help_text = pov_result.get("preflight_help_text")
            if preflight_subcommands or preflight_help_text:
                observed_surface = {
                    "subcommands": preflight_subcommands or [],
                    "help_text": preflight_help_text or "",
                }
            
        feedback = {
            "failure_category": pov_result.get("failure_category"),
            "validation_method": pov_result.get("validation_method"),
            "oracle_result": pov_result.get("oracle_result") or {},
            "selected_variant": pov_result.get("selected_variant"),
            "selected_binary": pov_result.get("selected_binary") or pov_result.get("target_binary"),
            "observed_surface": observed_surface,
            "preflight": pov_result.get("preflight") or {},
            "baseline_result": pov_result.get("baseline_result") or {},
            "stderr_excerpt": str(pov_result.get("stderr") or "")[:3000],
            "stdout_excerpt": str(pov_result.get("stdout") or "")[:3000],
            "proof_summary": pov_result.get("proof_summary") or ((pov_result.get("evidence") or {}).get("summary")),
        }
        # Task 6: Expose oracle_reason, retry_count, preflight_subcommands as top-level keys
        # so the refinement prompt receives structured data instead of buried-in-issues strings.
        feedback["oracle_reason"] = pov_result.get("oracle_reason") or \
            ((pov_result.get("oracle_result") or {}).get("reason"))
        feedback["retry_count"] = finding.get("retry_count", 0)
        feedback["preflight_subcommands"] = pov_result.get("preflight_subcommands") or []
        # Inject structured signal_detail (crash_type, actionable_hint, recovery_strategy)
        _sig_detail = finding.get('_signal_detail')
        if not _sig_detail:
            # Fallback: compute signal_detail from pov_result if available
            _rr = pov_result or {}
            _stderr_fb = str(_rr.get('stderr') or '')
            _stdout_fb = str(_rr.get('stdout') or '')
            _ec_fb = int(_rr.get('exit_code') or -1)
            if _stderr_fb or _stdout_fb:
                try:
                    from agents.oracle_policy import classify_signal_detailed
                    _sd_fb = classify_signal_detailed(_stdout_fb, _stderr_fb, _ec_fb)
                    if _sd_fb.recovery_strategy != 'success':
                        _sig_detail = {
                            'crash_type': _sd_fb.crash_type,
                            'reason': _sd_fb.reason,
                            'actionable_hint': _sd_fb.actionable_hint,
                            'recovery_strategy': _sd_fb.recovery_strategy,
                        }
                except Exception:
                    pass
        if _sig_detail and isinstance(_sig_detail, dict):
            feedback["signal_detail"] = _sig_detail
        issues = list((validation_result.get("issues") or []))
        if feedback.get("failure_category"):
            issues.append(f"Runtime failure category: {feedback['failure_category']}")
        oracle_reason = feedback.get("oracle_reason")
        if oracle_reason and oracle_reason != 'oracle_matched':
            issues.append(f"Runtime oracle result: {oracle_reason}")
        # Task 5: Strategy recommendation based on oracle_reason
        if oracle_reason == 'binary_ignored_input':
            _retry = feedback.get('retry_count', 0)
            if _retry >= 2:
                issues.append(
                    "STRATEGY: After multiple failed attempts, this binary is likely a TEST RUNNER "
                    "that ignores external input. Switch to writing a C harness that directly calls "
                    "the vulnerable function from the library headers. Compile with ASan flags."
                )
            else:
                issues.append(
                    "STRATEGY: The binary ignored your input entirely. Try a different subcommand "
                    "or pass input as a file argument instead of stdin."
                )
        stderr_excerpt = feedback.get("stderr_excerpt")
        if stderr_excerpt:
            issues.append(f"Runtime stderr excerpt: {stderr_excerpt[:240]}")
        feedback["issues"] = issues
        return feedback

    def _log(self, state: Optional[ScanState], message: str):
        """Add log message to state and stream to scan manager in real-time"""
        timestamp = datetime.now(timezone.utc).isoformat()
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
        openrouter_api_key: Optional[str] = None,
        target_type: str = 'repo',
        target_label: Optional[str] = None,
        benchmark_metadata: Optional[Dict[str, Any]] = None,
        repo_url: Optional[str] = None,
        target_metadata: Optional[Dict[str, Any]] = None,
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
            target_type=target_type,
            target_label=target_label,
            benchmark_metadata=benchmark_metadata,
            repo_url=repo_url,
            target_metadata=target_metadata,
            current_finding_idx=0,
            start_time=datetime.now(timezone.utc).isoformat(),
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
            scan_openrouter_usage=[],
            probe_result=None,
            trace_result=None,
            recon_high_value_files=None,
            recon_historical_vuln_types=None,
            recon_repo_activity=None,
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

























