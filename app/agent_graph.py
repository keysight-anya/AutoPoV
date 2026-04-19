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
        workflow.add_edge("trace_target", "generate_pov")
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
        if issues:
            return issues

        failure_category = str(runtime.get("failure_category") or "").strip()
        oracle = runtime.get("oracle_result") or {}
        oracle_reason = str(oracle.get("reason") or "").strip()
        stderr_text = str(runtime.get("stderr") or "").strip()
        stdout_text = str(runtime.get("stdout") or "").strip()
        exit_code = int(runtime.get("exit_code") or -1)

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

        # Wrong binary name — TARGET_SYMBOL doesn't match probe-discovered binary
        _probe_bin_name = str(((finding or {}).get('exploit_contract') or {}).get('probe_binary_name') or '').strip()
        if _probe_bin_name and ('[autopov] binary not found:' in _stderr_lower):
            # Extract what name was used
            _bn_match = re.search(r'\[autopov\] binary not found: ([\w.-]+)', stderr_text)
            _wrong_name = _bn_match.group(1) if _bn_match else 'unknown'
            if _wrong_name != _probe_bin_name:
                issues.append(
                    f"CRITICAL: Wrong binary name in TARGET_SYMBOL. "
                    f"The script searched for '{_wrong_name}' but the probe discovered the actual binary is "
                    f"'{_probe_bin_name}'. Change TARGET_SYMBOL = {_probe_bin_name!r}. "
                    f"Also set: TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') or {_probe_bin_name!r}"
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
        except Exception:
            pass

        # ——— Detect key-file-not-found: binary ran but couldn’t open its key material ———
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
        finding['exploit_contract'] = audit.get('normalized_contract') or (finding.get('exploit_contract') or {})
        finding['contract_audit'] = {
            'phase': audit.get('phase'),
            'is_ready': audit.get('is_ready'),
            'issues': list(audit.get('issues') or []),
            'warnings': list(audit.get('warnings') or []),
            'handoff_payload': audit.get('handoff_payload') or {},
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

            # Task 1: Classify the repo surface upfront so all downstream layers
            # can route correctly without per-repo guessing.
            try:
                repo_cls = self._classify_repo_surface(state["codebase_path"])
                state["repo_surface_class"] = repo_cls
                self._log(state, f"Repo surface class: {repo_cls}")
            except Exception as cls_err:
                state["repo_surface_class"] = 'unknown'
                self._log(state, f"  Warning: repo surface classification failed (non-fatal): {cls_err}")

            # Task 2A: For C library repos extract public API from headers so the
            # model can write function-harness PoVs rather than file-fuzzers.
            if state.get("repo_surface_class") == 'library_c':
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

        Returns one of:
          'cli_tool_c'        - C/C++ repo with a main() function (has a CLI binary)
          'library_c'         - C/C++ repo without main() at top level (pure library)
          'cli_tool_go'       - Go module repo
          'python_module'     - Python package without web framework imports
          'web_service_python'- Python package with flask/django/aiohttp/etc.
          'node_module'       - Node.js package without HTTP framework dep
          'web_service_node'  - Node.js package with express/fastify/koa/etc.
          'unknown'           - could not determine
        """
        import re as _re
        import os as _os
        from pathlib import Path as _Path

        cb = _Path(codebase_path)
        if not cb.is_dir():
            return 'unknown'

        # ── Go ───────────────────────────────────────────────────────────────
        if (cb / 'go.mod').is_file():
            return 'cli_tool_go'

        # ── Node.js ──────────────────────────────────────────────────────────
        pkg_json = cb / 'package.json'
        if pkg_json.is_file():
            try:
                import json as _json
                pkg = _json.loads(pkg_json.read_text(encoding='utf-8', errors='ignore'))
                all_deps = set()
                for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                    all_deps.update(pkg.get(section, {}).keys())
                _HTTP_FRAMEWORKS = {
                    'express', 'fastify', 'koa', '@hapi/hapi', 'hapi', 'restify',
                    'nest', '@nestjs/core', 'sails', 'loopback', 'polka', 'micro',
                    'connect',
                }
                if all_deps & _HTTP_FRAMEWORKS:
                    return 'web_service_node'
                return 'node_module'
            except Exception:
                return 'node_module'

        # ── Python ───────────────────────────────────────────────────────────
        _py_markers = ['setup.py', 'pyproject.toml', 'setup.cfg']
        if any((cb / m).is_file() for m in _py_markers):
            # Check for web framework imports in *.py files (shallow scan)
            _WEB_IMPORTS = _re.compile(
                r'(import|from)\s+(flask|django|aiohttp|tornado|bottle|cherrypy|fastapi|starlette)'
            )
            for _root, _dirs, _files in _os.walk(str(cb)):
                _dirs[:] = [d for d in _dirs if d not in {'.git', '__pycache__', '.venv', 'venv', 'node_modules', 'dist', 'build'}]
                for _fname in _files:
                    if not _fname.endswith('.py'):
                        continue
                    try:
                        _content = (_Path(_root) / _fname).read_text(encoding='utf-8', errors='ignore')[:4096]
                        if _WEB_IMPORTS.search(_content):
                            return 'web_service_python'
                    except OSError:
                        pass
            return 'python_module'

        # ── C/C++ ────────────────────────────────────────────────────────────
        _C_BUILD_MARKERS = ['CMakeLists.txt', 'Makefile', 'makefile', 'configure.ac', 'configure.in', 'meson.build']
        if any((cb / m).is_file() for m in _C_BUILD_MARKERS):
            # Search for main() in .c/.cpp files at depth ≤ 2
            # Match both modern (int main(...)) and K&R-style (main(...)) entry points.
            # Also catches 'int main(' split across two lines via '\s+' or simply bare 'main('.
            _MAIN_RE = _re.compile(r'\bint\s+main\s*\(|(?:^|\s)main\s*\(\s*int', _re.MULTILINE)
            _found_main = False
            for _root, _dirs, _files in _os.walk(str(cb)):
                # Limit depth to ≤ 2 relative to codebase root
                _rel = _os.path.relpath(_root, str(cb))
                _depth = 0 if _rel == '.' else _rel.count(_os.sep) + 1
                if _depth > 2:
                    _dirs[:] = []
                    continue
                _dirs[:] = [d for d in _dirs if d not in {'.git', 'CMakeFiles', '_codeql_build_dir', '.autopov-cmake-build', '.autopov-probe-build', 'CompilerIdC', 'CompilerIdCXX'}]
                for _fname in _files:
                    if not (_fname.endswith('.c') or _fname.endswith('.cpp') or _fname.endswith('.cc') or _fname.endswith('.cxx')):
                        continue
                    try:
                        _content = (_Path(_root) / _fname).read_text(encoding='utf-8', errors='ignore')[:8192]
                        if _MAIN_RE.search(_content):
                            _found_main = True
                            break
                    except OSError:
                        pass
                if _found_main:
                    break
            return 'cli_tool_c' if _found_main else 'library_c'

        return 'unknown'

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

        # Collect .h files at depth ≤ 2
        headers: list = []  # list of (priority, path)
        for _root, _dirs, _files in _os.walk(str(cb)):
            _rel = _os.path.relpath(_root, str(cb))
            _depth = 0 if _rel == '.' else _rel.count(_os.sep) + 1
            if _depth > 2:
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
        _SIG_RE = _re.compile(
            r'^\s*(?:(?:extern|static|inline|const|unsigned|signed|void|int|char|long|short|float|double|size_t|uint\w*|int\w*|\w+_t)\s+)+'
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
                repo_web_capable=state.get("repo_web_capable", False)
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
        # 2c: carry joern taint context forward to PoV generation
        if result.get("joern_context"):
            finding["joern_context"] = result["joern_context"]
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
                    repo_web_capable=state.get("repo_web_capable", False)
                )
                
                finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
                finding["llm_explanation"] = result.get("explanation", "")
                finding["confidence"] = result.get("confidence", 0.0)
                finding["inference_time_s"] = result.get("inference_time_s", 0.0)
                finding["code_chunk"] = result.get("vulnerable_code", "") or finding.get("code_chunk", "")
                finding["cwe_type"] = result.get("cwe_type") or finding.get("cwe_type") or "UNCLASSIFIED"
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
                    ec['target_binary'] = probe.probe_binary_path
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
                # Task 1/2A: Propagate repo_surface_class and library_api_context so
                # PoV generation and guardrails can route without re-reading state.
                _repo_cls = state.get('repo_surface_class') or ''
                if _repo_cls and not ec.get('repo_surface_class'):
                    ec['repo_surface_class'] = _repo_cls
                _lib_api = state.get('library_api_context') or ''
                if _lib_api and not ec.get('library_api_context'):
                    ec['library_api_context'] = _lib_api
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
                finding['exploit_contract'] = ec

        return state

    def _node_trace_target(self, state: ScanState) -> ScanState:
        """Dynamic trace node: runs strace + valgrind after the probe and before PoV generation.

        Runs once per scan (like probe_target). Results are stored in state['trace_result']
        and injected as exploit_contract['trace_context'] for every finding.
        Only runs for native C/C++ targets; skips silently for other languages.
        """
        # Skip if already traced this scan
        if state.get('trace_result') is not None:
            return state

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
            if trace_ctx_str:
                for finding in state.get('findings', []):
                    ec = dict(finding.get('exploit_contract') or {})
                    if not ec.get('trace_context'):
                        ec['trace_context'] = trace_ctx_str
                    # Also propagate detected input surface if stronger than probe's
                    if trace.trace_input_surface and trace.trace_input_surface != 'unknown':
                        if not ec.get('trace_input_surface'):
                            ec['trace_input_surface'] = trace.trace_input_surface
                    finding['exploit_contract'] = ec
        except Exception as exc:
            self._log(state, f'Trace node error (non-fatal): {exc}')
            state['trace_result'] = {'trace_skipped': True, 'trace_skip_reason': f'exception:{exc}'}

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

        model_to_use = self._get_selected_model(state)
        self._log(state, f"Using selected model for PoV: {model_to_use}")
        
        verifier = get_verifier()
        audit = self._audit_finding_handoff(state, finding, phase='generation')
        if not audit.get('is_ready'):
            self._log(state, f"Skipping PoV generation because contract gate failed: {(audit.get('issues') or [])[:2]}")
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
        # This helps the model pick the right TARGET_SYMBOL from the first attempt.
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
            finding["exploit_contract"] = result.get("exploit_contract")
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
        if _retry_count > 0 and _oracle_reason in {'no_oracle_match', 'path_not_relevant', 'ambiguous_signal'}:
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
                        f"Update TARGET_SYMBOL = {_next_ep!r} in your script. "
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
        # If the current PoV script is byte-for-byte identical to any previous
        # attempt, the model is stuck in a loop. Inject a diversification hint
        # so the next attempt uses a completely different approach.
        import hashlib as _hashlib
        _current_pov_hash = _hashlib.md5(
            str(finding.get('pov_script') or '').strip().encode()
        ).hexdigest()
        _prior_hashes = set()
        for _hist_entry in (finding.get('refinement_history') or []):
            _hist_pov = str(_hist_entry.get('pov_script') or '').strip()
            if _hist_pov:
                _prior_hashes.add(_hashlib.md5(_hist_pov.encode()).hexdigest())
        if _current_pov_hash in _prior_hashes:
            _subcmds_str = ', '.join(_known_subs) if _known_subs else 'the available subcommands'
            _diversity_hint = (
                "CRITICAL: Your last attempt produced identical output to a previous attempt. "
                "You MUST use a completely different exploitation approach. "
                "If the previous approach used argv/CLI flags, try stdin or file input instead. "
                f"If the previous approach used one subcommand, try a different one from: {_subcmds_str}. "
                "Change the payload type, input format, or entire exploit strategy."
            )
            if not any('identical' in e.lower() or 'different approach' in e.lower() for e in validation_errors):
                validation_errors = [_diversity_hint] + list(validation_errors)
            self._log(state, "  Identical PoV detected — injecting diversity hint")
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
                'stdout': str(runtime_result.get('stdout') or '')[:600],
                'stderr': str(runtime_result.get('stderr') or '')[:600],
            })

        _coord_trace_ctx = str((finding.get('exploit_contract') or {}).get('trace_context') or '')
        _coord_contract = finding.get('exploit_contract') or {}
        model_to_use = self._get_selected_model(state)

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
            finding["exploit_contract"] = result.get("exploit_contract") or finding.get("exploit_contract")
            finding["refinement_model_mode"] = result.get("model_mode", "unknown")
            finding["retry_count"] += 1
            self._log(state, f"  PoV refined successfully (attempt {finding['retry_count']})")
            if total_tokens > 0:
                self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
        else:
            error_text = result.get('error') or 'Model did not return executable PoV code'
            self._log(state, f"  PoV refinement failed: {error_text}")
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
                "timestamp": datetime.utcnow().isoformat()
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
            result = runner.run_pov(
                pov_script=finding["pov_script"],
                scan_id=state["scan_id"],
                pov_id=str(idx),
                execution_profile=execution_profile,
                target_language=target_language,
                exploit_contract=_ec,
                codebase_path=state.get("codebase_path"),
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
            self._sync_findings_runtime(state, include_status=True)
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
                self._sync_findings_runtime(state, include_status=True)
        
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
            finding = state["findings"][idx]
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
                    finding["failure_reason"] = "pov_ran_no_crash_detected"
            state["findings"][idx] = finding
            self._sync_findings_runtime(state, include_status=True)
        
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
        if source in trusted_sources and confidence >= 0.8 and verdict in ["UNKNOWN", ""]:
            self._log(state, f"Finding {idx} from {source} has high confidence ({confidence:.2f}), trusting static analysis result")
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
        retryable_failures = {"guardrail_rejected", "path_exercised_no_oracle", "oracle_not_observed", "execution_error"}
        # Also retry 'exploit' failures when the oracle saw nothing (no_oracle_match / self_report_only):
        # the script likely failed due to wrong invocation (e.g. --help rejected), and
        # a refinement pass now has known_subcommands in the contract so can do better.
        if failure_category == "exploit" and oracle_reason in {"no_oracle_match", "self_report_only"}:
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
        if failure_category in retryable_failures and finding.get("retry_count", 0) < self._get_model_max_retries(state):
            self._log(state, f"Runtime proof failed with {failure_category}; attempting refinement ({finding.get('retry_count', 0) + 1}/{self._get_model_max_retries(state)})")
            return "refine_pov"
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
            "stderr_excerpt": str(pov_result.get("stderr") or "")[:1200],
            "stdout_excerpt": str(pov_result.get("stdout") or "")[:1200],
            "proof_summary": pov_result.get("proof_summary") or ((pov_result.get("evidence") or {}).get("summary")),
        }
        # Task 6: Expose oracle_reason, retry_count, preflight_subcommands as top-level keys
        # so the refinement prompt receives structured data instead of buried-in-issues strings.
        feedback["oracle_reason"] = pov_result.get("oracle_reason") or \
            ((pov_result.get("oracle_result") or {}).get("reason"))
        feedback["retry_count"] = finding.get("retry_count", 0)
        feedback["preflight_subcommands"] = pov_result.get("preflight_subcommands") or []
        issues = list((validation_result.get("issues") or []))
        if feedback.get("failure_category"):
            issues.append(f"Runtime failure category: {feedback['failure_category']}")
        oracle_reason = feedback.get("oracle_reason")
        if oracle_reason and oracle_reason != 'oracle_matched':
            issues.append(f"Runtime oracle result: {oracle_reason}")
        stderr_excerpt = feedback.get("stderr_excerpt")
        if stderr_excerpt:
            issues.append(f"Runtime stderr excerpt: {stderr_excerpt[:240]}")
        feedback["issues"] = issues
        return feedback

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
            scan_openrouter_usage=[],
            probe_result=None,
            trace_result=None,
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

























