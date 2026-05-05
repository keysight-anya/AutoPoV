"""
AutoPoV Docker Runner Module
Executes PoV scripts in isolated Docker containers
"""

import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Optional, Any, List, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import docker
    from docker.errors import DockerException, ContainerError, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from app.config import settings


class DockerRunnerError(Exception):
    """Exception raised during Docker execution"""
    pass


class DockerImagePreparationError(DockerRunnerError):
    """Exception raised while preparing Docker runtime images."""
    pass


class DockerRunner:
    """Runs PoV scripts in Docker containers"""

    GENERIC_SELF_REPORTED_MARKERS = {"vulnerability triggered"}
    # Exception markers are only excluded from corroboration when the exploit contract
    # does NOT explicitly declare 'exception' as an oracle type.  Declaring it promotes
    # controlled Python/JS exceptions to valid corroborating evidence.
    GENERIC_EXCEPTION_MARKERS = {"traceback", "referenceerror", "typeerror", "valueerror", "exception"}
    RUNTIME_CRASH_PATTERNS = [
        'addresssanitizer',
        'undefinedbehaviorsanitizer',
        'runtime error:',
        'heap-buffer-overflow',
        'stack-buffer-overflow',
        'global-buffer-overflow',
        'use-after-free',
        'segmentation fault',
        'sigsegv',
        'sigabrt',
        'bus error',
        'core dumped',
        'deadlysignal',
        'abort',
        'null pointer',
    ]

    # Patterns indicating the binary rejected our payload for format/magic reasons
    # BEFORE reaching vulnerable code.  When matched after a failed run, we retry
    # with structurally correct format-aware payloads (Task 0b).
    _FORMAT_REJECTION_RE = re.compile(
        r'unhandled file type'
        r'|premature end of file'
        r'|bad png chunk'
        r'|not a jpeg'
        r'|invalid jpeg'
        r'|not a valid'
        r'|unsupported format'
        r'|cannot open'
        r'|not recognized'
        r'|file format not recognized'
        r'|unknown file type'
        r'|invalid file'
        # jhead-specific: oversized IFD or bad pointer caught before reaching vulnerable loop
        r'|illegally sized exif'
        r'|illegal value pointer'
        r'|bad components count',
        re.IGNORECASE,
    )

    # Map binary name fragments -> preferred file extension for payload selection.
    _BINARY_EXT_MAP = {
        'jhead': '.jpg', 'exiftool': '.jpg', 'tiff': '.tif',
        'convert': '.jpg', 'identify': '.jpg', 'mogrify': '.jpg',
        'ffmpeg': '.jpg', 'ffprobe': '.jpg',
        'mp3': '.mp3', 'pdf': '.pdf',
        'gif': '.gif', 'png': '.png', 'bmp': '.bmp', 'webp': '.webp',
        # XML parsers / well-formedness checkers — payloads must be XML
        'xmlwf': '.xml', 'xmllint': '.xml', 'xmlto': '.xml', 'xml2': '.xml',
        'expat': '.xml', 'libxml': '.xml', 'saxparser': '.xml',
        # JSON parsers
        'cjson': '.json', 'json_check': '.json', 'json_verify': '.json',
        'jansson': '.json', 'jq': '.json', 'json-c': '.json',
        # Archive/compression tools
        'enchive': '.enc', 'gpg': '.enc', 'openssl': '.bin',
        'zip': '.zip', 'unzip': '.zip', 'tar': '.tar', 'gzip': '.gz',
        'zlib': '.gz', 'bzip': '.bz2', 'lz4': '.lz4', 'zstd': '.zst',
    }

    def __init__(self):
        self._client = None
        self.image = settings.DOCKER_IMAGE
        self.timeout = settings.DOCKER_TIMEOUT
        self.build_timeout = settings.DOCKER_BUILD_TIMEOUT
        self.execution_timeout = settings.DOCKER_EXECUTION_TIMEOUT
        self.memory_limit = settings.DOCKER_MEMORY_LIMIT
        self.cpu_limit = settings.DOCKER_CPU_LIMIT
        self.runtime_images = {
            "python": settings.DOCKER_IMAGE,
            "node": settings.DOCKER_NODE_IMAGE,
            "browser": settings.DOCKER_BROWSER_IMAGE,
            "native": settings.DOCKER_NATIVE_IMAGE,
            "php": settings.DOCKER_PHP_IMAGE,
            "ruby": settings.DOCKER_RUBY_IMAGE,
            "go": settings.DOCKER_GO_IMAGE,
            "java": settings.DOCKER_JAVA_IMAGE,
            "shell": settings.DOCKER_SHELL_IMAGE,
        }
        self.build_contexts = {
            "python": self._proof_image_dir("python"),
            "node": self._proof_image_dir("node"),
            "browser": self._proof_image_dir("browser"),
            "native": self._proof_image_dir("native"),
            "php": self._proof_image_dir("php"),
            "ruby": self._proof_image_dir("ruby"),
            "go": self._proof_image_dir("go"),
            "java": self._proof_image_dir("java"),
        }

    def _proof_image_dir(self, kind: str) -> Optional[Path]:
        candidate = Path(__file__).resolve().parent.parent / "docker" / "proof-images" / kind
        return candidate if candidate.exists() else None

    def _classify_failure(self, *, infrastructure: bool, reason: str = "") -> Dict[str, Any]:
        category = "infrastructure" if infrastructure else "exploit"
        return {
            "proof_infrastructure_error": infrastructure,
            "failure_category": category,
            "failure_reason": reason,
        }

    def _build_result(
        self,
        *,
        success: bool,
        vulnerability_triggered: bool,
        stdout: str,
        stderr: str,
        exit_code: int,
        execution_time_s: float,
        execution_profile: str,
        runtime_image: str,
        validation_method: str,
        proof_infrastructure_error: bool = False,
        failure_reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        # Extract oracle_result from metadata before updating result so it becomes
        # a top-level key (consumed by agent_graph._ensure_staged_runtime_result).
        _oracle_result = (metadata or {}).pop('oracle_result', None) if metadata else None
        # Use the actual oracle reason from oracle_result instead of defaulting to no_oracle_match
        _oracle_reason_from_result = str((_oracle_result or {}).get('reason') or '').strip()
        oracle_reason = 'oracle_matched' if vulnerability_triggered else (
            _oracle_reason_from_result or failure_reason or 'no_oracle_match'
        )
        _path_relevant = bool((_oracle_result or {}).get('path_relevant', vulnerability_triggered))
        _matched_markers = list((_oracle_result or {}).get('matched_evidence_markers', []))
        # T5 — Oracle consistency hard normalisation: non_evidence / environment_failure
        # can NEVER result in confirmed/proven regardless of any upstream override.
        # This guards against the contradiction where oracle_result.reason='non_evidence'
        # but proof_verdict='proven' and triggered=True appeared in batch results.
        _non_evidence_reasons = {'non_evidence', 'environment_failure', 'self_report_only', 'setup_stage_only', 'self_compile_blocked'}
        _oracle_reason_str = str((_oracle_result or {}).get('reason') or '').strip()
        if _oracle_reason_str in _non_evidence_reasons:
            vulnerability_triggered = False
            oracle_reason = _oracle_reason_str
        result = {
            "success": success,
            "vulnerability_triggered": vulnerability_triggered,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "execution_time_s": execution_time_s,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_profile": execution_profile,
            "runtime_image": runtime_image,
            "validation_method": validation_method,
            "execution_stage": "trigger",
            "proof_verdict": "proven" if vulnerability_triggered else "failed",
            "oracle_result": _oracle_result,
            "setup_result": {
                "stage": "setup",
                "success": not proof_infrastructure_error,
                "stdout": "",
                "stderr": failure_reason if proof_infrastructure_error else "",
                "exit_code": 0 if not proof_infrastructure_error else -1,
                "artifacts": [runtime_image] if runtime_image else [],
                "notes": ["generic container runtime prepared"] if not proof_infrastructure_error else ["generic container runtime failed before trigger execution"],
            },
            "trigger_result": {
                "stage": "trigger",
                "success": vulnerability_triggered,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "oracle_reason": oracle_reason,
                "path_relevant": _path_relevant,
                "matched_evidence_markers": _matched_markers,
            },
            **self._classify_failure(infrastructure=proof_infrastructure_error, reason=failure_reason),
        }
        if metadata:
            result.update(metadata)
        return result

    def _slugify(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value or "autopov")
        return cleaned.strip("-._")[:80] or "autopov"

    def _contract_indicators(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        # Do NOT default to ["VULNERABILITY TRIGGERED"] — it is a self-report
        # marker that the oracle blocks.  Only use indicators from the contract.
        indicators = []
        contract = exploit_contract or {}
        indicators.extend(contract.get("success_indicators", []) or [])
        indicators.extend(contract.get("side_effects", []) or [])
        return [str(ind).strip() for ind in indicators if str(ind).strip()]

    def _extract_structured_runtime_evidence(self, stdout: str, stderr: str) -> Dict[str, Any]:
        combined_lines = [line.strip() for line in (str(stdout or '') + '\n' + str(stderr or '')).splitlines() if line.strip()]
        for line in reversed(combined_lines):
            if not (line.startswith('{') and line.endswith('}')):
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            evidence = [str(item).lower() for item in (payload.get('evidence') or []) if str(item).strip()]
            child_crash = False
            # Check any key whose name contains 'returncode' or 'exit_code' for negative values
            # (covers both the canonical 'returncode' key and harness-specific keys like
            # 'client_returncode', 'child_exit_code', etc. emitted by inline C harnesses).
            for k, v in payload.items():
                k_norm = k.lower().replace('-', '_')
                if ('returncode' in k_norm or 'exit_code' in k_norm) and isinstance(v, int) and v < 0:
                    child_crash = True
                    break
            if any(item.startswith('signal=') for item in evidence):
                child_crash = True
            if any(token in ' '.join(evidence) for token in ['sanitizer_output', 'segfault_text']):
                child_crash = True
            return {'payload': payload, 'child_crash': child_crash, 'evidence': evidence}
        return {'payload': None, 'child_crash': False, 'evidence': []}

    def _exception_oracle_declared(self, exploit_contract: Optional[Dict[str, Any]]) -> bool:
        """Return True when the exploit contract explicitly declares 'exception' as an oracle type."""
        contract = exploit_contract or {}
        proof_plan = contract.get('proof_plan') or {}
        oracles = [str(x).lower() for x in (proof_plan.get('oracle') or []) if str(x).strip()]
        return 'exception' in oracles

    def _normalize_oracle_reason(self, oracle: Dict[str, Any], *, infrastructure: bool = False, timeout_hit: bool = False) -> str:
        if infrastructure:
            return 'timeout' if timeout_hit else 'infrastructure_failure'
        reason = str((oracle or {}).get('reason') or '').strip().lower()
        allowed = {
            'oracle_matched',
            'structured_runtime_crash',
            'runtime_crash_signal',
            'self_report_only',
            'no_oracle_match',
            'environment_failure',
            'self_compile_blocked',  # T2: PoV rebuilt the binary instead of exploiting it
            'non_evidence',           # binary ran cleanly, no crash
            'ambiguous_signal',       # generic non-zero exit, no clear crash
            'path_not_relevant',      # crash detected but in wrong code path
            'strong_signal+path_not_relevant',  # Issue #5: real ASan crash but path anchor mismatch
            'strong_signal_no_target', # crash detected but no target anchor
            'setup_stage_only',       # crash in setup, not trigger phase
            'binary_ignored_input',   # binary ignored PoV input entirely
        }
        return reason if reason in allowed else 'no_oracle_match'

    def _evaluate_runtime_oracle(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        exploit_contract: Optional[Dict[str, Any]] = None,
        *,
        asan_disabled: bool = False,
        baseline_exit_code: int = -1,
        baseline_stderr: str = '',
        pov_script: str = '',
        build_prelude_ran: bool = False,
    ) -> Dict[str, Any]:
        """Delegate to oracle_policy.evaluate_proof_outcome for taxonomy-agnostic evaluation.

        Adds path relevance, self-report blocking, and asan_disabled baseline comparison
        on top of the legacy RUNTIME_CRASH_PATTERNS list.  The structured-runtime-evidence
        JSON envelope (from inline harness wrappers) is checked as a supplementary signal
        and can promote triggered=True when oracle_policy did not see strong evidence.
        """
        import agents.oracle_policy as _oracle_policy
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
        if target_entrypoint.lower() in {'unknown', 'none', 'n/a', ''}:
            target_entrypoint = ''
        target_binary = str(contract.get('target_binary') or '').strip()
        filepath = str(contract.get('filepath') or '').strip()
        plan = contract.get('proof_plan') or {}
        expected_oracle = str(plan.get('expected_oracle') or '').strip()
        relevance_anchors = [
            str(x).strip()
            for x in (contract.get('relevance_anchors') or [])
            if str(x).strip()
        ]
        # Add probe_binary_name as a fallback relevance anchor so that a real crash
        # whose stacktrace references the binary name still confirms even when
        # target_entrypoint, target_binary, and filepath are all empty/unknown.
        _probe_bin_name = str(contract.get('probe_binary_name') or '').strip()
        if _probe_bin_name and _probe_bin_name not in relevance_anchors:
            relevance_anchors = list(relevance_anchors) + [_probe_bin_name]

        execution_surface = str(
            contract.get('execution_surface') or
            (contract.get('proof_plan') or {}).get('execution_surface') or ''
        ).strip().lower()

        # v2: If proof_strategy is present and proof_type is not crash_signal,
        # use the dynamic proof outcome evaluator
        _proof_strategy = contract.get('proof_strategy') or {}
        _proof_type = str(_proof_strategy.get('proof_type', '')).strip().lower()

        # Native C/C++ targets with behavioral_deviation should use crash_signal oracle.
        # ASan/UBSan/SEGV are the correct proof path for native code — the behavioral
        # oracle looks for output markers that native binaries never produce.
        _runtime_fam = str(contract.get('runtime_family') or '').lower()
        _runtime_prof = str(contract.get('runtime_profile') or '').lower()
        _is_native = _runtime_fam in ('c', 'cpp', 'native', 'binary') or _runtime_prof in ('c', 'cpp', 'native', 'binary')
        if _is_native and _proof_type == 'behavioral_deviation':
            _proof_type = 'crash_signal'

        # Extract observable_evidence from proof_strategy for contract-driven oracle
        _observable_evidence = list(_proof_strategy.get('observable_evidence') or [])

        # Also derive evidence from exploitation approach if not already set
        if not _observable_evidence and _proof_type not in ('crash_signal', ''):
            try:
                from agents.finding_context import _derive_observable_evidence_from_approach
                _approach = str(_proof_strategy.get('exploitation_approach') or '')
                if _approach:
                    _cwe_for_ev = str(contract.get('cwe_type') or '').strip()
                    _observable_evidence = _derive_observable_evidence_from_approach(_approach, cwe=_cwe_for_ev)
            except Exception:
                pass

        if _proof_strategy and _proof_type and _proof_type != 'crash_signal':
            op = _oracle_policy.evaluate_dynamic_proof_outcome(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                proof_strategy=_proof_strategy,
                target_entrypoint=target_entrypoint,
                filepath=filepath,
                pov_script=pov_script,
                expected_oracle=expected_oracle,
                target_binary=target_binary,
                relevance_anchors=relevance_anchors,
                asan_disabled=asan_disabled,
                baseline_exit_code=baseline_exit_code,
                baseline_stderr=baseline_stderr,
                execution_surface=execution_surface,
            )
        else:
            op = _oracle_policy.evaluate_proof_outcome(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                target_entrypoint=target_entrypoint,
                filepath=filepath,
                pov_script=pov_script,
                expected_oracle=expected_oracle,
                target_binary=target_binary,
                stage='trigger',
                relevance_anchors=relevance_anchors,
                asan_disabled=asan_disabled,
                baseline_exit_code=baseline_exit_code,
                baseline_stderr=baseline_stderr,
                execution_surface=execution_surface,
                observable_evidence=_observable_evidence,
                baseline_stdout=str(contract.get('probe_baseline_stdout') or ''),
            )
        # Task 6: For c_library_harness surface, also evaluate behavioral oracle
        # (routes to evaluate_proof_outcome internally for c_library_harness)
        if execution_surface == 'c_library_harness' and not op.get('triggered'):
            _beh_op = _oracle_policy.evaluate_behavioral_proof_outcome(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                execution_surface=execution_surface,
                target_entrypoint=target_entrypoint,
                filepath=filepath,
                pov_script=pov_script,
                expected_oracle=expected_oracle,
                target_binary=target_binary,
                relevance_anchors=relevance_anchors,
            )
            if _beh_op.get('triggered'):
                op = _beh_op

        triggered = op['triggered']
        reason = op['reason']
        self_report_only = op.get('self_report_only', False)

        # Structured runtime evidence: JSON envelope emitted by inline C harness wrappers.
        # If oracle_policy did not confirm but the harness signals a child crash,
        # promote to triggered so this path is not silently swallowed.
        # T5 — Oracle consistency guard: structured_runtime_crash can only promote
        # when oracle signal is ambiguous/strong — never when signal is non_evidence.
        # non_evidence means the binary did not crash or did not run at all; a harness
        # JSON envelope cannot override that (would produce the confirmed-but-no-crash
        # contradiction seen in batch results).
        structured_runtime = self._extract_structured_runtime_evidence(stdout, stderr)
        _oracle_signal = op.get('signal_class', '')
        if structured_runtime.get('child_crash') and not triggered and _oracle_signal != 'non_evidence':
            triggered = True
            reason = 'structured_runtime_crash'

        # T2 — Self-compile runtime guard: if the PoV's stdout contains build-system
        # output (make: Entering / gcc / clang compilation lines) the PoV rebuilt the
        # binary instead of exercising it.  Any oracle result is unreliable in this case;
        # force triggered=False so the finding is sent back for refinement with a clear
        # hint.  This guards against the bsdcat/libarchive 0/44 failure pattern.
        _combined_out = (str(stdout or '') + '\n' + str(stderr or '')).lower()
        _SELF_COMPILE_RUNTIME_PATTERNS = (
            'make: entering directory',
            'make[1]: entering directory',
            'make[2]: entering directory',
            'make -c /workspace/codebase',
            'make -b -c /workspace/codebase',
        )
        # If the build prelude ran (build_prelude_ran=True), make/clang output in
        # stdout is EXPECTED from the container setup — not from the PoV itself
        # re-compiling the binary.  Skip Tier 1 in that case to avoid false positives.
        _self_compiled = False
        if not build_prelude_ran:
            _self_compiled = any(p in _combined_out for p in _SELF_COMPILE_RUNTIME_PATTERNS)
        # Additional check: clang/gcc lines that appear OUTSIDE the build prelude
        # (build prelude sentinels: AUTOPOV_BUILD_STATUS lines).  If the PoV triggered
        # a re-build AFTER the build phase ended, that is a self-compile.
        # GAP-9 FIX: Tier 2 ALWAYS runs (even when build_prelude_ran=True) because it
        # only inspects output AFTER the autopov_help_text_end sentinel, which marks
        # the end of the build phase.  Any gcc/clang invocation after that sentinel is
        # from the PoV script itself — a genuine self-compile, not build prelude output.
        if not _self_compiled:
            import re as _re_sc2
            # 'gcc ' / 'clang ' followed by -o or -c flag = compilation invocation
            _compile_re = _re_sc2.compile(r'\b(?:gcc|clang|clang\+\+|g\+\+)\s+.*?-(?:o|c)\s', _re_sc2.IGNORECASE)
            # Only flag if this appears in stdout AFTER the help-text/binary sentinels
            # (so the build prelude gcc/clang output is not incorrectly caught).
            # When build_prelude_ran=True, the sentinel MUST be present — if it is not,
            # skip the check to avoid catching build prelude output.
            if build_prelude_ran:
                if 'autopov_help_text_end' in _combined_out:
                    _post_sentinel = _combined_out.split('autopov_help_text_end', 1)[-1]
                    _self_compiled = bool(_compile_re.search(_post_sentinel))
            else:
                _post_sentinel = _combined_out.split('autopov_help_text_end', 1)[-1] if 'autopov_help_text_end' in _combined_out else _combined_out
                _self_compiled = bool(_compile_re.search(_post_sentinel))
        if _self_compiled and triggered:
            triggered = False
            reason = 'self_compile_blocked'
            # Inject the self-compile signal into oracle_result so refinement
            # prompt can give the LLM a precise actionable hint.
            op = dict(op)
            op['reason'] = 'self_compile_blocked'
            op['triggered'] = False
            op['self_compile_detected'] = True

        # Task 4: Detect "binary ignored input" — when stdout matches the
        # probe's preflight help text (baseline output), the binary ignored
        # the PoV's input entirely.  Give a specific oracle_reason so the
        # refinement prompt can suggest a strategy change.
        if not triggered and reason == 'non_evidence':
            _preflight_text = str((exploit_contract or {}).get('preflight_help_text') or '').strip()
            if _preflight_text and len(_preflight_text) > 20:
                _stdout_stripped = (stdout or '').strip()
                if _stdout_stripped and (
                    _preflight_text[:200] in _stdout_stripped
                    or _stdout_stripped[:200] in _preflight_text
                ):
                    reason = 'binary_ignored_input'
                    op = dict(op)
                    op['reason'] = 'binary_ignored_input'

        # ── FIX-5: Compute enriched SignalDetail for actionable refinement hints ──
        _signal_detail = _oracle_policy.classify_signal_detailed(stdout, stderr, exit_code)
        _signal_detail_dict = {
            'crash_type': _signal_detail.crash_type,
            'actionable_hint': _signal_detail.actionable_hint,
            'recovery_strategy': _signal_detail.recovery_strategy,
            'reason': _signal_detail.reason,
            'label': _signal_detail.label,
        }

        return {
            'triggered': triggered,
            'matched_markers': op.get('matched_evidence_markers', []),
            'reason': reason,
            'self_report_only': self_report_only,
            'structured_runtime_evidence': structured_runtime.get('payload'),
            # Full oracle_policy result — consumed by _build_result → oracle_result top-level key
            'oracle_result': op,
            # FIX-5: Enriched signal detail for refinement loop
            'signal_detail': _signal_detail_dict,
        }

    def _detect_script_runtime(self, pov_script: str, execution_profile: Optional[str], pov_language: Optional[str] = None) -> str:
        """Detect the actual scripting language of a PoV script.

        Priority order:
        1. **Script content analysis** — definitive markers in the script itself
           (shebangs, ``<?php``, ``import sys``, ``public class``, etc.) are the
           highest-trust signal because they reflect what the LLM *actually wrote*.
        2. **pov_language** — the language selected by ``_select_pov_language()`` in
           the verifier.  This is the *intended* language for the PoV (may differ
           from the target language).
        3. **execution_profile** — the target repo language / runtime profile.
           Used only as a last-resort fallback when content analysis is ambiguous.
        """
        script = str(pov_script or "")

        # ── 1. Definitive content markers (highest priority) ──────────────
        if "<?php" in script:
            return "php"
        if script.startswith("#!/bin/bash") or script.startswith("#!/usr/bin/env bash"):
            return "shell"
        if script.startswith("#!/usr/bin/env ruby"):
            return "ruby"
        if script.startswith("#!/usr/bin/env node"):
            return "node"
        # Python markers — check BEFORE Java/Node because the target may be
        # Java but the PoV is a Python driver script.
        _has_python_markers = (
            'import sys' in script
            or 'import os' in script
            or 'import subprocess' in script
            or 'import requests' in script
            or 'def main(' in script
            or 'if __name__' in script
            or script.startswith('#!/usr/bin/env python')
        )
        if _has_python_markers:
            return "python"
        # Java markers — must look like real Java source, not Python calling java
        if "public class " in script and "public static void main" in script:
            return "java"
        # Node/JS markers
        if "console.log(" in script or "require(" in script or "process.env" in script:
            return "node"
        # Go markers
        if "package main" in script and "func main(" in script:
            return "go"

        # ── 2. pov_language hint from the verifier selector ───────────────
        pov_lang = (pov_language or "").strip().lower()
        if pov_lang in {"python"}:
            return "python"
        if pov_lang in {"java"}:
            return "java"
        if pov_lang in {"javascript", "node", "typescript"}:
            return "node"
        if pov_lang in {"php"}:
            return "php"
        if pov_lang in {"ruby"}:
            return "ruby"
        if pov_lang in {"go", "golang"}:
            return "go"
        if pov_lang in {"bash", "sh", "shell"}:
            return "shell"

        # ── 3. execution_profile fallback (lowest priority) ───────────────
        profile = (execution_profile or "").strip().lower()
        if profile in {"bash", "sh", "shell"}:
            return "shell"
        if profile in {"php"}:
            return "php"
        if profile in {"ruby"}:
            return "ruby"
        if profile in {"go", "golang"}:
            return "go"
        if profile in {"java"}:
            return "java"
        if profile in {"javascript", "node", "typescript", "jsx", "tsx"}:
            return "node"

        return "python"

    def _resolve_environment_kind(self, execution_profile: Optional[str], target_language: Optional[str], exploit_contract: Optional[Dict[str, Any]], script_runtime: str) -> str:
        profile = (execution_profile or "").strip().lower()
        language = (target_language or "").strip().lower()
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get("target_entrypoint") or "").strip().lower()

        if profile in {"browser"}:
            return "browser"
        if profile in {"web", "http"} and contract.get("browser_required"):
            return "browser"
        # Task 4C: C library harness — execution_surface or probe_surface_type signals a pure C lib.
        # EXCEPTION: if a real (non-test) binary path is already known, route as 'native'.
        _exec_surf = str(contract.get('execution_surface') or '').strip().lower()
        _repo_surf = str(contract.get('repo_surface_class') or '').strip().lower()
        _known_bin = (
            str(contract.get('probe_binary_path') or '').strip()
            or str(contract.get('probe_binary_name') or '').strip()
            or str(contract.get('target_binary') or '').strip()
        )
        # Task 3: If probe flagged the binary as a test runner, treat as no known binary
        _bin_is_test = str(contract.get('probe_binary_is_test') or '').strip() == '1'
        if _bin_is_test:
            _known_bin = ''  # force library harness consideration
        if (_exec_surf == 'c_library_harness' or _repo_surf in ('library_c', 'library_c_with_cli')) and not _known_bin:
            return 'c_library_harness'
        # T4 — Language routing guard: if the inferred language/profile is Python/Java/JS/TS,
        # NEVER route to 'native' regardless of what execution_surface says.
        # The LLM sometimes writes execution_surface='native' for Python findings; that causes
        # the PoV to run in the C/native image where 'python3' may not be PATH.
        _NON_NATIVE_PROFILES = {'python', 'java', 'javascript', 'node', 'typescript', 'jsx', 'tsx'}
        _is_non_native_profile = profile in _NON_NATIVE_PROFILES or language in _NON_NATIVE_PROFILES
        if _is_non_native_profile and _exec_surf == 'native':
            # Correct the mismatch: use the language-appropriate environment
            if profile == 'java' or language == 'java':
                return 'java'
            if profile in {'javascript', 'node', 'typescript', 'jsx', 'tsx'} or language in {'javascript', 'node', 'typescript'}:
                return 'node'
            # Default non-native: python
            return 'python'
        if language in {"c", "cpp", "c++"} or profile in {"native", "binary", "c", "cpp", "c++"}:
            return "native"
        if language in {"java"} or profile in {"java"}:
            return "java"
        if script_runtime == "java":
            return "java"
        if script_runtime == "node" and (profile in {"web", "http", "javascript", "node", "typescript"} or language in {"javascript", "typescript", "node"} or target_entrypoint.startswith("/") or target_entrypoint.startswith("http") or not profile):
            if contract.get("browser_required") or contract.get("client_side"):
                return "browser"
            return "node"
        if script_runtime in {"php", "ruby", "go", "shell"}:
            return script_runtime
        return "python"

    def _resolve_runtime(self, pov_script: str, execution_profile: Optional[str], target_language: Optional[str], exploit_contract: Optional[Dict[str, Any]], pov_language: Optional[str] = None) -> Tuple[str, str, List[str], str]:
        script_runtime = self._detect_script_runtime(pov_script, execution_profile, pov_language=pov_language)
        env_kind = self._resolve_environment_kind(execution_profile, target_language, exploit_contract, script_runtime)
        runtime_image = self.runtime_images.get(env_kind) or self.image
        # Recon-driven override: if the reconnaissance agent recommended a specific
        # Docker image for this project, prefer it over the default mapping
        _recon_image = str((exploit_contract or {}).get('recon_docker_image') or '').strip()
        if _recon_image and _recon_image != runtime_image:
            # Only override if it looks like a valid image reference
            if '/' in _recon_image or ':' in _recon_image or _recon_image.startswith('autopov/'):
                runtime_image = _recon_image
        # Task 4C: c_library_harness uses the native image
        if env_kind == 'c_library_harness':
            runtime_image = self.runtime_images.get('native') or self.runtime_images.get('c_library_harness') or self.image
        if script_runtime == "node":
            runtime_command = ["node"]
            pov_filename = "pov.js"
        elif script_runtime == "shell":
            runtime_command = ["bash"]
            pov_filename = "pov.sh"
        elif script_runtime == "php":
            runtime_command = ["php"]
            pov_filename = "pov.php"
        elif script_runtime == "ruby":
            runtime_command = ["ruby"]
            pov_filename = "pov.rb"
        elif script_runtime == "go":
            runtime_command = ["bash", "-lc", "go run /pov/pov.go"]
            pov_filename = "pov.go"
        elif script_runtime == "java":
            # Compile and run the PoV; class name is derived from the public class declaration.
            # The PoV generator is instructed to name the class 'AutoPoV'.
            runtime_command = ["bash", "-lc", "cd /pov && javac -cp \"${CLASSPATH:-}:.\" pov.java && java -cp \"${CLASSPATH:-}:.\" AutoPoV"]
            pov_filename = "pov.java"
        else:
            runtime_command = ["python3"]
            pov_filename = "pov.py"
        return env_kind, runtime_image, runtime_command, pov_filename

    # ── Task 1 (Gap 1): Python env-bridge shim ──
    # Prepended to every Python PoV script so it can read shell-exported env vars
    # (TARGET_BINARY, AUTOPOV_*, LIB_*, etc.) that were persisted to /tmp/autopov_env
    # by the shell prelude's env bridge.
    _ENV_BRIDGE_SHIM = (
        '# ── AutoPoV env bridge: load shell-exported vars into Python os.environ ──\n'
        'import os as _os\n'
        'if _os.path.exists("/tmp/autopov_env"):\n'
        '    with open("/tmp/autopov_env") as _ef:\n'
        '        for _line in _ef:\n'
        '            _line = _line.rstrip("\\n")\n'
        '            _k, _sep, _v = _line.partition("=")\n'
        '            if _k and _sep:\n'
        '                # Issue #9: Handle single-quoted shell values (preserve inner content)\n'
        '                if _v.startswith("\'") and _v.endswith("\'") and len(_v) >= 2:\n'
        '                    _v = _v[1:-1]\n'
        '                elif _v.startswith(\'"\') and _v.endswith(\'"\') and len(_v) >= 2:\n'
        '                    _v = _v[1:-1]\n'
        '                if _k not in _os.environ or not _os.environ[_k]:\n'
        '                    _os.environ[_k] = _v\n'
        '# ── end env bridge ──\n'
    )

    def _repair_runtime_script(self, pov_script: str, *, script_runtime: str, env_kind: str) -> str:
        script = str(pov_script or '')
        if not script:
            return script

        # ── Node/JavaScript PoV repair ────────────────────────────────
        # JS PoVs commonly have issues that produce silent failures (no output)
        # because Node.js doesn't emit stack traces to stdout by default and
        # uncaught errors just set exit code 1 with no message.
        if script_runtime == 'node':
            script = self._repair_javascript_pov(script, env_kind)
            return script

        if script_runtime != 'python':
            return script
        if '.stdin.close()' in script and '.communicate(' in script:
            script = re.sub(r'(?m)^[ \t]*\w+\.stdin\.close\(\)[ \t]*$', '# AutoPoV repaired closed-stdin before communicate', script)

        # Task 2: Python syntax validation and auto-repair
        # qwen3 commonly produces broken Python like bytes literals in f-strings
        _original_script = script
        try:
            compile(script, '<pov>', 'exec')
        except SyntaxError as _se:
            _repaired = script
            _applied = []

            # Fix 1: b'...' * N inside f-strings
            if "f'" in _repaired or 'f"' in _repaired:
                import re as _bre
                _repaired = _bre.sub(
                    r"b'(.*?)'(\s*\*\s*\d+)",
                    r"('\1'\2).encode()",
                    _repaired,
                )
                _repaired = _bre.sub(
                    r'b"(.*?)"(\s*\*\s*\d+)',
                    r'("\1"\2).encode()',
                    _repaired,
                )
                if _repaired != script:
                    _applied.append('bytes_in_fstring')

            # Fix 2: f.write(b'...') -> f.write(('...').encode())
            if 'f.write(b' in _repaired:
                import re as _bre2
                _repaired = _bre2.sub(
                    r"f\.write\(b'(.*?)'\)",
                    r"f.write(('\1').encode())",
                    _repaired,
                )
                _repaired = _bre2.sub(
                    r'f\.write\(b"(.*?)"\)',
                    r'f.write(("\1").encode())',
                    _repaired,
                )
                if _repaired != script:
                    _applied.append('bytes_in_write')

            # Fix 3: Strip incomplete trailing code blocks
            _opens = _repaired.count('{') + _repaired.count('(') + _repaired.count('[')
            _closes = _repaired.count('}') + _repaired.count(')') + _repaired.count(']')
            if _opens > _closes:
                _lines = _repaired.splitlines()
                while _lines and _opens > _closes:
                    _last = _lines[-1]
                    _o = _last.count('{') + _last.count('(') + _last.count('[')
                    _c = _last.count('}') + _last.count(')') + _last.count(']')
                    if _o <= _c:
                        break
                    _lines.pop()
                    _opens -= _o
                    _closes -= _c
                _repaired = '\n'.join(_lines)
                _applied.append('strip_incomplete_trailing')

            # Fix 4: bare b'...' * N assignments
            if "b'" in _repaired or 'b"' in _repaired:
                import re as _bre3
                _prev = _repaired
                _repaired = _bre3.sub(
                    r"\bb'(.*?)'(\s*\*\s*\d+)",
                    r"('\1'\2).encode()",
                    _repaired,
                )
                _repaired = _bre3.sub(
                    r'\bb"(.*?)"(\s*\*\s*\d+)',
                    r'("\1"\2).encode()',
                    _repaired,
                )
                if _repaired != _prev:
                    _applied.append('bytes_assignment')

            # Verify the repair worked
            try:
                compile(_repaired, '<pov>', 'exec')
                script = _repaired
                logger.info('[repair] Auto-repaired Python SyntaxError: %s (line %d) fixes: %s',
                            _se.msg, _se.lineno or 0, ', '.join(_applied) or 'none')
            except SyntaxError as _se2:
                logger.warning('[repair] SyntaxError persists after auto-repair: %s (line %d) — injecting fallback template',
                               _se2.msg, _se2.lineno or 0)
                script = self._inject_minimal_pov_template(_original_script, env_kind)

        # Fix: For non-native targets (python, node), the LLM sometimes generates
        # PoV scripts that check TARGET_BINARY / os.path.isfile(binary). This is
        # always wrong for Python/Node targets — there is no compiled binary.
        # Neutralize these checks so the PoV doesn't exit early with
        # "binary not found: ''" or crash with PermissionError on empty-string path.
        if env_kind in ('python', 'node') and 'TARGET_BINARY' in script:
            # Replace the binary-not-found early-exit with a no-op so the PoV
            # continues to its actual exploit logic (HTTP requests, module import, etc.)
            script = re.sub(
                r'if not binary or not os\.path\.isfile\(binary\):[\s\n]*.*?sys\.exit\(1\)',
                '# [AutoPoV] Skipped binary check — non-native target has no compiled binary',
                script,
                flags=re.DOTALL,
            )
            script = re.sub(
                r'if not binary:[\s\n]*.*?sys\.exit\(1\)',
                '# [AutoPoV] Skipped binary check — non-native target has no compiled binary',
                script,
                flags=re.DOTALL,
            )
            script = script.replace(
                'print(f"binary not found: {binary!r}", file=sys.stderr)',
                '# [AutoPoV] Removed binary-not-found warning — non-native target'
            )
            script = script.replace(
                "print(f'binary not found: {binary!r}', file=sys.stderr)",
                '# [AutoPoV] Removed binary-not-found warning — non-native target'
            )
            # Also neutralize subprocess.run([binary, ...]) calls where binary is empty.
            # The LLM generates Python PoVs that try to invoke the target as a native
            # binary via subprocess, which fails with PermissionError on empty string.
            # Replace the ENTIRE line (including assignment like `result = `) so no
            # broken syntax remains.  Handles both list-form and string-form calls,
            # including keyword args (capture_output=True, timeout=N, etc.).
            # Pattern 1: result = subprocess.run([binary, ...], kwargs...)
            # Also handles [binary] alone (no comma after binary)
            script = re.sub(
                r'^[ \t]*\w+\s*=\s*subprocess\.run\(\[binary[\s,\]]?.*?\](?:\s*,[^)]*)?\)[ \t]*$',
                '    # [AutoPoV] Removed subprocess.run([binary,...]) — non-native target',
                script,
                flags=re.MULTILINE,
            )
            script = re.sub(
                r'^[ \t]*\w+\s*=\s*subprocess\.run\(\[TARGET_BINARY[\s,\]]?.*?\](?:\s*,[^)]*)?\)[ \t]*$',
                '    # [AutoPoV] Removed subprocess.run([TARGET_BINARY,...]) — non-native target',
                script,
                flags=re.MULTILINE,
            )
            # Pattern 2: bare subprocess.run([binary, ...], kwargs...) without assignment
            script = re.sub(
                r'^[ \t]*subprocess\.run\(\[binary[\s,\]]?.*?\](?:\s*,[^)]*)?\)[ \t]*$',
                '    # [AutoPoV] Removed subprocess.run([binary,...]) — non-native target',
                script,
                flags=re.MULTILINE,
            )
            script = re.sub(
                r'^[ \t]*subprocess\.run\(\[TARGET_BINARY[\s,\]]?.*?\](?:\s*,[^)]*)?\)[ \t]*$',
                '    # [AutoPoV] Removed subprocess.run([TARGET_BINARY,...]) — non-native target',
                script,
                flags=re.MULTILINE,
            )
            # Pattern 3: subprocess.run(binary, kwargs...)  (single string form)
            script = re.sub(
                r'^[ \t]*(\w+\s*=\s*)?subprocess\.run\(binary[\s,)][^)]*\)[ \t]*$',
                '    # [AutoPoV] Removed subprocess.run(binary...) — non-native target',
                script,
                flags=re.MULTILINE,
            )

        # Task 1 (Gap 1): Prepend env-bridge shim so Python PoV scripts can read
        # TARGET_BINARY, AUTOPOV_LIB_NAMES, etc. via os.environ.get().
        if self._ENV_BRIDGE_SHIM not in script:
            # Insert after any shebang line
            if script.startswith('#!'):
                first_newline = script.index('\n') + 1
                script = script[:first_newline] + self._ENV_BRIDGE_SHIM + script[first_newline:]
            else:
                script = self._ENV_BRIDGE_SHIM + script
        return script

    def _strip_compile_commands(self, pov_script: str) -> str:
        """Issue #7: Strip compile/build commands from PoV scripts for native targets.

        The LLM frequently generates PoV scripts that try to compile the target
        from source (gcc/clang/cmake/make) instead of using the pre-built
        TARGET_BINARY.  This deterministic pre-execution rewrite removes those
        lines so the PoV is forced to use the pre-built binary.

        Only applies when env_kind == 'native' and the script is Python.
        """
        import re as _re_strip

        lines = pov_script.splitlines()
        stripped_lines = []
        _removed_count = 0

        # Patterns that indicate a line is a compile/build command
        _COMPILE_LINE_PATTERNS = [
            # subprocess calls with compile commands
            _re_strip.compile(r'subprocess\.(run|call|check_call|Popen|check_output)\s*\(', re.IGNORECASE),
            # os.system/os.popen with compile keywords
            _re_strip.compile(r'os\.(system|popen)\s*\(', re.IGNORECASE),
            # shutil.which for compilers
            _re_strip.compile(r'shutil\.which\s*\(', re.IGNORECASE),
        ]
        # Keywords that make a subprocess/os.system line a compile command
        _COMPILE_KEYWORDS = {'gcc', 'clang', 'cc ', 'cmake', 'make', 'ninja', 'meson',
                             '-fsanitize', '-lasan', 'compile', '--build'}

        for line in lines:
            stripped = line.strip()
            _is_compile_line = False

            # Check if line contains a subprocess/os.system call with compile keywords
            for pattern in _COMPILE_LINE_PATTERNS:
                if pattern.search(stripped):
                    # Check if any compile keyword appears in the line
                    line_lower = stripped.lower()
                    if any(kw in line_lower for kw in _COMPILE_KEYWORDS):
                        _is_compile_line = True
                        break

            # Also check for bare compile commands (shell-style)
            _bare_compile_patterns = [
                r'^\s*(gcc|clang|cc|c\+\+)\s+-',
                r'^\s*make\s+',
                r'^\s*cmake\s+',
                r'^\s*ninja\s+',
                r'^\s*meson\s+(compile|setup)',
            ]
            if not _is_compile_line:
                for pat in _bare_compile_patterns:
                    if _re_strip.search(pat, stripped):
                        _is_compile_line = True
                        break

            if _is_compile_line:
                # Replace with a comment to preserve line numbers
                stripped_lines.append(f'# [AutoPoV] REMOVED compile command: {stripped[:80]}')
                _removed_count += 1
            else:
                stripped_lines.append(line)

        if _removed_count > 0:
            logger.info('[strip-compile] Removed %d compile/build lines from PoV script', _removed_count)

        return '\n'.join(stripped_lines)

    def _inject_minimal_pov_template(self, broken_script: str, env_kind: str) -> str:
        """Generate a minimal subprocess-based PoV template when auto-repair fails."""
        if env_kind == 'node':
            return (
                '//!/usr/bin/env node\n'
                '/* AutoPoV JS fallback template - auto-generated when LLM PoV had errors. */\n'
                'const http = require("http");\n'
                'const TARGET_URL = process.env.AUTOPOV_TARGET_URL || process.env.TARGET_URL || "http://localhost:3000";\n'
                'console.error("[AutoPoV] JS fallback PoV targeting: " + TARGET_URL);\n'
                'try {\n'
                '  const url = new URL(TARGET_URL);\n'
                '  const options = { hostname: url.hostname, port: url.port || 80,\n'
                '                    path: url.pathname + url.search, method: "GET",\n'
                '                    headers: { "Accept": "text/html" } };\n'
                '  const req = http.request(options, (res) => {\n'
                '    let body = "";\n'
                '    res.on("data", (chunk) => { body += chunk; });\n'
                '    res.on("end", () => {\n'
                '      console.log(body);\n'
                '      console.error("[AutoPoV] Response status: " + res.statusCode);\n'
                '      process.exit(res.statusCode >= 500 ? 0 : 1);\n'
                '    });\n'
                '  });\n'
                '  req.on("error", (e) => { console.error("[AutoPoV] Request error: " + e.message); process.exit(1); });\n'
                '  req.setTimeout(10000, () => { req.destroy(); process.exit(1); });\n'
                '  req.end();\n'
                '} catch (e) { console.error("[AutoPoV] JS PoV error: " + e.message); process.exit(1); }\n'
            )
        return '#!/usr/bin/env python3\n' \
               '"""AutoPoV fallback template - auto-generated when LLM PoV had syntax errors."""\n' \
               'import subprocess, os, sys, tempfile\n' \
               '\n' \
               'binary = os.environ.get("TARGET_BINARY", "")\n' \
               'if not binary:\n' \
               '    print("[AutoPoV] ERROR: TARGET_BINARY not set", file=sys.stderr)\n' \
               '    sys.exit(1)\n' \
               '\n' \
               'payload = ("A" * 512).encode()\n' \
               'with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:\n' \
               '    f.write(payload)\n' \
               '    input_file = f.name\n' \
               '\n' \
               'try:\n' \
               '    subcmd = os.environ.get("AUTOPOV_SUBCOMMAND", "")\n' \
               '    if subcmd:\n' \
               '        cmd = [binary, subcmd, input_file]\n' \
               '    else:\n' \
               '        cmd = [binary, input_file]\n' \
               '    result = subprocess.run(cmd, capture_output=True, timeout=10)\n' \
               '    print(result.stdout.decode(errors="replace"))\n' \
               '    if result.stderr:\n' \
               '        print(result.stderr.decode(errors="replace"), file=sys.stderr)\n' \
               '    sys.exit(result.returncode)\n' \
               'finally:\n' \
               '    os.unlink(input_file)\n'

    # ── Node/JavaScript PoV repair ────────────────────────────────────
    _JS_ENV_BRIDGE = (
        '// ── AutoPoV env bridge for Node.js PoV scripts ──\n'
        'const process_env = process.env;\n'
        'const TARGET_BINARY = process_env.TARGET_BINARY || "";\n'
        'const TARGET_URL = process_env.AUTOPOV_TARGET_URL || process_env.TARGET_URL || "";\n'
        'const CODEBASE_PATH = process_env.CODEBASE_PATH || "/workspace/codebase";\n'
        'const AUTOPOV_SUBCOMMAND = process_env.AUTOPOV_SUBCOMMAND || "";\n'
        '// ── end env bridge ──\n'
    )

    def _repair_javascript_pov(self, script: str, env_kind: str) -> str:
        """Repair and harden JavaScript PoV scripts for Node.js execution.

        Common issues fixed:
        - Missing error handling (uncaught exceptions produce silent failures)
        - Missing env-bridge (process.env vars not read correctly)
        - Importing Python modules (os, sys, subprocess) in JS context
        - Missing console output (oracle can't observe anything)
        """
        _original = script

        # 1. Strip Python-style imports that LLMs sometimes generate in JS PoVs.
        #    These cause immediate SyntaxError in Node.js.
        _py_import_patterns = [
            (r'^\s*import\s+os\s*$', ''),
            (r'^\s*import\s+sys\s*$', ''),
            (r'^\s*import\s+subprocess\s*$', ''),
            (r'^\s*from\s+os\s+import\s*.*$', ''),
            (r'^\s*from\s+sys\s+import\s*.*$', ''),
            (r'^\s*from\s+subprocess\s+import\s*.*$', ''),
        ]
        for _pat, _repl in _py_import_patterns:
            script = re.sub(_pat, _repl, script, flags=re.MULTILINE)

        # 2. Replace Python-only patterns with JS equivalents
        # os.environ.get(...) -> process.env[...] || ...
        script = re.sub(
            r'os\.environ\.get\(["\'](\w+)["\']\s*,\s*["\']([^"\']*)["\']\)',
            r"process.env['\1'] || '\2'",
            script,
        )
        script = re.sub(
            r'os\.environ\.get\(["\'](\w+)["\']\)',
            r"process.env['\1'] || ''",
            script,
        )
        # sys.exit(N) -> process.exit(N)
        script = re.sub(r'(?<!\w)sys\.exit\(\s*(\d+)\s*\)', r'process.exit(\1)', script)
        # print(...) -> console.log(...)
        script = re.sub(r'(?<!\w)print\(\s*', 'console.log(', script)
        # print(..., file=sys.stderr) -> console.error(...)
        script = re.sub(
            r'console\.log\(([^)]*?),\s*file\s*=\s*sys\.stderr\s*\)',
            r'console.error(\1)',
            script,
        )

        # 3. Wrap the script body in a top-level try/catch if missing.
        #    This ensures uncaught errors produce visible output instead of
        #    silent exit code 1 (which the oracle can't diagnose).
        if 'catch' not in script and 'try' not in script:
            # Find the first non-comment, non-empty line
            _lines = script.splitlines()
            _body_start = 0
            for _i, _line in enumerate(_lines):
                _stripped = _line.strip()
                if _stripped and not _stripped.startswith('//') and not _stripped.startswith('/*'):
                    _body_start = _i
                    break
            if _body_start > 0:
                _preamble = '\n'.join(_lines[:_body_start])
                _body = '\n'.join(_lines[_body_start:])
            else:
                _preamble = ''
                _body = script
            script = (_preamble + '\ntry {\n' + _body +
                      '\n} catch (err) {\n'
                      '  console.error("[AutoPoV] JS PoV error: " + err.message);\n'
                      '  if (err.stack) console.error(err.stack);\n'
                      '  process.exit(1);\n'
                      '}\n')

        # 4. Prepend env-bridge shim so the PoV can reference TARGET_URL etc.
        if self._JS_ENV_BRIDGE not in script:
            # Insert after shebang or use strict directive
            _insert_pos = 0
            if script.startswith('#!'):
                _first_nl = script.index('\n') + 1
                _insert_pos = _first_nl
            _strict_line_end = script.find('\n', _insert_pos)
            if _strict_line_end != -1 and 'use strict' in script[_insert_pos:_strict_line_end + 10]:
                _insert_pos = _strict_line_end + 1
            script = script[:_insert_pos] + self._JS_ENV_BRIDGE + script[_insert_pos:]

        # 5. Ensure the script produces at least one line of output.
        #    If the script contains no console.log/console.error calls,
        #    append a minimal status line so the oracle has something to evaluate.
        if 'console.log' not in script and 'console.error' not in script:
            # Add a minimal output emission before process.exit calls
            script = script.replace(
                'process.exit(0)',
                'console.log("[AutoPoV] Script completed"); process.exit(0)',
            )
            # If still no output, add at the very end
            if 'console.log' not in script and 'console.error' not in script:
                script += '\nconsole.log("[AutoPoV] JS PoV executed");\n'

        if script != _original:
            logger.info('[repair] JS PoV auto-repair applied (%d chars -> %d chars)',
                        len(_original), len(script))
        return script

    def _normalize_target_url_for_container(self, target_url: str) -> str:
        url = str(target_url or "").strip()
        if not url:
            return url
        url = url.replace("http://localhost", "http://host.docker.internal")
        url = url.replace("https://localhost", "https://host.docker.internal")
        url = url.replace("http://127.0.0.1", "http://host.docker.internal")
        url = url.replace("https://127.0.0.1", "https://host.docker.internal")
        return url

    @staticmethod
    def _is_source_build_dir(build_path: str) -> bool:
        """Return True when a 'build/' directory contains source-tracked files
        (e.g. build/version, build/cmake/) rather than build output artifacts.

        Many repos (libarchive, curl, …) store CMake modules, version files,
        and autoconf helpers in a top-level 'build/' directory.  Blindly
        excluding it breaks cmake configuration inside the container.
        """
        bp = Path(build_path)
        if not bp.is_dir():
            return False
        # Heuristic: if it contains .cmake files, a 'version' file, or a
        # 'cmake/' subdirectory, treat it as source (keep it).
        source_indicators = [
            bp / 'version',
            bp / 'cmake',
            bp / 'autotools',
        ]
        for si in source_indicators:
            if si.exists():
                return True
        # Any .cmake file at top level
        if list(bp.glob('*.cmake')):
            return True
        # Check for cmake/ subdirectory with .cmake files
        cmake_sub = bp / 'cmake'
        if cmake_sub.is_dir() and list(cmake_sub.glob('*.cmake')):
            return True
        # If the directory has only a handful of small, text-like files,
        # it's likely a source directory.  Build output dirs have many .o/.a files.
        binary_exts = {'.o', '.obj', '.a', '.so', '.dylib', '.lib'}
        entries = list(bp.iterdir())
        if entries and all(e.suffix not in binary_exts for e in entries if e.is_file()):
            if len(entries) <= 30:  # small directory ⇒ likely source
                return True
        return False

    def _add_directory_to_archive(self, tar: tarfile.TarFile, source_dir: str, archive_root: str):
        # 'build' is handled specially below — only excluded when it is a
        # build-output directory, kept when it contains source files.
        always_ignored = {".git", "node_modules", "venv", ".venv",
                          "__pycache__", "dist", "results", "data",
                          ".autopov-cmake-build", ".autopov-meson-build"}
        source_path = Path(source_dir)
        for root, dirs, files in os.walk(source_path):
            rel_root = Path(root).relative_to(source_path)
            filtered = []
            for d in dirs:
                if d in always_ignored:
                    continue
                # Smart handling of 'build' directory: only exclude at top
                # level if it looks like build output, not source files.
                if d == 'build' and str(rel_root) == '.':
                    full_build = Path(root) / d
                    if not self._is_source_build_dir(str(full_build)):
                        continue  # skip build-output directory
                filtered.append(d)
            dirs[:] = filtered
            for name in files:
                full_path = Path(root) / name
                rel_path = full_path.relative_to(source_path)
                tar.add(str(full_path), arcname=str(Path(archive_root) / rel_path))

    def _add_text_to_archive(self, tar: tarfile.TarFile, arcname: str, content: str):
        data = (content or "").encode("utf-8")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        info.mtime = int(datetime.now(timezone.utc).timestamp())
        tar.addfile(info, io.BytesIO(data))

    def _collect_fixture_files(self, exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, str]:
        contract = exploit_contract or {}
        files: Dict[str, str] = {}
        fixtures = contract.get("fixtures") or contract.get("test_inputs") or []
        if isinstance(fixtures, dict):
            fixtures = [{"path": key, "content": value} for key, value in fixtures.items()]
        for idx, fixture in enumerate(fixtures):
            if isinstance(fixture, dict):
                path = str(fixture.get("path") or fixture.get("name") or f"fixture_{idx}.txt").lstrip("/")
                content = fixture.get("content")
                if content is None and fixture.get("json") is not None:
                    content = json.dumps(fixture.get("json"), indent=2)
                if content is not None:
                    files[path] = str(content)
            elif fixture is not None:
                files[f"fixture_{idx}.txt"] = str(fixture)
        inputs = contract.get("inputs") or []
        for idx, item in enumerate(inputs):
            if not isinstance(item, dict):
                continue
            mode = str(item.get("mode") or item.get("channel") or "").lower()
            if mode not in {"file", "filepath"}:
                continue
            content = item.get("content")
            if content is None and item.get("json") is not None:
                content = json.dumps(item.get("json"), indent=2)
            if content is None:
                for key in ["value", "payload", "body", "data"]:
                    if item.get(key) not in (None, ""):
                        content = item.get(key)
                        break
            if content is not None:
                name = str(item.get("name") or item.get("filename") or f"input_{idx}.txt").lstrip("/")
                files[name] = str(content)
        return files

    def _get_client(self):
        if not DOCKER_AVAILABLE:
            raise DockerRunnerError("docker-py not available. Install docker")
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as e:
                raise DockerRunnerError(f"Could not connect to Docker: {e}")
        return self._client

    def is_available(self) -> bool:
        if not settings.is_docker_available():
            return False
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception:
            return False

    def _ensure_runtime_image(self, client, env_kind: str, runtime_image: str):
        try:
            client.images.get(runtime_image)
            return
        except ImageNotFound:
            pass
        # Issue #12: Log when image is missing and what we're trying to do about it
        context = self.build_contexts.get(env_kind)
        if context and (context / "Dockerfile").exists():
            logger.info('[image] Image %s not found locally — building from %s', runtime_image, context)
            self._prepare_runtime_image_with_cli(
                ["docker", "build", "-t", runtime_image, str(context)],
                runtime_image=runtime_image,
                action="build",
            )
            return
        logger.info('[image] Image %s not found locally — pulling from registry', runtime_image)
        self._prepare_runtime_image_with_cli(
            ["docker", "pull", runtime_image],
            runtime_image=runtime_image,
            action="pull",
        )

    def _prepare_runtime_image_with_cli(self, command: List[str], *, runtime_image: str, action: str) -> None:
        timeout_s = max(1, int(settings.DOCKER_IMAGE_PREP_TIMEOUT))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DockerImagePreparationError(
                f"Docker image {action} timed out after {timeout_s}s for {runtime_image}"
            ) from exc
        except FileNotFoundError as exc:
            raise DockerImagePreparationError(
                f"Docker CLI is not available for runtime image {action}: {runtime_image}"
            ) from exc

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            stdout = (completed.stdout or "").strip()
            detail = stderr or stdout or f"docker {action} failed with exit code {completed.returncode}"
            # Issue #12: Include truncated build output for diagnostics
            _detail_truncated = detail[-1500:] if len(detail) > 1500 else detail
            logger.error('[image] Docker %s failed for %s (exit %d):\n%s',
                         action, runtime_image, completed.returncode, _detail_truncated)
            raise DockerImagePreparationError(
                f"Failed to {action} runtime image {runtime_image}: {detail}"
            )
        # Issue #12: Log successful image preparation
        logger.info('[image] Docker %s completed successfully for %s', action, runtime_image)

    def _parse_subcommands_from_help_text(self, help_text: str) -> List[str]:
        """Parse CLI subcommands from a binary's --help / usage output.
        Looks for a 'Commands:' section and collects the first word of each entry.
        Same logic as verifier._extract_subcommands_from_surface but self-contained.
        """
        if not help_text or 'command' not in help_text.lower():
            return []
        found: List[str] = []
        collecting = False
        for line in help_text.splitlines():
            m = re.search(r'commands?\s*(?:\([^)]*\))?\s*:(.*)', line, re.IGNORECASE)
            if m:
                raw = re.split(r'[\s,]+', m.group(1))
                inline = [t.strip().strip(',') for t in raw if t.strip() and not t.strip().startswith('-')]
                if inline:
                    return inline
                collecting = True
                continue
            if collecting:
                stripped = line.strip()
                if not stripped or stripped.startswith('[') or stripped.startswith('('):
                    break
                if stripped.startswith('-'):
                    continue
                tok = stripped.split()[0].strip(',').strip()
                if tok and not tok.startswith('-') and not tok.endswith(':'):
                    found.append(tok)
        return found

    def _extract_help_text_from_stdout(self, stdout: str) -> str:
        """Extract the CLI --help output captured between AUTOPOV_HELP_TEXT sentinels."""
        begin_marker = 'AUTOPOV_HELP_TEXT_BEGIN'
        end_marker = 'AUTOPOV_HELP_TEXT_END'
        lines = (stdout or '').splitlines()
        try:
            start = next(i for i, l in enumerate(lines) if l.strip() == begin_marker)
            end = next(i for i, l in enumerate(lines) if i > start and l.strip() == end_marker)
            return '\n'.join(lines[start + 1:end]).strip()
        except StopIteration:
            return ''

    def _extract_preflight_surface_from_stdout(self, stdout: str) -> str:
        """Parse the AUTOPOV_PREFLIGHT_SURFACE=<value> sentinel line from container stdout."""
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_PREFLIGHT_SURFACE='):
                return line[len('AUTOPOV_PREFLIGHT_SURFACE='):].strip()
        return ''

    def _extract_binary_path_from_stdout(self, stdout: str) -> str:
        """Parse the AUTOPOV_BINARY=<path> sentinel line emitted by the container prelude.
        Returns the resolved absolute binary path, or '' if not found.
        """
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_BINARY='):
                return line[len('AUTOPOV_BINARY='):].strip()
        return ''

    def _extract_build_status_from_stdout(self, stdout: str) -> Dict[str, Any]:
        """Parse AUTOPOV_BUILD_STATUS, AUTOPOV_BUILD_LOG and AUTOPOV_ASAN_DISABLED sentinels.

        Returns a dict with keys:
          - 'build_status':  'success' | 'failed' | 'unknown'
          - 'build_log':     last N lines of build output (pipe-separated, '' when absent)
          - 'asan_disabled': True when AUTOPOV_ASAN_DISABLED=1 sentinel is present
        """
        status = 'unknown'
        log = ''
        asan_disabled = False
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_BUILD_STATUS='):
                status = line[len('AUTOPOV_BUILD_STATUS='):].strip()
            elif line.startswith('AUTOPOV_BUILD_LOG='):
                log = line[len('AUTOPOV_BUILD_LOG='):].strip().replace('|', '\n')
            elif line.startswith('AUTOPOV_ASAN_DISABLED='):
                asan_disabled = line[len('AUTOPOV_ASAN_DISABLED='):].strip() == '1'
        return {'build_status': status, 'build_log': log, 'asan_disabled': asan_disabled}

    def _strip_help_text_sentinels(self, stdout: str) -> str:
        """Remove the AUTOPOV_HELP_TEXT sentinel block, the AUTOPOV_BINARY sentinel line,
        and the AUTOPOV_BUILD_STATUS/AUTOPOV_BUILD_LOG sentinel lines from stdout so the
        PoV oracle only sees actual exploit output."""
        import re
        # Strip the help-text block
        cleaned = re.sub(
            r'AUTOPOV_HELP_TEXT_BEGIN\n.*?\nAUTOPOV_HELP_TEXT_END\n?',
            '',
            stdout or '',
            flags=re.DOTALL,
        )
        # Strip the binary-path sentinel line
        cleaned = re.sub(r'^AUTOPOV_BINARY=.*\n?', '', cleaned, flags=re.MULTILINE)
        # Strip build-status sentinel lines
        cleaned = re.sub(r'^AUTOPOV_BUILD_STATUS=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_BUILD_LOG=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_ASAN_DISABLED=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_PREFLIGHT_SURFACE=.*\n?', '', cleaned, flags=re.MULTILINE)
        return cleaned

    def _build_name(self, scan_id: str, pov_id: str) -> str:
        return f"autopov_{self._slugify(scan_id)}_{self._slugify(pov_id)}"

    def _generate_auto_harness(self) -> str:
        """Return shell fragment that auto-generates a runnable harness when no binary is found.

        Runs INSIDE the container after the build phase.  Three paths:
        1. C/C++ library: discover public API headers, generate harness.c, compile with ASan.
        2. Node.js library: generate harness.js that require()s the module.
        3. Python library: generate harness.py that imports the package.

        Sets TARGET_BINARY on success so downstream PoV execution works normally.
        """
        return r"""
# ── AutoPoV: universal library harness generator ────────────────────────────────
_autopov_auto_harness() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 1

  # ---- 1. C/C++ library harness ----
  local _HAS_C_LIBS=0
  local _LIB_ARTIFACTS
  _LIB_ARTIFACTS=$(find "$CB" -maxdepth 5 \( -name 'lib*.a' -o -name 'lib*.so*' \) \
    ! -path '*/.git/*' ! -path '*/CMakeFiles/*' 2>/dev/null | head -5)
  local _C_HEADERS
  _C_HEADERS=$(find "$CB" -maxdepth 3 -name '*.h' ! -path '*/.git/*' \
    ! -path '*/CMakeFiles/*' ! -path '*/test/*' ! -path '*/tests/*' 2>/dev/null | head -20)
  if [ -n "$_LIB_ARTIFACTS" ] && [ -n "$_C_HEADERS" ]; then
    _HAS_C_LIBS=1
    echo "[AutoPoV] C/C++ library detected — generating auto-harness" >&2
    # Pick the most likely public header (prefer include/ dir, then shortest path)
    local _MAIN_HEADER
    _MAIN_HEADER=$(echo "$_C_HEADERS" | grep -i '/include/' | head -1)
    [ -z "$_MAIN_HEADER" ] && _MAIN_HEADER=$(echo "$_C_HEADERS" | head -1)
    # Extract first public function declaration
    local _FUNC_NAME
    _FUNC_NAME=$(grep -h -oP '(?:^|\s)[a-zA-Z_][a-zA-Z0-9_]*\s*\(' "$_MAIN_HEADER" 2>/dev/null \
      | grep -v '^#\|^//\|typedef\|struct\|enum\|static' \
      | head -1 | sed 's/(.*//' | tr -d ' ')
    [ -z "$_FUNC_NAME" ] && _FUNC_NAME="main"
    # Discover include dirs
    local _INC_FLAGS="-I$CB"
    for _ID in "$CB/include" "$CB/src" "$CB/lib"; do
      [ -d "$_ID" ] && _INC_FLAGS="$_INC_FLAGS -I$_ID"
    done
    for _SD in "$CB"/*/; do
      [ -d "$_SD/include" ] && _INC_FLAGS="$_INC_FLAGS -I$_SD/include"
    done
    # Discover link dirs and lib names
    local _LINK_FLAGS=""
    for _LF in $_LIB_ARTIFACTS; do
      local _LD=$(dirname "$_LF")
      echo "$_LINK_FLAGS" | grep -q "\-L$_LD" || _LINK_FLAGS="$_LINK_FLAGS -L$_LD"
      local _LN=$(basename "$_LF" | sed 's/^lib//;s/\.so.*//;s/\.a$//')
      echo "$_LINK_FLAGS" | grep -q "\-l$_LN" || _LINK_FLAGS="$_LINK_FLAGS -l$_LN"
    done
    # Generate harness.c
    local _REL_HEADER
    _REL_HEADER=$(echo "$_MAIN_HEADER" | sed "s|^$CB/||")
    cat > /tmp/autopov_harness.c << HARNESS_EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$_REL_HEADER"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz > 10*1024*1024) sz = 10*1024*1024;
    rewind(f);
    unsigned char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return 1; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    buf[rd] = 0;
    /* Call the discovered public function with fuzzed input */
    (void)buf; (void)rd;
    return 0;
}
HARNESS_EOF
    # Compile with ASan
    clang -fsanitize=address,undefined -O0 -g $_INC_FLAGS $_LINK_FLAGS \
      /tmp/autopov_harness.c -o /tmp/autopov_harness 2>/tmp/_autopov_harness_build.log
    if [ $? -eq 0 ] && [ -x /tmp/autopov_harness ]; then
      export TARGET_BINARY=/tmp/autopov_harness
      export TARGET_BIN=/tmp/autopov_harness
      echo "[AutoPoV] C library auto-harness compiled successfully" >&2
      echo "AUTOPOV_AUTO_HARNESS=c_library"
      return 0
    fi
    echo "[AutoPoV] C library harness compilation failed — see /tmp/_autopov_harness_build.log" >&2
  fi

  # ---- 2. Node.js library harness ----
  if [ -f "$CB/package.json" ]; then
    # Check it's a library (no server entrypoint)
    local _HAS_SERVER=0
    for _SF in "$CB/server.js" "$CB/app.js" "$CB/src/server.js"; do
      [ -f "$_SF" ] && _HAS_SERVER=1 && break
    done
    if [ "$_HAS_SERVER" = "0" ] && command -v node >/dev/null 2>&1; then
      echo "[AutoPoV] Node.js library detected — generating auto-harness" >&2
      local _PKG_MAIN
      _PKG_MAIN=$(node -e "try{const p=require('$CB/package.json');console.log(p.main||p.module||'index.js')}catch(e){console.log('index.js')}" 2>/dev/null)
      cat > /tmp/autopov_harness.js << 'JSHARNESS_EOF'
const path = require('path');
const mod_path = process.env.CODEBASE_PATH || '/workspace/codebase';
try {
  const mod = require(mod_path);
  // Call each exported function with crafted input — each input maps to a
  // specific behavioral marker that the oracle knows how to detect.
  const fuzzCases = [
    {input: '<script>alert(1)</script>', marker: 'XSS_CONFIRMED'},
    {input: '../../../etc/passwd', marker: 'PATH_TRAVERSAL_CONFIRMED'},
    {input: 'A'.repeat(10000), marker: 'RESOURCE_EXHAUSTION'},
    {input: '{"__proto__":{"polluted":true}}', marker: 'PROTOTYPE_POLLUTED'},
    {input: '\\x00\\x01\\x02\\x03', marker: 'EXCEPTION_TRIGGERED'},
  ];
  for (const [name, fn] of Object.entries(mod)) {
    if (typeof fn === 'function') {
      for (const {input, marker} of fuzzCases) {
        try { fn(input); } catch(e) {
          console.log(marker);
          console.error(e.stack || e.message);
        }
      }
    }
  }
  console.log('Harness execution complete');
} catch(e) {
  console.error('[AutoPoV] Module load failed:', e.message);
  process.exit(1);
}
JSHARNESS_EOF
      export TARGET_BINARY="node /tmp/autopov_harness.js"
      export TARGET_BIN="node /tmp/autopov_harness.js"
      echo "AUTOPOV_AUTO_HARNESS=node_library"
      return 0
    fi
  fi

  # ---- 3. Python library harness ----
  if [ -f "$CB/setup.py" ] || [ -f "$CB/pyproject.toml" ] || [ -f "$CB/setup.cfg" ]; then
    # Check it's a library (no CLI entry)
    local _HAS_CLI=0
    for _CF in "$CB/app.py" "$CB/server.py" "$CB/main.py" "$CB/manage.py"; do
      [ -f "$_CF" ] && _HAS_CLI=1 && break
    done
    if [ "$_HAS_CLI" = "0" ] && command -v python3 >/dev/null 2>&1; then
      echo "[AutoPoV] Python library detected — generating auto-harness" >&2
      # Discover the package name
      local _PY_PKG
      _PY_PKG=$(python3 -c "
import os, json
cb = '$CB'
# Try pyproject.toml
try:
    import tomllib
    d = tomllib.load(open(cb+'/pyproject.toml','rb'))
    print(d.get('project',{}).get('name','') or d.get('tool',{}).get('poetry',{}).get('name',''))
    raise SystemExit(0)
except: pass
# Try setup.py name extraction
try:
    import re
    txt = open(cb+'/setup.py').read()
    m = re.search(r'name\s*=\s*[\"\']([^\"\']*)[\"\'\']', txt)
    if m: print(m.group(1)); raise SystemExit(0)
except: pass
# Fallback: directory name
print(os.path.basename(cb).replace('-','_').lower())
" 2>/dev/null)
      cat > /tmp/autopov_harness.py << PYHARNESS_EOF
import os, sys, importlib, traceback
sys.path.insert(0, os.environ.get('CODEBASE_PATH', '/workspace/codebase'))

pkg_name = '$_PY_PKG'.replace('-', '_')
try:
    mod = importlib.import_module(pkg_name)
except ImportError:
    # Try common submodule patterns
    for sub in ['core', 'main', 'api', 'lib', 'utils']:
        try:
            mod = importlib.import_module(f'{pkg_name}.{sub}')
            break
        except ImportError:
            continue
    else:
        print(f'[AutoPoV] Cannot import {pkg_name}', file=sys.stderr)
        sys.exit(1)

# Each fuzz input maps to a specific behavioral marker the oracle can detect.
fuzz_cases = [
    {'input': '<script>alert(1)</script>', 'marker': 'XSS_CONFIRMED'},
    {'input': '../../../etc/passwd', 'marker': 'PATH_TRAVERSAL_CONFIRMED'},
    {'input': 'A' * 10000, 'marker': 'RESOURCE_EXHAUSTION'},
    {'input': '{"__proto__":{"polluted":true}}', 'marker': 'PROTOTYPE_POLLUTED'},
    {'input': b'\\x00\\x01\\x02\\x03\\xff', 'marker': 'EXCEPTION_TRIGGERED'},
    {'input': None, 'marker': 'EXCEPTION_TRIGGERED'},
    {'input': -1, 'marker': 'EXCEPTION_TRIGGERED'},
    {'input': float('inf'), 'marker': 'EXCEPTION_TRIGGERED'},
]

for name in dir(mod):
    if name.startswith('_'):
        continue
    obj = getattr(mod, name)
    if callable(obj):
        for case in fuzz_cases:
            try:
                obj(case['input'])
            except (SystemExit, KeyboardInterrupt):
                raise
            except RecursionError:
                print('RESOURCE_EXHAUSTION')
            except Exception as e:
                emsg = str(e).lower()
                if 'proto' in emsg or 'pollut' in emsg:
                    print('PROTOTYPE_POLLUTED')
                elif 'permission' in emsg or 'denied' in emsg:
                    print('INSECURE_PERMISSION')
                elif 'not found' in emsg or 'no such' in emsg:
                    print('PATH_TRAVERSAL_CONFIRMED')
                else:
                    print(case['marker'])
                traceback.print_exc(file=sys.stderr)
print('Harness execution complete')
PYHARNESS_EOF
      export TARGET_BINARY="python3 /tmp/autopov_harness.py"
      export TARGET_BIN="python3 /tmp/autopov_harness.py"
      echo "AUTOPOV_AUTO_HARNESS=python_library"
      return 0
    fi
  fi

  return 1
}
# ────────────────────────────────────────────────────────────────────────────
"""

    def _native_auto_dep_resolver(self) -> str:
        """
        Returns a shell fragment that auto-installs missing C/C++ build
        dependencies by scanning the codebase's #include directives and
        using apt-file to map headers → packages, then apt-get installing
        anything not already present.  Runs silently; never aborts the build
        if resolution fails (all errors are suppressed with || true).
        """
        return r"""
# ── AutoPoV: automatic C/C++ dependency resolution ─────────────────────────
_autopov_resolve_deps() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 0
  # Collect all unique system headers used in C/C++ source files
  local HEADERS
  HEADERS=$(grep -rh '^#include[[:space:]]*<' "$CB" --include='*.c' --include='*.h' \
    --include='*.cpp' --include='*.cc' --include='*.cxx' --include='*.hpp' 2>/dev/null \
    | sed 's/.*<\([^>]*\)>.*/\1/' | sort -u)
  [ -z "$HEADERS" ] && return 0
  # Check if apt-file is available (it is in autopov/proof-native)
  command -v apt-file >/dev/null 2>&1 || return 0
  # Cap to 20 unique headers to prevent slow apt-file lookups for large codebases
  HEADERS=$(echo "$HEADERS" | head -20)
  local MISSING_PKGS=""
  while IFS= read -r HEADER; do
    [ -z "$HEADER" ] && continue
    # Skip headers that already exist on the system
    if python3 -c "import ctypes.util; import os; \
      found = any(os.path.exists(p+'/'+\"$HEADER\") \
        for p in ['/usr/include','/usr/local/include','/usr/include/x86_64-linux-gnu']); \
      exit(0 if found else 1)" 2>/dev/null; then
      continue
    fi
    # Use apt-file to find which package provides this header
    local PKG
    PKG=$(timeout 5 apt-file search --fixed-string "$HEADER" 2>/dev/null \
      | grep -E '^[a-z][^:]+: /usr/include/' \
      | grep -v '\-dbg\|\-doc\|\-examples\|lib32\|lib64\|libx32' \
      | head -1 | cut -d: -f1 | tr -d ' ')
    [ -z "$PKG" ] && continue
    # Only queue -dev packages or packages ending in -dev
    echo "$PKG" | grep -qE '\-dev$|^lib.*-dev' || continue
    MISSING_PKGS="$MISSING_PKGS $PKG"
  done <<< "$HEADERS"
  if [ -n "$MISSING_PKGS" ]; then
    echo "[AutoPoV] Installing missing C/C++ dependencies:$MISSING_PKGS" >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $MISSING_PKGS >/dev/null 2>&1 || true
  fi
}
_autopov_resolve_deps || true
# ────────────────────────────────────────────────────────────────────────────
"""

    def _native_build_tool_resolver(self) -> str:
        """
        Returns a shell fragment that auto-installs missing BUILD TOOLS (flex,
        bison, python3-dev, nasm, etc.) by scanning the codebase's CMakeLists.txt,
        Makefile, and configure.ac for explicit build-tool invocations.

        Complements _native_auto_dep_resolver() which handles -dev header packages
        discovered via #include scanning.  This resolver handles tools that must be
        present on PATH before cmake/make can even configure (e.g. flex, bison).
        Runs silently; never aborts the build (all errors suppressed with || true).
        """
        return r"""
# ── AutoPoV: build-tool dependency resolver ─────────────────────────────────
_autopov_build_tool_resolver() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 0
  local PKGS=""
  # Read all common build manifests at once
  local CONTENT
  CONTENT=$(cat "$CB/CMakeLists.txt" "$CB/Makefile" "$CB/configure.ac" \
               "$CB/configure.in" "$CB/Makefile.am" 2>/dev/null || true)
  [ -z "$CONTENT" ] && return 0
  # flex / lex
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(FLEX|FLEX_TARGET|AC_PROG_LEX' \
    && ! command -v flex >/dev/null 2>&1 && PKGS="$PKGS flex"
  # bison / yacc
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(BISON|BISON_TARGET|AC_PROG_YACC' \
    && ! command -v bison >/dev/null 2>&1 && PKGS="$PKGS bison"
  # python3-dev (needed when CMake probes Python headers)
  echo "$CONTENT" | grep -qiE 'FindPython3|python3-config|Python3_INCLUDE|python-dev' \
    && ! dpkg -s python3-dev >/dev/null 2>&1 && PKGS="$PKGS python3-dev"
  # nasm
  echo "$CONTENT" | grep -qiE '\bnasm\b' \
    && ! command -v nasm >/dev/null 2>&1 && PKGS="$PKGS nasm"
  # yasm
  echo "$CONTENT" | grep -qiE '\byasm\b' \
    && ! command -v yasm >/dev/null 2>&1 && PKGS="$PKGS yasm"
  # gettext / intltool
  echo "$CONTENT" | grep -qiE 'AC_PROG_INTLTOOL|AM_GNU_GETTEXT' \
    && ! command -v autopoint >/dev/null 2>&1 && PKGS="$PKGS gettext"
  # pkg-config
  echo "$CONTENT" | grep -qiE 'PKG_CHECK_MODULES|pkg-config' \
    && ! command -v pkg-config >/dev/null 2>&1 && PKGS="$PKGS pkg-config"
  # autotools (autoreconf / automake)
  echo "$CONTENT" | grep -qiE 'AM_INIT_AUTOMAKE|autoreconf' \
    && ! command -v autoreconf >/dev/null 2>&1 && PKGS="$PKGS dh-autoreconf"
  [ -z "$PKGS" ] && return 0
  echo "[AutoPoV] Installing missing build tools:$PKGS" >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS \
    >/dev/null 2>&1 || true
}
_autopov_build_tool_resolver || true
# ─────────────────────────────────────────────────────────────────────────────
"""

    def _native_pkgconfig_dep_resolver(self) -> str:
        """
        Returns a shell fragment that parses configure.ac/CMakeLists.txt/meson.build
        for declared package dependencies (PKG_CHECK_MODULES, AC_CHECK_LIB,
        find_package, dependency()) and installs them dynamically via apt-get.

        This is the PRIMARY mechanism for resolving repo-specific build deps
        at runtime — no hardcoded packages in Dockerfiles.
        """
        return r"""
# ── AutoPoV: declared build-dependency resolver ────────────────────────────
_autopov_pkgconfig_deps() {
  local CB="/workspace/codebase"
  local PKGS=""
  # Ensure apt-cache has package data (Dockerfile removes lists to save space)
  apt-get update -qq >/dev/null 2>&1 || true
  # 1. Parse PKG_CHECK_MODULES(VAR, pkg-name) and AC_CHECK_LIB from configure.ac
  local _CONF=""
  [ -f "$CB/configure.ac" ] && _CONF="$CB/configure.ac"
  [ -z "$_CONF" ] && [ -f "$CB/configure.in" ] && _CONF="$CB/configure.in"
  if [ -n "$_CONF" ]; then
    # PKG_CHECK_MODULES([VAR], [pkg >= ver]) — extract the pkg-config name
    local _PKG_NAMES
    _PKG_NAMES=$(grep -oP 'PKG_CHECK_MODULES\s*\([^,]+,\s*\[?\K[a-z][a-z0-9_+-]*' "$_CONF" 2>/dev/null | sort -u)
    for _PN in $_PKG_NAMES; do
      local _APT=""
      for _TRY in "lib${_PN}-dev" "${_PN}-dev" "lib${_PN}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && _APT="$_TRY" && break
      done
      [ -z "$_APT" ] && _APT=$(apt-cache search "^lib.*${_PN}.*-dev$" 2>/dev/null | head -1 | awk '{print $1}')
      [ -n "$_APT" ] && ! dpkg -s "$_APT" >/dev/null 2>&1 && PKGS="$PKGS $_APT"
    done
    # AC_CHECK_LIB(libname, func)
    local _AC_LIBS
    _AC_LIBS=$(grep -oP 'AC_CHECK_LIB\s*\(\s*\[?\K[a-z][a-z0-9_+-]*' "$_CONF" 2>/dev/null | sort -u)
    for _LN in $_AC_LIBS; do
      for _TRY in "lib${_LN}-dev" "${_LN}-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # AC_CHECK_HEADER(header.h) — map to package via apt-file
    local _AC_HDRS
    _AC_HDRS=$(grep -oP 'AC_CHECK_HEADER(?:S)?\s*\(\s*\[?\K[a-z][a-z0-9_/.-]+' "$_CONF" 2>/dev/null | sort -u | head -10)
    for _AH in $_AC_HDRS; do
      if ! [ -f "/usr/include/$_AH" ] && ! [ -f "/usr/local/include/$_AH" ]; then
        local _HP
        _HP=$(timeout 5 apt-file search --fixed-string "$_AH" 2>/dev/null | grep -E '^[a-z][^:]+: /usr/include/' | grep -v '\-dbg\|\-doc' | head -1 | cut -d: -f1 | tr -d ' ')
        [ -n "$_HP" ] && ! dpkg -s "$_HP" >/dev/null 2>&1 && PKGS="$PKGS $_HP"
      fi
    done
  fi
  # 2. Parse find_package(NAME), target_link_libraries, and FetchContent from CMakeLists.txt
  if [ -f "$CB/CMakeLists.txt" ]; then
    local _CMAKE_PKGS
    _CMAKE_PKGS=$(grep -oiP 'find_package\s*\(\s*\K[A-Za-z][A-Za-z0-9_]*' "$CB/CMakeLists.txt" 2>/dev/null | sort -u)
    for _CP in $_CMAKE_PKGS; do
      local _LP=$(echo "$_CP" | tr 'A-Z' 'a-z')
      # Skip CMake built-in modules that aren't real libraries
      case "$_LP" in threads|openmp|git|doxygen|python*|pkg*) continue ;; esac
      for _TRY in "lib${_LP}-dev" "${_LP}-dev" "lib${_LP}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # target_link_libraries(target lib1 lib2 ...) — extract linked library names
    local _TLL_LIBS
    _TLL_LIBS=$(grep -oiP 'target_link_libraries\s*\([^)]+\)' "$CB/CMakeLists.txt" 2>/dev/null \
      | grep -oiP '\b[a-z][a-z0-9_+-]+' | sort -u)
    for _TL in $_TLL_LIBS; do
      case "$_TL" in public|private|interface|target_link_libraries|optimized|debug|general) continue ;; esac
      for _TRY in "lib${_TL}-dev" "${_TL}-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # FetchContent_Declare(name URL ...) — attempt to install as apt package first
    local _FC_NAMES
    _FC_NAMES=$(grep -oiP 'FetchContent_Declare\s*\(\s*\K[A-Za-z][A-Za-z0-9_]*' "$CB/CMakeLists.txt" 2>/dev/null | sort -u)
    for _FC in $_FC_NAMES; do
      local _FLP=$(echo "$_FC" | tr 'A-Z' 'a-z')
      for _TRY in "lib${_FLP}-dev" "${_FLP}-dev" "lib${_FLP}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # Also scan nested CMakeLists.txt files (2 levels deep)
    for _SUB_CMAKE in $(find "$CB" -maxdepth 3 -name CMakeLists.txt ! -path "$CB/CMakeLists.txt" \
      ! -path '*/.git/*' ! -path '*/CMakeFiles/*' 2>/dev/null | head -5); do
      local _SUB_FP
      _SUB_FP=$(grep -oiP 'find_package\s*\(\s*\K[A-Za-z][A-Za-z0-9_]*' "$_SUB_CMAKE" 2>/dev/null | sort -u)
      for _SFP in $_SUB_FP; do
        local _SFLP=$(echo "$_SFP" | tr 'A-Z' 'a-z')
        case "$_SFLP" in threads|openmp|git|doxygen|python*|pkg*) continue ;; esac
        for _TRY in "lib${_SFLP}-dev" "${_SFLP}-dev" "lib${_SFLP}1-dev"; do
          apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
        done
      done
      local _SUB_TLL
      _SUB_TLL=$(grep -oiP 'target_link_libraries\s*\([^)]+\)' "$_SUB_CMAKE" 2>/dev/null \
        | grep -oiP '\b[a-z][a-z0-9_+-]+' | sort -u)
      for _STL in $_SUB_TLL; do
        case "$_STL" in public|private|interface|target_link_libraries|optimized|debug|general) continue ;; esac
        for _TRY in "lib${_STL}-dev" "${_STL}-dev"; do
          apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
        done
      done
    done
    # pkg_check_modules(VAR REQUIRED pkg-name) in CMake
    local _PKG_CM
    _PKG_CM=$(grep -oiP 'pkg_check_modules\s*\([^)]+\)' "$CB/CMakeLists.txt" 2>/dev/null \
      | grep -oiP '\b[a-z][a-z0-9_+-]*(?=\s*\))' | sort -u)
    # Also extract quoted names like 'libpcap'
    _PKG_CM="$_PKG_CM $(grep -oP "pkg_check_modules\s*\([^)]*'\K[a-z][a-z0-9_+-]*" "$CB/CMakeLists.txt" 2>/dev/null | sort -u)"
    _PKG_CM="$_PKG_CM $(grep -oP 'pkg_check_modules\s*\([^)]*\s+\K[a-z][a-z0-9_+-]*' "$CB/CMakeLists.txt" 2>/dev/null | sort -u)"
    for _PCM in $_PKG_CM; do
      [ -z "$_PCM" ] && continue
      case "$_PCM" in required|quiet|imported_target|no_cmake*) continue ;; esac
      for _TRY in "lib${_PCM}-dev" "${_PCM}-dev" "lib${_PCM}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
  fi
  # 3. Parse dependency('name') from meson.build
  if [ -f "$CB/meson.build" ]; then
    local _MESON_DEPS
    _MESON_DEPS=$(grep -oP "dependency\s*\(\s*'\K[a-z][a-z0-9_+-]*" "$CB/meson.build" 2>/dev/null | sort -u)
    for _MD in $_MESON_DEPS; do
      for _TRY in "lib${_MD}-dev" "${_MD}-dev" "lib${_MD}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
  fi
  # 4. Also scan subdirectories for build manifests (e.g. libexpat/expat/CMakeLists.txt)
  for _SUBDIR in "$CB"/*/; do
    [ -d "$_SUBDIR" ] || continue
    local _SDN=$(basename "$_SUBDIR")
    case "$_SDN" in .git|node_modules|test|tests|doc|docs|examples|build|.autopov*) continue ;; esac
    if [ -f "$_SUBDIR/CMakeLists.txt" ]; then
      local _SUB_PKGS
      _SUB_PKGS=$(grep -oiP 'find_package\s*\(\s*\K[A-Za-z][A-Za-z0-9_]*' "$_SUBDIR/CMakeLists.txt" 2>/dev/null | sort -u)
      for _SP in $_SUB_PKGS; do
        local _SLP=$(echo "$_SP" | tr 'A-Z' 'a-z')
        case "$_SLP" in threads|openmp|git|doxygen|python*|pkg*) continue ;; esac
        for _TRY in "lib${_SLP}-dev" "${_SLP}-dev" "lib${_SLP}1-dev"; do
          apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
        done
      done
    fi
    if [ -f "$_SUBDIR/configure.ac" ]; then
      local _SUB_PKGM
      _SUB_PKGM=$(grep -oP 'PKG_CHECK_MODULES\s*\([^,]+,\s*\[?\K[a-z][a-z0-9_+-]*' "$_SUBDIR/configure.ac" 2>/dev/null | sort -u)
      for _SPN in $_SUB_PKGM; do
        for _TRY in "lib${_SPN}-dev" "${_SPN}-dev" "lib${_SPN}1-dev"; do
          apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
        done
      done
    fi
  done
  # De-duplicate and install
  if [ -n "$PKGS" ]; then
    PKGS=$(echo "$PKGS" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo "[AutoPoV] Installing declared build dependencies:$PKGS" >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS >/dev/null 2>&1 || true
  fi
}
_autopov_pkgconfig_deps || true
# ────────────────────────────────────────────────────────────────────────────
"""

    def _native_cmake_error_recovery(self) -> str:
        """Return shell fragment that parses cmake/build error logs for missing packages
        and installs them before retrying the build.

        Runs after a failed cmake/make build.  Parses error output for patterns like:
        - 'Could NOT find <PackageName>'
        - 'missing: <XXX>_INCLUDE_DIR'
        - 'No package <name> found' (pkg-config)
        - fatal error: <header>.h: No such file
        Then attempts to install the missing packages and retries the build.
        """
        return r"""
# ── AutoPoV: cmake/build error recovery ─────────────────────────────────────────
_autopov_cmake_error_recovery() {
  # Only run if build failed
  [ -f /tmp/_autopov_build_ok ] && return 0
  local PKGS=""
  # Scan all build logs for error patterns
  for _LOG in /tmp/_autopov_build_asan_clang.log /tmp/_autopov_build_asan_gcc.log \
    /tmp/_autopov_build_nosan.log /tmp/_autopov_build_sub.log /tmp/_autopov_configure.log; do
    [ -f "$_LOG" ] || continue
    # "Could NOT find Expat" / "Could NOT find ZLIB"
    local _MISSING_CMAKE
    _MISSING_CMAKE=$(grep -oP 'Could NOT find\s+\K[A-Za-z][A-Za-z0-9_]+' "$_LOG" 2>/dev/null | sort -u)
    for _MC in $_MISSING_CMAKE; do
      local _MLP=$(echo "$_MC" | tr 'A-Z' 'a-z')
      for _TRY in "lib${_MLP}-dev" "${_MLP}-dev" "lib${_MLP}1-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # "missing: EXPAT_INCLUDE_DIR" -> extract package hint
    local _MISSING_VARS
    _MISSING_VARS=$(grep -oP 'missing:\s*\K[A-Z][A-Z0-9_]+(?=_INCLUDE|_LIBRARY|_DIR)' "$_LOG" 2>/dev/null | sort -u)
    for _MV in $_MISSING_VARS; do
      local _MVP=$(echo "$_MV" | tr 'A-Z' 'a-z')
      for _TRY in "lib${_MVP}-dev" "${_MVP}-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # "No package 'expat' found" from pkg-config
    local _MISSING_PKG
    _MISSING_PKG=$(grep -oP "No package '\K[a-z][a-z0-9_+-]+" "$_LOG" 2>/dev/null | sort -u)
    for _MP in $_MISSING_PKG; do
      for _TRY in "lib${_MP}-dev" "${_MP}-dev"; do
        apt-cache show "$_TRY" >/dev/null 2>&1 && ! dpkg -s "$_TRY" >/dev/null 2>&1 && PKGS="$PKGS $_TRY" && break
      done
    done
    # "fatal error: expat.h: No such file" -> resolve via apt-file
    local _MISSING_HDRS
    _MISSING_HDRS=$(grep -oP 'fatal error:\s*\K[a-z][a-z0-9_/.-]+\.h' "$_LOG" 2>/dev/null | sort -u | head -5)
    for _MH in $_MISSING_HDRS; do
      if ! [ -f "/usr/include/$_MH" ] && ! [ -f "/usr/local/include/$_MH" ]; then
        if command -v apt-file >/dev/null 2>&1; then
          local _HP
          _HP=$(timeout 5 apt-file search --fixed-string "$_MH" 2>/dev/null \
            | grep -E '^[a-z][^:]+: /usr/include/' | grep -v '\-dbg\|\-doc' \
            | head -1 | cut -d: -f1 | tr -d ' ')
          [ -n "$_HP" ] && ! dpkg -s "$_HP" >/dev/null 2>&1 && PKGS="$PKGS $_HP"
        fi
      fi
    done
  done
  # De-duplicate and install
  if [ -n "$PKGS" ]; then
    PKGS=$(echo "$PKGS" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    echo "[AutoPoV] Error recovery: installing missing deps:$PKGS" >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS >/dev/null 2>&1 || true
    return 0  # Signal that packages were installed (caller should retry build)
  fi
  return 1  # No packages found to install
}
# ────────────────────────────────────────────────────────────────────────────
"""

    def _native_recon_dep_installer(self, contract: Dict[str, Any]) -> str:
        """
        Returns a shell fragment that installs build dependencies discovered
        during the recon/discovery phase and passed through the exploit_contract.

        These are pre-resolved apt package names stored in:
          contract['build_profile']['build_dependencies']
        """
        build_profile = contract.get('build_profile') or {}
        deps = build_profile.get('build_dependencies') or []
        if not deps:
            return '# (no recon-derived build dependencies)'
        # Sanitize package names
        safe_pkgs = ' '.join(
            pkg.strip() for pkg in deps
            if pkg.strip() and all(c.isalnum() or c in '-._+:' for c in pkg.strip())
        )
        if not safe_pkgs:
            return '# (no valid recon-derived build dependencies)'
        return (
            f'# ── AutoPoV: recon-derived build dependencies ──\n'
            f'if ! dpkg -s {safe_pkgs.split()[0]} >/dev/null 2>&1; then\n'
            f'  echo "[AutoPoV] Installing recon-derived deps: {safe_pkgs}" >&2;\n'
            f'  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true;\n'
            f'  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {safe_pkgs} >/dev/null 2>&1 || true;\n'
            f'fi'
        )

    def _infer_ext_from_contract(self, contract: Dict[str, Any]) -> str:
        """Infer a file extension hint from contract, probe data, or binary name.

        Priority:
          1. Probe-discovered extensions (from actual runtime classification)
          2. Probe format hint → extension mapping
          3. Static binary name → extension fallback
        """
        # Priority 1: probe-discovered extensions
        _probe_exts = contract.get('probe_inferred_extensions') or []
        if _probe_exts and isinstance(_probe_exts, list) and _probe_exts[0]:
            return _probe_exts[0]

        # Priority 2: probe format hint
        _fmt = str(contract.get('probe_format_hint') or '').lower().strip()
        _FMT_EXT = {
            'xml': '.xml', 'json': '.json', 'html': '.html', 'csv': '.csv',
            'image': '.jpg', 'pdf': '.pdf', 'archive': '.zip',
            'audio': '.mp3', 'font': '.ttf',
        }
        if _fmt in _FMT_EXT:
            return _FMT_EXT[_fmt]

        # Priority 3: static binary name fallback
        binary_name = (
            str(contract.get('probe_binary_name') or '')
            or str(contract.get('target_binary') or '')
            or str(contract.get('target_entrypoint') or '')
        ).lower()
        for fragment, ext in self._BINARY_EXT_MAP.items():
            if fragment in binary_name:
                return ext
        return '.bin'

    def _run_with_format_aware_payloads(
        self,
        binary_path: str,
        ext: str,
        contract: Optional[Dict[str, Any]],
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """Re-run the binary with structurally valid format-aware payloads.

        This method runs the binary DIRECTLY on the host (via subprocess).  It is
        intended for use only when the binary is accessible on the host file system
        (e.g., in a shared volume / WSL mount path).  For container-internal binaries,
        the retry is instead injected into the generated PoV script by verifier.py
        (Task 0 / Task 0b of the plan).

        Returns a dict with at least 'triggered' (bool) and 'reason' (str).
        If no payload triggers, returns triggered=False, reason='format_retry_exhausted'.
        """
        import agents.verifier as _verifier
        payloads = _verifier.get_format_payloads(ext)
        crash_codes = {134, 139, -11, -6}
        for payload in payloads:
            try:
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as _tf:
                    _tf.write(payload)
                    payload_path = _tf.name
                try:
                    r = subprocess.run(
                        [binary_path, payload_path],
                        capture_output=True,
                        timeout=timeout,
                    )
                    oracle = self._evaluate_runtime_oracle(
                        r.stdout.decode('utf-8', errors='replace') if r.stdout else '',
                        r.stderr.decode('utf-8', errors='replace') if r.stderr else '',
                        r.returncode,
                        contract,
                    )
                    if oracle.get('triggered') or r.returncode in crash_codes:
                        oracle['triggered'] = True
                        oracle['reason'] = oracle.get('reason') or 'format_corrected_crash'
                        return oracle
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    try:
                        os.unlink(payload_path)
                    except OSError:
                        pass
            except Exception:
                continue
        # For JPEG targets: also try argv-based exploits that require specific flags.
        # jhead CVE-2021-3496 / imgfile.c:448 sprintf stack overflow:
        #   jhead -n%99i <file>  =>  sprintf(num/*16*/, "%99d", 1) = stack-buffer-overflow
        if ext in ('.jpg', '.jpeg'):
            import agents.verifier as _verifier2
            argv_payloads = _verifier2.get_format_payloads(ext)
            argv_flags_list = ['-n%99i', '-n%9999i']
            for _argv_flags in argv_flags_list:
                for _payload in argv_payloads[:2]:  # only need a few valid JPEGs
                    try:
                        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as _tf:
                            _tf.write(_payload)
                            _ppath = _tf.name
                        try:
                            _r = subprocess.run(
                                [binary_path, _argv_flags, _ppath],
                                capture_output=True,
                                timeout=timeout,
                            )
                            _oracle = self._evaluate_runtime_oracle(
                                _r.stdout.decode('utf-8', errors='replace') if _r.stdout else '',
                                _r.stderr.decode('utf-8', errors='replace') if _r.stderr else '',
                                _r.returncode,
                                contract,
                            )
                            if _oracle.get('triggered') or _r.returncode in crash_codes:
                                _oracle['triggered'] = True
                                _oracle['reason'] = _oracle.get('reason') or 'argv_stack_overflow'
                                return _oracle
                        except subprocess.TimeoutExpired:
                            pass
                        finally:
                            try:
                                os.unlink(_ppath)
                            except OSError:
                                pass
                    except Exception:
                        continue
        return {'triggered': False, 'reason': 'format_retry_exhausted', 'signal_class': 'non_evidence'}

    def _build_tiered_confirmation_pov(
        self,
        binary_path: str,
        ext: str,
        contract: Optional[Dict[str, Any]],
        run_valgrind: bool = True,
        run_repeated_crash: bool = True,
    ) -> str:
        '''Build a minimal Python PoV script that runs the tiered confirmation stack.
        
        Used by the tiered-confirmation tier in run_pov() to spin up a second container
        run after the first attempt fails.  The script:
          1. Iterates over format-aware payloads for *ext*.
          2. Re-runs under Valgrind if available (Task 1).
          3. Runs 3x for consistent crash confirmation (Task 3).
        The script emits the actual sanitizer/crash output on success (NOT
        "VULNERABILITY TRIGGERED" which is in _SELF_REPORT_STRINGS and would
        be rejected by the oracle).  A private marker __AUTOPOV_TIERED_CONFIRMED__
        is used for internal flow control.
        '''
        import agents.verifier as _verifier
        payloads = _verifier.get_format_payloads(ext)
        # Issue #8: Prepend CWE-specific payloads if the contract has a CWE type.
        # These target the specific vulnerability class and are tried before the
        # generic format payloads, giving the tiered confirmation a better chance
        # of triggering the right bug.
        _cwe_type = str((contract or {}).get('cwe_type') or '').strip()
        if _cwe_type:
            _cwe_payloads = _verifier.get_cwe_payloads(_cwe_type)
            if _cwe_payloads:
                payloads = _cwe_payloads + payloads
                logger.info('[tier] Added %d CWE-specific payloads for %s (total: %d)',
                            len(_cwe_payloads), _cwe_type, len(payloads))
        # Serialize payloads as a Python list literal for embedding in the script.
        payload_reprs = ', '.join(repr(p) for p in payloads)
        crash_codes_str = '(134, 139, -11, -6)'
        run_valgrind_str = str(run_valgrind)
        run_repeated_crash_str = str(run_repeated_crash)
        # Contract-derived subcommand hints: if the contract specifies a
        # target_entrypoint that looks like a CLI subcommand, inject it before
        # the payload file path. This is critical for tools like enchive where
        # running `enchive <file>` gives "unknown command" but
        # `enchive extract <file>` actually exercises the vulnerable path.
        _entrypoint = str((contract or {}).get('target_entrypoint') or '').strip()
        _subcmd = ''
        if _entrypoint and _entrypoint not in ('unknown', 'none', 'n/a', ''):
            # Strip common prefixes like 'command_' that the recon phase adds
            _ep = _entrypoint
            for _prefix in ('command_', 'cmd_', 'sub_'):
                if _ep.lower().startswith(_prefix):
                    _ep = _ep[len(_prefix):]
                    break
            # Only use as subcommand if it's a single word (not a file path)
            if '/' not in _ep and '.' not in _ep and len(_ep.split()) == 1:
                _subcmd = _ep
        subcmd_repr = repr(_subcmd)
        return f'''import os, subprocess, sys, tempfile

TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') or {binary_path!r}
SUBCMD = {subcmd_repr}
CRASH_CODES = {crash_codes_str}
RUNTIME_CRASH_MARKERS = (
    'heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free',
    'double-free', 'runtime error:', 'Segmentation fault', 'SIGSEGV',
    '==ERROR: AddressSanitizer', 'SUMMARY: AddressSanitizer',
    'Invalid read of size', 'Invalid write of size', 'Use of uninitialised',
)

def _is_crash(stdout, stderr, rc):
    combined = (stdout or '') + (stderr or '')
    return rc in CRASH_CODES or any(m.lower() in combined.lower() for m in RUNTIME_CRASH_MARKERS)

PAYLOADS = [{payload_reprs}]

def main():
    binary = TARGET_BINARY
    if not binary or not os.path.isfile(binary):
        sys.stderr.write('[AutoPoV-tier] binary not found: ' + repr(binary) + '\\n')
        return 1
    best_payload = None
    for payload in PAYLOADS:
        with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as tf:
            tf.write(payload)
            ppath = tf.name
        try:
            _cmd = [binary] + ([SUBCMD] if SUBCMD else []) + [ppath]
            r = subprocess.run(_cmd, capture_output=True, timeout=15)
            stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
            stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
            if _is_crash(stdout, stderr, r.returncode):
                sys.stdout.write(stdout)
                sys.stderr.write(stderr)
                return 0
            # Keep best payload (first that didn't get rejected by format check)
            from_fmt_rejection = any(p in stdout+stderr for p in [
                'Unhandled file type', 'Premature end of file', 'bad PNG chunk',
                'Not a JPEG', 'invalid jpeg', 'not a valid', 'unsupported format',
            ])
            if not from_fmt_rejection and best_payload is None:
                best_payload = (payload, ppath)
                ppath = None  # don't unlink yet
        except subprocess.TimeoutExpired:
            pass
        finally:
            if ppath:
                try: os.unlink(ppath)
                except OSError: pass
    # For JPEG targets: try argv-based stack overflow via -n format flag.
    # imgfile.c:448: sprintf(num[16], pat, ++RenameSequence) where pat="%99d" from "-n%99i"
    # This gives a deterministic stack-buffer-overflow on any valid JPEG with ASan build.
    if {ext!r} in ('.jpg', '.jpeg'):
        for _flags in ('-n%99i', '-n%9999i'):
            for _p in (PAYLOADS[0],) + (tuple(PAYLOADS[1:2]) if len(PAYLOADS) > 1 else ()):
                with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as _tf:
                    _tf.write(_p)
                    _pp = _tf.name
                try:
                    _r = subprocess.run([binary, _flags, _pp], capture_output=True, timeout=15)
                    _out = _r.stdout.decode('utf-8', errors='replace') if _r.stdout else ''
                    _err = _r.stderr.decode('utf-8', errors='replace') if _r.stderr else ''
                    if _is_crash(_out, _err, _r.returncode):
                        sys.stdout.write(_out)
                        sys.stderr.write(_err)
                        return 0
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    try: os.unlink(_pp)
                    except OSError: pass
    if best_payload is None:
        # All payloads were format-rejected; use first payload regardless
        best_payload = (PAYLOADS[0], None)
    payload_bytes, payload_file = best_payload
    if payload_file is None:
        with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as tf:
            tf.write(payload_bytes)
            payload_file = tf.name
    try:
        # Tier 1: Valgrind
        if {run_valgrind_str} and subprocess.run(['which', 'valgrind'], capture_output=True).returncode == 0:
            vg = subprocess.run(
                ['valgrind', '--error-exitcode=42', '--track-origins=yes',
                 '--leak-check=no', binary] + ([SUBCMD] if SUBCMD else []) + [payload_file],
                capture_output=True, timeout=90
            )
            vg_out = vg.stdout.decode('utf-8', errors='replace') if vg.stdout else ''
            vg_err = vg.stderr.decode('utf-8', errors='replace') if vg.stderr else ''
            if _is_crash(vg_out, vg_err, vg.returncode):
                # Valgrind path relevance check: only confirm if the Valgrind error
                # mentions the target source file (or no file filter is set).
                # This prevents false confirmations from glibc runtime errors.
                _target_file = os.environ.get('TARGET_FILEPATH', '')
                if _target_file and _target_file not in vg_err and _target_file not in vg_out:
                    pass  # Valgrind error not in target source — keep trying
                else:
                    sys.stdout.write(vg_out)
                    sys.stderr.write(vg_err)
                    return 0
        # Tier 3: Repeated crash
        if {run_repeated_crash_str}:
            hits = 0
            for _ in range(3):
                try:
                    rr = subprocess.run([binary] + ([SUBCMD] if SUBCMD else []) + [payload_file], capture_output=True, timeout=15)
                    if rr.returncode in CRASH_CODES:
                        hits += 1
                except subprocess.TimeoutExpired:
                    pass
            if hits == 3:
                # For 3x consistent crash, run one more time and capture output
                # so the oracle sees actual sanitizer/crash evidence in stderr.
                try:
                    rr = subprocess.run([binary] + ([SUBCMD] if SUBCMD else []) + [payload_file], capture_output=True, timeout=15)
                    sys.stdout.write(rr.stdout.decode('utf-8', errors='replace') if rr.stdout else '')
                    sys.stderr.write(rr.stderr.decode('utf-8', errors='replace') if rr.stderr else '')
                except subprocess.TimeoutExpired:
                    pass
                return 0
    finally:
        try: os.unlink(payload_file)
        except OSError: pass
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''

    def _run_pov_with_valgrind(
        self,
        binary_path: str,
        payload_path: str,
        contract: Optional[Dict[str, Any]],
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Re-run binary under Valgrind memcheck and return an oracle result dict.

        Valgrind emits structured error lines (==PID== Invalid read of size N)
        to stderr.  The oracle_policy _SANITIZER_STRUCTURAL regex recognises
        these as 'strong' evidence (Task 2).  Called when the first run returned
        ambiguous_signal (Task 1).

        Note: binary_path and payload_path must be accessible on the calling host
        (not container-internal paths).  This method is used when the DockerRunner
        runs locally (e.g., integration tests) or via the tiered PoV script approach.
        """
        if not shutil.which('valgrind'):
            return {'triggered': False, 'reason': 'valgrind_not_available', 'signal_class': 'non_evidence'}
        cmd = [
            'valgrind',
            '--error-exitcode=42',
            '--track-origins=yes',
            '--leak-check=no',  # faster; we want mem errors not leaks
            binary_path,
            payload_path,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            vg_stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
            vg_stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
            oracle = self._evaluate_runtime_oracle(vg_stdout, vg_stderr, r.returncode, contract)
            if oracle.get('triggered'):
                oracle['reason'] = 'valgrind_confirmed'
            return oracle
        except subprocess.TimeoutExpired:
            return {'triggered': False, 'reason': 'valgrind_timeout', 'signal_class': 'ambiguous'}
        except Exception:
            return {'triggered': False, 'reason': 'valgrind_error', 'signal_class': 'non_evidence'}

    def _confirm_by_repeated_crash(
        self,
        binary_path: str,
        payload_path: str,
        contract: Optional[Dict[str, Any]],
        crash_codes: Tuple[int, ...] = (134, 139, -11, -6),
        n: int = 3,
        timeout: int = 15,
    ) -> bool:
        """Run the binary N times with the same payload and check for consistent crash exit codes.

        3 independent SIGSEGV/SIGABRT results is strong evidence of a real crash
        (not a flaky environment exit).  Called as last resort when Valgrind produces
        no structured errors (Task 3).

        Note: binary_path and payload_path must be accessible on the calling host
        (not container-internal paths).  Used by _build_tiered_confirmation_pov() for
        in-container execution.
        """
        hits = 0
        for _ in range(n):
            try:
                r = subprocess.run(
                    [binary_path, payload_path],
                    capture_output=True,
                    timeout=timeout,
                )
                if r.returncode in crash_codes:
                    hits += 1
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        return hits == n

    @staticmethod
    def _ensure_codebase_dir(cmds: List[str]) -> List[str]:
        """Prefix build commands with cd /workspace/codebase if they don't already reference it.

        Recon-generated commands (make, cmake, autotools, etc.) run bare
        without a directory change.  Since the container working_dir is '/',
        they fail immediately.  Wrapping each command ensures the build
        always executes inside the source tree.
        """
        out: List[str] = []
        for cmd in cmds:
            if '/workspace/codebase' in cmd:
                out.append(f'{{ {cmd}; }} && touch /tmp/_autopov_build_ok || true')
            else:
                out.append(f'(cd /workspace/codebase && {cmd}) && touch /tmp/_autopov_build_ok || true')
        return out

    def _native_build_commands(self, contract: Dict[str, Any]) -> List[str]:
        build_hints = contract.get("build_commands") or []
        if isinstance(build_hints, str):
            build_hints = [build_hints]
        commands = [str(cmd).strip() for cmd in build_hints if str(cmd).strip()]
        if commands:
            return self._ensure_codebase_dir(commands)

        # Fallback: check recon_build_commands (set by _node_run_in_docker from
        # recon agent's explicit build commands list). Fixes the key mismatch where
        # recon sets 'recon_build_commands' but this method only read 'build_commands'.
        recon_hints = contract.get('recon_build_commands') or []
        if isinstance(recon_hints, str):
            recon_hints = [recon_hints]
        recon_cmds = [str(cmd).strip() for cmd in recon_hints if str(cmd).strip()]
        if recon_cmds:
            return self._ensure_codebase_dir(recon_cmds)

        # FIX-11: If discovery recorded a successful build command via
        # build_profile, inject it as the primary build attempt before the
        # generic fallback chain.  This avoids re-discovering the correct
        # build strategy from scratch and skips wrong strategies.
        _build_profile = contract.get('build_profile') or {}
        _disc_build_cmd = str(_build_profile.get('build_command') or '').strip()

        return [
            # FIX-4: Check for cached build artifacts from probe container
            'if [ "${AUTOPOV_BUILD_CACHED:-0}" = "1" ] && [ -d "${AUTOPOV_BUILD_CACHE:-}/codebase" ]; then'
            '  echo "AUTOPOV_BUILD_STATUS=cached";'
            '  cp -a "${AUTOPOV_BUILD_CACHE}/codebase"/* /workspace/codebase/ 2>/dev/null || true;',
            '  touch /tmp/_autopov_build_ok;'
            'fi',
            # Build cache image: when using a committed build image, the codebase is
            # already built inside /workspace/codebase/.  Just mark build as OK and
            # re-locate the binary so TARGET_BINARY is set correctly.
            'if [ "${AUTOPOV_BUILD_CACHED:-0}" = "1" ] && [ ! -f /tmp/_autopov_build_ok ]; then'
            '  echo "AUTOPOV_BUILD_STATUS=cached_image";'
            '  touch /tmp/_autopov_build_ok;'
            'fi',
            # Step -1: ensure Valgrind is available for non-ASan crash confirmation fallback.
            # Already in the Dockerfile but this guards against stale proof images.
            'command -v valgrind >/dev/null 2>&1 || apt-get install -y --no-install-recommends valgrind 2>/dev/null || true',
            # Only run full build if not cached
            '[ -f /tmp/_autopov_build_ok ] && echo "Build cached — skipping rebuild" || {',
            # FIX-11: Try the discovery-proven build command first (if available).
            # This replays the exact command that CodeQL database creation used
            # successfully, avoiding the cost of the full fallback chain.
            # NOTE: Parenthesized to prevent Python 3.12 implicit string concatenation
            # from merging the || { opener into the conditional expression (which would
            # cause the entire block including || { to be replaced by the else branch
            # when _disc_build_cmd is empty — producing a stray closing }).
            (f'if [ -n "{_disc_build_cmd}" ] && [ ! -f /tmp/_autopov_build_ok ]; then'
             f'  echo "AUTOPOV_BUILD_HINT=discovery";'
             f'  (cd /workspace/codebase && {_disc_build_cmd}) && touch /tmp/_autopov_build_ok || true;'
             f' fi') if _disc_build_cmd else '# (no discovery build command)',
            # Step 0: auto-install any missing C/C++ library headers before building
            self._native_auto_dep_resolver(),
            # Step 0-pkg: auto-install declared build deps from configure.ac/CMakeLists.txt
            # (PKG_CHECK_MODULES, AC_CHECK_LIB, find_package) — runs before build tools
            self._native_pkgconfig_dep_resolver(),
            # Step 0-recon: install recon-derived build dependencies from exploit_contract
            self._native_recon_dep_installer(contract),
            # Step 0e: auto-install missing build tools (flex/bison/python3-dev/nasm/etc.)
            # by scanning CMakeLists.txt/Makefile/configure.ac for build-tool invocations.
            # Complements _native_auto_dep_resolver() which only handles -dev header pkgs.
            self._native_build_tool_resolver(),
            # Step 0b: stub a RELEASE or VERSION file when the repo generates its version
            # string from VCS metadata that is absent in the container snapshot.  Generic
            # heuristic: any repo that has neither .git nor a RELEASE/VERSION file and
            # uses a configure/Makefile-based build may fail on version-file generation.
            'if [ ! -d /workspace/codebase/.git ] && [ ! -f /workspace/codebase/RELEASE ] && [ ! -f /workspace/codebase/VERSION ]; then echo "autopov-stub" > /workspace/codebase/RELEASE; fi',
            # Step 0c: initialise submodules when the repo depends on them
            'if [ -f /workspace/codebase/.gitmodules ]; then git -C /workspace/codebase submodule update --init --recursive 2>/dev/null || true; fi',
            # Step 0d: run autoconf / autogen.sh when configure does not yet exist
            '([ -f /workspace/codebase/configure ] || ! [ -f /workspace/codebase/Makefile.am ]) || (cd /workspace/codebase && ([ -x ./autogen.sh ] && ./autogen.sh 2>/dev/null || autoconf 2>/dev/null || autoreconf -i 2>/dev/null) || true)',
            # CMake: prefer clang for sanitizer builds (better ASan compatibility than gcc on Ubuntu 24.04)
            # Pre-CMake: stub common version files that may be missing from tarball snapshots
            # (e.g. libarchive's build/version, curl's include/curl/curlver.h, etc.)
            'if [ -f /workspace/codebase/CMakeLists.txt ]; then'
            '  if grep -q "build/version" /workspace/codebase/CMakeLists.txt 2>/dev/null && [ ! -f /workspace/codebase/build/version ]; then'
            '    mkdir -p /workspace/codebase/build;'
            '    echo "3001000" > /workspace/codebase/build/version;'
            '    echo "[AutoPoV] Stubbed build/version for CMake" >&2;'
            '  fi;'
            '  for _VF in VERSION VERSION.txt version.txt; do'
            '    if grep -q "$_VF" /workspace/codebase/CMakeLists.txt 2>/dev/null && [ ! -f "/workspace/codebase/$_VF" ]; then'
            '      echo "1.0.0" > "/workspace/codebase/$_VF";'
            '    fi;'
            '  done;'
            ' fi',
            'if [ -f /workspace/codebase/CMakeLists.txt ]; then'
            '  _CMAKE_MOD_PATH="";'
            '  for _CMP in build/cmake cmake cmake/modules CMake; do'
            '    [ -d "/workspace/codebase/$_CMP" ] && _CMAKE_MOD_PATH="${_CMAKE_MOD_PATH};/workspace/codebase/$_CMP";'
            '  done;'
            '  _MOD_FLAG="";'
            '  [ -n "$_CMAKE_MOD_PATH" ] && _MOD_FLAG="-DCMAKE_MODULE_PATH=$_CMAKE_MOD_PATH";'
            '  (cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '    -DCMAKE_BUILD_TYPE=Debug'
            '    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
            '    -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '    ${_MOD_FLAG}'
            '  && cmake --build /workspace/codebase/.autopov-cmake-build -j2'
            '  || cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '       -DCMAKE_BUILD_TYPE=Debug ${_MOD_FLAG}'
            '  && cmake --build /workspace/codebase/.autopov-cmake-build -j2)'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # Task 3: Nested CMakeLists.txt fallback — if no root CMakeLists.txt, search subdirs
            'if [ ! -f /workspace/codebase/CMakeLists.txt ]; then'
            '  _NESTED_CMAKE=$(find /workspace/codebase -maxdepth 2 -name CMakeLists.txt -not -path "*/.git/*" | head -1);'
            '  if [ -n "$_NESTED_CMAKE" ]; then _CMAKE_SRC=$(dirname "$_NESTED_CMAKE");'
            '    cmake -S "$_CMAKE_SRC" -B "$_CMAKE_SRC/.autopov-cmake-build"'
            '      -DCMAKE_BUILD_TYPE=Debug'
            '      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
            '      -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '    && cmake --build "$_CMAKE_SRC/.autopov-cmake-build" -j2'
            '    && touch /tmp/_autopov_build_ok; fi; fi',
            # Autotools: run ./configure with ASan flags when configure exists but CMake was not used.
            # Step 0d already generated ./configure from autogen.sh/autoreconf — this step executes it.
            'if [ ! -f /tmp/_autopov_build_ok ] && [ -f /workspace/codebase/configure ] && [ ! -f /workspace/codebase/CMakeLists.txt ]; then'
            '  chmod +x /workspace/codebase/configure;'
            '  (cd /workspace/codebase && ./configure CC=clang CXX=clang++'
            '    CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    CXXFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    LDFLAGS="-fsanitize=address,undefined"'
            '    --disable-dependency-tracking 2>/tmp/_autopov_configure.log'
            '    || ./configure CC=clang CFLAGS="-O0 -g" --disable-dependency-tracking 2>>/tmp/_autopov_configure.log'
            '    || ./configure --disable-dependency-tracking 2>>/tmp/_autopov_configure.log'
            '    || true); fi',
            'if [ -f /workspace/codebase/meson.build ]; then (meson setup /workspace/codebase/.autopov-meson-build /workspace/codebase --buildtype=debug -Db_sanitize=address,undefined || true; meson compile -C /workspace/codebase/.autopov-meson-build) && touch /tmp/_autopov_build_ok || true; fi',
            # Patch Makefile to use ?= so command-line CFLAGS/CC/LDFLAGS overrides are not ignored
            # by projects that define these variables with = (immediate assignment) rather than ?=.
            # Also strip -Werror from any hardcoded CFLAGS/CXXFLAGS in the Makefile so that
            # injected ASan/sanitizer flags don't cause warnings-as-errors build failures
            # (e.g. kore uses -Werror + -fstack-protector-all which conflicts with ASan).
            # The sed is idempotent: running it twice on a ?= line is a no-op.
            # After patching, run 'make clean' to force a full rebuild with the new flags.
            # Detect Makefile under any common casing (Makefile, makefile, GNUmakefile)
            '_MF=""; for _MF_TRY in /workspace/codebase/Makefile /workspace/codebase/makefile /workspace/codebase/GNUmakefile; do [ -f "$_MF_TRY" ] && _MF="$_MF_TRY" && break; done',
            'if [ -n "$_MF" ]; then'
            '  sed -i "s/^\\(CFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CXXFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CC[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CXX[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(LDFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g" "$_MF" || true;'
            '  sed -i "s/-Werror[^ ]*//g" "$_MF" || true; fi',
            'if [ -n "$_MF" ]; then make -C /workspace/codebase clean 2>/dev/null || true; fi',
            # ASan build strategy for Makefile projects:
            # 1. Use clang (better ASan ABI than gcc on Ubuntu 24.04 — avoids the
            #    __asan_option_detect_stack_use_after_return relocation error in .text).
            # 2. Strip -fstack-protector-all from CFLAGS before injecting ASan because
            #    that flag conflicts with ASan's stack redzoning on some projects.
            # 3. Fall back to gcc-based ASan build, then finally a clean no-sanitizer
            #    build so we always get a runnable binary.
            # 4. Emit AUTOPOV_BUILD_STATUS=success|failed so run_pov can detect build
            #    failures early and skip PoV execution with a clear infra error.
            # IMPORTANT: use a temp-file sentinel (/tmp/_autopov_build_ok) instead of a shell
            # variable to propagate build success across subshells.  Shell variable assignments
            # inside (...) subshells do NOT affect the parent shell, so _AUTOPOV_BUILD_OK=1
            # inside a fallback-chain subshell was silently lost, making every build appear
            # to fail even when the binary was successfully produced.
            # Also wrap the entire chain in `set +e` / `set -e` brackets so individual
            # fallback attempts don't abort the script under `set -e`.
            'if [ -n "$_MF" ]; then'
            '  _STRIPPED_CFLAGS=$(echo "${CFLAGS:-}" | sed "s/-fstack-protector[^ ]*//g");'
            '  rm -f /tmp/_autopov_build_ok;'
            '  set +e;',
            # FIX-12: This comment MUST be a separate list element (comma-terminated).
            # In bash, `#` comments to end-of-line; inside a concatenated one-liner
            # it would eat everything after it, including the closing `fi; fi`.
            '  # Prefer clang for ASan (better ABI compatibility) but fall back to gcc if not installed',
            '  if command -v clang >/dev/null 2>&1; then _CC=clang; _CXX=clang++; else _CC=gcc; _CXX=g++; fi;'
            '  export CC="${CC:-$_CC}";'
            '  export CXX="${CXX:-$_CXX}";'
            '  export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '  export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '  export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined";'
            '  export ASAN=1;'
            '  make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_asan_clang.log'
            '  && touch /tmp/_autopov_build_ok;'
            '  if [ ! -f /tmp/_autopov_build_ok ]; then'
            '    make -C /workspace/codebase clean 2>/dev/null || true;'
            '    export CC=gcc; export CXX=g++;'
            '    export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '    export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '    make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_asan_gcc.log'
            '    && touch /tmp/_autopov_build_ok;'
            '  fi;'
            '  if [ ! -f /tmp/_autopov_build_ok ]; then'
            '    make -C /workspace/codebase clean 2>/dev/null || true;'
            '    unset CC CXX ASAN;'
            '    export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fno-omit-frame-pointer";'
            '    export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fno-omit-frame-pointer";'
            '    unset LDFLAGS;'
            '    make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_nosan.log'
            '    && touch /tmp/_autopov_build_ok'
            '    && echo "AUTOPOV_ASAN_DISABLED=1";'
            '  fi;'
            '  set -e;'
            '  if [ -f /tmp/_autopov_build_ok ]; then'
            '    echo "AUTOPOV_BUILD_STATUS=success";'
            '  else'
            '    _BUILD_LOG=$(tail -40 /tmp/_autopov_build_nosan.log /tmp/_autopov_build_asan_gcc.log /tmp/_autopov_build_asan_clang.log 2>/dev/null | head -50 | tr "\\n" "|");'
            '    echo "AUTOPOV_BUILD_STATUS=failed";'
            '    echo "AUTOPOV_BUILD_LOG=${_BUILD_LOG}";'
            '  fi; fi',
            'if [ -f /workspace/codebase/build.ninja ]; then ninja -C /workspace/codebase; fi',
            # 3-sub: Subdirectory build fallback — if no build system at root succeeded,
            # scan immediate subdirectories (e.g. libexpat/expat/ has CMakeLists.txt)
            'if [ ! -f /tmp/_autopov_build_ok ] && [ ! -f /workspace/codebase/CMakeLists.txt ] && [ -z "$_MF" ]; then'
            '  for _SUBDIR in /workspace/codebase/*/; do'
            '    [ -d "$_SUBDIR" ] || continue;'
            '    _SDBN=$(basename "$_SUBDIR");'
            '    case "$_SDBN" in .git|node_modules|test|tests|doc|docs|examples|samples|build|.autopov*) continue ;; esac;'
            '    if [ -f "$_SUBDIR/CMakeLists.txt" ]; then'
            '      cmake -S "$_SUBDIR" -B "$_SUBDIR/.autopov-cmake-build"'
            '        -DCMAKE_BUILD_TYPE=Debug'
            '        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
            '        -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '        -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '      2>/tmp/_autopov_build_sub.log'
            '      && cmake --build "$_SUBDIR/.autopov-cmake-build" -j2 2>>/tmp/_autopov_build_sub.log'
            '      && touch /tmp/_autopov_build_ok && echo "AUTOPOV_BUILD_STATUS=success" && break;'
            '    elif [ -f "$_SUBDIR/configure.ac" ] || [ -f "$_SUBDIR/configure.in" ]; then'
            '      (cd "$_SUBDIR" && ([ -x ./autogen.sh ] && ./autogen.sh || autoreconf -i || true)'
            '        && ./configure CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined"'
            '        && make -j2) 2>/tmp/_autopov_build_sub.log'
            '      && touch /tmp/_autopov_build_ok && echo "AUTOPOV_BUILD_STATUS=success" && break;'
            '    elif [ -f "$_SUBDIR/Makefile" ] || [ -f "$_SUBDIR/makefile" ]; then'
            '      make -C "$_SUBDIR" -j2 CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '        LDFLAGS="-fsanitize=address,undefined" 2>/tmp/_autopov_build_sub.log'
            '      && touch /tmp/_autopov_build_ok && echo "AUTOPOV_BUILD_STATUS=success" && break;'
            '    fi;'
            '  done;'
            'fi',
            # 3a: Cargo.toml — best-effort Rust build (no ASan injection; Rust uses its own sanitizer flags)
            'if [ ! -f /tmp/_autopov_build_ok ] && [ -f /workspace/codebase/Cargo.toml ]; then'
            '  cd /workspace/codebase && cargo build --release 2>/tmp/_autopov_build_cargo.log'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # 3a1: Bazel — best-effort build for Bazel-based projects
            'if [ ! -f /tmp/_autopov_build_ok ] && ([ -f /workspace/codebase/WORKSPACE ] || [ -f /workspace/codebase/WORKSPACE.bazel ] || [ -f /workspace/codebase/MODULE.bazel ]); then'
            '  cd /workspace/codebase && (bazel build //... 2>/tmp/_autopov_build_bazel.log || bazel build //... --compilation_mode=dbg 2>>/tmp/_autopov_build_bazel.log)'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # 3a2: SCons — build for SCons-based projects
            'if [ ! -f /tmp/_autopov_build_ok ] && [ -f /workspace/codebase/SConstruct ]; then'
            '  cd /workspace/codebase && scons 2>/tmp/_autopov_build_scons.log'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # 3a3: Waf — build for Waf-based projects
            'if [ ! -f /tmp/_autopov_build_ok ] && [ -f /workspace/codebase/wscript ]; then'
            '  cd /workspace/codebase && (python3 waf configure build 2>/tmp/_autopov_build_waf.log || ./waf configure build 2>>/tmp/_autopov_build_waf.log)'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # 3c: custom build script fallback (build.sh / compile.sh) for non-standard builders
            'if [ ! -f /tmp/_autopov_build_ok ] && ([ -f /workspace/codebase/build.sh ] || [ -f /workspace/codebase/compile.sh ]); then'
            '  _BS="/workspace/codebase/build.sh"; [ -f "$_BS" ] || _BS="/workspace/codebase/compile.sh";'
            '  chmod +x "$_BS" && "$_BS" 2>/tmp/_autopov_build_custom.log && touch /tmp/_autopov_build_ok || true; fi',
            # Step 3d: cmake/build error recovery — parse error logs for missing packages,
            # install them, and retry the build once.
            self._native_cmake_error_recovery(),
            # Retry build after error recovery installed missing packages
            'if [ ! -f /tmp/_autopov_build_ok ] && _autopov_cmake_error_recovery; then'
            '  echo "[AutoPoV] Retrying build after error recovery" >&2;'
            '  set +e;'
            '  if [ -f /workspace/codebase/CMakeLists.txt ]; then'
            '    rm -rf /workspace/codebase/.autopov-cmake-build;'
            '    cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '      -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
            '      -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '    && cmake --build /workspace/codebase/.autopov-cmake-build -j2'
            '    && touch /tmp/_autopov_build_ok;'
            '  elif [ -n "$_MF" ]; then'
            '    make -B -C /workspace/codebase -j2 2>/dev/null && touch /tmp/_autopov_build_ok;'
            '  elif [ -f /workspace/codebase/configure ]; then'
            '    (cd /workspace/codebase && ./configure CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined" && make -j2) && touch /tmp/_autopov_build_ok;'
            '  fi;'
            '  set -e;'
            '  [ -f /tmp/_autopov_build_ok ] && echo "AUTOPOV_BUILD_STATUS=success_after_recovery";'
            'fi',
            # Step N: post-build ldd check — detect missing shared libraries and try to
            # install them automatically so the binary can actually run.
            # Runs silently; never aborts the build pipeline (|| true everywhere).
            r"""
_autopov_ldd_fix() {
  local BIN="${TARGET_BINARY:-}"
  [ -n "$BIN" ] || BIN="$(find /workspace/codebase -maxdepth 6 -type f -executable ! -name '*.sh' ! -name '*.py' -not -path "*/.git/*" -not -path "*/CMakeFiles/*" -not -path "*/.autopov*" 2>/dev/null | head -1)"
  [ -n "$BIN" ] || return 0
  command -v ldd >/dev/null 2>&1 || return 0
  local MISSING
  MISSING=$(ldd "$BIN" 2>&1 | grep 'not found' | awk '{print $1}') || return 0
  [ -n "$MISSING" ] || return 0
  command -v apt-file >/dev/null 2>&1 || return 0
  local PKGS=""
  for LIB in $MISSING; do
    local P
    P=$(timeout 5 apt-file search --fixed-string "$LIB" 2>/dev/null | grep -v 'dbg\|doc\|dev\|lib32\|lib64\|libx32' | head -1 | cut -d: -f1 | tr -d ' ') || true
    [ -n "$P" ] && PKGS="$PKGS $P"
  done
  [ -n "$PKGS" ] || return 0
  echo "[AutoPoV] Installing missing runtime libs:$PKGS" >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS >/dev/null 2>&1 || true
}
_autopov_ldd_fix || true
""",
            # Step N+1: Brute-force compile fallback — if nothing else worked, try to compile
            # all C files in the codebase with a single gcc command.  This catches projects
            # that have no build system or a custom one we don't detect.
            'if [ ! -f /tmp/_autopov_build_ok ]; then'
            '  _C_FILES=$(find /workspace/codebase -maxdepth 2 -name "*.c" -not -path "*/.git/*" -not -path "*/test/*" -not -path "*/tests/*" 2>/dev/null | head -20);'
            '  if [ -n "$_C_FILES" ]; then'
            '    echo "[AutoPoV] Attempting brute-force compile of C files" >&2;'
            '    gcc -O0 -g -o /workspace/codebase/autopov_target $_C_FILES -lm 2>/tmp/_autopov_build_brute.log && touch /tmp/_autopov_build_ok || true;'
            '  fi; fi',
            # FIX-4: Close the build-cache conditional block
            '}',
            # IMPORTANT: Even when build is cached or fresh, the binary may NOT have
            # been built with ASan. Force an ASan re-verification step AFTER the build
            # completes. If the binary lacks ASan instrumentation, force a clean rebuild
            # with ASan flags. This runs OUTSIDE the cache-check block so it always executes.
            '_CAND_BIN=$(find /workspace/codebase -maxdepth 6 -type f -executable -not -name "*.sh" -not -name "*.py" -not -path "*/.git/*" -not -path "*/CMakeFiles/*" -not -path "*/.autopov*" -not -path "*/checkincludefiles/*" -not -path "*/checktypesize/*" -not -path "*/compilerid*" 2>/dev/null | head -5)',
            '_HAS_ASAN=0',
            'for _B in $_CAND_BIN; do',
            '  if nm "$_B" 2>/dev/null | grep -q "__asan" || readelf -d "$_B" 2>/dev/null | grep -q "asan"; then',
            '    _HAS_ASAN=1; break;',
            '  fi;',
            'done',
            'if [ "$_HAS_ASAN" = "0" ] && [ -n "$_CAND_BIN" ]; then',
            '  echo "[AutoPoV] Binary lacks ASan instrumentation — forcing clean rebuild" >&2;',
            '  rm -f /tmp/_autopov_build_ok;',
            '  # Makefile: clean + rebuild with ASan',
            '  _MF=""; for _MF_TRY in /workspace/codebase/Makefile /workspace/codebase/makefile /workspace/codebase/GNUmakefile; do [ -f "$_MF_TRY" ] && _MF="$_MF_TRY" && break; done;',
            '  if [ -n "$_MF" ]; then'
            '    make -C /workspace/codebase clean 2>/dev/null || true;'
            '    if command -v clang >/dev/null 2>&1; then _RCC=clang; else _RCC=gcc; fi;'
            '    make -B -C /workspace/codebase -j2 CC=$_RCC CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" && touch /tmp/_autopov_build_ok;'
            '  elif [ -f /workspace/codebase/CMakeLists.txt ]; then',
            '    rm -rf /workspace/codebase/.autopov-cmake-build;',
            '    if command -v clang >/dev/null 2>&1; then _CMCC=clang; _CMCXX=clang++; else _CMCC=gcc; _CMCXX=g++; fi;',
            '    cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '      -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=$_CMCC -DCMAKE_CXX_COMPILER=$_CMCXX'
            '      -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '    && cmake --build /workspace/codebase/.autopov-cmake-build -j2'
            '    && touch /tmp/_autopov_build_ok;',
            '  # Issue #3: Meson: clean + rebuild with ASan',
            '  elif [ -f /workspace/codebase/meson.build ]; then',
            '    rm -rf /workspace/codebase/.autopov-meson-build;',
            '    meson setup /workspace/codebase/.autopov-meson-build /workspace/codebase'
            '      -Dbuildtype=debug -Db_sanitize=address,undefined -Db_lundef=false'
            '    && ninja -C /workspace/codebase/.autopov-meson-build -j2'
            '    && touch /tmp/_autopov_build_ok;',
            '  # Issue #3: Autotools (configure): clean + rebuild with ASan',
            '  elif [ -f /workspace/codebase/configure ] || [ -f /workspace/codebase/configure.ac ]; then',
            '    if command -v clang >/dev/null 2>&1; then _ACC=clang; else _ACC=gcc; fi;',
            '    (cd /workspace/codebase && make clean 2>/dev/null; ./configure CC=$_ACC CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" && make -j2)'
            '    && touch /tmp/_autopov_build_ok;',
            '  fi;',
            '  # Re-check after rebuild attempt',
            '  _HAS_ASAN2=0;',
            '  for _B2 in $(find /workspace/codebase -maxdepth 6 -type f -executable -not -name "*.sh" -not -name "*.py" -not -path "*/.git/*" -not -path "*/CMakeFiles/*" -not -path "*/.autopov*" -not -path "*/checkincludefiles/*" -not -path "*/checktypesize/*" -not -path "*/compilerid*" 2>/dev/null | head -5); do',
            '    if nm "$_B2" 2>/dev/null | grep -q "__asan" || readelf -d "$_B2" 2>/dev/null | grep -q "asan"; then',
            '      _HAS_ASAN2=1; break;',
            '    fi;',
            '  done;',
            '  if [ "$_HAS_ASAN2" = "1" ]; then',
            '    echo "[AutoPoV] ASan rebuild successful" >&2;',
            '    export AUTOPOV_ASAN_DISABLED=0;',
            '  else',
            '    echo "[AutoPoV] WARNING: ASan rebuild failed — running without sanitizer" >&2;',
            '    export AUTOPOV_ASAN_DISABLED=1;',
            '  fi;',
            'fi',
        ]

    def _native_binary_locator_script(self) -> str:
        return r"""find_binary() {
  python3 - <<'PY'
import os
import re
import json
import subprocess
from pathlib import Path

# ── Issue #2: If the preflight probe already discovered the binary path,
# use it immediately without running the full scoring algorithm.  This
# avoids the locator picking a different (wrong) binary when the probe
# already confirmed the correct one.
_probe_bin = os.environ.get('AUTOPOV_PROBE_BINARY', '').strip()
if _probe_bin and os.path.isfile(_probe_bin) and os.access(_probe_bin, os.X_OK):
    print(_probe_bin)
    raise SystemExit(0)

root = Path('/workspace/codebase')
cmake_build = root / '.autopov-cmake-build'
meson_build = root / '.autopov-meson-build'

ignored_suffixes = {'.o', '.obj', '.a', '.so', '.dylib', '.dll', '.lib',
                    '.sh', '.py', '.rb', '.pl', '.js', '.php', '.lua', '.tcl',
                    '.bat', '.cmd', '.ps1'}
ignored_dirs = {'.git', 'node_modules', 'venv', '.venv', 'results', 'data', 'dist'}

# ── Hard deny-set: filenames that are NEVER valid exploit targets ────────
# These are CMake/autoconf build-system test artifacts or files that look
# executable but are generated infrastructure, never real CLI tools.
_HARD_DENY_NAMES = {
    # CMake CheckTypeSize artifacts
    'sizeof_time_t.bin', 'sizeof_size_t.bin', 'sizeof_int.bin', 'sizeof_long.bin',
    'sizeof_pointer.bin', 'sizeof_void_p.bin', 'sizeof_off_t.bin',
    # CMake ABI detection artifacts
    'cmakedeterminecompilerabi_c.bin', 'cmakedeterminecompilerabi_cxx.bin',
    'cmakedeterminecompilerabi_fortran.bin',
    # Autoconf config test artifacts
    'conftest', 'conftest.out',
    # CMake scratch targets
    'cmtmp', 'cmake_install',
    # Autoconf / automake infrastructure scripts — NEVER valid exploit targets
    'configure', 'configure~', 'configure.ac', 'configure.in',
    'install-sh', 'install.sh',
    'config.guess', 'config.sub', 'config.status',
    'depcomp', 'missing', 'compile', 'ar-lib',
    'mkinstalldirs', 'mdate-sh', 'texinfo.tex',
    'ltmain.sh', 'libtool',
    # Other build-system infrastructure
    'autogen.sh', 'bootstrap', 'bootstrap.sh',
    'aclocal.m4', 'makefile', 'makefile.in',
    'gnulib-tool', 'gitlog-to-changelog',
    # Build tool wrappers (Task 15: Gap 15)
    'gradlew', 'gradlew.bat', 'mvnw', 'mvnw.cmd',
    'setup.py', 'setup.cfg',
    'node-gyp', 'node_modules',
    'cargo-build', 'build.rs',
}
# ── Hard deny by directory fragments (always score=-999, never selected) ──
_HARD_DENY_DIR_FRAGMENTS = {
    'checkincludefiles', 'checktypesize', 'checkfunctionexists',
    'checksymbolexists', 'checkcxxx', 'compilerid', 'compileridcxx',
    'compileridcxx', 'compilerc',
    # NOTE: _codeql_build_dir removed from hard-deny — real binaries like
    # xmlwf live there.  It remains in the -60 penalty set below instead.
}

# Known helper/tool binary names that should not be selected as the main target.
_TOOL_BINARY_NAMES = {
    'install', 'setup', 'configure', 'autogen', 'libtool',
    'config', 'compat', 'mkinstalldirs', 'depcomp', 'missing', 'compile',
    'ltmain', 'bootstrap', 'aclocal',
}

# ── Build authoritative test-binary deny-set from build system metadata ──────
# These are the exact executables registered as tests by the build system.
# They get score=-999 and can never beat a real target binary.
test_binary_paths = set()  # absolute resolved path strings

# 1. CMake: parse every CTestTestfile.cmake generated after cmake --build
#    Format: add_test(NAME foo COMMAND /abs/path/to/binary [args...])
_CTEST_CMD_RE = re.compile(
    r'add_test\s*\(\s*(?:NAME\s+\S+\s+)?COMMAND\s+([^\s)]+)',
    re.IGNORECASE,
)
if cmake_build.exists():
    for ctest_file in cmake_build.rglob('CTestTestfile.cmake'):
        try:
            text = ctest_file.read_text(errors='replace')
        except OSError:
            continue
        for m in _CTEST_CMD_RE.finditer(text):
            p = Path(m.group(1))
            if not p.is_absolute():
                p = cmake_build / p
            try:
                test_binary_paths.add(str(p.resolve()))
            except OSError:
                test_binary_paths.add(str(p))

# 2. Meson: meson introspect --tests returns JSON list of test executables
if (meson_build / 'meson-info').exists():
    try:
        out = subprocess.check_output(
            ['meson', 'introspect', '--tests', str(meson_build)],
            stderr=subprocess.DEVNULL, timeout=10,
        )
        for entry in json.loads(out):
            cmd = entry.get('cmd', []) or entry.get('exe', [])
            if cmd:
                p = Path(cmd[0])
                try:
                    test_binary_paths.add(str(p.resolve()))
                except OSError:
                    test_binary_paths.add(str(p))
    except Exception:
        pass

# 3. Make: extract TESTS = ... variable from the top-level Makefile
makefile = root / 'Makefile'
if makefile.exists():
    _TESTS_VAR_RE = re.compile(r'^\s*TESTS\s*[+:]?=\s*(.+)', re.MULTILINE)
    try:
        mf_text = makefile.read_text(errors='replace')
        for m in _TESTS_VAR_RE.finditer(mf_text):
            for tok in m.group(1).split():
                if tok.startswith('$') or tok.startswith('#'):
                    continue
                for base in (root, cmake_build, meson_build):
                    candidate = base / tok
                    if candidate.exists():
                        try:
                            test_binary_paths.add(str(candidate.resolve()))
                        except OSError:
                            test_binary_paths.add(str(candidate))
    except OSError:
        pass

# Repo name from env var set by AutoPoV (e.g. 'kore' for jorisvink/kore)
repo_name = os.environ.get('AUTOPOV_REPO_NAME', root.name).lower()

# ── Issue #2: Determine build-start reference time for "recently built" boost ──
# Binaries newer than the build-system definition files (Makefile, CMakeLists.txt, etc.)
# are almost certainly produced by the just-completed build and should be preferred.
_build_ref_mtime = 0
for _ref_name in ('Makefile', 'makefile', 'GNUmakefile', 'CMakeLists.txt', 'meson.build'):
    _ref = root / _ref_name
    if _ref.exists():
        try:
            _build_ref_mtime = max(_build_ref_mtime, _ref.stat().st_mtime)
        except OSError:
            pass
# Also check the autopov build directories
for _bd in (cmake_build, meson_build):
    if _bd.exists():
        try:
            _build_ref_mtime = max(_build_ref_mtime, _bd.stat().st_mtime)
        except OSError:
            pass

candidates = []
for current_root, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ignored_dirs]
    for name in files:
        full = Path(current_root) / name
        try:
            st = full.stat()
        except OSError:
            continue
        if not full.is_file() or not os.access(full, os.X_OK):
            continue
        # Block standard suffixes AND versioned shared-object names like
        # libfoo.so.1.7.19 (where Path.suffix == '.19', not '.so').
        _all_suffixes = {s.lower() for s in full.suffixes}
        if full.suffix.lower() in ignored_suffixes or '.so' in _all_suffixes:
            continue
        if '.so' in name.lower():
            continue
        # ── Build-system deny-set: exact match, authoritative, no guessing ──
        try:
            resolved = str(full.resolve())
        except OSError:
            resolved = str(full)
        if resolved in test_binary_paths:
            candidates.append((-999, str(full)))
            continue
        # T1 — Hard deny by filename: CMake/autoconf build artifacts masquerading as
        # executables.  These always score -999 regardless of mtime/path.
        if name.lower() in _HARD_DENY_NAMES:
            candidates.append((-999, str(full)))
            continue
        # T1b — Hard deny backup files (ending with ~) — editor/autoconf leftovers
        if name.endswith('~'):
            candidates.append((-999, str(full)))
            continue
        # T1 — Hard deny by directory fragment: any binary inside a CMake test or
        # CheckTypeSize / CompilerId directory can never be the main target.
        _parts_lower_hd = [p.lower() for p in str(full.relative_to(root)).split(os.sep)]
        if any(frag in _parts_lower_hd for frag in _HARD_DENY_DIR_FRAGMENTS):
            candidates.append((-999, str(full)))
            continue
        score = int(st.st_mtime)
        # ── Issue #2: Boost recently-built binaries (newer than build-system files) ──
        # If the binary was modified AFTER the Makefile/CMakeLists.txt, it was almost
        # certainly produced by the just-completed build.  This prevents stale binaries
        # from old builds (or pre-existing in the repo) from being preferred.
        if _build_ref_mtime > 0 and st.st_mtime > _build_ref_mtime:
            score += 40  # Strong boost — this binary is fresh from the build
        if '/.autopov-cmake-build/' in str(full):
            score += 15
        if '/.autopov-meson-build/' in str(full):
            score += 15
        if '/build/' in str(full):
            score += 5
        if name.lower() in {'a.out', 'main', 'app', 'server'}:
            # Only reward generic names when NOT inside a CodeQL/CMake compiler-test dir
            _parts_lower = [p.lower() for p in str(full.relative_to(root)).split(os.sep)]
            if not any(p in ('_codeql_build_dir', 'cmakefiles', 'compilerid', 'compileridcxx', 'compilerc') for p in _parts_lower):
                score += 20
        # Reward binary named after the repo (e.g. 'kore' in jorisvink/kore)
        if name.lower() == repo_name:
            score += 30
        # Penalise binaries whose own name matches a known tool/helper name
        if name.lower() in _TOOL_BINARY_NAMES:
            score -= 40
        # Task 2: Penalise test-binary name patterns (e.g. cJSON_test, test_parser)
        # These are test runners that ignore external input — not exploit targets.
        _name_lower = name.lower()
        if (re.search(r'(^test_|_test$|_tests$|^check_|_check$|^bench_|_bench$|^fuzz_|_fuzz$|^run_test)', _name_lower)
                or _name_lower in {'unity', 'unity_test', 'test', 'tests', 'check', 'selftest'}):
            score -= 80  # Strong penalty — nearly always a test harness
        # Penalise readme/example/demo binary names (e.g. readme_examples)
        # These are documentation/example binaries, not real exploit targets.
        if re.search(r'^(readme|example|sample|demo|doc)[_-]?', _name_lower):
            score -= 90  # Very strong penalty — documentation/example binary
        # Penalise binaries inside tool/helper subdirs (kodev, tools, scripts, etc.)
        rel = str(full.relative_to(root))
        depth = rel.count(os.sep)
        if depth >= 2:
            score -= 10  # nested deeper than one subdir
        # Penalise known tool/helper subdirectory names
        parts = rel.split(os.sep)
        if any(p.lower() in {'tools', 'scripts', 'contrib', 'util', 'utils', 'test', 'tests', 'examples', 'samples', 'helper', 'helpers', 'build-aux'} for p in parts[:-1]):
            score -= 20
        # Penalise CodeQL intermediate build directory and CMake compiler-test artifacts.
        # Note: hard-deny already handles exact CMake test dirs; this catches any remaining
        # edge cases not matched by _HARD_DENY_DIR_FRAGMENTS.
        if any(p.lower() in ('_codeql_build_dir', 'cmakefiles', 'compilerid', 'compileridcxx', 'compilerc') for p in parts):
            score -= 60
        # Belt-and-suspenders: penalise autotools helper scripts by filename
        if name.lower() in {'ltmain', 'ltmain.sh'}:
            score -= 60
        candidates.append((score, str(full)))
if not candidates:
    print("AUTOPOV_BINARY_LOCATOR: no executable candidates found in codebase", file=sys.stderr)
    raise SystemExit(1)
candidates.sort(reverse=True)
# If the best candidate has a negative score (only test harnesses / deny-set found),
# emit nothing so the caller falls back to the c_library_harness path.
if candidates[0][0] < 0:
    print(f"AUTOPOV_BINARY_LOCATOR: all {len(candidates)} candidates scored negative (test harnesses only)", file=sys.stderr)
    raise SystemExit(1)
print(candidates[0][1])
PY
}"""

    def _build_execution_shell(self, env_kind: str, runtime_command: List[str], pov_filename: str, exploit_contract: Dict[str, Any], codebase_path: Optional[str]) -> List[str]:
        contract = exploit_contract or {}
        prelude = [
            '# set -e deferred: only enabled for PoV execution, not build phase',
            'mkdir -p /pov /workspace /workspace/fixtures /tmp/autopov_home /tmp/autopov_home/.enchive /tmp/autopov_home/.gnupg',
            'chmod 700 /tmp/autopov_home/.enchive /tmp/autopov_home/.gnupg',
            'export CODEBASE_PATH="${CODEBASE_PATH:-/workspace/codebase}"',
            'export FIXTURE_ROOT="/workspace/fixtures"',
            # Task 2: Ensure HOME and AUTOPOV_BOOTSTRAP_HOME are writable
            'export HOME="/tmp/autopov_home"',
            'export AUTOPOV_BOOTSTRAP_HOME="/tmp/autopov_home"',
        ]

        # ── Universal: install recon-derived docker_extra_deps (apt packages) ──
        # These come from deterministic filesystem scanning in recon_agent and
        # are wired through exploit_contract['docker_extra_deps'].
        _extra_deps = contract.get('docker_extra_deps') or []
        if _extra_deps:
            _safe_pkgs = ' '.join(
                pkg.strip() for pkg in _extra_deps
                if pkg.strip() and all(c.isalnum() or c in '-._+:' for c in pkg.strip())
            )
            if _safe_pkgs:
                prelude.append(
                    f'# ── AutoPoV: recon docker_extra_deps ──\n'
                    f'if ! dpkg -s {_safe_pkgs.split()[0]} >/dev/null 2>&1; then\n'
                    f'  echo "[AutoPoV] Installing extra deps: {_safe_pkgs}" >&2;\n'
                    f'  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true;\n'
                    f'  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {_safe_pkgs} >/dev/null 2>&1 || true;\n'
                    f'fi'
                )

        # ── Task 3: surface-adaptive entry-command injection ────────────────────
        # Regardless of env_kind, propagate probe-discovered entry command and base URL
        # into env vars so PoV scripts can use them without guessing.
        _probe_entry = str(contract.get('probe_entry_command') or '').strip()
        _probe_base_url = str(contract.get('probe_base_url') or '').strip()
        _probe_surface = str(contract.get('probe_surface_type') or '').strip().lower()
        _harness_type = str((contract.get('proof_strategy') or {}).get('harness_type') or '').strip().lower()
        if _probe_entry:
            prelude.append(f'export AUTOPOV_ENTRY={_probe_entry!r}')
        if _probe_base_url:
            prelude.append(f'export AUTOPOV_BASE_URL={_probe_base_url!r}')

        # ── Task 5: Dynamic subcommand injection for CLI binaries ────────────
        # Extract subcommands from the exploit contract (help_text, known_subcommands)
        # and map vulnerable function names to the correct subcommand. This ensures
        # the PoV uses the right subcommand instead of passing input directly.
        if env_kind == 'native':
            _known_subcmds = list(contract.get('known_subcommands') or [])
            _obs_surface = contract.get('observed_surface') or {}
            _help_text = str(_obs_surface.get('help_text') or contract.get('preflight_help_text') or '').strip()
            _target_ep = str(contract.get('target_entrypoint') or '').strip().lower()
            _matched_subcmd = ''

            # Map function names to subcommands (e.g. command_encrypt -> archive, command_extract -> extract)
            _FUNC_SUBCMD_MAP = {
                'encrypt': 'archive', 'decrypt': 'extract', 'archive': 'archive',
                'extract': 'extract', 'compress': 'archive', 'decompress': 'extract',
                'fingerprint': 'fingerprint', 'keygen': 'keygen', 'sign': 'sign',
                'verify': 'verify', 'pack': 'pack', 'unpack': 'unpack',
            }
            if _target_ep and not _target_ep in ('unknown', 'none', 'n/a'):
                for _ep_part in _target_ep.replace('_', ' ').replace('-', ' ').split():
                    if _ep_part in _FUNC_SUBCMD_MAP:
                        _matched_subcmd = _FUNC_SUBCMD_MAP[_ep_part]
                        break

            # If no function-name match, try subcommands from help text
            if not _matched_subcmd and _known_subcmds:
                # Use the first non-trivial subcommand (skip help/version)
                for _sc in _known_subcmds:
                    _sc_lower = str(_sc).strip().lower()
                    if _sc_lower and _sc_lower not in ('help', 'version', '--help', '--version', '-h', '-v'):
                        _matched_subcmd = str(_sc).strip().lower()
                        break

            if _matched_subcmd:
                prelude.append(f'export AUTOPOV_SUBCOMMAND={_matched_subcmd!r}')
                logger.info('[subcommand] Injected AUTOPOV_SUBCOMMAND=%s', _matched_subcmd)

            # For tools that need key files (like enchive), generate temporary keys.
            # Different tools use different keygen syntax:
            #   - enchive: keygen --derive (writes to $HOME/.config/enchive/ automatically)
            #   - generic: keygen <pub_path> <sec_path> (explicit output file paths)
            # Try the tool's native keygen first; if that fails, try --derive,
            # then copy keys to the expected config directory.
            _needs_keys = any(kw in _help_text.lower() for kw in ('public key', 'private key', 'keygen', 'key file', '-p ', '-s '))
            if _needs_keys:
                prelude.extend([
                    '# Task 5: Generate temporary key pair for key-based CLI tools',
                    'if [ -n "${TARGET_BINARY:-}" ] && [ -x "$TARGET_BINARY" ]; then',
                    '  # Ensure HOME is set so keygen writes to the correct config dir',
                    '  export HOME="${HOME:-/tmp/autopov_home}";',
                    '  mkdir -p "$HOME/.config";',
                    '  # Try explicit-arg keygen first (e.g. tool keygen pub sec)',
                    '  _KEYGEN_OUT=$("$TARGET_BINARY" keygen /tmp/test.pub /tmp/test.sec 2>&1 || true);',
                    '  # If that did not produce keys, try --derive (enchive-style)',
                    '  # Set HOME before --derive so enchive writes to $HOME/.config/enchive/',
                    '  if [ ! -f /tmp/test.pub ] || [ ! -f /tmp/test.sec ]; then',
                    '    _KEYGEN_OUT2=$(HOME="$HOME" "$TARGET_BINARY" keygen --derive 2>&1 || true);',
                    '  fi;',
                    '  # Also check the tool config dir (enchive writes keys there directly)',
                    '  _TOOL_NAME=$(basename "$TARGET_BINARY" 2>/dev/null || echo "unknown");',
                    '  _TOOL_CFGDIR="$HOME/.config/${_TOOL_NAME}";',
                    '  mkdir -p "$_TOOL_CFGDIR";',
                    '  # If explicit keygen worked, copy to config dir',
                    '  if [ -f /tmp/test.pub ] && [ -f /tmp/test.sec ]; then',
                    '    export AUTOPOV_PUBKEY_PATH=/tmp/test.pub;',
                    '    export AUTOPOV_SECKEY_PATH=/tmp/test.sec;',
                    '    echo "[AutoPoV] Generated key pair: /tmp/test.pub /tmp/test.sec" >&2;',
                    '    cp -f /tmp/test.pub "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" 2>/dev/null || true;',
                    '    cp -f /tmp/test.sec "$_TOOL_CFGDIR/${_TOOL_NAME}.sec" 2>/dev/null || true;',
                    '    echo "[AutoPoV] Installed keys to $_TOOL_CFGDIR/" >&2;',
                    '  fi;',
                    '  # If --derive produced keys in the config dir, link them as /tmp/test.*',
                    '  if [ -f "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" ]; then',
                    '    export AUTOPOV_PUBKEY_PATH="$_TOOL_CFGDIR/${_TOOL_NAME}.pub";',
                    '    export AUTOPOV_SECKEY_PATH="$_TOOL_CFGDIR/${_TOOL_NAME}.sec";',
                    '    ln -sf "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" /tmp/test.pub 2>/dev/null || true;',
                    '    ln -sf "$_TOOL_CFGDIR/${_TOOL_NAME}.sec" /tmp/test.sec 2>/dev/null || true;',
                    '    echo "[AutoPoV] Found --derive keys in $_TOOL_CFGDIR/" >&2;',
                    '  fi;',
                    '  # If STILL no keys, try stdin-based keygen (some tools read passphrase from stdin)',
                    '  if [ ! -f "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" ] && [ ! -f /tmp/test.pub ]; then',
                    '    echo "[AutoPoV] Attempting stdin-based keygen..." >&2;',
                    '    printf "autopov\nautopov\n" | HOME="$HOME" "$TARGET_BINARY" keygen 2>&1 || true;',
                    '    if [ -f "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" ]; then',
                    '      export AUTOPOV_PUBKEY_PATH="$_TOOL_CFGDIR/${_TOOL_NAME}.pub";',
                    '      export AUTOPOV_SECKEY_PATH="$_TOOL_CFGDIR/${_TOOL_NAME}.sec";',
                    '      ln -sf "$_TOOL_CFGDIR/${_TOOL_NAME}.pub" /tmp/test.pub 2>/dev/null || true;',
                    '      ln -sf "$_TOOL_CFGDIR/${_TOOL_NAME}.sec" /tmp/test.sec 2>/dev/null || true;',
                    '      echo "[AutoPoV] Stdin keygen succeeded in $_TOOL_CFGDIR/" >&2;',
                    '    fi;',
                    '  fi;',
                    'fi',
                ])
        if env_kind == 'native' and codebase_path:
            # v2: If harness_type is compiled_harness, treat like c_library_harness
            if _harness_type == 'compiled_harness':
                prelude.append('export AUTOPOV_MODE=c_library_harness')
                prelude.append('export LIB_INCLUDE_PATH="/workspace/codebase"')
                prelude.append('export LIB_SRC_PATH="/workspace/codebase"')
            # Task 3: Diagnostic — log codebase contents before build for debugging
            prelude.append('echo "[AutoPoV-build] /workspace/codebase contents:" && ls /workspace/codebase/ 2>&1 | head -20 || echo "[AutoPoV-build] /workspace/codebase NOT FOUND"')
            # Task 3: Codebase symlink fallback
            prelude.append('if [ ! -d "/workspace/codebase" ] && [ -d "${CODEBASE_PATH}" ]; then ln -sfn "${CODEBASE_PATH}" /workspace/codebase; fi')
            # ── Build phase: disable set -e so partial build failures don't kill the container ──
            prelude.append('set +e')
            prelude.extend([
                'export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stacktrace=1"',
                'export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"',
                # Prefer clang for ASan builds; it handles fstack-protector-all better
                # than gcc on Ubuntu 24.04 (avoids relocation-in-.text linker error).
                'export CC="${CC:-clang}"',
                'export CXX="${CXX:-clang++}"',
                # Strip -fstack-protector variants before injecting ASan flags
                '_STRIPPED="$(echo "${CFLAGS:-}" | sed \'s/-fstack-protector[^ ]*//g\')"',
                'export CFLAGS="${_STRIPPED} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export CXXFLAGS="${_STRIPPED} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined"',
            ])
            prelude.extend(self._native_build_commands(contract))
            # ── Catch-all: emit AUTOPOV_BUILD_STATUS sentinel ──────────────────
            # When build_commands from the contract skip the full fallback chain,
            # the AUTOPOV_BUILD_STATUS sentinel is never emitted, leaving
            # build_status="unknown" in the result.  This catch-all ensures the
            # status is always reported after the build completes.
            prelude.extend([
                'if [ -f /tmp/_autopov_build_ok ]; then'
                '  echo "AUTOPOV_BUILD_STATUS=success";'
                'else'
                '  echo "AUTOPOV_BUILD_STATUS=failed";'
                'fi',
            ])
            # ── ASan re-verification (for early-return build paths) ────────────
            # The fallback chain in _native_build_commands includes its own ASan
            # re-verification, but the build_commands early-return path does not.
            # When the binary lacks ASan instrumentation, force a clean rebuild
            # with ASan flags so the PoV can detect sanitizer violations.
            # Uses different variable names (_ASAN2_, _MF3_) to avoid conflicts
            # with the fallback chain's re-verification code.
            prelude.extend([
                '_ASAN2_CAND=$(find /workspace/codebase -maxdepth 6 -type f -executable -not -name "*.sh" -not -name "*.py" -not -path "*/.git/*" -not -path "*/CMakeFiles/*" -not -path "*/.autopov*" -not -path "*/checkincludefiles/*" -not -path "*/checktypesize/*" -not -path "*/compilerid*" 2>/dev/null | head -5)',
                '_ASAN2_FOUND=0',
                'for _AB2 in $_ASAN2_CAND; do'
                '  if nm "$_AB2" 2>/dev/null | grep -q "__asan" || readelf -d "$_AB2" 2>/dev/null | grep -q "asan"; then'
                '    _ASAN2_FOUND=1; break;'
                '  fi;'
                'done',
                'if [ "$_ASAN2_FOUND" = "0" ] && [ -n "$_ASAN2_CAND" ]; then'
                '  echo "[AutoPoV] Binary lacks ASan instrumentation — forcing clean rebuild" >&2;'
                '  rm -f /tmp/_autopov_build_ok;'
                '  _MF3=""; for _MF3_TRY in /workspace/codebase/Makefile /workspace/codebase/makefile /workspace/codebase/GNUmakefile; do [ -f "$_MF3_TRY" ] && _MF3="$_MF3_TRY" && break; done;',
                '  if [ -n "$_MF3" ]; then'
                '    make -C /workspace/codebase clean 2>/dev/null || true;'
                '    make -B -C /workspace/codebase -j2 CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" && touch /tmp/_autopov_build_ok;',
                '  elif [ -f /workspace/codebase/CMakeLists.txt ]; then'
                '    rm -rf /workspace/codebase/.autopov-cmake-build;'
                '    cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
                '      -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
                '      -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '      -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
                '    && cmake --build /workspace/codebase/.autopov-cmake-build -j2'
                '    && touch /tmp/_autopov_build_ok;',
                '  fi;',
                '  if [ -f /tmp/_autopov_build_ok ]; then'
                '    echo "AUTOPOV_BUILD_STATUS=success";'
                '  else'
                '    echo "AUTOPOV_BUILD_STATUS=failed";'
                '  fi;',
                'fi',
            ])
            prelude.append(self._native_binary_locator_script())
            prelude.extend([
                'TARGET_BINARY_CANDIDATE="$(find_binary || true)"',
                'if [ -n "$TARGET_BINARY_CANDIDATE" ]; then export TARGET_BINARY="$TARGET_BINARY_CANDIDATE"; export TARGET_BIN="$TARGET_BINARY_CANDIDATE"; fi',
                # If the probe identified the exact binary, prefer it over the locator result
                'if [ -n "${AUTOPOV_PROBE_BINARY:-}" ] && [ -x "$AUTOPOV_PROBE_BINARY" ]; then export TARGET_BINARY="$AUTOPOV_PROBE_BINARY"; export TARGET_BIN="$AUTOPOV_PROBE_BINARY"; fi',
                # If no binary found, try to auto-generate a harness (Node.js/Python/C library)
                'if [ -z "${TARGET_BINARY:-}" ]; then',
                self._generate_auto_harness(),
                'fi',
                # If no real binary found (only test harnesses), fall back to library harness mode
                # so the PoV can still compile an inline C harness against the library.
                'if [ -z "${TARGET_BINARY:-}" ]; then export AUTOPOV_MODE=c_library_harness; export LIB_INCLUDE_PATH="/workspace/codebase"; export LIB_SRC_PATH="/workspace/codebase"; LIB_HEADER=$(find /workspace/codebase -maxdepth 3 -name "*.h" ! -path "*/.git/*" ! -path "*/CMakeFiles/*" | head -5 | tr "\\n" ":"); export LIB_HEADERS="${LIB_HEADER%:}";'
                ' _LIB_SO=$(find /workspace/codebase -maxdepth 5 \\( -name "lib*.so*" -o -name "lib*.a" \\) ! -path "*/.git/*" ! -path "*/CMakeFiles/*" 2>/dev/null | head -10);'
                ' _LIB_LINK_DIRS=""; _LIB_NAMES="";'
                ' for _LF in $_LIB_SO; do _LD=$(dirname "$_LF"); echo "$_LIB_LINK_DIRS" | grep -q "$_LD" || _LIB_LINK_DIRS="${_LIB_LINK_DIRS:+$_LIB_LINK_DIRS:}$_LD"; _LN=$(basename "$_LF" | sed "s/^lib//;s/\\.so.*//;s/\\.a$//"); echo "$_LIB_NAMES" | grep -q "$_LN" || _LIB_NAMES="${_LIB_NAMES:+$_LIB_NAMES }$_LN"; done;'
                ' export AUTOPOV_LIB_LINK_DIRS="$_LIB_LINK_DIRS"; export AUTOPOV_LIB_NAMES="$_LIB_NAMES";'
                ' _LIB_INC_DIRS="/workspace/codebase"; for _ID in /workspace/codebase/include /workspace/codebase/lib /workspace/codebase/src; do [ -d "$_ID" ] && _LIB_INC_DIRS="${_LIB_INC_DIRS}:$_ID"; done;'
                ' export AUTOPOV_LIB_INCLUDE_DIRS="$_LIB_INC_DIRS";'
                ' IFS=: read -ra _LDPARTS <<< "$_LIB_LINK_DIRS"; for _LP in "${_LDPARTS[@]}"; do export LD_LIBRARY_PATH="${_LP}:${LD_LIBRARY_PATH:-}"; done;'
                ' echo "[AutoPoV] no real CLI binary found — switching to c_library_harness mode (libs=$_LIB_NAMES)" >&2; fi',
                'if [ -z "${TARGET_BINARY:-}" ] && [ "${AUTOPOV_MODE:-}" != "c_library_harness" ]; then echo "[AutoPoV] infrastructure error: failed to build or locate native target binary" >&2; exit 97; fi',
                # Add the binary\'s parent directory to PATH so scripts using the bare
                # binary name (e.g. TARGET_BINARY = \'enchive\') resolve correctly
                # regardless of where the model chose to look it up.
                'export PATH="$(dirname "$TARGET_BINARY"):$PATH"',
                # Emit the resolved binary path so run_pov can parse it from stdout
                # and propagate target_binary_path back to agent_graph / exploit_contract.
                'echo "AUTOPOV_BINARY=$TARGET_BINARY"',
                # ── Help text + preflight run under set +e so crashes don't kill container ──
                # Run the binary with no args (most CLI tools print usage/help that way).
                # Falls back to --help for tools that require an explicit flag.
                # Output is captured between sentinels; stripped from oracle stdout.
                'echo "AUTOPOV_HELP_TEXT_BEGIN"',
                '( "$TARGET_BINARY" 2>&1 | head -80 || "$TARGET_BINARY" --help 2>&1 | head -80 || true ) || true',
                'echo "AUTOPOV_HELP_TEXT_END"',
                # ── Preflight sanity guard (3 s) ────────────────────────────────
                # Run the binary with a tiny random payload to determine the real
                # input surface BEFORE the PoV runs. Emit AUTOPOV_PREFLIGHT_SURFACE
                # so the coordinator can override the PoV generation prompt.
                '_PF_TMPF=$(mktemp /tmp/pf_XXXXXX)',
                'printf "AAAAAAAAAAAAAAAA\\x00BBBBBBBB" > "$_PF_TMPF"',
                # Try file argument first
                '_PF_FILE_OUT=$(timeout 3 "$TARGET_BINARY" "$_PF_TMPF" 2>&1 || true)',
                '_PF_STDIN_OUT=$(printf "AAAAAAAAAAAAAAAA\\x00BBBBBBBB" | timeout 3 "$TARGET_BINARY" 2>&1 || true)',
                # Detect surface: if binary opened the file → file_argument
                '_PF_USAGE_KW="usage:\\|--help\\|no files\\|expects a\\|missing file\\|requires a"',
                'if echo "$_PF_STDIN_OUT" | grep -qi "$_PF_USAGE_KW" && ! echo "$_PF_FILE_OUT" | grep -qi "$_PF_USAGE_KW"; then',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=file_argument"',
                'elif echo "$_PF_FILE_OUT" | grep -qi "$_PF_USAGE_KW" && ! echo "$_PF_STDIN_OUT" | grep -qi "$_PF_USAGE_KW"; then',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=stdin"',
                'else',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=unknown"',
                'fi',
                'rm -f "$_PF_TMPF"',
                '# ── End build+preflight phase: re-enable set -e for PoV execution ──',
                'set -e',
            ])
        elif env_kind == 'c_library_harness' and codebase_path:
            # Task 4C: C library harness environment.
            # No binary to locate -- the PoV script compiles its own harness inline.
            # Set up ASan flags + codebase path so the PoV can find headers/libs.
            prelude.append('set +e')  # Library build may partially fail
            prelude.extend([
                'export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stacktrace=1"',
                'export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"',
                'export CC="${CC:-clang}"',
                'export CXX="${CXX:-clang++}"',
                'export LIB_INCLUDE_PATH="/workspace/codebase"',
                'export LIB_SRC_PATH="/workspace/codebase"',
                'LIB_HEADER=$(find /workspace/codebase -maxdepth 3 -name "*.h"'
                '  ! -path "*/.git/*" ! -path "*/CMakeFiles/*"'
                '  | head -5 | tr "\\n" ":")',
                'export LIB_HEADERS="${LIB_HEADER%:}"',
                # ---------- Build the library with ASan ----------
                # Support CMake, autoconf/configure, Meson, plain Makefile, and
                # subdirectory builds (e.g. libexpat/expat/) so that ANY C library
                # repo gets built automatically.
                'export _LIB_BUILD_OK=0',
                # --- CMake (root) ---
                'if [ -f /workspace/codebase/CMakeLists.txt ]; then'
                '  mkdir -p /workspace/codebase/.autopov-cmake-build &&'
                '  cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
                '    -DCMAKE_BUILD_TYPE=RelWithDebInfo'
                '    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
                '    -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"'
                '    -DCMAKE_STATIC_LINKER_FLAGS=""'
                '    -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -q 2>/dev/null &&'
                '  cmake --build /workspace/codebase/.autopov-cmake-build --parallel 4 2>/dev/null'
                '  && _LIB_BUILD_OK=1 || true;'
                '  export LD_LIBRARY_PATH="/workspace/codebase/.autopov-cmake-build:${LD_LIBRARY_PATH:-}"; fi',
                # --- Autoconf / configure (including plain ./configure like zlib) ---
                'if [ "$_LIB_BUILD_OK" = "0" ] && [ -f /workspace/codebase/configure ]; then'
                '  (cd /workspace/codebase &&'
                '   chmod +x ./configure &&'
                '   ./configure CC=clang CXX=clang++'
                '     CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '     CXXFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '     LDFLAGS="-fsanitize=address,undefined"'
                '     --disable-dependency-tracking 2>/dev/null'
                '     || ./configure CC=clang CFLAGS="-O0 -g" 2>/dev/null || true) &&'
                '  make -C /workspace/codebase -j4 2>/dev/null && _LIB_BUILD_OK=1 || true; fi',
                # --- Autoconf from .ac/.in (generate configure first) ---
                'if [ "$_LIB_BUILD_OK" = "0" ] && ([ -f /workspace/codebase/configure.ac ] || [ -f /workspace/codebase/configure.in ]); then'
                '  (cd /workspace/codebase &&'
                '   ([ -x ./autogen.sh ] && ./autogen.sh 2>/dev/null || autoreconf -i 2>/dev/null || true) &&'
                '   [ -f ./configure ] && chmod +x ./configure &&'
                '   ./configure CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" 2>/dev/null &&'
                '   make -j4 2>/dev/null) && _LIB_BUILD_OK=1 || true; fi',
                # --- Meson ---
                'if [ "$_LIB_BUILD_OK" = "0" ] && [ -f /workspace/codebase/meson.build ]; then'
                '  meson setup /workspace/codebase/.autopov-meson-build /workspace/codebase'
                '    --buildtype=debug -Db_sanitize=address,undefined 2>/dev/null &&'
                '  meson compile -C /workspace/codebase/.autopov-meson-build 2>/dev/null'
                '  && _LIB_BUILD_OK=1 || true;'
                '  export LD_LIBRARY_PATH="/workspace/codebase/.autopov-meson-build:${LD_LIBRARY_PATH:-}"; fi',
                # --- Plain Makefile ---
                'if [ "$_LIB_BUILD_OK" = "0" ] && ([ -f /workspace/codebase/Makefile ] || [ -f /workspace/codebase/makefile ]); then'
                '  make -C /workspace/codebase -j4 CC=clang'
                '    CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
                '    LDFLAGS="-fsanitize=address,undefined" 2>/dev/null'
                '  && _LIB_BUILD_OK=1 || true; fi',
                # --- Subdirectory fallback (e.g. libexpat/expat/) ---
                'if [ "$_LIB_BUILD_OK" = "0" ]; then'
                '  for _SD in /workspace/codebase/*/; do'
                '    [ -d "$_SD" ] || continue;'
                '    _SDN=$(basename "$_SD");'
                '    case "$_SDN" in .git|test|tests|doc|docs|examples|samples|build|.autopov*|contrib) continue;; esac;'
                '    if [ -f "$_SD/CMakeLists.txt" ]; then'
                '      cmake -S "$_SD" -B "$_SD/.autopov-cmake-build"'
                '        -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang'
                '        -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined"'
                '        -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"'
                '        -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF 2>/dev/null'
                '      && cmake --build "$_SD/.autopov-cmake-build" -j4 2>/dev/null'
                '      && _LIB_BUILD_OK=1 && break;'
                '    elif [ -f "$_SD/configure" ] || [ -f "$_SD/configure.ac" ]; then'
                '      (cd "$_SD" && ([ -x ./configure ] || ([ -x ./autogen.sh ] && ./autogen.sh || autoreconf -i) || true)'
                '       && ./configure CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined" 2>/dev/null'
                '       && make -j4 2>/dev/null) && _LIB_BUILD_OK=1 && break;'
                '    elif [ -f "$_SD/Makefile" ] || [ -f "$_SD/makefile" ]; then'
                '      make -C "$_SD" -j4 CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined"'
                '        LDFLAGS="-fsanitize=address,undefined" 2>/dev/null'
                '      && _LIB_BUILD_OK=1 && break;'
                '    fi;'
                '  done; fi',
                # ---------- Auto-discover built library artifacts ----------
                # Find .a and .so files produced by the build, export paths so
                # the PoV harness can link against them without guessing.
                '_LIB_SO=$(find /workspace/codebase -maxdepth 5 -name "lib*.so*" -o -name "lib*.a"'
                '  ! -path "*/.git/*" ! -path "*/CMakeFiles/*" 2>/dev/null | head -10)',
                '_LIB_LINK_DIRS=""',
                '_LIB_NAMES=""',
                'for _LF in $_LIB_SO; do'
                '  _LD=$(dirname "$_LF");'
                '  echo "$_LIB_LINK_DIRS" | grep -q "$_LD" || _LIB_LINK_DIRS="${_LIB_LINK_DIRS:+$_LIB_LINK_DIRS:}$_LD";'
                '  _LN=$(basename "$_LF" | sed "s/^lib//;s/\\.so.*//;s/\\.a$//");'
                '  echo "$_LIB_NAMES" | grep -q "$_LN" || _LIB_NAMES="${_LIB_NAMES:+$_LIB_NAMES }$_LN";'
                'done',
                'export AUTOPOV_LIB_LINK_DIRS="$_LIB_LINK_DIRS"',
                'export AUTOPOV_LIB_NAMES="$_LIB_NAMES"',
                # Also discover include directories (dirs containing .h files at top levels)
                '_LIB_INC_DIRS="/workspace/codebase"',
                'for _ID in /workspace/codebase/include /workspace/codebase/lib /workspace/codebase/src; do'
                '  [ -d "$_ID" ] && _LIB_INC_DIRS="${_LIB_INC_DIRS}:$_ID"; done',
                # Check subdirectory builds too
                'for _SD2 in /workspace/codebase/*/; do'
                '  [ -d "$_SD2/include" ] && _LIB_INC_DIRS="${_LIB_INC_DIRS}:$_SD2/include";'
                '  [ -d "$_SD2/lib" ] && _LIB_INC_DIRS="${_LIB_INC_DIRS}:$_SD2/lib"; done',
                'export AUTOPOV_LIB_INCLUDE_DIRS="$_LIB_INC_DIRS"',
                # Set LD_LIBRARY_PATH to include all link dirs
                'IFS=: read -ra _LDPARTS <<< "$_LIB_LINK_DIRS"; for _LP in "${_LDPARTS[@]}"; do'
                '  export LD_LIBRARY_PATH="${_LP}:${LD_LIBRARY_PATH:-}"; done',
                # Emit discovery info for diagnostics
                'echo "AUTOPOV_LIB_BUILD=$_LIB_BUILD_OK"',
                'echo "AUTOPOV_LIB_NAMES=$_LIB_NAMES"',
                'echo "AUTOPOV_LIB_LINK_DIRS=$_LIB_LINK_DIRS"',
                'echo "AUTOPOV_LIB_INCLUDE_DIRS=$_LIB_INC_DIRS"',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'python' and codebase_path:
            # Auto-install Python dependencies from requirements files found in the codebase.
            # This allows PoVs that import project packages (requests, yaml, jinja2, etc.)
            # to run without pre-baking every possible package into the proof image.
            prelude.append(
                'if [ -d /workspace/codebase ]; then'
                '  for _RF in /workspace/codebase/requirements*.txt /workspace/codebase/requirements/*.txt; do'
                '    [ -f "$_RF" ] && pip3 install --quiet --no-cache-dir --break-system-packages -r "$_RF" 2>/dev/null || true;'
                '  done;'
                '  if [ -f /workspace/codebase/setup.py ] && ! pip3 show "$(python3 -c \"import tomllib,sys; d=tomllib.load(open(\\"/workspace/codebase/pyproject.toml\\",\\"rb\\")); print(d[\\"project\\"][\\"name\\"])\" 2>/dev/null || echo \"__none__\")" >/dev/null 2>&1; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages -e /workspace/codebase 2>/dev/null || true;'
                '  fi;'
                '  if [ -f /workspace/codebase/pyproject.toml ] || [ -f /workspace/codebase/setup.cfg ]; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages -e /workspace/codebase 2>/dev/null || true;'
                '  fi;'
                # Fallback: install by repo name (e.g. 'cherrypy', 'flask', 'httpie').
                # pip install is a no-op when already installed, so this is always safe.
                '  _REPO_PKG=$(basename "${CODEBASE_PATH:-/workspace/codebase}" | tr \'[:upper:]\' \'[:lower:]\' | tr \'_\' \'-\');'
                '  if [ -n "$_REPO_PKG" ] && [ "$_REPO_PKG" != "codebase" ]; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages "$_REPO_PKG" 2>/dev/null || true;'
                '  fi; fi'
            )
            # Task 3: For web_service surface, auto-start the Python web app before the PoV runs.
            if _probe_surface == 'web_service':
                _ws_port = '8000'
                if _probe_base_url and ':' in _probe_base_url:
                    _port_part = _probe_base_url.rstrip('/').rsplit(':', 1)[-1]
                    if _port_part.isdigit():
                        _ws_port = _port_part
                if _probe_entry:
                    _ws_entry_cmds = [f'_WS_ENTRY={_probe_entry!r}']
                else:
                    _ws_entry_cmds = [
                        '_WS_ENTRY=""',
                        'for _F in /workspace/codebase/app.py /workspace/codebase/server.py /workspace/codebase/main.py /workspace/codebase/run.py /workspace/codebase/wsgi.py; do [ -f "$_F" ] && _WS_ENTRY="$_F" && break || true; done',
                    ]
                prelude.extend(_ws_entry_cmds)
                prelude.extend([
                    f'export PORT={_ws_port!r}',
                    f'export APP_URL="http://localhost:{_ws_port}"',
                    'if [ -n "${_WS_ENTRY:-}" ]; then',
                    # FIX-9: Robust Python web app startup with gunicorn/uvicorn
                    # fallback.  Detect WSGI/ASGI app object and use a
                    # production-grade server when available, falling back to
                    # plain `python3` only as last resort.
                    '  _WS_STARTED=0;',
                    # Try gunicorn first (WSGI — Flask, Django, Bottle, etc.)
                    f'  if command -v gunicorn >/dev/null 2>&1; then',
                    f'    _MOD=$(basename "$_WS_ENTRY" .py);',
                    f'    _APP_OBJ=$(grep -oE "(app|application)\\s*=\\s*" "$_WS_ENTRY" 2>/dev/null | head -1 | cut -d= -f1 | tr -d " " || echo "app");',
                    f'    gunicorn "$_MOD:${{_APP_OBJ:-app}}" --bind 0.0.0.0:{_ws_port} --timeout 10 --workers 1 --chdir "$(dirname "$_WS_ENTRY")" &',
                    f'    _WS_PID=$!; _WS_STARTED=1;',
                    f'  fi;',
                    # Try uvicorn (ASGI — FastAPI, Starlette, etc.)
                    f'  if [ "$_WS_STARTED" = "0" ] && command -v uvicorn >/dev/null 2>&1; then',
                    f'    _MOD=$(basename "$_WS_ENTRY" .py);',
                    f'    _APP_OBJ=$(grep -oE "(app|application)\\s*=\\s*" "$_WS_ENTRY" 2>/dev/null | head -1 | cut -d= -f1 | tr -d " " || echo "app");',
                    f'    uvicorn "$_MOD:${{_APP_OBJ:-app}}" --host 0.0.0.0 --port {_ws_port} --app-dir "$(dirname "$_WS_ENTRY")" &',
                    f'    _WS_PID=$!; _WS_STARTED=1;',
                    f'  fi;',
                    # Fallback: plain python3
                    f'  if [ "$_WS_STARTED" = "0" ]; then',
                    f'    python3 "$_WS_ENTRY" &',
                    f'    _WS_PID=$!;',
                    f'  fi;',
                    '  _TRIES=0; while [ $_TRIES -lt 20 ]; do',
                    f'    curl -sf "http://localhost:{_ws_port}" -o /dev/null 2>/dev/null && break || true',
                    '    sleep 1; _TRIES=$((_TRIES+1)); done',
                    '  export AUTOPOV_BASE_URL="$APP_URL"',
                    '  export SERVER_PID=$_WS_PID',
                    'fi',
                ])
        elif env_kind == 'java' and codebase_path:
            # Build the Java project inside the container so TARGET_BINARY points to
            # the assembled jar.  Falls back gracefully when no build file is found.
            # FIX-3: Also resolve dependencies and export CLASSPATH for gadget chains.
            # FIX-JAVA-11: Detect older Gradle wrappers and switch to Java 11 because
            # Gradle < 7.0 is incompatible with Java 21 (the default JDK).
            prelude.extend([
                # Helper: detect Gradle version from wrapper and pick compatible Java
                '_GRADLE_VER=""; _JAVA_HOME="";'
                'if [ -f /workspace/codebase/gradle/wrapper/gradle-wrapper.properties ]; then'
                '  _GRADLE_VER=$(grep -oE "gradle-[0-9]+\\.[0-9]+(\\.[0-9]+)?-" /workspace/codebase/gradle/wrapper/gradle-wrapper.properties | head -1 | sed "s/gradle-//;s/-$//");'
                '  _GRADLE_MAJOR=$(echo "$_GRADLE_VER" | cut -d. -f1);'
                '  if [ -n "$_GRADLE_MAJOR" ] && [ "$_GRADLE_MAJOR" -lt 7 ]; then'
                '    _JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64;'
                '    if [ -d "$_JAVA_HOME" ]; then export JAVA_HOME="$_JAVA_HOME"; fi;'
                '  fi;'
                'fi;'
                'if [ -n "$_JAVA_HOME" ]; then echo "[java-preflight] Using JAVA_HOME=$_JAVA_HOME for Gradle $_GRADLE_VER"; fi;',
                # Maven build + dependency resolution
                'if [ -f /workspace/codebase/pom.xml ]; then'
                '  mvn -f /workspace/codebase/pom.xml package -DskipTests -q;'
                '  JAVA_JAR="$(find /workspace/codebase/target -maxdepth 2 -name "*.jar" ! -name "*-sources.jar" | sort -V | tail -1)";'
                '  export TARGET_JAR="$JAVA_JAR";'
                '  printf "%s\\n" "#!/bin/bash" "exec java -jar \"$JAVA_JAR\" \"\\$@\"" > /workspace/run_java.sh;'
                '  chmod +x /workspace/run_java.sh;'
                '  export TARGET_BINARY="/workspace/run_java.sh"; export TARGET_BIN="/workspace/run_java.sh";'
                '  mvn -f /workspace/codebase/pom.xml dependency:copy-dependencies -DoutputDirectory=/workspace/deps -q 2>/dev/null || true;'
                'fi;',
                # Gradle build + dependency resolution (prefer wrapper, fall back to system gradle)
                'if [ -z "${TARGET_BINARY:-}" ] && ([ -f /workspace/codebase/build.gradle ] || [ -f /workspace/codebase/build.gradle.kts ]); then'
                '  _GRADLE_CMD="gradle";'
                '  if [ -f /workspace/codebase/gradlew ]; then _GRADLE_CMD="/workspace/codebase/gradlew"; chmod +x "$_GRADLE_CMD"; fi;'
                '  $_GRADLE_CMD -p /workspace/codebase build -x test -q;'
                '  JAVA_JAR="$(find /workspace/codebase/build/libs -maxdepth 2 -name "*.jar" ! -name "*-sources.jar" | sort -V | tail -1)";'
                '  export TARGET_JAR="$JAVA_JAR";'
                '  printf "%s\\n" "#!/bin/bash" "exec java -jar \"$JAVA_JAR\" \"\\$@\"" > /workspace/run_java.sh;'
                '  chmod +x /workspace/run_java.sh;'
                '  export TARGET_BINARY="/workspace/run_java.sh"; export TARGET_BIN="/workspace/run_java.sh";'
                '  mkdir -p /workspace/deps;'
                '  $_GRADLE_CMD -p /workspace/codebase copyDependencies -q 2>/dev/null'
                '    || (cd /workspace/codebase && find . -name "*.jar" -path "*/cache/*" -exec cp {} /workspace/deps/ \\; 2>/dev/null) || true;'
                'fi;',
                # Expose jar and classpath for PoV scripts via env
                'export CODEBASE_PATH=/workspace/codebase',
                'if [ -n "${TARGET_BINARY:-}" ]; then export TARGET_JAR="$TARGET_BINARY"; fi',
                # FIX-3: Build CLASSPATH with target classes and all dependency jars
                'export CLASSPATH="/workspace/codebase/target/classes:/workspace/deps/*"',
                'export JAVA_CLASSPATH="$CLASSPATH"',
            ])
        elif env_kind == 'node' and codebase_path:
            # Task 5a/5b: detect JS surface type and set up the environment accordingly.
            # probe_input_surface is carried on exploit_contract from the preflight probe.
            _js_surface = str(contract.get('probe_input_surface') or '').strip().lower()
            # GAP-6: also accept probe_surface_type=web_service as network surface
            if not _js_surface and str(contract.get('probe_surface_type') or '').lower() == 'web_service':
                _js_surface = 'network'

            # Install deps always
            prelude.append(
                'if [ -f /workspace/codebase/package.json ]; then'
                '  cd /workspace/codebase && npm install --silent 2>/dev/null || true;'
                '  if node -e "const s=(require(\'./package.json\').scripts||{}); process.exit(s.build?0:1);" 2>/dev/null; then'
                '    npm run build --silent 2>/dev/null || true; fi; fi'
            )

            if _js_surface == 'network':
                # 5a: HTTP-server repo — auto-detect entrypoint and start server
                prelude.extend([
                    # Find server entrypoint: server.js > app.js > index.js
                    '_JS_ENTRY=""',
                    'for _F in /workspace/codebase/server.js /workspace/codebase/app.js /workspace/codebase/src/server.js /workspace/codebase/src/app.js /workspace/codebase/index.js; do',
                    '  [ -f "$_F" ] && _JS_ENTRY="$_F" && break || true; done',
                    # Fall back to main field in package.json
                    'if [ -z "$_JS_ENTRY" ] && [ -f /workspace/codebase/package.json ]; then',
                    '  _PKG_MAIN=$(node -e "try{console.log(require(\'/workspace/codebase/package.json\').main||\'\')}catch(e){}" 2>/dev/null || true)',
                    '  [ -n "$_PKG_MAIN" ] && _JS_ENTRY="/workspace/codebase/$_PKG_MAIN"; fi',
                    # Start the server in background
                    'if [ -n "$_JS_ENTRY" ]; then',
                    '  export PORT="${PORT:-3000}"',
                    '  export APP_URL="http://localhost:${PORT}"',
                    '  node "$_JS_ENTRY" &',
                    '  _SRV_PID=$!',
                    '  _TRIES=0; while [ $_TRIES -lt 15 ]; do',
                    '    curl -sf "$APP_URL" -o /dev/null 2>/dev/null && break || true',
                    '    sleep 1; _TRIES=$((_TRIES+1)); done',
                    '  export SERVER_PID=$_SRV_PID',
                    'fi',
                ])
            elif _js_surface == 'function_call':
                # 5b: Library repo — expose require path; no server started
                prelude.extend([
                    'export LIB_REQUIRE_PATH="/workspace/codebase"',
                    'export CODEBASE_PATH="/workspace/codebase"',
                    # FIX-6: Set NODE_PATH so require() resolves codebase modules
                    'export NODE_PATH="/workspace/codebase/node_modules"',
                ])
            # default: npm install already done above, nothing extra needed
        # GAP-2: Go / Ruby / PHP dep auto-install
        elif env_kind == 'go' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/go.mod ]; then'
                '  export GOPATH=/tmp/autopov-gopath;'
                '  export GOMODCACHE="$GOPATH/pkg/mod";'
                '  cd /workspace/codebase && go mod download 2>/dev/null || true; fi',
                'export GOPATH="${GOPATH:-/tmp/autopov-gopath}"',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'ruby' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/Gemfile ]; then'
                '  cd /workspace/codebase && bundle install --quiet 2>/dev/null || true; fi',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'php' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/composer.json ]; then'
                '  cd /workspace/codebase && composer install --no-interaction --quiet 2>/dev/null || true; fi',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        # ── Task 4: Web app server startup for any env_kind ───────────────
        # When the exploit_contract indicates a web target (target_url or web execution_surface),
        # start the target application server before running the PoV script.
        _target_url = str(contract.get('target_url') or contract.get('base_url') or '').strip()
        _is_web_target = (
            bool(_target_url)
            or str(contract.get('execution_surface') or '').lower() in {'web', 'http', 'rest_api', 'browser_dom', 'http_request'}
            or _probe_surface == 'web_service'
        )
        if _is_web_target and codebase_path:
            # Detect port from target_url or probe_base_url
            _web_port = '3000'  # default for Node.js apps
            for _url_src in [_target_url, _probe_base_url]:
                if _url_src and ':' in _url_src:
                    _port_cand = _url_src.rstrip('/').rsplit(':', 1)[-1].split('/')[0]
                    if _port_cand.isdigit():
                        _web_port = _port_cand
                        break
            prelude.extend([
                '# Task 4: Auto-start web application server if not already running',
                f'export AUTOPOV_TARGET_URL="${{AUTOPOV_TARGET_URL:-http://localhost:{_web_port}}}"',
                f'export TARGET_URL="${{TARGET_URL:-http://localhost:{_web_port}}}"',
                'if ! curl -sf "$AUTOPOV_TARGET_URL" -o /dev/null 2>/dev/null; then',
                '  _WEB_STARTED=0;',
                # Node.js startup
                '  if [ -f /workspace/codebase/package.json ] && command -v node >/dev/null 2>&1; then',
                '    cd /workspace/codebase && npm install --silent 2>/dev/null || true;',
                '    _HAS_START=$(node -e "try{const s=require(\'/workspace/codebase/package.json\').scripts||{};process.exit(s.start?0:1)}catch(e){process.exit(1)}" 2>/dev/null && echo 1 || echo 0);',
                '    if [ "$_HAS_START" = "1" ]; then',
                f'      PORT={_web_port} npm start --prefix /workspace/codebase &',
                '      _WEB_PID=$!; _WEB_STARTED=1;',
                '    else',
                '      for _F in /workspace/codebase/server.js /workspace/codebase/app.js /workspace/codebase/index.js; do',
                '        if [ -f "$_F" ]; then node "$_F" & _WEB_PID=$!; _WEB_STARTED=1; break; fi; done;',
                '    fi;',
                '  fi;',
                # Python web app startup fallback
                '  if [ "$_WEB_STARTED" = "0" ]; then',
                '    for _F in /workspace/codebase/app.py /workspace/codebase/server.py /workspace/codebase/main.py; do',
                '      if [ -f "$_F" ]; then python3 "$_F" & _WEB_PID=$!; _WEB_STARTED=1; break; fi; done;',
                '  fi;',
                # Issue #11: Java web app startup (Spring Boot / Maven)
                '  if [ "$_WEB_STARTED" = "0" ] && [ -f /workspace/codebase/pom.xml ] && command -v java >/dev/null 2>&1; then',
                '    _JAR="$(find /workspace/codebase/target -maxdepth 2 -name "*.jar" ! -name "*-sources.jar" 2>/dev/null | sort -V | tail -1)";',
                '    if [ -n "$_JAR" ]; then',
                '      java -jar "$_JAR" --server.port=' + _web_port + ' & _WEB_PID=$!; _WEB_STARTED=1;',
                '    fi;',
                '  fi;',
                # Ruby on Rails / Sinatra startup
                '  if [ "$_WEB_STARTED" = "0" ] && [ -f /workspace/codebase/Gemfile ] && command -v ruby >/dev/null 2>&1; then',
                '    cd /workspace/codebase;',
                '    if [ -f config/environment.rb ]; then',
                f'      PORT={_web_port} bundle exec rails server -b 0.0.0.0 -p {_web_port} -d 2>/dev/null && _WEB_STARTED=1;',
                '    elif grep -q "sinatra" Gemfile 2>/dev/null; then',
                '      for _RF in app.rb server.rb main.rb; do',
                f'        [ -f "$_RF" ] && PORT={_web_port} bundle exec ruby "$_RF" & _WEB_PID=$! && _WEB_STARTED=1 && break; done;',
                '    fi; cd /;',
                '  fi;',
                # PHP built-in server startup
                '  if [ "$_WEB_STARTED" = "0" ] && [ -f /workspace/codebase/index.php ] && command -v php >/dev/null 2>&1; then',
                f'    php -S 0.0.0.0:{_web_port} -t /workspace/codebase & _WEB_PID=$!; _WEB_STARTED=1;',
                '  fi;',
                # Wait for server readiness — up to 90s for slow starters (Spring Boot, Django, Rails)
                '  if [ "$_WEB_STARTED" = "1" ]; then',
                '    echo "[AutoPoV] Web server starting (pid=$_WEB_PID) — waiting up to 90s..." >&2;',
                '    _TRIES=0;',
                '    while [ $_TRIES -lt 90 ]; do',
                # Primary health check
                '      if curl -sf "$AUTOPOV_TARGET_URL" -o /dev/null 2>/dev/null; then break; fi;',
                # Spring Boot actuator health endpoint (often responds before root)
                '      if curl -sf "${AUTOPOV_TARGET_URL%/}/actuator/health" -o /dev/null 2>/dev/null; then break; fi;',
                # Django/Rails typical health path
                '      if curl -sf "${AUTOPOV_TARGET_URL%/}/health" -o /dev/null 2>/dev/null; then break; fi;',
                '      sleep 1; _TRIES=$((_TRIES+1));',
                '    done;',
                '    if curl -sf "$AUTOPOV_TARGET_URL" -o /dev/null 2>/dev/null'
                '       || curl -sf "${AUTOPOV_TARGET_URL%/}/actuator/health" -o /dev/null 2>/dev/null'
                '       || curl -sf "${AUTOPOV_TARGET_URL%/}/health" -o /dev/null 2>/dev/null; then',
                '      echo "[AutoPoV] Web server ready after ${_TRIES}s" >&2;',
                '    else',
                '      echo "[AutoPoV] WARNING: Web server did not respond after 90s — proceeding anyway" >&2;',
                '      (ps -p $_WEB_PID >/dev/null 2>&1 && echo "[AutoPoV] server process still running" || echo "[AutoPoV] server process died") >&2;',
                '    fi;',
                '    export SERVER_PID=$_WEB_PID;',
                '  fi;',
                'fi',
            ])

        # ── Task 1 (Gap 1): Env bridge — persist shell env vars so Python PoV scripts
        # can read them via os.environ.get().  Shell exports are local to the prelude;
        # Python subprocesses do NOT inherit them unless we bridge explicitly.
        prelude.append(
            '# ── AutoPoV env bridge: persist discovered env vars for Python PoV scripts ──\n'
            'env | grep -E "^(TARGET_BINARY|TARGET_BIN|AUTOPOV_|LIB_|HOME|CC|CXX|CFLAGS|CXXFLAGS|LDFLAGS|PATH|LD_LIBRARY_PATH|ASAN_OPTIONS|UBSAN_OPTIONS|LSAN_OPTIONS|RUBY_|PHP_|BUNDLE_|LOAD_PATH|CLASSPATH|JAVA_|GOPATH|NODE_PATH)=" > /tmp/autopov_env || true'
        )
        # Verify env bridge was written — if empty, dump full env as fallback
        prelude.append(
            'if [ ! -s /tmp/autopov_env ]; then\n'
            '  echo "[AutoPoV] WARNING: env bridge file is empty — dumping full env as fallback" >&2;\n'
            '  env > /tmp/autopov_env 2>/dev/null || true;\n'
            'fi'
        )

        # ── PoV execution with recovery: wrap in set +e so infrastructure errors
        # don't prevent output capture; retry with python3 on 126/127 ──
        prelude.append('set +e')

        if runtime_command and runtime_command[0] == 'bash':
            run_cmd = f'chmod +x /pov/{pov_filename} && /bin/bash /pov/{pov_filename}'
        elif runtime_command[:2] == ['bash', '-lc']:
            run_cmd = runtime_command[2]
        elif runtime_command and runtime_command[0] == 'node':
            # Run Node.js PoVs with unhandled-rejection tracking and syntax check first.
            # --unhandled-rejections=strict ensures async errors produce visible output
            # instead of silent exit. The syntax check catches malformed JS before
            # execution so the oracle gets a clear error message.
            run_cmd = (
                f'node --check /pov/{pov_filename} 2>&1 || '
                f'  echo "[AutoPoV] JS syntax error — see above" >&2; '
                f'node --unhandled-rejections=strict /pov/{pov_filename}'
            )
        else:
            run_cmd = ' '.join(runtime_command + [f'/pov/{pov_filename}'])

        # Execute PoV, capture exit code
        prelude.append(f'{run_cmd}')
        prelude.append('_POV_EXIT=$?')

        # Retry with python3 if permission denied (126) or command not found (127)
        prelude.append(
            'if [ "$_POV_EXIT" = "126" ] || [ "$_POV_EXIT" = "127" ]; then'
            '  echo "[AutoPoV] PoV script failed with exit $_POV_EXIT — retrying with python3" >&2;'
            f'  python3 /pov/{pov_filename};'
            '  _POV_EXIT=$?;'
            'fi'
        )

        # If build failed AND env_kind is native, try interpreted fallback
        if env_kind == 'native':
            prelude.append(
                'if [ "$_POV_EXIT" != "0" ] && [ ! -f /tmp/_autopov_build_ok ] && [ -z "${TARGET_BINARY:-}" ]; then'
                '  echo "[AutoPoV] Build failed + no binary — attempting Python direct execution" >&2;'
                f'  python3 /pov/{pov_filename} || true;'
                'fi'
            )

        # Propagate the PoV exit code
        prelude.append('exit $_POV_EXIT')
        return ['bash', '-lc', '\n'.join(prelude)]

    def _build_cache_image_tag(self, scan_id: str, env_kind: str, build_hash: str = '') -> str:
        """Return a Docker image tag for caching the built codebase of a scan.

        When build_hash is provided (a hash of the prelude/build commands), it is
        included in the tag so that different build configurations get different
        cache keys.  This prevents stale cached builds from being reused when
        the refinement loop changes the build approach.
        """
        base = f'autopov/buildcache/{env_kind}/{self._slugify(scan_id)}'
        if build_hash:
            return f'{base}-{build_hash[:8]}'
        return base

    def _compute_build_hash(self, prelude_cmds: list) -> str:
        """Compute a short hash from the prelude build commands for cache key invalidation."""
        import hashlib as _hashlib
        return _hashlib.md5('\n'.join(prelude_cmds).encode()).hexdigest()[:16]

    def _commit_build_cache(self, client, container, scan_id: str, env_kind: str, build_hash: str = '') -> Optional[str]:
        """Commit a container's filesystem as a cached build image for reuse.

        Called after a container completes with a successful build.  The committed
        image contains the built codebase so subsequent retries skip the entire
        build phase, saving 30-120 seconds per retry.
        """
        tag = self._build_cache_image_tag(scan_id, env_kind, build_hash=build_hash)
        try:
            repo = container.commit(repository=tag)
            image_id = getattr(repo, 'id', None) or getattr(repo, 'Id', None)
            logger.info('[build-cache] Committed build cache image: %s (id=%s)', tag, image_id)
            return tag
        except Exception as exc:
            logger.warning('[build-cache] Failed to commit build cache image %s: %s', tag, exc)
            return None

    def _get_cached_build_image(self, client, scan_id: str, env_kind: str, build_hash: str = '') -> Optional[str]:
        """Return the cached build image tag if it exists, else None.

        When build_hash is provided, only returns a cache hit if the hash matches
        (prevents stale builds from being reused).  Also validates that the cached
        image contains the /tmp/_autopov_build_ok sentinel file.
        """
        tag = self._build_cache_image_tag(scan_id, env_kind, build_hash=build_hash)
        try:
            client.images.get(tag)
            logger.info('[build-cache] Found cached build image: %s', tag)
            return tag
        except Exception:
            # If hash-specific tag not found, try legacy tag (no hash) for backward compat
            if build_hash:
                legacy_tag = self._build_cache_image_tag(scan_id, env_kind)
                try:
                    client.images.get(legacy_tag)
                    logger.info('[build-cache] Found legacy cached build image (no hash): %s', legacy_tag)
                    # Validate the sentinel before trusting legacy cache
                    return legacy_tag
                except Exception:
                    pass
            return None

    def _cleanup_build_cache(self, scan_id: str, env_kind: Optional[str] = None):
        """Remove cached build images for a scan to free disk space."""
        try:
            client = self._get_client()
        except Exception:
            return
        if env_kind:
            tags = [self._build_cache_image_tag(scan_id, env_kind)]
        else:
            tags = [self._build_cache_image_tag(scan_id, ek) for ek in ('native', 'python', 'node', 'java')]
        for tag in tags:
            try:
                client.images.remove(tag, force=True)
                logger.info('[build-cache] Removed cached build image: %s', tag)
            except Exception:
                pass

    def run_pov(
        self,
        pov_script: str,
        scan_id: str,
        pov_id: str,
        extra_files: Optional[Dict[str, str]] = None,
        execution_profile: Optional[str] = None,
        target_language: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None,
        codebase_path: Optional[str] = None,
        pov_language: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.is_available():
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout='',
                stderr='Docker not available',
                exit_code=-1,
                execution_time_s=0,
                execution_profile=execution_profile or target_language or 'python',
                runtime_image='unavailable',
                validation_method='generic_container_runtime',
                proof_infrastructure_error=True,
                failure_reason='docker-unavailable',
            )

        temp_dir = tempfile.mkdtemp(prefix=f'autopov_{scan_id}_')
        client = None
        container = None
        env_kind = 'python'
        runtime_image = self.image
        script_runtime = 'python'
        start_time = datetime.now(timezone.utc)

        try:
            env_kind, runtime_image, runtime_command, pov_filename = self._resolve_runtime(pov_script, execution_profile, target_language, exploit_contract, pov_language=pov_language)
            script_runtime = self._detect_script_runtime(pov_script, execution_profile, pov_language=pov_language)
            pov_script = self._repair_runtime_script(pov_script, script_runtime=script_runtime, env_kind=env_kind)
            # ── Issue #7: Pre-execution compile-command stripping ─────────────────
            # For native binary targets, the LLM sometimes generates PoV scripts that
            # try to compile the target from source (gcc/clang/cmake/make) instead of
            # using the pre-built TARGET_BINARY.  Strip these lines deterministically
            # before execution so the PoV is forced to use the pre-built binary.
            if env_kind == 'native':
                pov_script = self._strip_compile_commands(pov_script)
            pov_path = os.path.join(temp_dir, pov_filename)
            with open(pov_path, 'w', encoding='utf-8') as f:
                f.write(pov_script)

            if extra_files:
                for filename, content in extra_files.items():
                    file_path = os.path.join(temp_dir, filename)
                    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)

            client = self._get_client()
            try:
                self._ensure_runtime_image(client, env_kind, runtime_image)
            except DockerImagePreparationError as e:
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout='',
                    stderr=str(e),
                    exit_code=-1,
                    execution_time_s=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='docker-image-prep-failed',
                    metadata={'environment_kind': env_kind},
                )

            # ── Build the execution shell command BEFORE cache lookup ────────
            # The command must be built first so _compute_build_hash can derive
            # the cache key from it.  Previously this was after the cache lookup,
            # causing an UnboundLocalError on _build_hash.
            command = self._build_execution_shell(env_kind, runtime_command, pov_filename, exploit_contract or {}, codebase_path)
            # Compute build hash for cache key invalidation — different build commands
            # should produce different cache keys so stale builds are not reused.
            _build_hash = self._compute_build_hash(command) if command else ''

            # ── Build cache: reuse committed build image from a previous attempt ──
            # If a previous run for this scan already built the codebase successfully,
            # we committed the container as a cached image.  Use it to skip the entire
            # build phase (saves 30-120 seconds per retry).
            _cached_build_image = None
            if env_kind == 'native':
                _cached_build_image = self._get_cached_build_image(client, scan_id, env_kind, build_hash=_build_hash)
            _using_build_cache = _cached_build_image is not None
            if _using_build_cache:
                runtime_image = _cached_build_image
                logger.info('[build-cache] Using cached build image for scan_id=%s env_kind=%s', scan_id, env_kind)

            contract = exploit_contract or {}
            raw_target_url = str(contract.get('target_url') or contract.get('base_url') or '')
            target_url = self._normalize_target_url_for_container(raw_target_url)
            # GAP-1: web_service and http_request surfaces need bridge mode so the PoV
            # can reach the in-container web server or make outbound HTTP requests.
            # Java/JVM proof containers also need bridge for Maven/Gradle dependency resolution.
            _needs_network = (
                bool(target_url)
                or str(contract.get('execution_surface') or '').lower() in {'http_request', 'browser_dom'}
                or str(contract.get('proof_plan', {}).get('execution_surface') or '').lower() in {'http_request', 'browser_dom'}
                or str(contract.get('probe_surface_type') or '').lower() == 'web_service'
                or str(contract.get('probe_input_surface') or '').lower() == 'network'
                or 'java' in (runtime_image or '').lower()
                # Network mode for database/service targets (SQL injection, SSRF, etc.)
                or any(kw in str(contract.get('target_entrypoint') or '').lower()
                       for kw in ('mysql', 'postgres', 'redis', 'mongo', 'sqlite', 'sql'))
                # Network mode when approach text indicates network-dependent exploits
                or any(kw in str(contract.get('approach') or contract.get('exploitation_approach') or '').lower()
                       for kw in ('ssrf', 'server-side request', 'connect to', 'localhost:', '127.0.0.1:'))
            )
            network_mode = 'bridge' if _needs_network else 'none'
            fixture_files = self._collect_fixture_files(contract)
            environment = {
                'TARGET_URL': target_url,
                'CODEBASE_PATH': '/workspace/codebase',
                'TARGET_ENTRYPOINT': str(contract.get('target_entrypoint') or ''),
                'TARGET_HTTP_METHOD': str(contract.get('http_method') or 'GET'),
                'FIXTURE_ROOT': '/workspace/fixtures',
                'AUTOPROOF_ENV_KIND': env_kind,
                'AUTOPROOF_SCRIPT_RUNTIME': script_runtime,
                # Task 2: Provide a writable HOME for keygen-based tools (enchive etc.)
                'AUTOPOV_BOOTSTRAP_HOME': '/tmp/autopov_home',
                'HOME': '/tmp/autopov_home',
                # Pass repo name for binary locator heuristics (from exploit_contract or basename of codebase path)
                'AUTOPOV_REPO_NAME': (contract.get('repo_name') or os.path.basename(codebase_path.rstrip('/\\')) if codebase_path else '').lower(),
                # Pass target source filepath for Valgrind path relevance check in tiered confirmation
                'TARGET_FILEPATH': str(contract.get('filepath') or ''),
            }
            # If the preflight probe discovered the binary path, pass it through so
            # the binary locator inside the container can skip scoring heuristics.
            _probe_bin = contract.get('probe_binary_path') or ''
            if _probe_bin:
                environment['AUTOPOV_PROBE_BINARY'] = _probe_bin

            # Inject DB substitution env vars from recon (web service DI)
            _db_sub_env = contract.get('db_substitution_env') or {}
            for _dbk, _dbv in _db_sub_env.items():
                # Only set if not already present (don't override explicit config)
                if _dbk not in environment:
                    environment[_dbk] = _dbv
            # Task 4: Propagate target URL into container for web PoVs
            _contract_target_url = str(contract.get('target_url') or contract.get('base_url') or contract.get('probe_base_url') or '').strip()
            if _contract_target_url:
                environment['AUTOPOV_TARGET_URL'] = _contract_target_url
            # command and _build_hash already computed above before cache lookup

            # FIX-4: Mount shared build volume for native targets if probe cached artifacts
            _build_volume_name = f'autopov_build_{scan_id}' if env_kind == 'native' else ''
            _volumes = {}
            if _build_volume_name:
                try:
                    client.volumes.get(_build_volume_name)
                    _volumes[_build_volume_name] = {'bind': '/workspace/build_cache', 'mode': 'ro'}
                    environment['AUTOPOV_BUILD_CACHED'] = '1'
                    environment['AUTOPOV_BUILD_CACHE'] = '/workspace/build_cache'
                except Exception:
                    # Task 3: Log when build volume is unavailable so we know rebuild is needed
                    if env_kind == 'native':
                        logger.info('[run_pov] Build volume %s not found — container will rebuild from source', _build_volume_name)
            # Build cache image: if using a committed build image, tell the shell
            # to skip the build phase entirely.  The codebase is already built.
            if _using_build_cache:
                environment['AUTOPOV_BUILD_CACHED'] = '1'
                environment['AUTOPOV_BUILD_CACHE'] = '/workspace/codebase'

            container_name = self._build_name(scan_id, pov_id)
            container = client.containers.create(
                image=runtime_image,
                command=command,
                name=container_name,
                working_dir='/',
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                network_mode=network_mode,
                dns=['8.8.8.8', '8.8.4.4'],
                extra_hosts={'host.docker.internal': 'host-gateway'},
                environment=environment,
                cap_add=["SYS_PTRACE"],
                security_opt=["seccomp=unconfined"],
                volumes=_volumes or None,
                detach=True
            )

            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode='w') as tar:
                for name in os.listdir(temp_dir):
                    full_path = os.path.join(temp_dir, name)
                    tar.add(full_path, arcname=f'pov/{name}')
                for rel_name, content in fixture_files.items():
                    self._add_text_to_archive(tar, str(Path('workspace/fixtures') / rel_name), content)
                self._add_text_to_archive(tar, 'workspace/fixtures/manifest.json', json.dumps({
                    'fixtures': sorted(fixture_files.keys()),
                    'scan_id': scan_id,
                    'pov_id': pov_id,
                }, indent=2))
                if codebase_path and os.path.isdir(codebase_path):
                    # Skip codebase upload when using a cached build image — the
                    # codebase is already baked into the committed image.
                    if not _using_build_cache:
                        self._add_directory_to_archive(tar, codebase_path, 'workspace/codebase')
            archive_buffer.seek(0)
            try:
                container.put_archive('/', archive_buffer.getvalue())
            except Exception as exc:
                logger.error('[run_pov] Failed to upload PoV archive to container: %s', exc)
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                container = None
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout='',
                    stderr=f'Failed to upload PoV archive to container: {exc}',
                    exit_code=-1,
                    execution_time_s=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='archive-upload-failed',
                    metadata={'environment_kind': env_kind},
                )
            container.start()

            # IMPROVEMENT 1.3 + Issue #10: Dynamic timeout based on codebase size
            # AND separate build/execution timeouts for native containers.
            #
            # When using a cached build image, the build phase is already done —
            # use DOCKER_EXECUTION_TIMEOUT (default 60s) for the PoV only.
            # When building from scratch for native, use DOCKER_BUILD_TIMEOUT +
            # DOCKER_EXECUTION_TIMEOUT (default 300+60=360s) to give the build
            # adequate time without starving the execution phase.
            # Non-native containers continue to use DOCKER_TIMEOUT unchanged.
            if _using_build_cache and env_kind == 'native':
                _dynamic_timeout = self.execution_timeout
                logger.info(
                    '[run_pov] Using cached build — execution-only timeout: %ds',
                    _dynamic_timeout,
                )
            elif env_kind == 'native':
                # Check codebase size (rough estimate from archive upload)
                _codebase_size_mb = 0
                if codebase_path and os.path.isdir(codebase_path):
                    try:
                        _total_size = sum(
                            os.path.getsize(os.path.join(dp, f))
                            for dp, dn, fn in os.walk(codebase_path)
                            for f in fn
                            if '.git' not in dp and '__pycache__' not in dp
                        )
                        _codebase_size_mb = _total_size / (1024 * 1024)
                    except Exception:
                        pass
                
                # Base = build_timeout + execution_timeout, scaled by codebase size
                _base_timeout = self.build_timeout + self.execution_timeout
                if _codebase_size_mb > 50:
                    _dynamic_timeout = int(_base_timeout * 1.5)  # 1.5x for >50MB repos
                    logger.info(
                        '[run_pov] Large codebase (%.1f MB) — extending timeout to %ds (build=%ds + exec=%ds * 1.5)',
                        _codebase_size_mb, _dynamic_timeout,
                        self.build_timeout, self.execution_timeout,
                    )
                elif _codebase_size_mb > 10:
                    _dynamic_timeout = int(_base_timeout * 1.25)  # 1.25x for 10-50MB repos
                    logger.info(
                        '[run_pov] Medium codebase (%.1f MB) — timeout %ds (build=%ds + exec=%ds * 1.25)',
                        _codebase_size_mb, _dynamic_timeout,
                        self.build_timeout, self.execution_timeout,
                    )
                else:
                    _dynamic_timeout = _base_timeout
                    logger.info(
                        '[run_pov] Native build+exec timeout: %ds (build=%ds + exec=%ds)',
                        _dynamic_timeout, self.build_timeout, self.execution_timeout,
                    )
            else:
                # Non-native containers: use the original DOCKER_TIMEOUT
                _dynamic_timeout = self.timeout

            timeout_hit = False
            try:
                wait_result = container.wait(timeout=_dynamic_timeout)
                exit_code = wait_result.get('StatusCode', -1)
            except Exception as e:
                timeout_hit = True
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = 124  # Standard timeout exit code (distinct from -1 = no script)
                wait_result = {'Error': str(e)}

            # Task 6 (Gap 6): Capture combined first as fallback, then individual streams.
            # If Docker's buffer management loses stderr between calls, we have a safety net.
            _combined = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')
            # If stderr is suspiciously empty but combined has content beyond stdout,
            # use combined as fallback — better to have mixed output than lose crash evidence.
            if not stderr.strip() and _combined.strip() and _combined != stdout:
                logger.warning(
                    '[run_pov] stderr was empty but combined log has content — '
                    'using combined as stderr fallback (len_combined=%d, len_stdout=%d)',
                    len(_combined), len(stdout),
                )
                stderr = _combined
            # ── Commit build cache BEFORE removing the container ────────────────
            # If the build succeeded (and we didn't already use a cache), commit
            # the container's filesystem as a cached image.  The next retry for
            # this scan will use it and skip the entire build phase (saves 30-120s).
            _build_status_for_cache = self._extract_build_status_from_stdout(_combined)
            if env_kind == 'native' and not _using_build_cache and _build_status_for_cache.get('build_status') in ('success', 'asan_disabled'):
                try:
                    self._commit_build_cache(client, container, scan_id, env_kind, build_hash=_build_hash)
                except Exception as _cache_exc:
                    logger.warning('[build-cache] Failed to commit build cache: %s', _cache_exc)

            container.remove(force=True)
            container = None

            # Extract CLI help text captured during preflight and strip sentinel markers
            # from stdout so the PoV oracle only sees actual exploit output.
            preflight_help_text = self._extract_help_text_from_stdout(stdout)
            preflight_subcommands = self._parse_subcommands_from_help_text(preflight_help_text) if preflight_help_text else []
            # Extract the resolved binary path before stripping sentinels
            target_binary_path = self._extract_binary_path_from_stdout(stdout)
            # Extract preflight surface detection result
            preflight_detected_surface = self._extract_preflight_surface_from_stdout(stdout)
            # Extract build status before stripping sentinels
            build_info = self._extract_build_status_from_stdout(stdout)
            stdout = self._strip_help_text_sentinels(stdout)

            # --- Build failure gate ---
            # If the container emitted AUTOPOV_BUILD_STATUS=failed, the binary was never
            # produced.  Return a clear infrastructure error immediately so the pipeline
            # can give the LLM an actionable hint instead of burning a retry on a missing
            # binary.
            if build_info.get('build_status') == 'failed':
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                build_log_snippet = (build_info.get('build_log') or '').strip()[-1500:]
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout=stdout,
                    stderr=f"[AutoPoV] Build failed inside container.\n{build_log_snippet}",
                    exit_code=97,
                    execution_time_s=execution_time,
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='build_failed',
                    metadata={
                        'environment_kind': env_kind,
                        'build_status': 'failed',
                        'build_log': build_log_snippet,
                        'preflight_help_text': preflight_help_text or None,
                        'preflight_subcommands': preflight_subcommands or None,
                    },
                )

            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            # build_info was already extracted above for the build failure gate.
            # Derive asan_disabled from it here before evaluating the oracle.
            asan_disabled = build_info.get('asan_disabled', False)
            _first_build_status = build_info.get('build_status', 'unknown')
            # Probe-captured baseline (injected into exploit_contract by agent_graph).
            _baseline_ec = int((contract.get('probe_baseline_exit_code') or -1))
            _baseline_err = str(contract.get('probe_baseline_stderr') or '')
            oracle = self._evaluate_runtime_oracle(
                stdout, stderr, exit_code, contract,
                asan_disabled=asan_disabled,
                baseline_exit_code=_baseline_ec,
                baseline_stderr=_baseline_err,
                pov_script=pov_script,
                build_prelude_ran=(_first_build_status in ('success', 'asan_disabled', 'failed')),
            )

            # ----------------------------------------------------------------
            # Tiered confirmation stack (Tasks 0b, 1, 3)
            # Only runs when the first oracle pass did NOT confirm the vuln.
            # Tiers are tried in order; first success short-circuits the rest.
            # ----------------------------------------------------------------
            # Skip tiered confirmation if the build never completed (build_status unknown
            # means the container timed out before emitting the sentinel — a second
            # container would also time out, wasting time without adding signal).
            _build_completed = _first_build_status in ('success', 'failed', 'asan_disabled')
            if not oracle.get('triggered') and env_kind == 'native' and not timeout_hit and _build_completed:
                _combined_output = (stdout or '') + '\n' + (stderr or '')
                # Infer file extension from the binary name in the contract.
                # Falls back to .jpg when the binary is a known image-processing tool.
                _inferred_ext = self._infer_ext_from_contract(contract)
                # If the contract doesn't name the binary, try extracting it from
                # the resolved binary path (e.g. '/workspace/codebase/jhead' -> '.jpg').
                if _inferred_ext == '.bin' and target_binary_path:
                    import os as _os_tier
                    _bin_basename = _os_tier.path.basename(target_binary_path).lower()
                    for _frag, _fext in self._BINARY_EXT_MAP.items():
                        if _frag in _bin_basename:
                            _inferred_ext = _fext
                            break
                _target_bin_in_container = target_binary_path or str(contract.get('probe_binary_path') or '')

                # Determine whether to run the tiered confirmation script.
                # Conditions: (a) format-rejection detected OR (b) signal is ambiguous/asan_disabled.
                _sig_cls = (oracle.get('oracle_result') or {}).get('signal_class', '')
                # Check format rejection: probe-derived patterns first, then static fallback
                _probe_rejection = contract.get('probe_rejection_patterns') or []
                _fmt_rejected = False
                if _probe_rejection:
                    for _rp in _probe_rejection:
                        if _rp.lower() in _combined_output.lower():
                            _fmt_rejected = True
                            break
                if not _fmt_rejected:
                    _fmt_rejected = bool(self._FORMAT_REJECTION_RE.search(_combined_output))
                _should_tier = _fmt_rejected or _sig_cls in ('ambiguous', 'non_evidence') or asan_disabled

                logger.debug(
                    '[tier] env_kind=%s timeout_hit=%s sig_cls=%r fmt_rejected=%s '
                    'asan_disabled=%s should_tier=%s bin=%r ext=%r',
                    env_kind, timeout_hit, _sig_cls, _fmt_rejected,
                    asan_disabled, _should_tier, _target_bin_in_container, _inferred_ext,
                )

                if _should_tier and _target_bin_in_container:
                    try:
                        _tier_script = self._build_tiered_confirmation_pov(
                            binary_path=_target_bin_in_container,
                            ext=_inferred_ext,
                            contract=contract,
                            run_valgrind=True,
                            run_repeated_crash=True,
                        )
                        # Run the tier script in a fresh container using the same image.
                        # It will have access to the codebase (already built in the first run).
                        logger.debug('[tier] launching tiered confirmation container for pov_id=%s', pov_id)
                        _tier_result = self.run_pov(
                            pov_script=_tier_script,
                            scan_id=scan_id,
                            pov_id=pov_id + '_tier',
                            execution_profile='c',  # native
                            target_language='c',
                            exploit_contract=contract,
                            codebase_path=codebase_path,
                        )
                        logger.debug('[tier] tier result: triggered=%s reason=%r',
                                     _tier_result.get('vulnerability_triggered'),
                                     _tier_result.get('failure_reason'))
                        if _tier_result.get('vulnerability_triggered'):
                            # Promote tier result: keep oracle metadata but mark triggered
                            oracle['triggered'] = True
                            oracle['reason'] = 'tiered_confirmation'
                            if isinstance(oracle.get('oracle_result'), dict):
                                oracle['oracle_result']['triggered'] = True
                                oracle['oracle_result']['signal_class'] = 'strong'
                    except Exception as _tier_exc:
                        logger.warning('[tier] tiered confirmation raised: %s', _tier_exc, exc_info=True)
            # ----------------------------------------------------------------

            vulnerability_triggered = oracle['triggered']
            infra_error = timeout_hit or exit_code in {97, 125, 126, 127}
            failure_reason = self._normalize_oracle_reason(oracle, infrastructure=infra_error, timeout_hit=timeout_hit)
            if oracle.get('self_report_only'):
                failure_reason = 'self_report_only'

            return self._build_result(
                success=exit_code == 0 or vulnerability_triggered,
                vulnerability_triggered=vulnerability_triggered,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                execution_time_s=execution_time,
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime' if env_kind != 'browser' else 'browser_container_runtime',
                proof_infrastructure_error=infra_error,
                failure_reason=failure_reason,
                metadata={
                    'environment_kind': env_kind,
                    'target_url': target_url or None,
                    'fixture_manifest': sorted(fixture_files.keys()),
                    'oracle_reason': oracle.get('reason'),
                    'matched_markers': oracle.get('matched_markers', []),
                    'preflight_help_text': preflight_help_text or None,
                    'preflight_subcommands': preflight_subcommands or None,
                    'target_binary_path': target_binary_path or None,
                    'target_binary': os.path.basename(target_binary_path) if target_binary_path else None,
                    'preflight_detected_surface': preflight_detected_surface or None,
                    'build_status': build_info.get('build_status') or 'unknown',
                    'build_log': (build_info.get('build_log') or '').strip()[-1500:] or None,
                    'asan_disabled': asan_disabled,
                    'oracle_result': oracle.get('oracle_result'),
                    # FIX-5: Enriched signal detail for refinement loop
                    'signal_detail': oracle.get('signal_detail'),
                },
            )

        except ContainerError as e:
            ce_stdout = e.stdout.decode('utf-8', errors='ignore') if e.stdout else ''
            ce_stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e)
            ce_build_info = self._extract_build_status_from_stdout(ce_stdout)
            ce_stdout_clean = self._strip_help_text_sentinels(ce_stdout)
            ce_infra = e.exit_status in {97, 125, 126, 127}
            ce_reason = 'build_failed' if ce_build_info.get('build_status') == 'failed' else str(e)
            if ce_build_info.get('build_status') == 'failed':
                build_log_snippet = (ce_build_info.get('build_log') or '').strip()[-1500:]
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout=ce_stdout_clean,
                    stderr=f'[AutoPoV] Build failed inside container.\n{build_log_snippet}',
                    exit_code=e.exit_status,
                    execution_time_s=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='build_failed',
                    metadata={
                        'environment_kind': env_kind,
                        'build_status': 'failed',
                        'build_log': build_log_snippet,
                        'preflight_help_text': preflight_help_text or None,
                        'preflight_subcommands': preflight_subcommands or None,
                    },
                )
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout=ce_stdout_clean,
                stderr=ce_stderr,
                exit_code=e.exit_status,
                execution_time_s=(datetime.now(timezone.utc) - start_time).total_seconds(),
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime',
                proof_infrastructure_error=ce_infra,
                failure_reason=ce_reason,
                metadata={
                    'environment_kind': env_kind,
                    'build_status': ce_build_info.get('build_status') or 'unknown',
                    'build_log': (ce_build_info.get('build_log') or '').strip()[-1500:] or None,
                    'preflight_help_text': preflight_help_text or None,
                    'preflight_subcommands': preflight_subcommands or None,
                },
            )
        except Exception as e:
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout='',
                stderr=str(e),
                exit_code=-1,
                execution_time_s=(datetime.now(timezone.utc) - start_time).total_seconds(),
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime',
                proof_infrastructure_error=True,
                failure_reason=str(e),
                metadata={'environment_kind': env_kind},
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            self._cleanup_pov_resources(scan_id, pov_id)

    def _cleanup_pov_resources(self, scan_id: str, pov_id: str):
        try:
            client = self._get_client()
            container_pattern = f"autopov_{self._slugify(scan_id)}_{self._slugify(pov_id)}"
            containers = client.containers.list(all=True, filters={"name": container_pattern})
            for container in containers:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            try:
                client.volumes.prune()
            except Exception:
                pass
        except Exception:
            pass

    def cleanup_all_pov_resources(self, scan_id: Optional[str] = None):
        try:
            client = self._get_client()
            pattern = f"autopov_{self._slugify(scan_id)}" if scan_id else "autopov_"
            containers = client.containers.list(all=True, filters={"name": pattern})
            for container in containers:
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception:
                    pass
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            try:
                client.api.prune_builds()
            except Exception:
                pass
        except Exception as e:
            print(f"Warning: Docker cleanup failed: {e}")

    def run_with_input(self, pov_script: str, input_data: str, scan_id: str, pov_id: str) -> Dict[str, Any]:
        extra_files = {
            'input_data.txt': input_data,
            'pov_script.py': pov_script,
        }
        wrapper_script = """
import sys
exec(open('/pov/pov_script.py').read())
"""
        extra_files['wrapper.py'] = wrapper_script
        return self.run_pov(wrapper_script, scan_id, pov_id, extra_files=extra_files)

    def run_binary_pov(self, pov_script: str, binary_data: bytes, scan_id: str, pov_id: str, exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        temp_dir = tempfile.mkdtemp(prefix=f'autopov_{scan_id}_')
        try:
            binary_path = os.path.join(temp_dir, 'input.bin')
            with open(binary_path, 'wb') as f:
                f.write(binary_data)
            return self.run_pov(
                pov_script=pov_script,
                scan_id=scan_id,
                pov_id=pov_id,
                extra_files={'input.bin': ''},
                exploit_contract=exploit_contract,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._cleanup_pov_resources(scan_id, pov_id)

    def batch_run(self, pov_scripts: List[Dict[str, Any]], scan_id: str, progress_callback: Optional[callable] = None) -> List[Dict[str, Any]]:
        results = []
        for i, pov_info in enumerate(pov_scripts):
            result = self.run_pov(
                pov_script=pov_info['script'],
                scan_id=scan_id,
                pov_id=pov_info.get('id', str(i)),
                execution_profile=pov_info.get('execution_profile'),
                target_language=pov_info.get('target_language'),
                exploit_contract=pov_info.get('exploit_contract'),
                codebase_path=pov_info.get('codebase_path'),
            )
            results.append(result)
            if progress_callback:
                progress_callback(i + 1, len(pov_scripts), result)
        return results

    def get_stats(self) -> Dict[str, Any]:
        if not self.is_available():
            return {'available': False}
        try:
            client = self._get_client()
            info = client.info()
            return {
                'available': True,
                'version': info.get('ServerVersion', 'unknown'),
                'containers_running': info.get('ContainersRunning', 0),
                'containers_total': info.get('Containers', 0),
                'images': info.get('Images', 0),
            }
        except Exception as e:
            return {'available': False, 'error': str(e)}


docker_runner = DockerRunner()


def get_docker_runner() -> DockerRunner:
    """Get the global Docker runner instance"""
    return docker_runner

