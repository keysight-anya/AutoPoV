"""
Taxonomy-agnostic oracle policy for AutoPoV proof confirmation.

Scope: this module provides proof oracle evaluation for two evidence families:
  1. Crash/sanitizer/native-style evidence (ASan, UBSan, kernel signals, native
     crash output) — via evaluate_proof_outcome()
  2. Browser DOM execution and HTTP response effects — via evaluate_live_proof_outcome()

Design principles:
  - Zero CWE hardcoding — all decisions are derived from output structure
  - Zero repo hardcoding — patterns are properties of crash reporting tools
  - path relevance is a hard confirmation requirement when a target is known
  - strong signal alone does NOT auto-confirm when no target is known
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Structural crash patterns
# These are properties of ASan/UBSan/the kernel signal handler — universal
# across all bug classes and all repos.
# ---------------------------------------------------------------------------

_SANITIZER_STRUCTURAL = re.compile(
    r'(=+\d+=+\s*(error|warning):'   # ==1234== ERROR:  (ASan/Valgrind banner)
    r'|runtime error:'                 # UBSan runtime error (with or without file:line)
    r'|signal \d+ \(sig\w+\)'        # signal 11 (SIGSEGV)
    r'|#\d+\s+0x[0-9a-f]+ in \w+'   # stack frame: #0 0xdeadbeef in func
    r'|heap-use-after-free'
    r'|heap-buffer-overflow'
    r'|stack-buffer-overflow'
    r'|double-free'
    r'|use-after-free'
    r'|null pointer dereference'
    r'|deadlysignal'
    r'|invalid read of size'          # Valgrind per-error line
    r'|invalid write of size'         # Valgrind per-error line
    r'|use of uninitialised value'    # Valgrind UMR
    r'|heap block overrun'            # Valgrind heap overrun
    r'|address .* is .* bytes? .* alloc'  # Valgrind/ASan address context
    # ── Raw kernel/shell crash text (fires even without ASan) ──────────
    r'|segmentation fault'            # kernel/shell SIGSEGV
    r'|bus error'                     # SIGBUS (alignment / mmap fault)
    r'|illegal instruction'           # SIGILL
    r'|floating point exception'      # SIGFPE
    r'|\bcore dumped\b'              # accompanies any fatal signal
    # ── ASan leak reports and UBSan additional patterns ──────────────
    r'|detected memory leaks'         # ASan LeakSanitizer summary
    r'|direct leak of'               # ASan LeakSanitizer detail
    r'|indirect leak of'             # ASan LeakSanitizer detail
    r'|integer overflow'             # UBSan signed integer overflow
    r'|shift exponent .* is too large'  # UBSan shift overflow
    r'|unsigned integer overflow'     # UBSan unsigned overflow
    r'|load of misaligned address'    # UBSan alignment
    # ── IMPROVEMENT 3.1: Additional detection patterns ─────────────────
    r'|abort(?:ed|ing)?'              # glibc abort (double-free, heap corruption)
    r'|\babort\b.*\bsignal'          # abort with signal
    r'|assertion .* failed'          # assert() failure
    r'|glibc detected'               # glibc memory corruption detection
    r'|\*{3}.*error\*{3}'           # *** error *** pattern
    r'|free\(\): invalid (?:pointer|size|next)'  # glibc free() errors
    r'|malloc\(\): memory corruption'  # glibc malloc errors
    r'|corrupted double-linked list'  # glibc list corruption
    r'|backtrace:'                   # ASan/LSan backtrace header
    r'|memory map:'                  # ASan memory map
    # ── Python C-extension crash ────────────────────────────────────
    r'|segmentation fault \(core dumped\)'  # Python C-extension crash
    # ── JavaScript/Node.js errors ────────────────────────────────────
    r'|FATAL ERROR:'                 # Node.js fatal error
    r'|out of memory'               # OOM in any language
    # ── Java errors ──────────────────────────────────────────────────
    r'|java\.lang\.'               # Java exceptions
    r'|exception in thread'        # Java thread exception
    # ── Partial evidence (lower confidence but still useful) ──────────
    r'|assertion failed'           # Assert triggered
    r'|incorrect result'           # Wrong computation
    r'|member access within null'     # UBSan null member access
    r'|index \d+ out of bounds'      # UBSan array bounds
    r')',
    re.IGNORECASE,
)

# Evidence markers that appear in ASan/UBSan/crash output — used to build
# matched_evidence_markers for self-report detection.
_EVIDENCE_MARKER_STRINGS: List[str] = [
    'heap-use-after-free',
    'heap-buffer-overflow',
    'stack-buffer-overflow',
    'double-free',
    'use-after-free',
    'null pointer dereference',
    'addresssanitizer',
    'undefinedbehaviorsanitizer',
    'deadlysignal',
    'segmentation fault',
    'runtime error:',
    'sigsegv',
    'vulnerability triggered',
    'vuln triggered',
    # ASan leak reports
    'detected memory leaks',
    'direct leak of',
    'indirect leak of',
    # UBSan additional signals
    'integer overflow',
    'shift exponent',
    'load of misaligned address',
    'index out of bounds',
    # JVM crash signals
    'outofmemoryerror',
    'stackoverflowerror',
    'java.lang.nullpointerexception',
    # Node.js crash signals
    'maximum call stack size exceeded',
    'fatal error: out of memory',
    'javascript heap out of memory',
    # Behavioral evidence markers (printed by PoV scaffolds)
    'file_created_outside_allowed_dir',
    'insecure_permission',
    'sensitive_data_leaked',
    'exception_triggered',
    'timing_anomaly',
    'resource_exhaustion',
    'prototype_polluted',
    # Additional behavioral markers (used by _infer_exploitation_approach & scaffolds)
    'xss_confirmed',
    'command_injection_confirmed',
    'unauthorized_access_granted',
    'path_traversal_confirmed',
    'stack_trace_leaked',
    'internal_path_disclosed',
    # Additional behavioral markers (SQL injection, deserialization, SSRF, XXE, etc.)
    'sql_injection_confirmed',
    'code_injection_confirmed',
    'deserialization_confirmed',
    'ssrf_confirmed',
    'input_validation_bypassed',
    'xml_entity_expanded',
    'xxe_confirmed',
    'sensitive_method_exposed',
    'path_expansion_confirmed',
    'type_confusion_confirmed',
]

# ---------------------------------------------------------------------------
# Environment / infrastructure failure patterns
# Output that means the harness or runner couldn't start the target at all.
# Must be checked BEFORE the non_evidence path so these are not silently
# counted as "the target ran cleanly" (which would block refinement).
# ---------------------------------------------------------------------------
_ENVIRONMENT_FAILURE_PATTERNS: List[str] = [
    'awaiting native harness fallback',  # verifier.py fallback script: TARGET_BINARY not set
    'no such file or directory',         # binary path missing
    'permission denied',                 # binary not executable
    'command not found',                 # binary not on PATH
    'execvp',                            # low-level exec failure
    'syntax error',                      # bash script syntax error (broken prelude/build command)
    'target binary not found',
    'target binary is empty',
    'target binary was not built',
    # ── PoV script infrastructure failures (not target crashes) ──────────
    'traceback (most recent call last):',  # Python PoV script crash
    'nameerror:',                        # PoV script references undefined variable
    'attributeerror:',                   # PoV script method/type error
    'typeerror:',                        # PoV script type error
    'valueerror:',                       # PoV script value error
    'keyerror:',                         # PoV script key error
    'indexerror:',                       # PoV script index error
    'modulenotfounderror:',              # PoV missing Python dependency
    'no module named',                   # Python import failure
    'importerror:',                      # Python import failure
    'cannot find module',                # Node.js require() failure
    'connection refused',                # Target server not running
    '[errno 111]',                       # Connection refused errno
    'econnrefused',                      # Node.js connection refused
    'connectionrefusederror',            # Python connection refused
]

# Output that is definitively NOT crash evidence regardless of exit code.
# These are properties of the target's CLI or OS error reporting —
# universal across repos, no CWE needed.
# ---------------------------------------------------------------------------

_NON_EVIDENCE_PATTERNS: List[str] = [
    'unknown command',
    'unknown option',
    'missing command',
    'invalid option',
    'unrecognized option',
    'failed to read key',
    'failed to read',
    'no such file or directory',
    'usage:',
    'try --help',
    'error: missing',
]

# ---------------------------------------------------------------------------
# Self-report strings
# ---------------------------------------------------------------------------

_SELF_REPORT_STRINGS = {'vulnerability triggered', 'vuln triggered', 'vulnerability_triggered'}
_LIVE_SELF_REPORT_STRINGS = {
    'vulnerability triggered', 'vuln triggered', 'vulnerability_triggered',
    'script executed', 'xss triggered', 'exploit worked', 'proof succeeded',
}
_GENERIC_ORACLE_STRINGS = {'crash', 'error', 'failed', 'success'}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _has_strong_sanitizer_evidence(stderr_lower: str, stdout_lower: str) -> bool:
    """Return True if genuine sanitizer/crash evidence is present in stderr
    (or stdout when stderr is empty and the output is not obviously faked).

    This helper is shared by classify_signal() and classify_signal_detailed()
    so the sanitizer-first priority logic is consistent.
    """
    # Real sanitizer/crash output ALWAYS goes to stderr.  Searching stdout
    # allows PoV scripts to game the oracle by printing fake crash markers.
    # Require structural patterns to appear in stderr unless stderr is empty.
    if _SANITIZER_STRUCTURAL.search(stderr_lower):
        return True
    # Only fall back to stdout if stderr is empty AND stdout looks like it
    # might contain redirected sanitizer output (contains ==N== banner or
    # stack frame).
    if not stderr_lower.strip():
        if _SANITIZER_STRUCTURAL.search(stdout_lower):
            # Extra guard: reject obvious fake markers that PoV scripts print
            _fake_crash_markers = (
                'non-zero exit code indicating crash',
                'simulated crash',
                'fake crash',
                'mock crash',
            )
            if not any(fm in stdout_lower for fm in _fake_crash_markers):
                return True
    return False


def classify_signal(stdout: str, stderr: str, exit_code: int) -> str:
    """Classify runtime output into signal strength.

    Returns one of: 'strong', 'ambiguous', 'non_evidence'

    strong       — structured sanitizer/kernel crash output present
    non_evidence — output is provably CLI usage/error text, or clean exit
                   with no strong crash evidence
    ambiguous    — everything else (generic non-zero exit, vague error text)

    Scope: crash/sanitizer/native-style proof families only.

    Key design decisions:
    - Strong evidence is checked FIRST — if ASan fires, we return 'strong'
      even if "usage:" or a Python traceback also appears in the output.
      A real crash in the target C extension should NEVER be hidden by a
      Python traceback in the PoV driver script.
    - exit_code == 0 is only non_evidence when no strong structural marker
      exists.  Browser/app-layer proofs may exit 0 with valid DOM/response
      evidence, but those also produce strong structural markers.
    - Non-evidence patterns only dominate when strong evidence is absent.
    """
    stdout_lower = str(stdout or '').lower()
    stderr_lower = str(stderr or '').lower()
    combined = stdout_lower + '\n' + stderr_lower

    # ── PRIORITY 1: Strong sanitizer/crash evidence ────────────────────────
    # Check BEFORE environment failures.  A real ASan crash in a C extension
    # must NOT be suppressed just because the Python driver script also
    # produced a traceback.  The sanitizer evidence on stderr is the ground
    # truth; the traceback on stdout is just the PoV script's output wrapping.
    if _has_strong_sanitizer_evidence(stderr_lower, stdout_lower):
        return 'strong'

    # ── PRIORITY 1.5: Python/Node.js runtime crash evidence ────────────────
    # These are strong crash signals from interpreted runtimes — not just
    # generic errors, but fatal/crash-class exceptions that terminate the process.
    _python_crash = any(p in combined for p in (
        'recursionerror', 'memoryerror',
        'fatal python error', 'py_fatalerror',
        'fatal error: ', 'overflowerror:',
    ))
    if _python_crash:
        return 'strong'
    _node_crash = any(p in combined for p in (
        'fatal error:', 'heap out of memory',
        'fatal process', 'v8::internal',
        'cannot find module',  # missing native addon crash
    ))
    if _node_crash:
        return 'strong'

    # ── PRIORITY 2: Environment/infrastructure failure ─────────────────────
    # Only reach here when NO strong sanitizer evidence exists.  At this point,
    # a Python traceback, missing module, or permission error genuinely means
    # the harness could not start the target — not that the target crashed.
    # EXCEPTION: if a behavioral marker is also present, the Traceback is
    # evidence of the TARGET crashing (exploited by the PoV), not the PoV
    # script itself crashing.  In that case, return 'ambiguous' so the oracle
    # can evaluate the marker.
    if any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS):
        _behavioral_markers_env = (
            'file_created_outside_allowed_dir', 'insecure_permission',
            'sensitive_data_leaked', 'exception_triggered',
            'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
            'xss_confirmed', 'command_injection_confirmed',
            'unauthorized_access_granted', 'path_traversal_confirmed',
            'stack_trace_leaked', 'internal_path_disclosed',
        )
        if any(m in combined for m in _behavioral_markers_env):
            return 'ambiguous'
        return 'non_evidence'

    # Non-evidence: CLI usage/setup error text (no strong evidence present)
    if any(p in combined for p in _NON_EVIDENCE_PATTERNS):
        return 'non_evidence'

    # Clean exit with no strong evidence
    if exit_code == 0:
        # Exception: if the PoV script printed a conditional vulnerability marker
        # (e.g. print('VULNERABILITY TRIGGERED') after verifying a crash), treat
        # this as ambiguous so the script_surface_triggered_marker oracle can
        # accept it.  'VULNERABILITY TRIGGERED' by itself in stdout is NOT strong
        # evidence (it may be self-report), but it is not non_evidence either.
        if 'vulnerability triggered' in combined or 'vuln triggered' in combined:
            return 'ambiguous'
        # Check for behavioral evidence markers before declaring non_evidence.
        # These markers indicate a genuine side-effect was observed (e.g. file
        # created outside allowed dir), even with exit_code=0.
        _behavioral_markers = (
            'file_created_outside_allowed_dir', 'insecure_permission',
            'sensitive_data_leaked', 'exception_triggered',
            'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
            'xss_confirmed', 'command_injection_confirmed',
            'unauthorized_access_granted', 'path_traversal_confirmed',
            'stack_trace_leaked', 'internal_path_disclosed',
        )
        if any(m in combined for m in _behavioral_markers):
            return 'ambiguous'
        return 'non_evidence'

    return 'ambiguous'


@dataclass
class SignalDetail:
    """Enriched signal classification with actionable recovery hints.

    Returned by classify_signal_detailed() — a superset of classify_signal().
    The extra fields let the refinement loop give the LLM precise, actionable
    feedback instead of the vague 'ambiguous' or 'non_evidence' string.
    """
    label: str            # 'strong' | 'ambiguous' | 'non_evidence'
    reason: str           # human-readable: "ASan heap-buffer-overflow detected"
    crash_type: str       # 'asan_heap_overflow' | 'sigsegv' | 'ubsan' | 'clean_exit' |
                          # 'wrong_args' | 'exec_failed' | 'ran_cleanly' | 'raw_crash' |
                          # 'sanitizer_hit' | 'generic_nonzero'
    actionable_hint: str  # "binary did not start — check argv" etc.
    recovery_strategy: str  # 'fix_invocation' | 'try_different_input' | 'change_approach' |
                            # 'success' | 'check_build'


def classify_signal_detailed(stdout: str, stderr: str, exit_code: int) -> SignalDetail:
    """Classify runtime output into an enriched SignalDetail with actionable hints.

    Extends classify_signal() with fine-grained crash_type, human-readable reason,
    and recovery_strategy so the refinement prompt can be specific about what went
    wrong and how to fix it.

    Pattern priority (highest first):
      1. ASan / UBSan structural output  → sanitizer_hit / sigsegv / ubsan   → strong
      2. Binary execution failure         → exec_failed                        → non_evidence
      3. CLI usage / wrong-args output   → wrong_args                         → non_evidence
      4. Clean exit with no crash        → ran_cleanly                        → non_evidence
      5. Generic non-zero exit            → generic_nonzero                    → ambiguous

    IMPORTANT: sanitizer/structural patterns are checked BEFORE environment
    failures so that a real ASan crash in a C extension is never suppressed by
    a Python traceback in the PoV driver script.
    """
    stdout_lower = str(stdout or '').lower()
    stderr_lower = str(stderr or '').lower()
    combined = stdout_lower + '\n' + stderr_lower

    # ── 1. Strong structural evidence — ASan / UBSan / kernel signals –––––––––
    # Check BEFORE environment failures.  A real ASan crash in a C extension
    # must NOT be suppressed just because the Python driver script also
    # produced a traceback.  The sanitizer evidence on stderr is the ground truth.
    if _has_strong_sanitizer_evidence(stderr_lower, stdout_lower):
        # Narrow crash type for clearer feedback
        if 'heap-use-after-free' in combined or 'use-after-free' in combined:
            crash_type = 'asan_use_after_free'
            reason = 'ASan use-after-free detected'
        elif 'heap-buffer-overflow' in combined or 'heap buffer overflow' in combined:
            crash_type = 'asan_heap_overflow'
            reason = 'ASan heap-buffer-overflow detected'
        elif 'stack-buffer-overflow' in combined:
            crash_type = 'asan_stack_overflow'
            reason = 'ASan stack-buffer-overflow detected'
        elif 'double-free' in combined:
            crash_type = 'asan_double_free'
            reason = 'ASan double-free detected'
        elif 'null pointer dereference' in combined:
            crash_type = 'asan_null_deref'
            reason = 'ASan null-pointer dereference detected'
        elif 'runtime error:' in combined:
            crash_type = 'ubsan'
            reason = 'UBSan runtime error detected'
        elif any(s in combined for s in ('sigsegv', 'signal 11', 'segmentation fault')):
            crash_type = 'sigsegv'
            reason = 'Segmentation fault (SIGSEGV) detected'
        elif any(s in combined for s in ('sigabrt', 'signal 6', 'abort')):
            crash_type = 'sigabrt'
            reason = 'Process aborted (SIGABRT) detected'
        elif 'deadlysignal' in combined:
            crash_type = 'raw_crash'
            reason = 'ASan deadly signal detected'
        else:
            crash_type = 'sanitizer_hit'
            reason = 'Sanitizer / crash output detected'
        return SignalDetail(
            label='strong',
            reason=reason,
            crash_type=crash_type,
            actionable_hint='Crash signal confirmed. Verify path relevance and target entrypoint.',
            recovery_strategy='success',
        )

    # ── 2. Environment / infrastructure failure –––––––––––––––––––––––––––
    # Only reach here when NO strong sanitizer evidence exists.  At this point,
    # a Python traceback, missing module, or permission error genuinely means
    # the harness could not start the target — not that the target crashed.
    # EXCEPTION: if a behavioral marker is also present, the Traceback is
    # evidence of the TARGET crashing (exploited by the PoV), not the PoV
    # script itself crashing.  In that case, return 'ambiguous' so the oracle
    # can evaluate the marker.
    if any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS):
        _behavioral_markers_csd = (
            'file_created_outside_allowed_dir', 'insecure_permission',
            'sensitive_data_leaked', 'exception_triggered',
            'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
            'xss_confirmed', 'command_injection_confirmed',
            'unauthorized_access_granted', 'path_traversal_confirmed',
            'stack_trace_leaked', 'internal_path_disclosed',
        )
        if any(m in combined for m in _behavioral_markers_csd):
            return SignalDetail(
                label='ambiguous',
                reason='Environment failure pattern present but behavioral marker overrides — target exception is evidence',
                crash_type='behavioral',
                actionable_hint='Behavioral marker detected alongside infrastructure error. The target exception is genuine evidence.',
                recovery_strategy='success',
            )
        # Distinguish: binary missing vs. not built
        if any(p in combined for p in ('no such file or directory', 'execvp', 'command not found')):
            crash_type = 'exec_failed'
            if 'build failed' in combined or 'build_failed' in combined:
                hint = ('Build failed — the binary was not produced. Check build_log for compiler '
                        'errors and ensure all required libraries are installed.')
                strategy = 'check_build'
            else:
                hint = ('Binary path is wrong or the binary was not built. Use TARGET_BINARY env var '
                        'exactly as provided; do not hard-code a path.')
                strategy = 'fix_invocation'
        else:
            crash_type = 'exec_failed'
            hint = 'Binary could not be executed. Check TARGET_BINARY and file permissions.'
            strategy = 'fix_invocation'
        return SignalDetail(
            label='non_evidence',
            reason='Binary execution failed — harness could not start the target',
            crash_type=crash_type,
            actionable_hint=hint,
            recovery_strategy=strategy,
        )

    # ── 3. CLI usage / wrong-args output ––––––––––––––––––––––––––––––
    if any(p in combined for p in _NON_EVIDENCE_PATTERNS):
        crash_type = 'wrong_args'
        return SignalDetail(
            label='non_evidence',
            reason='Binary ran but rejected the arguments (CLI usage/error output only)',
            crash_type=crash_type,
            actionable_hint=('Binary started successfully but printed usage/error text and exited. '
                             'Check the argument format: use correct subcommand, flags, and input '
                             'mode as shown in probe_cli_flags or preflight help text.'),
            recovery_strategy='fix_invocation',
        )

    # ── 4. Clean exit with no crash –––––––––––––––––––––––––––––––––––––
    if exit_code == 0:
        # Exception: conditional VULNERABILITY TRIGGERED marker is ambiguous not non_evidence
        if 'vulnerability triggered' in combined or 'vuln triggered' in combined:
            return SignalDetail(
                label='ambiguous',
                reason='Exit 0 with VULNERABILITY TRIGGERED marker — may be conditional self-report',
                crash_type='marker_exit0',
                actionable_hint=(
                    'The script printed VULNERABILITY TRIGGERED and exited 0. '
                    'If the marker was printed only after detecting a crash or unexpected output '
                    'it will be accepted by the oracle. Ensure the marker is conditional, '
                    'not always printed.'
                ),
                recovery_strategy='success',
            )
        return SignalDetail(
            label='non_evidence',
            reason='Binary processed input cleanly (exit 0) — no crash observed',
            crash_type='ran_cleanly',
            actionable_hint=('The binary ran to completion without a crash. The exploit payload was '
                             'likely not large or malformed enough. Try a larger overflow payload, '
                             'a different input format, or a path that exercises the vulnerable '
                             'code more directly.'),
            recovery_strategy='try_different_input',
        )

    # ── 5. Generic non-zero exit (ambiguous) ––––––––––––––––––––––––––––––
    return SignalDetail(
        label='ambiguous',
        reason=f'Non-zero exit code ({exit_code}) without clear crash or usage output',
        crash_type='generic_nonzero',
        actionable_hint=('Binary exited non-zero but produced no recognisable crash or error text. '
                         'Check stdout/stderr for clues. The issue may be a missing configuration '
                         'file, wrong input format, or a runtime setup problem.'),
        recovery_strategy='change_approach',
    )

def is_path_relevant(combined_output: str, target_entrypoint: str, filepath: str, target_binary: str = '', relevance_anchors: Optional[List[str]] = None, execution_stage: str = 'trigger', execution_surface: str = '') -> bool:
    """Return True if the crash output references the intended target.

    Derived from target_entrypoint, filepath, and target_binary — no CWE needed.

    IMPORTANT: when a concrete target_entrypoint is known, it is the authoritative
    relevance anchor. File/binary-name matches are only fallbacks for contracts that
    do not yet know the target symbol. This prevents unrelated setup-stage crashes
    from confirming a different target in the same file/binary.

    execution_stage: when 'trigger', attempt to narrow the haystack to content
    produced after the trigger phase begins.  This prevents a sanitizer crash that
    fired during setup (e.g. command_keygen) from being credited to a different
    trigger-stage target (e.g. command_extract) in a monolithic PoV script.
    When no stage-boundary markers are found the full combined output is used.

    execution_surface: when 'function_harness', the PoV compiles and directly calls
    the vulnerable function — the ASan stacktrace will reference the function symbol
    but NOT the binary name or filepath basename.  Path relevance is automatically
    satisfied in this case because the crash is on-target by construction.
    """
    # ── Function-harness shortcut: crash is on-target by construction ─────────
    # A standalone C/C++ harness calls the vulnerable function directly; the
    # resulting ASan stacktrace mentions function symbols only, never the binary
    # name or filepath.  Accept the crash unconditionally for this surface.
    if execution_surface == 'function_harness':
        return True
    # ── repo_script / function_call shortcut ─────────────────────────────────
    # Python/Node package PoVs run against a module, not a binary.  The output
    # will reference the module name or the file, not an ELF binary name.
    # Treat as path-relevant when a concrete entrypoint is known OR when the
    # filepath is in the output (e.g. traceback mentions the file).
    if execution_surface in {'repo_script', 'function_call'}:
        _haystack = str(combined_output or '').lower()
        _ep = str(target_entrypoint or '').strip().lower()
        if _ep and _ep not in {'unknown', 'none', 'n/a'}:
            return True  # named entrypoint — on-target by construction
        if filepath:
            _bn = os.path.basename(filepath).lower()
            if _bn and _bn in _haystack:
                return True
        # No specific anchor found but still a script surface — accept as relevant
        # (the model is targeting the repo directly; path relevance is guaranteed).
        return True
    # ── Stage-aware haystack narrowing ────────────────────────────────────────
    # Monolithic PoV scripts often emit both setup and trigger output in one
    # stream.  When the caller declares we are evaluating the trigger stage,
    # try to restrict path-relevance checks to the post-trigger portion of the
    # output so that a sanitizer crash from a setup subcommand (e.g. keygen)
    # cannot satisfy path relevance for a trigger-stage target.
    text = str(combined_output or '')
    if execution_stage == 'trigger':
        # Recognised stage boundary markers written by well-structured harnesses.
        _STAGE_MARKERS = (
            '--- trigger ---',
            '[trigger]',
            'trigger phase',
            'running exploit',
            'TRIGGER START',
        )
        for marker in _STAGE_MARKERS:
            idx = text.lower().rfind(marker.lower())
            if idx != -1:
                text = text[idx:]
                break
    haystack = text.lower()
    # ── Standard relevance checks ─────────────────────────────────────────────
    anchors = [str(item).strip().lower() for item in (relevance_anchors or []) if str(item).strip()]
    if anchors:
        return any(anchor in haystack for anchor in anchors)
    concrete_entrypoint = str(target_entrypoint or '').strip().lower()
    if concrete_entrypoint and concrete_entrypoint not in {'unknown', 'none', 'n/a'}:
        if concrete_entrypoint in haystack:
            return True
        # Entrypoint not found — fall through to binary/filepath checks ONLY
        # when the entrypoint looks like a high-level name (CLI subcommand) that
        # wouldn't appear in a stack trace.  Specific C symbols (containing '_')
        # like 'command_extract' are authoritative anchors — if not found, the
        # crash is in a different code path and should be rejected.
        _looks_like_c_symbol = '_' in concrete_entrypoint or len(concrete_entrypoint) > 20
        if _looks_like_c_symbol:
            # Task 3 (Gap 3): Before rejecting, check secondary anchors.
            # Crashes often happen in internal helper functions, not the exact
            # target function.  Binary name or filepath in the stack trace is
            # sufficient to confirm path relevance.
            if target_binary:
                bin_name = os.path.basename(target_binary).lower().strip()
                if bin_name and bin_name in haystack:
                    return True
            if filepath:
                basename = os.path.basename(filepath).lower()
                if basename and basename in haystack:
                    return True
            return False
        # Short generic entrypoint (e.g. "extract", "parse") — accept binary
        # name match as fallback since these won't appear in sanitizer output.
        if target_binary:
            bin_name = os.path.basename(target_binary).lower().strip()
            if bin_name and bin_name in haystack:
                return True
        if filepath:
            basename = os.path.basename(filepath).lower()
            if basename and basename in haystack:
                return True
        return False
    if filepath:
        basename = os.path.basename(filepath).lower()
        if basename and basename in haystack:
            return True
    if target_binary:
        bin_name = os.path.basename(target_binary).lower().strip()
        if bin_name and bin_name in haystack:
            return True
    return False


def _is_conditional_marker(script: str, marker: str) -> bool:
    """Return True if every occurrence of *marker* in *script* is inside a
    conditional block (if/elif) with a NON-TRIVIAL condition.  Unconditional
    top-level prints are self-report; trivial conditions like `if True:` or
    `if 1:` are also self-report because they always execute.
    """
    lines = script.splitlines()
    marker_lower = marker.lower()
    found_any = False
    # Trivial conditions that always execute — these are NOT real guards
    _trivial_conditions = ('true', '1', 'yes', 'always', 'none', 'not false')
    for i, line in enumerate(lines):
        if marker_lower not in line.lower():
            continue
        found_any = True
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            return False  # top-level = unconditional
        # Walk backwards to find a guarding if/elif at a lower indent level
        found_guard = False
        guard_line = ''
        for j in range(i - 1, -1, -1):
            prev = lines[j]
            if not prev.strip():
                continue  # skip blank lines
            prev_indent = len(prev) - len(prev.lstrip())
            if prev_indent < indent and prev.lstrip().startswith(('if ', 'elif ', 'if(')):
                found_guard = True
                guard_line = prev.lstrip()
                break
            if prev_indent < indent:
                break  # hit a non-if statement at lower indent
        if not found_guard:
            return False
        # Reject trivial conditions that always execute (if True:, if 1:, etc.)
        # Extract the condition part after 'if ' or 'elif '
        _cond = guard_line
        if _cond.startswith('elif '):
            _cond = _cond[5:]
        elif _cond.startswith('if '):
            _cond = _cond[3:]
        elif _cond.startswith('if('):
            _cond = _cond[3:]
        # Strip trailing colon and whitespace
        _cond = _cond.rstrip(':').strip().lower()
        # Remove surrounding parentheses
        while _cond.startswith('(') and _cond.endswith(')'):
            _cond = _cond[1:-1].strip()
        if _cond in _trivial_conditions:
            return False
        # Also reject `if <variable>:` where variable is a string literal
        # that evaluates to truthy (e.g., if "always":)
        if _cond.startswith('"') or _cond.startswith("'"):
            return False
    return found_any  # True only if we found marker AND all were conditional


def is_self_report_only(pov_script: str, evidence_markers: List[str], self_report_strings: Optional[set[str]] = None) -> bool:
    """Return True when every matched evidence marker is a self-report string
    embedded in the PoV script itself — i.e. the script printed its own success
    unconditionally without any structural crash evidence from the target.

    IMPORTANT: pass only matched_evidence_markers here (strings from
    _EVIDENCE_MARKER_STRINGS that matched in stdout/stderr), NOT the
    non-evidence patterns list.  Mixing the two lists would incorrectly
    trigger self-report blocking on CLI error output.
    """
    if not evidence_markers:
        return False
    script_lower = str(pov_script or '').lower()
    self_report_values = self_report_strings or _SELF_REPORT_STRINGS
    # Negation patterns: phrases that precede a self-report string and negate it.
    # e.g. "No vulnerability triggered" should NOT count as a self-report hit.
    _NEGATION_PREFIXES = ('no ', 'not ', 'never ', 'failed to ', 'did not ', "couldn't ", 'cannot ')
    for marker in evidence_markers:
        m = marker.lower()
        # If any matched marker is NOT a self-report string, it is real evidence
        if m not in self_report_values:
            return False
        # Self-report candidate — confirm it is embedded as a literal in the script
        if m not in script_lower:
            return False
        # Extra guard: if the marker appears in the script only in a negated context
        # (e.g. print("No vulnerability triggered")), it does not count as self-report.
        # Check whether every occurrence in the script is preceded by a negation word.
        import re as _re_sr
        _pattern = _re_sr.compile(_re_sr.escape(m))
        _occurrences = [script_lower[max(0, mo.start()-15):mo.start()] for mo in _pattern.finditer(script_lower)]
        if _occurrences and all(
            any(neg in _ctx for neg in _NEGATION_PREFIXES)
            for _ctx in _occurrences
        ):
            # All occurrences in the script are negated — treat as not self-report
            return False
    # All matched markers are self-report strings embedded in the script.
    # Task 2 (Gap 2): Before confirming self-report, check if the marker
    # prints are inside conditional blocks (if/elif).  Conditional markers
    # that only fire on exploit success are NOT self-report.
    if all(_is_conditional_marker(str(pov_script or ''), m.lower()) for m in evidence_markers if m.lower() in (self_report_strings or _SELF_REPORT_STRINGS)):
        return False  # all markers are conditional — not self-report
    return True


def validate_expected_oracle(value: str) -> bool:
    """Return True when expected_oracle is specific enough to be useful as a
    supporting signal.

    Rejects generic strings that would cause false positives if treated as
    confirmation evidence.
    """
    v = (value or '').strip().lower()
    return (
        bool(v)
        and v not in _SELF_REPORT_STRINGS
        and v not in _GENERIC_ORACLE_STRINGS
    )


def evaluate_proof_outcome(
    stdout: str,
    stderr: str,
    exit_code: int,
    target_entrypoint: str = '',
    filepath: str = '',
    pov_script: str = '',
    expected_oracle: str = '',
    target_binary: str = '',
    stage: str = 'trigger',
    relevance_anchors: Optional[List[str]] = None,
    asan_disabled: bool = False,
    baseline_exit_code: int = -1,
    baseline_stderr: str = '',
    execution_surface: str = '',
    observable_evidence: Optional[List[str]] = None,
    baseline_stdout: str = '',
) -> dict:
    """Single entry-point for oracle evaluation.  Taxonomy-agnostic.

    Returns a dict compatible with the existing _evaluate_proof_outcome return
    shape so call sites need minimal changes.

    Confirmation rules (explicit):
      confirmed          = strong + (target_entrypoint OR target_binary) known
                           + path_relevant (entrypoint, filepath, OR binary-name match)
      unresolved         = strong + target known + NOT path_relevant
      unresolved         = strong + NO target known  (gate should prevent this,
                           but if it reaches here, do not auto-confirm)
      unresolved         = ambiguous
      not_confirmed      = non_evidence
      not_confirmed      = self_report_only

    expected_oracle is a Layer 4 *supporting* signal only — it can increase
    confidence but can never by itself set triggered=True.
    """
    combined = (str(stdout or '') + '\n' + str(stderr or '')).lower()
    signal = classify_signal(stdout, stderr, exit_code)

    # ── Layer 0: environment/infrastructure failure ─────────────────────────
    # The harness could not start the target binary at all.  Distinguish from
    # plain non_evidence so _derive_refinement_errors can give actionable
    # guidance ("set TARGET_BINARY") instead of generic "non_evidence".
    # EXCEPTION: if a behavioral marker is present alongside the environment
    # failure pattern, the Traceback etc. is evidence of the TARGET exception
    # (exploited by the PoV), not the PoV script itself crashing.  In that
    # case, skip the environment_failure return and let the oracle evaluate
    # the marker through the ambiguous signal path.
    is_env_failure = any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS)
    if signal == 'non_evidence' and is_env_failure:
        _behavioral_markers_l0 = (
            'file_created_outside_allowed_dir', 'insecure_permission',
            'sensitive_data_leaked', 'exception_triggered',
            'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
            'xss_confirmed', 'command_injection_confirmed',
            'unauthorized_access_granted', 'path_traversal_confirmed',
            'stack_trace_leaked', 'internal_path_disclosed',
        )
        _has_behavioral = any(m in combined for m in _behavioral_markers_l0)
        # Also check contract observable_evidence markers
        _obs_ev_l0 = list(observable_evidence or [])
        _has_contract = bool(_obs_ev_l0 and any(str(m).strip().lower() in combined for m in _obs_ev_l0))
        if not _has_behavioral and not _has_contract:
            return {
                'triggered': False,
                'signal_class': 'non_evidence',
                'reason': 'environment_failure',
                'disqualified': True,
                'path_relevant': False,
                'self_report_only': False,
                'model_oracle_matched': False,
                'matched_evidence_markers': [],
                'matched_markers': [],
                'setup_failure_detected': True,
            }
        # Behavioral or contract marker overrides — treat signal as ambiguous
        # so the oracle can evaluate the marker through the normal path.
        signal = 'ambiguous'

    # ── Layer 1: non-evidence hard stop ────────────────────────────────────
    # classify_signal already returned 'strong' if a genuine sanitizer crash
    # is present, so we never reach here with a real crash.
    #
    # Task 7: BEFORE giving up on non_evidence, check if contract's
    # observable_evidence markers are present in the output. This is the single
    # most impactful change — it means the oracle can confirm ANY vulnerability
    # type as long as the proof strategy defined the right markers.
    if signal == 'non_evidence':
        _obs_ev = list(observable_evidence or [])
        if _obs_ev:
            _contract_markers = [m for m in _obs_ev if str(m).strip().lower() in combined]
            if _contract_markers:
                # Check self-report guard
                _self_rep_contract = is_self_report_only(pov_script, _contract_markers) if pov_script else False
                # For contract-driven confirmation, path relevance is advisory, not a hard gate.
                # Contract markers are the PROOF that the PoV says to look for. If the
                # contract says "look for INSECURE_PERMISSION" and that appears in output,
                # that IS the proof — even if the output doesn't mention the binary name.
                # This makes the oracle extensible to ANY vulnerability type.
                _path_rel_contract = is_path_relevant(
                    combined, target_entrypoint, filepath, target_binary,
                    relevance_anchors=relevance_anchors,
                    execution_stage=stage, execution_surface=execution_surface,
                )
                # Accept contract markers when: (a) path-relevant, OR (b) not self-reported
                # and at least one target anchor EXISTS IN THE OUTPUT (not just in metadata).
                # Issue #6: Previously, _has_any_anchor only checked if metadata existed,
                # which allowed false positives where contract markers appeared in
                # unrelated program output. Now we require the anchor to actually appear
                # in the runtime output when path_relevant is False.
                _has_any_anchor = bool(target_entrypoint or target_binary or filepath
                                      or any(str(a).strip() for a in (relevance_anchors or [])))
                if _path_rel_contract:
                    # Path IS relevant — contract markers are on-target
                    _anchor_in_output = True
                else:
                    # Path NOT relevant — require at least one anchor IN the output
                    _anchor_in_output = any(
                        str(anchor).strip().lower() in combined.lower()
                        for anchor in [target_entrypoint, target_binary, filepath]
                        + list(relevance_anchors or [])
                        if str(anchor).strip()
                    )
                if not _self_rep_contract and (_path_rel_contract or (_has_any_anchor and _anchor_in_output)):
                    return {
                        'triggered': True,
                        'signal_class': 'contract_matched',
                        'reason': 'contract_matched+path_relevant' if _path_rel_contract else 'contract_matched+anchor_exists',
                        'disqualified': False,
                        'path_relevant': _path_rel_contract,
                        'self_report_only': False,
                        'model_oracle_matched': bool(
                            validate_expected_oracle(expected_oracle)
                            and expected_oracle.strip().lower() in combined
                        ),
                        'matched_evidence_markers': _contract_markers,
                        'matched_markers': _contract_markers,
                        'setup_failure_detected': False,
                    }
                elif _contract_markers and not _self_rep_contract:
                    # Markers found but no anchor at all
                    return {
                        'triggered': False,
                        'signal_class': 'contract_matched',
                        'reason': 'contract_matched+no_anchor',
                        'disqualified': False,
                        'path_relevant': False,
                        'self_report_only': False,
                        'model_oracle_matched': False,
                        'matched_evidence_markers': _contract_markers,
                        'matched_markers': _contract_markers,
                        'setup_failure_detected': False,
                    }

        # Task 7: Differential output analysis — compare baseline vs exploit
        _diff_result = _differential_analysis(
            baseline_stdout=baseline_stdout, baseline_stderr=baseline_stderr,
            exploit_stdout=stdout, exploit_stderr=stderr,
            observable_evidence=_obs_ev if _obs_ev else [],
        )
        if _diff_result.get('differential_evidence'):
            _path_rel_diff = is_path_relevant(
                combined, target_entrypoint, filepath, target_binary,
                relevance_anchors=relevance_anchors,
                execution_stage=stage, execution_surface=execution_surface,
            )
            if _path_rel_diff:
                return {
                    'triggered': True,
                    'signal_class': 'differential',
                    'reason': 'differential_output+path_relevant',
                    'disqualified': False,
                    'path_relevant': True,
                    'self_report_only': False,
                    'model_oracle_matched': False,
                    'matched_evidence_markers': _diff_result.get('novel_markers', []),
                    'matched_markers': _diff_result.get('novel_markers', []),
                    'setup_failure_detected': False,
                }

        return {
            'triggered': False,
            'signal_class': 'non_evidence',
            'reason': 'non_evidence',
            'disqualified': True,
            'path_relevant': False,
            'self_report_only': False,
            'model_oracle_matched': False,
            'matched_evidence_markers': [],
            # backward-compat keys
            'matched_markers': [],
            'setup_failure_detected': False,
        }

    # ── Build evidence markers (separate from non-evidence patterns) ───────
    evidence_markers = [p for p in _EVIDENCE_MARKER_STRINGS if p in combined]

    # ── Layer 2: path relevance ─────────────────────────────────────────────
    path_rel = is_path_relevant(combined, target_entrypoint, filepath, target_binary, relevance_anchors=relevance_anchors, execution_stage=stage, execution_surface=execution_surface)

    # ── Layer 3: self-report blocking ───────────────────────────────────────
    self_rep = is_self_report_only(pov_script, evidence_markers)
    if self_rep:
        return {
            'triggered': False,
            'signal_class': signal,
            'reason': 'self_report_only',
            'disqualified': False,
            'path_relevant': path_rel,
            'self_report_only': True,
            'model_oracle_matched': False,
            'matched_evidence_markers': evidence_markers,
            'matched_markers': evidence_markers,
            'setup_failure_detected': False,
        }

    # ── Layer 4: model-expectation alignment (supporting signal only) ───────
    oracle_matched = bool(
        validate_expected_oracle(expected_oracle)
        and expected_oracle.strip().lower() in combined
    )

    # ── Final confirmation decision ─────────────────────────────────────────
    # A "known target" is any of: target_entrypoint, target_binary, or filepath.
    # The gate only admits contracts that have at least one of these set, so this
    # fallback fires only when the gate was bypassed or for unknown families.
    has_any_target = bool(target_entrypoint or target_binary or filepath or any(str(item).strip() for item in (relevance_anchors or [])))
    if signal == 'strong':
        if stage != 'trigger':
            triggered = False
            reason = 'setup_stage_only'
        elif not has_any_target:
            # Nothing to anchor path relevance against — do not auto-confirm.
            triggered = False
            reason = 'strong_signal_no_target'
        elif not path_rel:
            triggered = False
            # Issue #5: Distinguish strong signal with path mismatch from weak signal.
            # A strong sanitizer crash with wrong path anchor is still a REAL crash —
            # it should be retryable (the PoV may just need to target the right binary),
            # not hard-rejected.  Use a distinct reason so agent_graph can allow retry.
            reason = 'strong_signal+path_not_relevant'
        else:
            triggered = True
            reason = 'strong_signal+path_relevant' + ('+oracle_aligned' if oracle_matched else '')
    else:
        # ambiguous — check contract markers first (Task 7), then ASAN-disabled
        # baseline-relative oracle OR exception evidence
        # When ASAN is not available, accept:
        #   1. Contract markers: observable_evidence markers present in output
        #   2. Exit code anomaly: baseline was clean (0 or benign) and exploit exited with crash code
        #   3. Stderr divergence: new content appeared in stderr compared to baseline
        #   4. Exception evidence: Python traceback / Java uncaught exception / Node unhandled rejection
        #      (fires when asan_disabled=False for non-native languages)
        triggered = False
        reason = 'ambiguous_signal'

        # Task 7: Contract-driven fallback in ambiguous path
        _obs_ev_amb = list(observable_evidence or [])
        if _obs_ev_amb and not triggered:
            _contract_markers_amb = [m for m in _obs_ev_amb if str(m).strip().lower() in combined]
            if _contract_markers_amb:
                _self_rep_amb = is_self_report_only(pov_script, _contract_markers_amb) if pov_script else False
                if path_rel and not _self_rep_amb:
                    triggered = True
                    reason = 'contract_matched+path_relevant+ambiguous'

        # Task 7: Exit code anomaly WITHOUT requiring asan_disabled=True
        # When exploit exit code is in crash range and baseline is benign, confirm.
        if not triggered and stage == 'trigger' and has_any_target:
            _crash_codes = {132, 134, 135, 136, 139, -4, -6, -7, -8, -11}
            _baseline_clean = baseline_exit_code in {0, 1, 2} or baseline_exit_code == -1
            _exploit_crash = exit_code in _crash_codes
            if _baseline_clean and _exploit_crash and path_rel:
                triggered = True
                reason = 'exit_code_anomaly+path_relevant'
            # Also fire when baseline is clean (0) and exploit is non-zero with contract markers
            elif _baseline_clean and exit_code not in {0} and _obs_ev_amb and path_rel:
                _has_contract_in_output = any(str(m).strip().lower() in combined for m in _obs_ev_amb)
                if _has_contract_in_output:
                    triggered = True
                    reason = 'exit_code_anomaly+contract_matched+path_relevant'

        if asan_disabled and stage == 'trigger' and has_any_target and not triggered:
            _crash_codes = {132, 134, 135, 136, 139, -4, -6, -7, -8, -11}
            _baseline_clean = baseline_exit_code in {0, 1, 2} or baseline_exit_code == -1
            _exploit_crash = exit_code in _crash_codes
            if _baseline_clean and _exploit_crash and path_rel:
                triggered = True
                reason = 'asan_disabled+exit_code_anomaly+path_relevant'
            elif baseline_stderr and stderr:
                # Check for meaningful new stderr content (not just usage echo)
                _base_lower = str(baseline_stderr or '').lower()
                _new_lines = [
                    ln for ln in stderr.lower().splitlines()
                    if ln.strip() and ln.strip() not in _base_lower
                    and not any(kw in ln for kw in ('usage:', '--help', 'error:', 'invalid'))
                ]
                if len(_new_lines) >= 2 and path_rel:
                    triggered = True
                    reason = 'asan_disabled+stderr_divergence+path_relevant'
            # Raw crash text fallback: kernel/libc crash messages visible even without ASan
            if not triggered and path_rel:
                _raw_crash_patterns = [
                    'segmentation fault',
                    'bus error',
                    'illegal instruction',
                    'floating point exception',
                    'killed',
                    'core dumped',
                    'aborted',
                ]
                if any(p in combined for p in _raw_crash_patterns) and exit_code != 0:
                    triggered = True
                    reason = 'asan_disabled+raw_crash_text+path_relevant'
        # Exception-evidence oracle: fires for Python/Java/JavaScript where ASan is absent.
        # Requires: non-ASan build (asan_disabled=False), trigger stage, known target, path
        # relevance, a recognisable language runtime exception marker, and a non-clean exit code.
        # GUARD: skip if the exception is a PoV script infrastructure failure (missing module,
        # undefined variable, connection refused) — these are NOT target vulnerabilities.
        _infra_failure_hit = any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS)
        if not triggered and not _infra_failure_hit and not asan_disabled and stage == 'trigger' and has_any_target and path_rel:
            _exception_patterns = [
                'traceback (most recent call last)',  # Python
                'exception in thread',               # Java thread exception
                'at java.',                          # Java stack frame
                'uncaughtexception',                 # Node.js global handler
                'unhandledpromiserejection',         # Node.js promise rejection
                'unhandledpromiserejectionwarning',  # Node.js older warning form
                'java.lang.outofmemoryerror',       # JVM OOM
                'java.lang.stackoverflowerror',     # JVM stack overflow
                'maximum call stack size exceeded',  # Node.js stack overflow
            ]
            _exception_hit = any(p in combined for p in _exception_patterns)
            # exit code not in clean/usage set: 0 = clean, 1/2 = common usage-error exits
            _crash_exit = exit_code not in {0, 1, 2}
            if _exception_hit and _crash_exit:
                triggered = True
                reason = 'exception_evidence+path_relevant'

        # Script-surface oracle: for non-native execution surfaces, a
        # 'VULNERABILITY TRIGGERED' self-print that is NOT unconditionally
        # embedded in the script text — i.e. it is only printed when the exploit
        # condition fires — IS valid proof.  Uses is_self_report_only() which does
        # AST-level analysis to verify the marker is behind a real conditional.
        # Blocklist approach: only native crash surfaces are excluded (they require
        # sanitizer/signal evidence instead).  All other surfaces — including empty
        # — get this adaptive oracle automatically.
        _native_only_surfaces = {'native_elf', 'c_library_harness'}
        if not triggered and execution_surface not in _native_only_surfaces and stage == 'trigger':
            _vt_markers = [p for p in _EVIDENCE_MARKER_STRINGS if p in combined]
            if _vt_markers and not is_self_report_only(pov_script, _vt_markers, self_report_strings=_LIVE_SELF_REPORT_STRINGS):
                # GUARD: Do NOT accept script_surface_triggered_marker if exit_code is 0
                # and there is no actual crash/sanitizer evidence. This prevents false
                # positives where the PoV prints the marker due to build output in stdout
                # or other non-crash conditions.
                _has_crash_evidence = (
                    exit_code in (134, 139, -11, -6)
                    or 'segmentation fault' in combined
                    or 'bus error' in combined
                    or 'aborted' in combined
                    or 'core dumped' in combined
                    or 'addresssanitizer' in combined
                    or 'heap-buffer-overflow' in combined
                    or 'stack-buffer-overflow' in combined
                    or 'use-after-free' in combined
                )
                if exit_code != 0 or _has_crash_evidence:
                    triggered = True
                    reason = 'script_surface_triggered_marker'
                else:
                    # Check for contract-driven behavioral markers (e.g. FILE_CREATED_OUTSIDE_ALLOWED_DIR,
                    # PROTOTYPE_POLLUTED) that are not self-reported.  These are valid proof even with
                    # exit_code=0 because the evidence IS the observable side-effect, not a crash signal.
                    _obs_ev_ss = list(observable_evidence or [])
                    _contract_markers_ss = [m for m in _obs_ev_ss if str(m).strip().lower() in combined] if _obs_ev_ss else []
                    _self_rep_ss = is_self_report_only(pov_script, _contract_markers_ss) if _contract_markers_ss else False
                    if _contract_markers_ss and not _self_rep_ss:
                        triggered = True
                        reason = 'script_surface+contract_markers'
                    else:
                        # PoV self-reported marker but binary ran cleanly — likely false positive
                        triggered = False
                        reason = 'self_reported_marker_without_crash_evidence'

    return {
        'triggered': triggered,
        'signal_class': signal,
        'reason': reason,
        'disqualified': False,
        'path_relevant': path_rel,
        'self_report_only': False,
        'model_oracle_matched': oracle_matched,
        'matched_evidence_markers': evidence_markers,
        # backward-compat keys
        'matched_markers': evidence_markers,
        'setup_failure_detected': False,
    }


# ---------------------------------------------------------------------------
# Task 6: Behavioral proof oracle
# ---------------------------------------------------------------------------

# Patterns for behavioural evidence that does NOT require a crash signal.
# Used when execution_surface='c_library_harness' or when asan_disabled=True
# and the PoV demonstrates a concrete effect (data exfil, path traversal, etc.)
_BEHAVIORAL_EVIDENCE_PATTERNS = {
    # C library harness compiled and ran cleanly but ASan fired
    'asan_compiled_harness': re.compile(
        r'(heap-buffer-overflow|heap-use-after-free|stack-buffer-overflow'
        r'|double-free|use-after-free|runtime error:'
        r'|==\d+== ERROR: AddressSanitizer'
        r'|==\d+== ERROR: UndefinedBehaviorSanitizer)',
        re.IGNORECASE,
    ),
    # SQL injection: data returned that should only be accessible to the attacker
    'sql_injection': re.compile(
        r'(sql.*syntax.*error|you have an error in your sql syntax'
        r'|unclosed quotation mark|pg::syntaxerror'
        r'|sqlite.*error|operationalerror.*sqlite'
        r'|mysql.*error.*1064)',
        re.IGNORECASE,
    ),
    # Path traversal: file read outside webroot
    'path_traversal': re.compile(
        r'(root:.*:0:0|/etc/passwd|/etc/shadow'
        r'|directory listing|index of /)'
        ,
        re.IGNORECASE,
    ),
    # XSS execution in a non-browser headless context (script executed confirmation)
    'xss_execution': re.compile(
        r'(xss triggered|script executed|alert\([^)]*\)|onerror executed'
        r'|document\.cookie)',
        re.IGNORECASE,
    ),
    # JVM crash signals
    'jvm_crash': re.compile(
        r'(java\.lang\.OutOfMemoryError|java\.lang\.StackOverflowError'
        r'|EXCEPTION_ACCESS_VIOLATION|SIGSEGV.*libjvm'
        r'|fatal error.*java runtime environment'
        r'|#\s*a fatal error has been detected by the java runtime)',
        re.IGNORECASE,
    ),
    # Node.js crash beyond unhandled rejection
    'node_crash': re.compile(
        r'(maximum call stack size exceeded'
        r'|fatal error.*javascript heap out of memory'
        r'|abort.*signal.*node)',
        re.IGNORECASE,
    ),
    # ── Generic behavioral patterns (CWE-agnostic, match structured markers) ──
    # File permission violations
    'permission_violation': re.compile(
        r'(insecure.permission|world.readable|world.writable|mode\s*0o[67][67][67]'
        r'|permission.*0o[0-7]{3}|chmod.*777|umask\s*0{1,3})',
        re.IGNORECASE,
    ),
    # Filesystem state changes (path traversal, unauthorized writes)
    'file_state_change': re.compile(
        r'(file.created.outside|path.traversal.confirmed|wrote.outside.allowed'
        r'|file.exists.at.traversed|escaped.directory|traversal.successful'
        r'|unauthorized.file|unexpected.file)',
        re.IGNORECASE,
    ),
    # Information exposure / data leakage
    'information_exposure': re.compile(
        r'(sensitive.data.leaked|internal.path.disclosed|error.message.contains'
        r'|debug.info.leaked|secret.exposed|stack.trace.leaked|credential.exposed)',
        re.IGNORECASE,
    ),
    # Authentication / authorization bypass
    'auth_bypass': re.compile(
        r'(unauthorized.access|auth.bypass|access.granted.without'
        r'|missing.auth|privilege.escalat)',
        re.IGNORECASE,
    ),
    # Command injection: shell command was executed
    'command_injection': re.compile(
        r'(command.injection.confirmed|shell.injection.confirmed'
        r'|os.command.executed|shell.command.executed|subprocess.executed)',
        re.IGNORECASE,
    ),
    # LDAP injection
    'ldap_injection': re.compile(
        r'(ldap.injection.confirmed|ldap.query.manipulated)',
        re.IGNORECASE,
    ),
    # XPath injection
    'xpath_injection': re.compile(
        r'(xpath.injection.confirmed|xpath.query.manipulated)',
        re.IGNORECASE,
    ),
    # XML External Entity (XXE)
    'xxe_injection': re.compile(
        r'(xxe.confirmed|entity.resolved|external.entity.loaded'
        r'|dtd.retrieved|xxe.success)',
        re.IGNORECASE,
    ),
    # Open redirect
    'open_redirect': re.compile(
        r'(open.redirect.confirmed|redirect.to.external.host'
        r'|external.redirect.allowed|location.header.manipulated)',
        re.IGNORECASE,
    ),
    # Server-Side Request Forgery (SSRF)
    'ssrf': re.compile(
        r'(ssrf.confirmed|internal.resource.accessed|server.side.request.forged'
        r'|localhost.accessed|metadata.endpoint.accessed)',
        re.IGNORECASE,
    ),
}


def evaluate_behavioral_proof_outcome(
    stdout: str,
    stderr: str,
    exit_code: int,
    execution_surface: str = '',
    target_entrypoint: str = '',
    filepath: str = '',
    pov_script: str = '',
    expected_oracle: str = '',
    target_binary: str = '',
    relevance_anchors: Optional[List[str]] = None,
) -> dict:
    """Evaluate behavioral (non-crash) proof outcomes.

    Covers:
      - c_library_harness: inline C harness compiled + run with ASan
      - SQL injection: DB error text appears in response
      - Path traversal: /etc/passwd or directory listing visible
      - XSS execution in headless context

    Returns a dict with the same shape as evaluate_proof_outcome() so callers
    can handle both uniformly.
    """
    combined = (str(stdout or '') + '\n' + str(stderr or '')).lower()
    surface = execution_surface.strip().lower()

    # For c_library_harness, a sanitizer hit in the harness output IS the proof.
    # Route directly to the standard crash oracle which handles ASan perfectly.
    if surface == 'c_library_harness':
        return evaluate_proof_outcome(
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
            asan_disabled=False,
            execution_surface='repo_script',  # treat as script surface for path relevance
        )

    # Detect behavioral patterns in combined output
    matched_patterns: List[str] = []
    for pattern_name, pattern_re in _BEHAVIORAL_EVIDENCE_PATTERNS.items():
        if pattern_name == 'asan_compiled_harness':
            continue  # handled above
        if pattern_re.search(combined):
            matched_patterns.append(pattern_name)

    if not matched_patterns:
        # No behavioral evidence found — fall back to the standard crash oracle
        return evaluate_proof_outcome(
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
            asan_disabled=True,
            execution_surface=execution_surface,
        )

    # Behavioral evidence present — check path relevance
    path_rel = is_path_relevant(
        combined,
        target_entrypoint,
        filepath,
        target_binary,
        relevance_anchors=relevance_anchors,
        execution_stage='trigger',
        execution_surface=execution_surface,
    )
    triggered = path_rel
    reason = ('behavioral_evidence+path_relevant' if path_rel else 'behavioral_evidence+path_not_relevant') + '+' + ','.join(matched_patterns)
    return {
        'triggered': triggered,
        'signal_class': 'behavioral',
        'reason': reason,
        'disqualified': False,
        'path_relevant': path_rel,
        'self_report_only': False,
        'model_oracle_matched': bool(
            validate_expected_oracle(expected_oracle)
            and expected_oracle.strip().lower() in combined
        ),
        'matched_evidence_markers': matched_patterns,
        'matched_markers': matched_patterns,
        'setup_failure_detected': False,
    }

def evaluate_live_proof_outcome(
    evidence_markers: List[str],
    *,
    target_route: str = '',
    target_dom_selector: str = '',
    target_url: str = '',
    response_preview: str = '',
    pov_script: str = '',
    stage: str = 'trigger',
    runtime_family: str = 'http',
) -> dict:
    family = str(runtime_family or 'http').lower()
    selector = str(target_dom_selector or '').strip().lower()
    route = str(target_route or target_url or '').strip().lower()
    preview = str(response_preview or '').strip().lower()
    evidence = [str(item).strip() for item in (evidence_markers or []) if str(item).strip()]
    haystack = ('\n'.join(evidence) + '\n' + preview).lower()
    if stage != 'trigger':
        return {
            'triggered': False,
            'signal_class': 'live',
            'reason': 'setup_stage_only',
            'disqualified': False,
            'path_relevant': False,
            'self_report_only': False,
            'model_oracle_matched': False,
            'matched_evidence_markers': evidence,
            'matched_markers': evidence,
            'setup_failure_detected': False,
        }
    if not evidence:
        return {
            'triggered': False,
            'signal_class': 'live',
            'reason': 'no_oracle_match',
            'disqualified': False,
            'path_relevant': False,
            'self_report_only': False,
            'model_oracle_matched': False,
            'matched_evidence_markers': [],
            'matched_markers': [],
            'setup_failure_detected': False,
        }
    self_reports = _LIVE_SELF_REPORT_STRINGS if family in {'http', 'live_app', 'browser', 'web'} else _SELF_REPORT_STRINGS
    if is_self_report_only(pov_script, evidence, self_report_strings=self_reports):
        return {
            'triggered': False,
            'signal_class': 'live',
            'reason': 'self_report_only',
            'disqualified': False,
            'path_relevant': False,
            'self_report_only': True,
            'model_oracle_matched': False,
            'matched_evidence_markers': evidence,
            'matched_markers': evidence,
            'setup_failure_detected': False,
        }
    path_relevant = False
    if family in {'browser', 'web'} and selector:
        candidates = [selector]
        if selector.startswith('#') and len(selector) > 1:
            ident = selector[1:]
            candidates.extend([ident, f'id="{ident}"', f"id='{ident}'"])
        if selector.startswith('.') and len(selector) > 1:
            klass = selector[1:]
            candidates.extend([klass, f'class="{klass}"', f"class='{klass}'"])
        path_relevant = any(candidate in haystack for candidate in candidates)
    elif route:
        # Live HTTP proofs often execute directly against the targeted route, while
        # the strongest evidence is a status/header/body marker that may not repeat
        # the route string verbatim in the captured output. Treat that targeted
        # request context as relevant unless we have an explicit selector mismatch.
        path_relevant = True if evidence else (route in haystack)
    else:
        path_relevant = True
    if not path_relevant:
        return {
            'triggered': False,
            'signal_class': 'live',
            'reason': 'path_not_relevant',
            'disqualified': False,
            'path_relevant': False,
            'self_report_only': False,
            'model_oracle_matched': False,
            'matched_evidence_markers': evidence,
            'matched_markers': evidence,
            'setup_failure_detected': False,
        }
    return {
        'triggered': True,
        'signal_class': 'live',
        'reason': 'live_evidence',
        'disqualified': False,
        'path_relevant': True,
        'self_report_only': False,
        'model_oracle_matched': False,
        'matched_evidence_markers': evidence,
        'matched_markers': evidence,
        'setup_failure_detected': False,
    }


# ---------------------------------------------------------------------------
# Dynamic proof outcome evaluator (v2 Proof Strategy)
# ---------------------------------------------------------------------------

def evaluate_dynamic_proof_outcome(
    stdout: str,
    stderr: str,
    exit_code: int,
    proof_strategy: dict,
    target_entrypoint: str = '',
    filepath: str = '',
    pov_script: str = '',
    expected_oracle: str = '',
    target_binary: str = '',
    relevance_anchors: Optional[List[str]] = None,
    asan_disabled: bool = False,
    baseline_exit_code: int = -1,
    baseline_stderr: str = '',
    execution_surface: str = '',
    observable_evidence: Optional[List[str]] = None,
    baseline_stdout: str = '',
) -> dict:
    """Universal oracle dispatcher that routes by proof_type.

    When proof_strategy is present in the exploit contract, this function
    selects the appropriate evaluation logic based on the proof_type field
    instead of assuming crash signals.

    Returns the same dict shape as evaluate_proof_outcome() for uniform handling.
    """
    proof_type = str((proof_strategy or {}).get('proof_type', 'crash_signal')).strip().lower()
    observable_evidence = list((proof_strategy or {}).get('observable_evidence') or [])
    combined = (str(stdout or '') + '\n' + str(stderr or '')).lower()

    # ── crash_signal: delegate to the standard crash oracle ──────────────
    if proof_type == 'crash_signal':
        return evaluate_proof_outcome(
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            target_entrypoint=target_entrypoint, filepath=filepath,
            pov_script=pov_script, expected_oracle=expected_oracle,
            target_binary=target_binary, stage='trigger',
            relevance_anchors=relevance_anchors, asan_disabled=asan_disabled,
            baseline_exit_code=baseline_exit_code, baseline_stderr=baseline_stderr,
            execution_surface=execution_surface,
        )

    # ── Helper: check observable_evidence markers in combined output ──────
    # Uses both exact substring matching and normalized fuzzy matching to handle
    # real-world output variations (e.g. "heap-buffer-overflow" matching within
    # "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...")
    matched_markers = []
    # Crash-like evidence that PoV scripts can easily fake by printing to stdout.
    # Real sanitizer/crash output always goes to stderr; reject stdout-only matches.
    _crash_like_keywords = (
        'addresssanitizer', 'memorysanitizer', 'threadsanitizer',
        'heap-buffer-overflow', 'heap-use-after-free', 'stack-buffer-overflow',
        'double-free', 'use-after-free', 'segmentation fault', 'sigsegv',
        'sigabrt', 'sigill', 'sigfpe', 'asan', 'msan', 'tsan', 'ubsan',
    )
    for ev in observable_evidence:
        ev_lower = str(ev).strip().lower()
        if not ev_lower:
            continue
        # For behavioral_deviation proofs, crash-like evidence must be in stderr
        # (from the actual binary), not stdout (which the PoV script controls).
        _is_crash_like = any(kw in ev_lower for kw in _crash_like_keywords)
        _search_target = combined
        if proof_type == 'behavioral_deviation' and _is_crash_like:
            _search_target = (stderr or '').lower()
            if not _search_target:
                continue
        # Exact substring match
        if ev_lower in _search_target:
            matched_markers.append(ev)
            continue
        # Normalized match: strip punctuation/whitespace, check if any word sequence matches
        import re as _re
        ev_words = _re.sub(r'[^a-z0-9]+', ' ', ev_lower).strip()
        search_normalized = _re.sub(r'[^a-z0-9]+', ' ', _search_target)
        if ev_words and ev_words in search_normalized:
            matched_markers.append(ev)
            continue
        # Token containment: if the evidence is a multi-word phrase, check if all
        # significant tokens (3+ chars) appear within a 200-char window
        ev_tokens = [t for t in ev_words.split() if len(t) >= 3]
        if len(ev_tokens) >= 2:
            for i in range(0, len(_search_target) - 50, 50):
                window = _search_target[i:i+200]
                if all(tok in window for tok in ev_tokens):
                    matched_markers.append(ev)
                    break

    # ── ANTI-GAMING: Reject behavioral_deviation proofs where the PoV script
    # itself contains the observable_evidence markers as literal strings.
    # If the LLM printed "COMMAND_INJECTION_CONFIRMED" or "rm -rf /" in the
    # PoV script, those markers in stdout are fake — the target did not produce them.
    #
    # EXCEPTION: If the marker is only printed conditionally (inside if/elif
    # guarding on target output/behavior), it is NOT gaming — the PoV only
    # prints it when the target actually exhibited the vulnerability.
    # Also, if the marker appears in stderr (not just stdout), it was produced
    # by the target binary, not the PoV script.
    if proof_type == 'behavioral_deviation' and matched_markers and pov_script:
        _script_lower = pov_script.lower()
        _gaming_markers = []
        for _mk in matched_markers:
            _mk_lower = str(_mk).lower()
            # Skip crash-like markers (these are already stderr-only via _crash_like_keywords)
            if any(kw in _mk_lower for kw in _crash_like_keywords):
                continue
            # If the marker appears in stderr, the target binary produced it — not gaming
            if _mk_lower in (stderr or '').lower():
                continue
            if _mk_lower in _script_lower:
                _gaming_markers.append(_mk)
        if _gaming_markers:
            # Check if ALL gaming markers are conditional (inside if/elif blocks
            # that guard on target behavior).  Conditional markers are NOT gaming —
            # the PoV only prints them when the target is actually vulnerable.
            _all_conditional = all(
                _is_conditional_marker(pov_script, str(m).lower())
                for m in _gaming_markers
            )
            if _all_conditional:
                # All markers are conditional — the PoV only prints them on exploit success.
                # This is legitimate verification, not gaming.
                pass
            else:
                return _build_dynamic_result(
                    triggered=False,
                    proof_type=proof_type,
                    matched_markers=[],
                    path_relevant=False,
                    reason='pov_script_gaming',
                    expected_oracle=expected_oracle,
                    combined=combined,
                )

    # ── Helper: check path relevance ─────────────────────────────────────
    # For non-crash dynamic proof types, path relevance is advisory, not a
    # hard gate.  Unlike crash signals (where the crash MUST be in the target
    # function's stack frame), dynamic proofs like exceptions, timing, and
    # behavioral deviations produce evidence in program *output* — the
    # entrypoint/filepath won't appear in a traceback or timing log.  When
    # matched observable_evidence markers confirm the vulnerability, that IS
    # sufficient proof even without a path-relevant stack frame.
    path_rel = is_path_relevant(
        combined, target_entrypoint, filepath, target_binary,
        relevance_anchors=relevance_anchors,
        execution_stage='trigger', execution_surface=execution_surface,
    )

    # ── exception: traceback/exception patterns + non-zero exit ──────────
    if proof_type == 'exception':
        # GUARD: if the exception is a PoV script infrastructure failure (missing
        # module, undefined variable, connection refused), do NOT confirm.
        # EXCEPTION: if a behavioral marker is also present, the Traceback is
        # evidence of the TARGET crashing (exploited by the PoV), not the PoV
        # script itself crashing.  In that case, allow the oracle to evaluate
        # the marker.
        _infra_failure_hit = any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS)
        if _infra_failure_hit:
            _exc_behavioral_markers = (
                'file_created_outside_allowed_dir', 'insecure_permission',
                'sensitive_data_leaked', 'exception_triggered',
                'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
                'xss_confirmed', 'command_injection_confirmed',
                'unauthorized_access_granted', 'path_traversal_confirmed',
                'stack_trace_leaked', 'internal_path_disclosed',
            )
            if any(m in combined for m in _exc_behavioral_markers):
                # Behavioral marker present — the exception is evidence of the
                # target crashing, not a PoV infrastructure failure.  Fall through
                # to the normal exception evaluation below.
                pass
            else:
                return _build_dynamic_result(
                    triggered=False,
                    proof_type=proof_type,
                    matched_markers=matched_markers,
                    path_relevant=path_rel,
                    reason='environment_failure',
                    expected_oracle=expected_oracle,
                    combined=combined,
                )
        _exception_patterns = (
            'traceback (most recent call last)', 'exception:', 'error:',
            'raise ', 'uncaughtexception', 'unhandled promise rejection',
            'fatal error', 'typeerror:', 'valueerror:', 'runtimeerror:',
            'indexerror:', 'keyerror:', 'attributeerror:',
        )
        has_exception = any(p in combined for p in _exception_patterns)
        has_nonzero = exit_code != 0
        triggered = bool((has_exception or has_nonzero) and (matched_markers or has_exception))
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='exception_evidence' if triggered else 'no_exception_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── resource_exhaustion: leak sanitizer, RSS, exit code 23/42 ────────
    if proof_type == 'resource_exhaustion':
        _resource_patterns = (
            'definitely lost', 'indirectly lost', 'possibly lost',
            'leak_check', 'memory leak', 'oom', 'out of memory',
            'killed', 'rss', 'memory usage',
        )
        has_resource_ev = any(p in combined for p in _resource_patterns)
        has_leak_exit = exit_code in (23, 42, 137)
        triggered = bool(has_resource_ev or has_leak_exit or matched_markers)
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='resource_exhaustion_evidence' if triggered else 'no_resource_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── timing_difference: ratio/timing keywords + conditional self-report ─
    if proof_type == 'timing_difference':
        _timing_patterns = (
            'timing ratio', 'time difference', 'elapsed', 'milliseconds',
            'seconds', 'timing_confirmed', 'timing attack',
            'side channel', 'time:', 'duration:',
        )
        has_timing_ev = any(p in combined for p in _timing_patterns)
        triggered = bool(has_timing_ev or matched_markers)
        # Self-report is accepted for timing proofs when combined with timing data
        if 'vulnerability triggered' in combined and has_timing_ev:
            triggered = True
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='timing_evidence' if triggered else 'no_timing_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── behavioral_deviation: observable_evidence in output ───────────────
    if proof_type == 'behavioral_deviation':
        # GUARD: infrastructure/setup failures must NOT be misclassified as
        # behavioral deviations just because error text happens to match a pattern.
        # EXCEPTION: if a behavioral marker is also present, the error output is
        # evidence of the TARGET crashing (exploited by the PoV), not a PoV
        # infrastructure failure.  In that case, fall through to normal evaluation.
        _infra_failure_hit = any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS)
        if _infra_failure_hit:
            _bd_behavioral_markers = (
                'file_created_outside_allowed_dir', 'insecure_permission',
                'sensitive_data_leaked', 'exception_triggered',
                'timing_anomaly', 'resource_exhaustion', 'prototype_polluted',
                'xss_confirmed', 'command_injection_confirmed',
                'unauthorized_access_granted', 'path_traversal_confirmed',
                'stack_trace_leaked', 'internal_path_disclosed',
            )
            if any(m in combined for m in _bd_behavioral_markers):
                # Behavioral marker present — the error is evidence of the target
                # vulnerability, not a PoV infrastructure failure.  Fall through.
                pass
            else:
                return _build_dynamic_result(
                    triggered=False,
                    proof_type=proof_type,
                    matched_markers=[],
                    path_relevant=path_rel,
                    reason='environment_failure',
                    expected_oracle=expected_oracle,
                    combined=combined,
                )
        triggered = bool(matched_markers)  # already bool via bool()
        # Check expanded behavioral evidence patterns (CWE-agnostic)
        if not triggered:
            for _pat_name, _pat_re in _BEHAVIORAL_EVIDENCE_PATTERNS.items():
                if _pat_name == 'asan_compiled_harness':
                    continue
                if _pat_re.search(combined):
                    matched_markers.append(_pat_name)
                    triggered = True
        # Also try the behavioral oracle for broader pattern matching
        if not triggered:
            _beh = evaluate_behavioral_proof_outcome(
                stdout=stdout, stderr=stderr, exit_code=exit_code,
                execution_surface=execution_surface,
                target_entrypoint=target_entrypoint, filepath=filepath,
                pov_script=pov_script, expected_oracle=expected_oracle,
                target_binary=target_binary, relevance_anchors=relevance_anchors,
            )
            if _beh.get('triggered'):
                return _beh
        # ── SELF-REPORT ACCEPTANCE: when the PoV explicitly states
        # "vulnerability triggered" AND actual observable_evidence markers
        # were matched in the output, accept it — the LLM was instructed to
        # emit this only when the behavioral condition was verified.
        # This mirrors state_change's self-report logic.
        # REQUIRE matched_markers (not just proof_strategy claims) to prevent
        # PoV scripts from gaming the oracle by printing "VULNERABILITY TRIGGERED"
        # without producing any real evidence.
        if not triggered and 'vulnerability triggered' in combined and matched_markers:
            matched_markers.append('self_report_with_evidence')
            triggered = True
        # ── CRASH FALLBACK: If behavioral oracle found nothing but crash
        # signals are clearly present (ASan/UBSan/SEGV/SIGABRT), this is
        # almost certainly a memory corruption vuln in a native target where
        # the proof_type was mis-classified.  Fall through to crash oracle.
        if not triggered:
            _crash_indicators = (
                'addresssanitizer', 'memorysanitizer', 'threadsanitizer',
                'undefinedbehaviorsanitizer', 'leaksanitizer',
                'heap-buffer-overflow', 'stack-buffer-overflow',
                'use-after-free', 'double-free', 'segmentation fault',
                'signal 11', 'signal 6', 'sigabrt', 'sigsegv',
            )
            if any(ci in combined for ci in _crash_indicators):
                return evaluate_proof_outcome(
                    stdout=stdout, stderr=stderr, exit_code=exit_code,
                    target_entrypoint=target_entrypoint, filepath=filepath,
                    pov_script=pov_script, expected_oracle=expected_oracle,
                    target_binary=target_binary, stage='trigger',
                    relevance_anchors=relevance_anchors, asan_disabled=asan_disabled,
                    baseline_exit_code=baseline_exit_code, baseline_stderr=baseline_stderr,
                    execution_surface=execution_surface,
                )
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='behavioral_deviation_evidence' if triggered else 'no_behavioral_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── information_disclosure / observable_output: direct content match ──
    if proof_type in ('information_disclosure', 'observable_output'):
        triggered = bool(matched_markers)  # already bool via bool()
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason=f'{proof_type}_evidence' if triggered else f'no_{proof_type}_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── state_change: evidence markers + behavioral patterns + self-report ──
    if proof_type == 'state_change':
        triggered = bool(matched_markers)
        # Check expanded behavioral evidence patterns (CWE-agnostic)
        if not triggered:
            for _pat_name, _pat_re in _BEHAVIORAL_EVIDENCE_PATTERNS.items():
                if _pat_name == 'asan_compiled_harness':
                    continue
                if _pat_re.search(combined):
                    matched_markers.append(_pat_name)
                    triggered = True
        if not triggered and 'vulnerability triggered' in combined:
            triggered = bool(matched_markers)
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='state_change_evidence' if triggered else 'no_state_change_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── multi_step_chain: evidence markers + conditional self-report ──────
    if proof_type == 'multi_step_chain':
        triggered = bool(matched_markers)
        if not triggered and 'vulnerability triggered' in combined:
            triggered = bool(matched_markers)  # accept self-report only with actual output evidence
        return _build_dynamic_result(
            triggered=triggered,
            proof_type=proof_type,
            matched_markers=matched_markers,
            path_relevant=path_rel,
            reason='multi_step_evidence' if triggered else 'no_multi_step_evidence',
            expected_oracle=expected_oracle,
            combined=combined,
        )

    # ── Unknown proof_type: fall back to standard crash oracle ────────────
    return evaluate_proof_outcome(
        stdout=stdout, stderr=stderr, exit_code=exit_code,
        target_entrypoint=target_entrypoint, filepath=filepath,
        pov_script=pov_script, expected_oracle=expected_oracle,
        target_binary=target_binary, stage='trigger',
        relevance_anchors=relevance_anchors, asan_disabled=asan_disabled,
        baseline_exit_code=baseline_exit_code, baseline_stderr=baseline_stderr,
        execution_surface=execution_surface,
    )


def _differential_analysis(
    baseline_stdout: str,
    baseline_stderr: str,
    exploit_stdout: str,
    exploit_stderr: str,
    observable_evidence: Optional[List[str]] = None,
) -> dict:
    """Compare baseline vs exploit output to detect behavioral differences.

    Returns a dict with:
      - 'differential_evidence': True if novel lines contain evidence markers
      - 'novel_lines': lines present in exploit but not baseline
      - 'novel_markers': observable_evidence markers found in novel lines
    """
    _base = (str(baseline_stdout or '') + '\n' + str(baseline_stderr or '')).lower().strip()
    _exploit = (str(exploit_stdout or '') + '\n' + str(exploit_stderr or '')).lower().strip()

    if not _base or not _exploit:
        return {'differential_evidence': False, 'novel_lines': [], 'novel_markers': []}

    # Split into lines and find novel content
    _base_lines = set(ln.strip() for ln in _base.splitlines() if ln.strip())
    _exploit_lines = [ln.strip() for ln in _exploit.splitlines() if ln.strip()]
    _novel = [ln for ln in _exploit_lines if ln not in _base_lines]

    if not _novel:
        return {'differential_evidence': False, 'novel_lines': [], 'novel_markers': []}

    # Check if any novel lines contain observable_evidence markers
    _obs = list(observable_evidence or [])
    _novel_text = '\n'.join(_novel)
    _novel_markers = [m for m in _obs if str(m).strip().lower() in _novel_text]

    return {
        'differential_evidence': bool(_novel_markers),
        'novel_lines': _novel[:50],  # cap for memory
        'novel_markers': _novel_markers,
    }


def _build_dynamic_result(
    triggered: bool,
    proof_type: str,
    matched_markers: list,
    path_relevant: bool,
    reason: str,
    expected_oracle: str = '',
    combined: str = '',
) -> dict:
    """Build a result dict with the standard oracle shape for dynamic proof types."""
    return {
        'triggered': triggered,
        'signal_class': 'dynamic_' + proof_type,
        'reason': reason,
        'disqualified': False,
        'path_relevant': path_relevant,
        'self_report_only': False,
        'model_oracle_matched': bool(
            validate_expected_oracle(expected_oracle)
            and str(expected_oracle).strip().lower() in combined
        ),
        'matched_evidence_markers': matched_markers,
        'matched_markers': matched_markers,
        'setup_failure_detected': False,
        'proof_type': proof_type,
    }
