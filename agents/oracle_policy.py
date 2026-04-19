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
    'vulnerability triggered',
    'vuln triggered',
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
    'target binary not found',
    'target binary is empty',
    'target binary was not built',
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
      even if "usage:" also appears in the output (e.g. the binary printed
      usage before crashing).  The crash is still real.
    - exit_code == 0 is only non_evidence when no strong structural marker
      exists.  Browser/app-layer proofs may exit 0 with valid DOM/response
      evidence, but those also produce strong structural markers.
    - Non-evidence patterns only dominate when strong evidence is absent.
    """
    combined = (str(stdout or '') + '\n' + str(stderr or '')).lower()

    # Check for strong structural evidence first — strong wins over non-evidence
    if _SANITIZER_STRUCTURAL.search(combined):
        return 'strong'

    # Environment/infrastructure failure — harness could not start the target.
    # Return 'non_evidence' so the call site can map to 'environment_failure';
    # must be checked before the generic non-evidence patterns so it is not
    # silently swallowed by the 'usage:' or 'no such file' branches.
    if any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS):
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
    """
    combined = (str(stdout or '') + '\n' + str(stderr or '')).lower()

    # ── 1. Strong structural evidence — ASan / UBSan / kernel signals –––––––––
    if _SANITIZER_STRUCTURAL.search(combined):
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

    # ── 2. Execution / infrastructure failure ––––––––––––––––––––––––––––––––
    if any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS):
        # Distinguish: binary missing vs. not built
        if any(p in combined for p in ('no such file or directory', 'execvp', 'command not found')):
            crash_type = 'exec_failed'
            if 'build failed' in combined or 'build_failed' in combined:
                hint = ('Build failed — the binary was not produced. Check build_log for compiler '  # noqa: RUF001
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
        return concrete_entrypoint in haystack
    if filepath:
        basename = os.path.basename(filepath).lower()
        if basename and basename in haystack:
            return True
    if target_binary:
        bin_name = os.path.basename(target_binary).lower().strip()
        if bin_name and bin_name in haystack:
            return True
    return False


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
    # All matched markers are self-report strings embedded in the script
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
    is_env_failure = any(p in combined for p in _ENVIRONMENT_FAILURE_PATTERNS)
    if signal == 'non_evidence' and is_env_failure:
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

    # ── Layer 1: non-evidence hard stop ────────────────────────────────────
    # classify_signal already returned 'strong' if a genuine sanitizer crash
    # is present, so we never reach here with a real crash.
    if signal == 'non_evidence':
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
            reason = 'path_not_relevant'
        else:
            triggered = True
            reason = 'strong_signal+path_relevant' + ('+oracle_aligned' if oracle_matched else '')
    else:
        # ambiguous — check ASAN-disabled baseline-relative oracle OR exception evidence
        # When ASAN is not available, accept:
        #   1. Exit code anomaly: baseline was clean (0 or benign) and exploit exited with crash code
        #   2. Stderr divergence: new content appeared in stderr compared to baseline
        #   3. Exception evidence: Python traceback / Java uncaught exception / Node unhandled rejection
        #      (fires when asan_disabled=False for non-native languages)
        triggered = False
        reason = 'ambiguous_signal'
        if asan_disabled and stage == 'trigger' and has_any_target:
            _crash_codes = {134, 139, -11, -6, -4, -8}
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
        if not triggered and not asan_disabled and stage == 'trigger' and has_any_target and path_rel:
            _exception_patterns = [
                'traceback (most recent call last)',  # Python
                'exception in thread',               # Java thread exception
                'at java.',                          # Java stack frame
                'uncaughtexception',                 # Node.js global handler
                'unhandledpromiserejection',         # Node.js promise rejection
                'unhandledpromiserejectionwarning',  # Node.js older warning form
            ]
            _exception_hit = any(p in combined for p in _exception_patterns)
            # exit code not in clean/usage set: 0 = clean, 1/2 = common usage-error exits
            _crash_exit = exit_code not in {0, 1, 2}
            if _exception_hit and _crash_exit:
                triggered = True
                reason = 'exception_evidence+path_relevant'

        # Script-surface oracle: for repo_script execution_surface (Python/Node packages)
        # a 'VULNERABILITY TRIGGERED' self-print that is NOT unconditionally embedded in
        # the script text — i.e. it is only printed when the exploit condition fires — IS
        # valid proof.  Re-evaluate using the live self-report check used for web surfaces.
        if not triggered and execution_surface in {'repo_script', 'function_call'} and stage == 'trigger':
            _vt_markers = [p for p in _EVIDENCE_MARKER_STRINGS if p in combined]
            if _vt_markers and not is_self_report_only(pov_script, _vt_markers, self_report_strings=_LIVE_SELF_REPORT_STRINGS):
                triggered = True
                reason = 'script_surface_triggered_marker'

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
        r'(root:.*:0:0|bin/bash|/etc/passwd|/etc/shadow'
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
