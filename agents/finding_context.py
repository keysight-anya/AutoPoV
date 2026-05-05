"""
Unified Finding Context Synthesizer.

Merges all intelligence sources (recon, probe, CodeQL/Semgrep, Joern, OSV,
investigation) into a single FindingContext per finding.  Resolution rules
ensure probe-confirmed data wins over recon-inferred, which wins over static
analysis guesses.  The resulting context is consumed by narrative prompt
builders in prompts.py.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FindingContext dataclass
# ---------------------------------------------------------------------------

@dataclass
class FindingContext:
    """Single unified context object for one finding, resolved from all sources."""

    # ── Identity (CodeQL/Semgrep + investigation) ──
    cwe: str = 'UNCLASSIFIED'
    cwe_source: str = ''            # tool | llm_inferred
    filepath: str = ''
    line_number: int = 0
    language: str = ''
    root_cause: str = ''
    impact: str = ''

    # ── Trigger path (Joern + recon + probe) ──
    data_flow_path: str = ''        # "main() -> read_file() -> parse_input()"
    entry_function: str = ''        # probe entry > recon entrypoint > contract
    entry_command: str = ''         # exact invocation string

    # ── Input specification (probe > recon > static guess) ──
    input_method: str = 'unknown'   # file_argument | stdin | network | function_call
    input_format: str = ''          # xml | json | image | archive | ...
    input_extensions: List[str] = field(default_factory=list)
    rejection_patterns: List[str] = field(default_factory=list)
    sample_files: List[str] = field(default_factory=list)

    # ── Binary surface (probe > recon) ──
    binary_name: str = ''
    binary_path: str = ''
    subcommands: List[str] = field(default_factory=list)
    bootstrap_subcommand: str = ''
    help_text: str = ''             # truncated to 1500 chars
    needs_key_bootstrap: bool = False
    needs_passphrase: bool = False
    multi_step_protocol: List[str] = field(default_factory=list)
    exported_names: str = ''            # probe-discovered exports (Python/Node module)
    interesting_strings: List[str] = field(default_factory=list)  # strings(1) output from binary

    # ── Proof strategy (investigation > recon > CVE hint) ──
    proof_type: str = 'crash_signal'
    harness_type: str = 'subprocess_binary'
    observable_evidence: List[str] = field(default_factory=list)
    trigger_steps: List[str] = field(default_factory=list)
    exploit_plan_steps: List[Dict[str, Any]] = field(default_factory=list)
    cve_proof_hint: str = ''        # from OSV — actionable

    # ── CVE data (OSV enricher) ──
    cve_id: str = ''
    cve_summary: str = ''
    cve_cvss: float = 0.0
    cve_fix_version: str = ''
    seed_poc: str = ''              # existing PoC fetched from CVE references
    poc_analysis: Dict[str, Any] = field(default_factory=dict)  # structured analysis of seed_poc

    # ── Code context ──
    vulnerable_code: str = ''
    code_context: str = ''
    joern_context: str = ''
    joern_unreachable: bool = False

    # ── Runtime feedback (previous attempts) ──
    attempt_number: int = 0
    runtime_feedback: str = ''
    runtime_feedback_dict: Dict[str, Any] = field(default_factory=dict)
    failed_pov: str = ''
    validation_errors: List[str] = field(default_factory=list)

    # ── Surface classification ──
    surface_type: str = ''          # native_elf | python_module | node_module | web_service
    repo_surface_class: str = ''    # library_c | cli_tool_c | python_module
    project_type: str = 'unknown'
    runtime_family: str = 'native'
    base_url: str = ''              # for web_service targets

    # ── Recon-derived extras ──
    attack_surfaces: List[Dict[str, str]] = field(default_factory=list)
    recon_proof_strategies: Dict[str, Any] = field(default_factory=dict)
    recon_entrypoints: List[Dict[str, str]] = field(default_factory=list)
    recon_binary_candidates: List[str] = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)
    library_api_context: str = ''   # Joern-extracted C library public API signatures

    # ── Cross-scan learning ──
    previous_winning_strategies: List[Dict[str, Any]] = field(default_factory=list)

    # ── Raw contract passthrough (for fields not explicitly modeled) ──
    exploit_contract_extra: Dict[str, Any] = field(default_factory=dict)

    # ── Proof category (dynamically inferred, CWE-agnostic) ──
    proof_category: str = 'crash'   # 'crash' or 'behavioral' — dynamically inferred

    # ── Exploitation approach hint (inferred, CWE-agnostic) ──
    exploitation_approach: str = ''  # concrete hint for PoV generator

    # ── Confidence tracking ──
    confidence_notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Dynamic proof category inference (CWE-agnostic)
# ---------------------------------------------------------------------------

def _infer_proof_category(ctx: FindingContext) -> str:
    """Dynamically decide proof category from vulnerability text, not CWE IDs.

    Scans the investigator's explanation, impact, vulnerable code, and trigger
    steps for keywords that indicate a memory-corruption crash (as opposed to
    a behavioral / state-change vulnerability).  Crash signals are split into
    universal (valid for any language) and native-only (C/C++ specific) so that
    e.g. integer overflow and sprintf are not misclassified as crash signals
    for Python/Java targets.

    Returns 'crash' or 'behavioral'.
    """
    text = ' '.join([
        ctx.root_cause, ctx.impact, ctx.vulnerable_code,
        ctx.code_context, ' '.join(ctx.trigger_steps),
    ]).lower()

    _is_native = ctx.runtime_family == 'native'

    # ── Universal crash signals (valid for ALL languages) ──────────────────
    # These are unambiguous crash indicators regardless of language.
    _UNIVERSAL_CRASH_SIGNALS = [
        'null pointer', 'null deref', 'memory corruption',
    ]
    if any(kw in text for kw in _UNIVERSAL_CRASH_SIGNALS):
        return 'crash'

    # ── Native-only crash signals (C/C++ only) ──────────────────────────────
    # These cause crashes in C/C++ but are behavioral in Python/Java.
    # e.g. integer overflow in Python produces wrong values, not crashes;
    # sprintf in Python/Java is just string formatting, not a buffer overflow.
    if _is_native:
        _NATIVE_CRASH_SIGNALS = [
            'buffer overflow', 'heap overflow', 'stack overflow',
            'use-after-free', 'double free', 'dangling pointer',
            'out-of-bounds', 'heap-buffer', 'stack-buffer',
            'integer overflow', 'signedness', 'underflow',
            'format string', 'wildcopy', 'overread',
            # Dangerous C functions that cause crashes
            'gets(', 'strcpy', 'strcat', 'sprintf',
            # Data race (ASan/TSan detects these in native code)
            'data race', 'data-race',
        ]
        if any(kw in text for kw in _NATIVE_CRASH_SIGNALS):
            return 'crash'

    # ── Check behavioral signals ──────────────────────────────────────────
    # These point to non-crash, state-change / behavioral vulnerabilities.
    # Note: overly generic terms ('write', 'file', 'exec') have been removed
    # because they appear in crash descriptions too (e.g. "writes past buffer").
    _BEHAVIORAL_SIGNALS = [
        # filesystem / path (specific terms only — no 'file' or 'write')
        'path traversal', 'directory traversal', 'traverse',
        'symlink', 'unlink', 'rename', 'arbitrary file',
        # permissions
        'permission', 'chmod', 'umask', 'chown',
        'world-writable', 'world-readable', 'setuid', 'setgid',
        # information exposure
        'leak', 'expose', 'disclose', 'sensitive', 'verbose',
        'error message', 'internal path',
        # auth / access
        'auth', 'credential', 'hardcoded', 'bypass', 'unauthorized',
        'access control', 'privilege', 'escalat', 'impersonat',
        # concurrency (behavioral aspects — 'data race' is crash for native)
        'race condition', 'toctou', 'timing', 'side channel', 'concurrent',
        # process control (CWE-114) — specific terms only
        'command injection', 'system(',
        'popen', 'os.system', 'subprocess',
        # XSS / injection (CWE-79)
        'xss', 'cross-site', 'script injection', 'innerhtml',
        'document.write', 'eval(', 'unescaped', 'unsanitized',
        # resource / DoS
        'denial of service', 'dos', 'redos', 'infinite loop',
        'resource exhaust', 'amplification',
        # misc behavioral
        'unsafe', 'deprecated', 'dangerous function',
    ]
    if any(kw in text for kw in _BEHAVIORAL_SIGNALS):
        return 'behavioral'

    # Non-native runtimes (Python/Node/Java) rarely crash → safer as behavioral.
    if not _is_native:
        return 'behavioral'

    # Default: crash for native targets with no clear behavioral or crash signals
    return 'crash'


# ---------------------------------------------------------------------------
# Exploitation approach inference (CWE-agnostic)
# ---------------------------------------------------------------------------

# CWE-to-behavioral-marker mapping — ensures the markers that the approach text
# tells PoVs to print are ALWAYS in the oracle's _EVIDENCE_MARKER_STRINGS.
# This keeps the marker vocabulary synchronized between PoV generation and oracle.
_CWE_BEHAVIORAL_MARKERS: dict = {
    # XSS / injection
    'CWE-79': ['XSS_CONFIRMED'],
    'CWE-079': ['XSS_CONFIRMED'],
    # Command injection
    'CWE-78': ['COMMAND_INJECTION_CONFIRMED'],
    'CWE-078': ['COMMAND_INJECTION_CONFIRMED'],
    'CWE-077': ['COMMAND_INJECTION_CONFIRMED'],
    'CWE-114': ['COMMAND_INJECTION_CONFIRMED'],
    # Path traversal
    'CWE-22': ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'PATH_TRAVERSAL_CONFIRMED'],
    'CWE-022': ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'PATH_TRAVERSAL_CONFIRMED'],
    'CWE-073': ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'PATH_TRAVERSAL_CONFIRMED'],
    'CWE-041': ['FILE_CREATED_OUTSIDE_ALLOWED_DIR', 'PATH_TRAVERSAL_CONFIRMED'],
    # Information disclosure
    'CWE-200': ['SENSITIVE_DATA_LEAKED', 'STACK_TRACE_LEAKED', 'INTERNAL_PATH_DISCLOSED'],
    'CWE-201': ['SENSITIVE_DATA_LEAKED'],
    'CWE-215': ['STACK_TRACE_LEAKED'],
    'CWE-312': ['SENSITIVE_DATA_LEAKED'],
    'CWE-313': ['SENSITIVE_DATA_LEAKED'],
    'CWE-359': ['SENSITIVE_DATA_LEAKED'],
    # Auth / session
    'CWE-287': ['UNAUTHORIZED_ACCESS_GRANTED'],
    'CWE-614': ['UNAUTHORIZED_ACCESS_GRANTED'],
    'CWE-384': ['UNAUTHORIZED_ACCESS_GRANTED'],
    'CWE-306': ['UNAUTHORIZED_ACCESS_GRANTED'],
    # DoS / resource
    'CWE-400': ['RESOURCE_EXHAUSTION', 'TIMING_ANOMALY'],
    'CWE-1333': ['RESOURCE_EXHAUSTION', 'TIMING_ANOMALY'],
    'CWE-770': ['RESOURCE_EXHAUSTION'],
    'CWE-772': ['RESOURCE_EXHAUSTION'],
    # Prototype pollution
    'CWE-1321': ['PROTOTYPE_POLLUTED'],
    'CWE-915': ['PROTOTYPE_POLLUTED'],
    # Permissions
    'CWE-732': ['INSECURE_PERMISSION'],
    'CWE-276': ['INSECURE_PERMISSION'],
    'CWE-733': ['INSECURE_PERMISSION'],
    # Exception
    'CWE-248': ['EXCEPTION_TRIGGERED'],
    'CWE-755': ['EXCEPTION_TRIGGERED'],
    'CWE-390': ['EXCEPTION_TRIGGERED'],
    # Insecure defaults / misconfiguration
    'CWE-16': ['INSECURE_PERMISSION', 'SENSITIVE_DATA_LEAKED'],
    'CWE-272': ['UNAUTHORIZED_ACCESS_GRANTED'],
    'CWE-311': ['SENSITIVE_DATA_LEAKED'],
    'CWE-319': ['SENSITIVE_DATA_LEAKED'],
    'CWE-639': ['UNAUTHORIZED_ACCESS_GRANTED'],
    'CWE-863': ['UNAUTHORIZED_ACCESS_GRANTED'],
    # SQL injection
    'CWE-089': ['SQL_INJECTION_CONFIRMED'],
    'CWE-89': ['SQL_INJECTION_CONFIRMED'],
    # Code injection
    'CWE-094': ['CODE_INJECTION_CONFIRMED'],
    'CWE-94': ['CODE_INJECTION_CONFIRMED'],
    # Deserialization
    'CWE-502': ['DESERIALIZATION_CONFIRMED'],
    'CWE-503': ['DESERIALIZATION_CONFIRMED'],
    # SSRF
    'CWE-918': ['SSRF_CONFIRMED'],
    'CWE-918': ['SSRF_CONFIRMED'],
    # Input validation
    'CWE-020': ['INPUT_VALIDATION_BYPASSED'],
    'CWE-20': ['INPUT_VALIDATION_BYPASSED'],
    # XML / XXE
    'CWE-611': ['XXE_CONFIRMED'],
    'CWE-776': ['XML_ENTITY_EXPANDED', 'XXE_CONFIRMED'],
    'CWE-777': ['XML_ENTITY_EXPANDED'],
    'CWE-778': ['XML_ENTITY_EXPANDED'],
    # Sensitive method exposure
    'CWE-749': ['SENSITIVE_METHOD_EXPOSED'],
    # Resource exhaustion (additional)
    'CWE-908': ['RESOURCE_EXHAUSTION'],
    # Type confusion
    'CWE-346': ['TYPE_CONFUSION_CONFIRMED'],
    # Path expansion / link following
    'CWE-047': ['PATH_EXPANSION_CONFIRMED'],
    'CWE-47': ['PATH_EXPANSION_CONFIRMED'],
    'CWE-059': ['PATH_EXPANSION_CONFIRMED'],
    'CWE-59': ['PATH_EXPANSION_CONFIRMED'],
}


def _get_behavioral_markers_for_cwe(cwe: str) -> list:
    """Return the standardized behavioral markers for a CWE type.

    Falls back to keyword-based matching if the exact CWE is not in the mapping.
    """
    cwe_normalized = str(cwe or '').strip().upper()
    # Try exact match first
    if cwe_normalized in _CWE_BEHAVIORAL_MARKERS:
        return _CWE_BEHAVIORAL_MARKERS[cwe_normalized]
    # Try without leading zeros (CWE-079 → CWE-79)
    cwe_stripped = cwe_normalized.lstrip('CWE-').lstrip('0') or '0'
    cwe_alt = f'CWE-{cwe_stripped}'
    if cwe_alt in _CWE_BEHAVIORAL_MARKERS:
        return _CWE_BEHAVIORAL_MARKERS[cwe_alt]
    # Try with leading zero (CWE-79 → CWE-079)
    cwe_padded = f'CWE-{int(cwe_stripped):03d}'
    if cwe_padded in _CWE_BEHAVIORAL_MARKERS:
        return _CWE_BEHAVIORAL_MARKERS[cwe_padded]
    return []


def _infer_exploitation_approach(ctx: FindingContext) -> str:
    """Return a concrete exploitation hint string for the PoV generator.

    This gives the LLM a specific, actionable instruction about HOW to
    demonstrate the vulnerability — not just WHAT the vulnerability is.
    The hint is keyword-driven and CWE-agnostic.
    """
    text = ' '.join([
        ctx.root_cause, ctx.impact, ctx.vulnerable_code,
        ctx.code_context, ' '.join(ctx.trigger_steps),
    ]).lower()

    # Permission-related (CWE-732, CWE-276, etc.)
    _PERM_KW = ('permission', 'chmod', 'umask', 'setuid', 'setgid', 'world-writable',
                'world-readable', 'chown', 'mode')
    if any(kw in text for kw in _PERM_KW):
        return (
            'Check file/directory permissions after the binary writes output. '
            'Use os.stat() to verify mode bits. Print INSECURE_PERMISSION:<octal_mode> '
            'if any created file is world-writable (mode & 0o002).'
        )

    # Path traversal / directory escape
    _PATH_KW = ('traversal', 'traverse', 'path', 'directory', 'symlink', 'escape')
    if any(kw in text for kw in _PATH_KW):
        return (
            'Feed a crafted path (e.g. "../../../tmp/escaped_file") as input. '
            'After execution, check if files were created outside the expected directory. '
            'Print FILE_CREATED_OUTSIDE_ALLOWED_DIR:<path> for each escaped write. '
            'Print PATH_TRAVERSAL_CONFIRMED:<path> if a file was written outside the allowed directory.'
        )

    # Process control / command injection (CWE-114, CWE-78)
    _PROC_KW = ('process', 'spawn', 'exec', 'command injection', 'system(', 'popen',
                'os.system', 'subprocess')
    if any(kw in text for kw in _PROC_KW):
        return (
            'Monitor process spawning or command execution. Inject a marker command '
            '(e.g. "echo COMMAND_INJECTION_CONFIRMED") into user-controllable input. '
            'Check stdout for the COMMAND_INJECTION_CONFIRMED marker string after execution.'
        )

    # Dangerous functions (CWE-676)
    _DANGER_KW = ('gets(', 'strcpy', 'strcat', 'sprintf', 'dangerous function',
                  'unsafe', 'deprecated')
    if any(kw in text for kw in _DANGER_KW):
        return (
            'Feed crafted oversized input to trigger the dangerous function call. '
            'For buffer overflows via gets/strcpy/sprintf, provide input longer than '
            'the destination buffer. The ASan-instrumented binary will report the overflow.'
        )

    # XSS / script injection (CWE-79)
    _XSS_KW = ('xss', 'cross-site', 'script injection', 'innerhtml', 'document.write',
               'unescaped', 'unsanitized')
    if any(kw in text for kw in _XSS_KW):
        return (
            'Inject a payload like <script>alert(1)</script> into user input fields. '
            'Check the output/response for the unescaped script tag. '
            'Print XSS_CONFIRMED if the payload appears unescaped in the output.'
        )

    # Information disclosure
    _INFO_KW = ('leak', 'expose', 'disclose', 'sensitive', 'stack trace', 'error message')
    if any(kw in text for kw in _INFO_KW):
        return (
            'Feed malformed or unexpected input and capture stdout/stderr. '
            'Search output for sensitive data patterns (passwords, keys, /etc/passwd, '
            'stack traces, internal paths). Print SENSITIVE_DATA_LEAKED if found. '
            'Print STACK_TRACE_LEAKED if a stack trace is disclosed. '
            'Print INTERNAL_PATH_DISCLOSED if internal filesystem paths appear in output.'
        )

    # Race condition / TOCTOU
    _RACE_KW = ('race', 'toctou', 'concurrent', 'timing', 'side channel')
    if any(kw in text for kw in _RACE_KW):
        return (
            'Run the target concurrently from multiple threads/processes. '
            'Check for corrupted state, duplicate operations, or unexpected exceptions. '
            'For TOCTOU: swap a symlink between check and use phases. '
            'Print TIMING_ANOMALY if a timing side channel is detected.'
        )

    # Resource exhaustion / DoS / ReDoS
    _DOS_KW = ('denial of service', 'dos', 'redos', 'infinite loop', 'resource exhaust',
               'amplification')
    if any(kw in text for kw in _DOS_KW):
        return (
            'Feed a crafted payload designed to cause exponential processing time '
            '(e.g. nested regex, deeply nested JSON/XML, zip bomb). '
            'Measure execution time; print RESOURCE_EXHAUSTION:<seconds> if it exceeds 5s. '
            'Print TIMING_ANOMALY:ratio=<ratio> if exploit is >2x slower than baseline.'
        )

    # Auth bypass
    _AUTH_KW = ('auth', 'credential', 'hardcoded', 'bypass', 'unauthorized', 'privilege')
    if any(kw in text for kw in _AUTH_KW):
        return (
            'Attempt to access protected resources without valid credentials, '
            'or with default/hardcoded credentials. Print UNAUTHORIZED_ACCESS_GRANTED '
            'if access succeeds without proper authentication.'
        )

    # Prototype pollution
    _PROTO_KW = ('prototype', 'pollut', '__proto__', 'object.merge', 'deep_merge', 'deepextend')
    if any(kw in text for kw in _PROTO_KW):
        return (
            'Inject {"__proto__":{"polluted":true}} into merge/extend functions. '
            'After the merge, check if Object.prototype.polluted is set. '
            'Print PROTOTYPE_POLLUTED if the pollution succeeded.'
        )

    # SQL injection (CWE-89)
    _SQL_KW = ('sql injection', 'sql query', 'sql statement', 'select ', 'insert ', 'drop ', 'union select')
    if any(kw in text for kw in _SQL_KW):
        return (
            'Inject SQL payloads (e.g. "\' OR 1=1 --", "\'; DROP TABLE--") into user inputs. '
            'Check if the database query succeeds with injected input. '
            'Print SQL_INJECTION_CONFIRMED if the injection succeeds.'
        )

    # Code injection (CWE-94)
    _CODEINJ_KW = ('code injection', 'eval(', 'exec(', 'code execution', 'arbitrary code')
    if any(kw in text for kw in _CODEINJ_KW):
        return (
            'Inject a code payload (e.g. Python eval/exec, PHP assert, JS Function constructor) '
            'into user-controllable input. Check if the injected code executes. '
            'Print CODE_INJECTION_CONFIRMED if code execution occurs.'
        )

    # Deserialization (CWE-502)
    _DESER_KW = ('deserializ', 'pickle', 'unmarshal', 'yaml.load', 'objectinputstream', 'readobject')
    if any(kw in text for kw in _DESER_KW):
        return (
            'Craft a serialized payload that executes code when deserialized. '
            'For Python pickle, use __reduce__; for Java, use CommonsCollections gadgets. '
            'Print DESERIALIZATION_CONFIRMED if code execution occurs during deserialization.'
        )

    # SSRF (CWE-918)
    _SSRF_KW = ('ssrf', 'server-side request', 'request forgery', 'internal service', 'metadata endpoint')
    if any(kw in text for kw in _SSRF_KW):
        return (
            'Provide a URL pointing to an internal service (e.g. http://169.254.169.254/). '
            'Check if the server makes the request and returns internal data. '
            'Print SSRF_CONFIRMED if internal resource content is returned.'
        )

    # XXE (CWE-611)
    _XXE_KW = ('xxe', 'xml external', 'entity expansion', 'doctype', 'xml injection')
    if any(kw in text for kw in _XXE_KW):
        return (
            'Inject an XML payload with external entity declaration pointing to /etc/passwd. '
            'Check if the parsed output contains the file contents. '
            'Print XXE_CONFIRMED if external entity content appears in output.'
        )

    # Input validation bypass (CWE-20)
    _INPUT_KW = ('input validation', 'improper validation', 'validation bypass', 'insufficient validation')
    if any(kw in text for kw in _INPUT_KW):
        return (
            'Provide input that violates expected validation rules. '
            'Check if the target processes the invalid input without rejection. '
            'Print INPUT_VALIDATION_BYPASSED if invalid input is accepted.'
        )

    # Default: generic approach — use EXCEPTION_TRIGGERED instead of self-report
    return (
        'Craft malformed or boundary-case input and feed it to the target. '
        'Monitor both exit code and output for signs of the vulnerability triggering. '
        'Print EXCEPTION_TRIGGERED if an unhandled exception occurs in the target.'
    )


def _derive_observable_evidence_from_approach(approach_text: str, cwe: str = '') -> list:
    """Extract observable evidence markers from the exploitation approach text.

    Uses the _CWE_BEHAVIORAL_MARKERS mapping as the primary source to ensure
    markers are always in the oracle's _EVIDENCE_MARKER_STRINGS. Falls back to
    regex extraction for markers not in the mapping.

    This is fully dynamic and keyword-driven — no CWE hardcoding.
    """
    import re as _re
    markers = []

    # Priority 1: Use the deterministic CWE-to-marker mapping
    if cwe:
        cwe_markers = _get_behavioral_markers_for_cwe(cwe)
        if cwe_markers:
            markers.extend(cwe_markers)

    # Priority 2: Extract uppercase SNAKE_CASE tokens from the approach text
    # (catches markers the mapping doesn't cover yet)
    _marker_re = _re.compile(r'\b([A-Z][A-Z0-9_]{2,})\b')
    # Validate extracted tokens against the oracle's known evidence markers to
    # avoid generating markers the oracle can never match.  Unknown tokens are
    # still included but logged as a warning so they can be registered later.
    try:
        from agents.oracle_policy import _EVIDENCE_MARKER_STRINGS as _ORACLE_MARKERS
        _oracle_lower = set(m.lower() for m in _ORACLE_MARKERS)
    except Exception:
        _oracle_lower = set()
    for match in _marker_re.finditer(str(approach_text or '')):
        token = match.group(1)
        # Filter out common non-marker tokens
        _SKIP = {'ASAN', 'UBSAN', 'MSAN', 'TSAN', 'CWE', 'THE', 'AND', 'FOR',
                 'NOT', 'USE', 'CAN', 'HAS', 'BUT', 'ARE', 'ALL', 'ANY',
                 'AFTER', 'BEFORE', 'CHECK', 'FEED', 'MONITOR', 'MEASURE',
                 'INJECT', 'SEARCH', 'PRINT', 'RUN', 'LOOK', 'VERIFY',
                 'TODO', 'NULL', 'TRUE', 'FALSE', 'JSON', 'HTTP', 'HTTPS',
                 'SQL', 'XML', 'HTML', 'CSS', 'API', 'URL', 'SSH', 'TCP',
                 'UDP', 'DNS', 'TLS', 'SSL', 'CSV', 'YAML', 'TOML'}
        if token not in _SKIP and len(token) >= 3 and token not in markers:
            if _oracle_lower and token.lower() not in _oracle_lower:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    '[finding_context] Derived marker %r not in oracle _EVIDENCE_MARKER_STRINGS — '
                    'oracle may not confirm this marker. Consider registering it.', token)
            markers.append(token)

    # Universal fallback markers — crash/sanitizer evidence (NOT self-report)
    _FALLBACK = ['AddressSanitizer', 'SIGSEGV']
    for fb in _FALLBACK:
        if fb not in markers:
            markers.append(fb)

    return markers


# ---------------------------------------------------------------------------
# Synthesizer
# ---------------------------------------------------------------------------

def synthesize_finding_context(
    finding: Dict[str, Any],
    exploit_contract: Optional[Dict[str, Any]] = None,
    recon_report: Optional[Dict[str, Any]] = None,
    probe_dict: Optional[Dict[str, Any]] = None,
    repo_profile: Optional[Dict[str, Any]] = None,
    # Extra arguments for direct prompt builder compat
    vulnerable_code: str = '',
    code_context: str = '',
    joern_context: str = '',
    runtime_feedback: Any = '',
    observed_surface: Optional[Dict[str, Any]] = None,
) -> FindingContext:
    """Build a unified FindingContext by merging all available intel sources.

    Resolution priority: probe > investigation > recon > static analysis guess.
    """
    ctx = FindingContext()
    ec = dict(exploit_contract or finding.get('exploit_contract') or {})
    rr = dict(recon_report or {})
    pr = dict(probe_dict or {})
    rp = dict(repo_profile or {})
    obs = dict(observed_surface or {})
    notes = ctx.confidence_notes

    # ── Identity ──
    ctx.cwe = str(finding.get('cwe_type') or ec.get('cwe_type') or 'UNCLASSIFIED').strip()
    ctx.cwe_source = str(ec.get('cwe_source') or '').strip()
    ctx.filepath = str(finding.get('filepath') or '').strip()
    ctx.line_number = int(finding.get('line_number') or 0)
    ctx.language = str(finding.get('language') or ec.get('target_language') or '').strip()

    # ── Root cause: investigation > finding explanation > CVE summary ──
    _inv_root = str(ec.get('root_cause') or '').strip()
    _finding_expl = str(finding.get('explanation') or finding.get('llm_explanation') or '').strip()
    _cve_sum = str(ec.get('cve_summary') or '').strip()
    if _inv_root:
        ctx.root_cause = _inv_root
        notes.append('root_cause: investigation')
    elif _finding_expl:
        ctx.root_cause = _finding_expl
        notes.append('root_cause: finding-explanation')
    elif _cve_sum:
        ctx.root_cause = _cve_sum[:300]
        notes.append('root_cause: cve-summary')

    ctx.impact = str(ec.get('impact') or '').strip()

    # ── Data flow (Joern) ──
    ctx.joern_context = joern_context or str(ec.get('joern_context') or '').strip()
    ctx.joern_unreachable = bool(ec.get('joern_unreachable'))
    # Extract compact data flow path from Joern context
    _joern = ctx.joern_context
    if _joern:
        # Try to extract a single-line path summary
        for line in _joern.split('\n'):
            if '->' in line and len(line) < 300:
                ctx.data_flow_path = line.strip()
                break
        if not ctx.data_flow_path:
            ctx.data_flow_path = _joern[:200].replace('\n', ' ').strip()

    # ── Binary surface: probe > recon > contract ──
    _probe_bin = str(pr.get('probe_binary_path') or '').strip()
    _recon_bins = list(rr.get('binary_candidates') or [])
    _contract_bin = str(ec.get('target_binary') or ec.get('probe_binary_name') or '').strip()
    if _probe_bin:
        ctx.binary_path = _probe_bin
        ctx.binary_name = os.path.basename(_probe_bin)
        notes.append('binary: probe-confirmed')
    elif _recon_bins:
        ctx.binary_name = str(_recon_bins[0])
        notes.append('binary: recon-discovered')
    elif _contract_bin:
        ctx.binary_path = _contract_bin
        ctx.binary_name = os.path.basename(_contract_bin) if '/' in _contract_bin else _contract_bin
        notes.append('binary: contract-fallback')

    # ── Subcommands: probe > contract > recon ──
    _probe_subcmds = list(pr.get('probe_discovered_subcommands') or [])
    _contract_subcmds = list(ec.get('known_subcommands') or [])
    _recon_subcmds = list(ec.get('recon_subcommands') or [])
    # Also pull from observed_surface
    _obs_subcmds = list(obs.get('subcommands') or []) + list(obs.get('commands') or [])
    if _probe_subcmds:
        ctx.subcommands = _probe_subcmds
        notes.append('subcommands: probe-confirmed')
    elif _contract_subcmds:
        ctx.subcommands = _contract_subcmds
        notes.append('subcommands: contract')
    elif _recon_subcmds:
        ctx.subcommands = _recon_subcmds
        notes.append('subcommands: recon')
    # Merge any extras from observed_surface not already present
    for s in _obs_subcmds:
        if s and s not in ctx.subcommands:
            ctx.subcommands.append(s)

    ctx.bootstrap_subcommand = (
        str(pr.get('probe_bootstrap_subcommand') or '').strip()
        or str(ec.get('bootstrap_subcommand') or rp.get('bootstrap_subcommand') or '').strip()
    )

    # ── Help text ──
    ctx.help_text = (
        str(pr.get('probe_help_text') or '').strip()
        or str(obs.get('help_text') or '').strip()
    )[:1500]

    # ── Input method: probe > recon attack_surfaces > unknown ──
    _probe_surface = str(pr.get('probe_input_surface') or '').strip()
    _recon_atk = list(rr.get('attack_surfaces') or [])
    _contract_surface = str(ec.get('probe_input_surface') or '').strip()
    if _probe_surface and _probe_surface != 'unknown':
        ctx.input_method = _probe_surface
        notes.append('input_method: probe-confirmed')
    elif _contract_surface and _contract_surface != 'unknown':
        ctx.input_method = _contract_surface
        notes.append('input_method: contract')
    elif _recon_atk:
        _first_type = str(_recon_atk[0].get('type') or '').strip()
        if _first_type:
            ctx.input_method = _first_type
            notes.append('input_method: recon-attack-surface')

    # ── Input format: probe > recon > binary name heuristic ──
    _probe_fmt = str(pr.get('probe_format_hint') or ec.get('probe_format_hint') or '').strip().lower()
    _recon_fmts = list(rr.get('input_format_hints') or [])
    _rp_fmt = str(rp.get('input_format') or '').strip().lower()
    if _probe_fmt:
        ctx.input_format = _probe_fmt
        notes.append('input_format: probe-confirmed')
    elif _rp_fmt:
        ctx.input_format = _rp_fmt
        notes.append('input_format: repo-profile')
    elif _recon_fmts:
        ctx.input_format = str(_recon_fmts[0]).strip().lower()
        notes.append('input_format: recon-hint')
    else:
        # Binary name heuristic
        _bn = ctx.binary_name.lower()
        _FORMAT_SIGNALS = {
            'xml': ('xml', 'expat', 'libxml', 'xmlwf', 'xmllint', 'tidy', 'pugixml'),
            'json': ('json', 'cjson', 'jansson', 'parson', 'jsmn', 'yajl', 'simdjson'),
            'image': ('jpeg', 'jpg', 'png', 'gif', 'tiff', 'bmp', 'webp', 'exif'),
            'pdf': ('pdf', 'mupdf', 'poppler', 'pdfium'),
            'archive': ('zip', 'tar', 'gzip', 'bzip2', 'xz', 'lzma', 'zlib', 'libarchive'),
            'audio': ('mp3', 'ogg', 'flac', 'wav', 'aac', 'opus', 'sox'),
            'font': ('ttf', 'otf', 'woff', 'freetype', 'harfbuzz'),
            'html': ('html', 'gumbo', 'lexbor'),
        }
        for fmt, signals in _FORMAT_SIGNALS.items():
            if any(s in _bn for s in signals):
                ctx.input_format = fmt
                notes.append(f'input_format: binary-name-heuristic ({fmt})')
                break

    # ── Extensions + rejection patterns ──
    ctx.input_extensions = list(pr.get('probe_inferred_extensions') or ec.get('probe_inferred_extensions') or rp.get('accepted_extensions') or [])
    ctx.rejection_patterns = list(pr.get('probe_rejection_patterns') or ec.get('probe_rejection_patterns') or rp.get('rejection_patterns') or [])

    # ── Sample files (recon) ──
    ctx.sample_files = list(rr.get('sample_input_files') or rp.get('sample_input_files') or obs.get('repo_sample_files') or [])

    # ── Protocol intelligence ──
    ctx.multi_step_protocol = list(ec.get('multi_step_protocol') or rp.get('multi_step_protocol') or [])
    ctx.needs_key_bootstrap = bool(ec.get('needs_key_bootstrap') or rp.get('needs_key_bootstrap') or ctx.bootstrap_subcommand)
    ctx.needs_passphrase = bool(ec.get('needs_passphrase') or rp.get('needs_passphrase'))

    # ── Entry function: contract > recon entrypoints > filepath ──
    _target_ep = str(ec.get('target_entrypoint') or '').strip()
    _recon_eps = list(rr.get('entrypoints') or [])
    if _target_ep:
        ctx.entry_function = _target_ep
        notes.append('entry_function: contract')
    elif _recon_eps:
        ctx.entry_function = str(_recon_eps[0].get('name', ''))
        notes.append('entry_function: recon-entrypoint')

    ctx.entry_command = str(pr.get('probe_entry_command') or ec.get('probe_entry_command') or '').strip()

    # ── Probe exports + interesting strings ──
    ctx.exported_names = str(pr.get('probe_exports') or ec.get('probe_exports') or '').strip()
    ctx.interesting_strings = list(pr.get('probe_interesting_strings') or ec.get('probe_interesting_strings') or [])[:15]

    # ── Proof strategy: contract > recon > profile defaults ──
    _ps = ec.get('proof_strategy')
    if isinstance(_ps, dict) and _ps.get('proof_type'):
        ctx.proof_type = str(_ps['proof_type'])
        ctx.harness_type = str(_ps.get('harness_type') or ctx.harness_type)
        ctx.observable_evidence = list(_ps.get('observable_evidence') or [])
        notes.append('proof_strategy: investigation')
    else:
        _recon_strats = rr.get('proof_strategies') or {}
        if _recon_strats:
            for _cat, _strat in _recon_strats.items():
                if isinstance(_strat, dict):
                    ctx.proof_type = str(_strat.get('proof_type') or ctx.proof_type)
                    ctx.harness_type = str(_strat.get('harness_type') or ctx.harness_type)
                    notes.append('proof_strategy: recon')
                    break
        elif rp:
            ctx.proof_type = str(rp.get('default_proof_type') or ctx.proof_type)
            ctx.harness_type = str(rp.get('default_harness_type') or ctx.harness_type)
            notes.append('proof_strategy: profile-defaults')

    # ── Trigger steps: contract > exploit plan > CVE hint ──
    _trigger = list(ec.get('trigger_steps') or [])
    _plan = ec.get('exploit_plan')
    _cve_hint = ''
    _ps_dict = ec.get('proof_strategy') or {}
    if isinstance(_ps_dict, dict):
        _cve_hint = str(_ps_dict.get('cve_proof_hint') or '').strip()
    if _trigger:
        ctx.trigger_steps = _trigger
        notes.append('trigger_steps: contract')
    elif _plan and isinstance(_plan, dict):
        _steps = _plan.get('exploit_steps') or []
        ctx.exploit_plan_steps = _steps
        ctx.trigger_steps = [str(s.get('action', '')) for s in _steps if s.get('action')]
        notes.append('trigger_steps: exploit-plan')
    elif _cve_hint:
        ctx.trigger_steps = [_cve_hint]
        notes.append('trigger_steps: cve-proof-hint')

    ctx.cve_proof_hint = _cve_hint

    # ── Success indicators ──
    _success = list(ec.get('success_indicators') or [])
    if _success and not ctx.observable_evidence:
        ctx.observable_evidence = _success

    # ── CVE data ──
    ctx.cve_id = str(ec.get('cve_id') or finding.get('cve_id') or '').strip()
    ctx.cve_summary = str(ec.get('cve_summary') or '').strip()
    ctx.cve_cvss = float(ec.get('cve_cvss') or 0)
    ctx.cve_fix_version = str(ec.get('cve_fix_version') or '').strip()
    ctx.seed_poc = str(ec.get('seed_poc') or '').strip()
    ctx.poc_analysis = dict(ec.get('poc_analysis') or {})

    # ── Code context ──
    ctx.vulnerable_code = vulnerable_code or str(finding.get('code_chunk') or '').strip()
    ctx.code_context = code_context or ''

    # ── Runtime feedback ──
    if isinstance(runtime_feedback, dict):
        ctx.runtime_feedback_dict = runtime_feedback
        ctx.runtime_feedback = ''
    elif isinstance(runtime_feedback, str):
        ctx.runtime_feedback = runtime_feedback
    ctx.attempt_number = int(finding.get('_attempt_number') or 0)

    # ── Surface classification ──
    ctx.surface_type = str(pr.get('probe_surface_type') or ec.get('probe_surface_type') or '').strip()
    ctx.repo_surface_class = str(ec.get('repo_surface_class') or '').strip()
    ctx.project_type = str(rr.get('project_type') or rp.get('project_type') or 'unknown').strip()
    ctx.runtime_family = str(rr.get('runtime_family') or rp.get('runtime_family') or 'native').strip()
    ctx.base_url = str(pr.get('probe_base_url') or ec.get('probe_base_url') or '').strip()

    # ── Recon extras ──
    ctx.attack_surfaces = list(rr.get('attack_surfaces') or [])
    ctx.recon_proof_strategies = dict(rr.get('proof_strategies') or {})
    ctx.recon_entrypoints = list(rr.get('entrypoints') or [])
    ctx.recon_binary_candidates = list(rr.get('binary_candidates') or [])
    ctx.framework_hints = list(rr.get('framework_hints') or [])
    ctx.library_api_context = str(ec.get('library_api_context') or '').strip()

    # ── Cross-scan winning strategies ──
    ctx.previous_winning_strategies = list(ec.get('previous_winning_strategies') or [])

    # ── Extra contract fields for passthrough ──
    _MODELED_KEYS = {
        'cwe_type', 'cwe_source', 'root_cause', 'impact', 'target_entrypoint',
        'target_binary', 'probe_binary_name', 'execution_surface', 'trigger_steps',
        'success_indicators', 'inputs', 'proof_strategy', 'exploit_plan',
        'known_subcommands', 'recon_subcommands', 'multi_step_protocol',
        'bootstrap_subcommand', 'needs_key_bootstrap', 'needs_passphrase',
        'probe_input_surface', 'probe_surface_type', 'probe_entry_command',
        'probe_base_url', 'probe_format_hint', 'probe_inferred_extensions',
        'probe_rejection_patterns', 'probe_discovered_subcommands',
        'probe_bootstrap_subcommand', 'probe_exports', 'probe_interesting_strings',
        'cve_id', 'cve_summary', 'cve_cvss', 'seed_poc', 'poc_analysis',
        'cve_fix_version', 'cve_enriched', 'cve_osv_id', 'cve_cvss_vector',
        'cve_severity', 'joern_unreachable', 'joern_context',
        'vulnerable_function_source', 'library_api_context', 'repo_surface_class',
        'taxonomy_refs', 'runtime_feedback', 'protocol_hint', 'sample_input_files',
        'previous_winning_strategies', 'proof_category',
    }
    ctx.exploit_contract_extra = {
        k: v for k, v in ec.items()
        if k not in _MODELED_KEYS and v
    }

    # ── Dynamic proof category (CWE-agnostic) ──
    ctx.proof_category = _infer_proof_category(ctx)
    notes.append(f'proof_category: {ctx.proof_category} (dynamic inference)')

    # ── Exploitation approach hint (CWE-agnostic) ──
    ctx.exploitation_approach = _infer_exploitation_approach(ctx)
    notes.append(f'exploitation_approach: {ctx.exploitation_approach[:60]}...')

    logger.info(
        'FindingContext synthesized: cwe=%s binary=%s format=%s method=%s proof_cat=%s notes=%d',
        ctx.cwe, ctx.binary_name, ctx.input_format, ctx.input_method, ctx.proof_category, len(notes),
    )
    return ctx
