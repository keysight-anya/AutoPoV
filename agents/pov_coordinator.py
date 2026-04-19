"""
AutoPoV PoV Coordinator Agent
Stateful agent that analyzes the full attempt history after each failed PoV
run and returns a targeted action + injected constraints for the next retry.

Unlike the blind refinement loop (which passes one error message to the LLM),
the coordinator sees ALL previous attempts and the binary's actual runtime
output so it can recognize patterns across multiple failures and choose a
fundamentally different strategy rather than repeating the same approach.

Model used: always `state['model_name']` — passed in by agent_graph.py.
No default or fallback model is set here.

Public API
----------
    decision = decide(attempt_log, exploit_contract, trace_context, model_name, openrouter_client)
    # decision.action         : str (action key — see CoordinatorDecision)
    # decision.rationale      : str (one-sentence explanation)
    # decision.injected_constraints : dict (forced into next refinement prompt)
    # decision.abandon        : bool (True → skip remaining retries)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Decision schema
# ---------------------------------------------------------------------------

VALID_ACTIONS = {
    'refine_payload',       # same surface, try a different payload shape/size
    'refine_surface',       # switch input mode (file→stdin or stdin→file)
    'switch_entrypoint',    # try a different subcommand / entry function
    'try_stdin',            # force stdin input mode
    'try_file_arg',         # force file-argument input mode
    'escalate_asan',        # ask PoV to compile the target with ASan flags
    'fix_binary_name',      # TARGET_SYMBOL was wrong
    'fix_encoding',         # bytes/text mismatch
    'refine_format',        # wrong file format (e.g. sent JPEG to XML parser)
    'abandon',              # no viable path found — skip remaining retries
}


@dataclass
class CoordinatorDecision:
    action: str = 'refine_payload'
    rationale: str = ''
    injected_constraints: Dict[str, Any] = field(default_factory=dict)
    abandon: bool = False


# ---------------------------------------------------------------------------
# Heuristic fast-path (no LLM cost, covers the most common failure patterns)
# ---------------------------------------------------------------------------

def _heuristic_decision(
    attempt_log: List[Dict[str, Any]],
    exploit_contract: Dict[str, Any],
    trace_context: str,
) -> Optional[CoordinatorDecision]:
    """Return a decision without an LLM call when the pattern is unambiguous.

    Returns None when heuristics are inconclusive — caller should use LLM.
    """
    if not attempt_log:
        return None

    last = attempt_log[-1]
    stderr = str(last.get('stderr') or '').lower()
    stdout = str(last.get('stdout') or '').lower()
    combined = stderr + '\n' + stdout
    oracle_reason = str(last.get('oracle_reason') or '')
    exit_code = int(last.get('exit_code') or -1)

    # ── bytes/text encoding error ──────────────────────────────────────────
    if "'bytes' object has no attribute 'encode'" in combined or \
       'bytes.*text=true' in combined:
        return CoordinatorDecision(
            action='fix_encoding',
            rationale='PoV passed bytes with text=True to subprocess.',
            injected_constraints={
                'encoding_fix': (
                    "CRITICAL: Do NOT mix bytes payload with text=True. "
                    "Either use text=True with a string payload, or remove text=True "
                    "and pass raw bytes. E.g.: input=payload.decode('latin-1') if using text=True."
                )
            },
        )

    # ── wrong binary name ──────────────────────────────────────────────────
    probe_bin = str(exploit_contract.get('probe_binary_name') or '').strip()
    if probe_bin and '[autopov] binary not found:' in combined:
        _m = re.search(r'\[autopov\] binary not found: ([\w.\-]+)', combined)
        wrong = _m.group(1) if _m else 'unknown'
        if wrong != probe_bin:
            return CoordinatorDecision(
                action='fix_binary_name',
                rationale=f"Script searched for '{wrong}' but probe found '{probe_bin}'.",
                injected_constraints={
                    'binary_name_fix': (
                        f"CRITICAL: Wrong binary name. "
                        f"Change TARGET_SYMBOL = {probe_bin!r}. "
                        f"Also set: TARGET_BINARY = os.environ.get('TARGET_BINARY') "
                        f"or os.environ.get('TARGET_BIN') or {probe_bin!r}"
                    )
                },
            )

    # ── wrong input surface: binary printed usage immediately ──────────────
    probe_surface = str(exploit_contract.get('probe_input_surface') or '').strip()
    usage_indicators = ('usage:', '--help', 'missing command', 'missing file', 'no files to process',
                        'expected file', 'requires', 'positional argument')
    if oracle_reason in ('no_oracle_match', 'non_evidence') and \
       any(kw in combined for kw in usage_indicators):
        # If trace confirmed file_argument but PoV used stdin
        if probe_surface == 'file_argument' or \
           (trace_context and 'file_argument' in trace_context):
            return CoordinatorDecision(
                action='try_file_arg',
                rationale='Binary printed usage — not receiving input. Probe confirmed file_argument surface.',
                injected_constraints={
                    'input_surface_override': 'file_argument',
                    'surface_fix': (
                        "INPUT SURFACE FIX: Write your payload to a temp file and pass "
                        "its path as argv[1]. Do NOT pipe bytes to stdin."
                    )
                },
            )
        elif probe_surface == 'stdin' or \
             (trace_context and 'stdin' in trace_context and 'stdin (fd=0)' in trace_context):
            return CoordinatorDecision(
                action='try_stdin',
                rationale='Binary printed usage — not receiving input. Probe confirmed stdin surface.',
                injected_constraints={
                    'input_surface_override': 'stdin',
                    'surface_fix': (
                        "INPUT SURFACE FIX: Pass payload via subprocess.run(argv, "
                        "input=payload, capture_output=True). "
                        "If payload is bytes, remove text=True."
                    )
                },
            )

    # ── trace identified format mismatch ──────────────────────────────────
    if trace_context and 'FILE EXTENSIONS OBSERVED:' in trace_context:
        _ext_m = re.search(r'FILE EXTENSIONS OBSERVED: ([^\n]+)', trace_context)
        if _ext_m:
            exts = _ext_m.group(1).strip()
            # Check if any previous attempt used a generic binary payload
            for att in attempt_log:
                pov = str(att.get('pov_script') or '').lower()
                if ('b\'\\xff\\xd8' in pov or "b'\\x89png" in pov or '_generic' in pov):
                    return CoordinatorDecision(
                        action='refine_format',
                        rationale=f'PoV sent image/binary payload but target opens: {exts}',
                        injected_constraints={
                            'format_fix': (
                                f"FORMAT FIX: The binary expects files with these extensions: {exts}. "
                                f"Do NOT send JPEG, PNG or random binary. "
                                f"Craft a payload matching the expected format."
                            )
                        },
                    )

    # ── all attempts used the same approach — force diversity ──────────────
    if len(attempt_log) >= 2:
        import hashlib
        hashes = set()
        for att in attempt_log:
            h = hashlib.md5(str(att.get('pov_script') or '').strip().encode()).hexdigest()
            hashes.add(h)
        if len(hashes) == 1:  # all identical
            return CoordinatorDecision(
                action='refine_payload',
                rationale='All attempts produced identical PoV — model is stuck. Force diversity.',
                injected_constraints={
                    'diversity_force': (
                        "CRITICAL: Your previous attempts produced identical code. "
                        "You MUST use a completely different approach. "
                        "If you used file input, try stdin. "
                        "If you used one payload, use a structurally different one. "
                        "Change the exploit strategy entirely."
                    )
                },
            )

    # ── valgrind found errors — escalate with specific payload ─────────────
    if trace_context and 'VALGRIND MEMORY ERRORS' in trace_context:
        crash_input = ''
        _cm = re.search(r'Triggered with input mode: (\w+)', trace_context)
        if _cm:
            crash_input = _cm.group(1)
        constraints: Dict[str, Any] = {
            'valgrind_escalation': (
                "VALGRIND CONFIRMED memory errors in this binary. "
                "The vulnerability is real. "
                "Your PoV MUST reach the same code path that valgrind flagged. "
                "Use a large, structurally malformed payload to overflow or corrupt memory."
            )
        }
        if crash_input == 'stdin':
            constraints['input_surface_override'] = 'stdin'
        elif crash_input == 'file':
            constraints['input_surface_override'] = 'file_argument'
        return CoordinatorDecision(
            action='escalate_asan',
            rationale='Valgrind detected real memory errors — escalate payload to trigger them.',
            injected_constraints=constraints,
        )

    # ── too many retries with no signal at all — abandon ──────────────────
    if len(attempt_log) >= 3:
        no_signal_count = sum(
            1 for att in attempt_log
            if att.get('oracle_reason') in ('no_oracle_match', 'non_evidence', 'path_not_relevant')
        )
        if no_signal_count == len(attempt_log):
            return CoordinatorDecision(
                action='abandon',
                rationale='All attempts produced zero oracle signal. No viable path found.',
                abandon=True,
            )

    return None  # heuristics inconclusive — use LLM


# ---------------------------------------------------------------------------
# LLM-based coordinator
# ---------------------------------------------------------------------------

_COORDINATOR_SYSTEM = """You are the PoV Coordinator for an automated vulnerability proof system.
You receive a history of failed PoV execution attempts and must decide the BEST next action.

Respond ONLY with a JSON object — no prose, no code fences:
{
  "action": "<one of: refine_payload|refine_surface|switch_entrypoint|try_stdin|try_file_arg|escalate_asan|fix_binary_name|fix_encoding|refine_format|abandon>",
  "rationale": "<one sentence why>",
  "injected_constraints": {
    "<key>": "<instruction string to inject into the next PoV generation prompt>"
  },
  "abandon": false
}

Rules:
- If binary exits immediately with usage/help text → try_file_arg or try_stdin
- If binary not found → fix_binary_name
- If bytes + text=True error → fix_encoding
- If wrong file format (e.g. JPEG sent to XML parser) → refine_format
- If all attempts identical → refine_payload with diversity_force key
- If 3+ attempts with zero oracle signal → abandon
- injected_constraints values are verbatim strings injected into the refinement prompt
"""


def _build_coordinator_prompt(
    attempt_log: List[Dict[str, Any]],
    exploit_contract: Dict[str, Any],
    trace_context: str,
) -> str:
    parts = []

    if trace_context:
        parts.append(f"DYNAMIC TRACE:\n{trace_context}\n")

    parts.append(f"EXPLOIT CONTRACT:\n{json.dumps(exploit_contract, indent=2, default=str)[:1500]}\n")

    parts.append(f"ATTEMPT HISTORY ({len(attempt_log)} attempts):")
    for i, att in enumerate(attempt_log, 1):
        pov_snippet = str(att.get('pov_script') or '')[:400]
        parts.append(
            f"\n--- Attempt {i} ---\n"
            f"oracle_reason: {att.get('oracle_reason')}\n"
            f"exit_code: {att.get('exit_code')}\n"
            f"stdout (first 200): {str(att.get('stdout') or '')[:200]}\n"
            f"stderr (first 200): {str(att.get('stderr') or '')[:200]}\n"
            f"pov_script (first 400):\n{pov_snippet}\n"
        )

    return '\n'.join(parts)


def decide(
    attempt_log: List[Dict[str, Any]],
    exploit_contract: Dict[str, Any],
    trace_context: str,
    model_name: str,
    openrouter_client: Any,
) -> CoordinatorDecision:
    """Analyze the full attempt history and return the best next action.

    Always uses `model_name` — the same model selected for the scan.
    Never defaults to any specific model.
    """
    contract = exploit_contract or {}

    # 1. Try heuristics first (free, fast, deterministic)
    heuristic = _heuristic_decision(attempt_log, contract, trace_context)
    if heuristic is not None:
        return heuristic

    # 2. Fall back to LLM coordinator
    if not openrouter_client or not model_name:
        # No LLM available — return a generic refine_payload
        return CoordinatorDecision(
            action='refine_payload',
            rationale='No LLM available for coordination — generic retry.',
            injected_constraints={},
        )

    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        prompt_text = _build_coordinator_prompt(attempt_log, contract, trace_context)
        messages = [
            SystemMessage(content=_COORDINATOR_SYSTEM),
            HumanMessage(content=prompt_text),
        ]
        response = openrouter_client.invoke(messages)
        raw_text = getattr(response, 'content', str(response)) or ''

        # Strip think blocks (qwen3 etc.)
        raw_text = re.sub(r'<think>[\s\S]*?</think>', '', raw_text).strip()
        # Strip code fences
        raw_text = re.sub(r'^```[a-z]*\n?', '', raw_text).strip()
        raw_text = re.sub(r'\n?```$', '', raw_text).strip()

        parsed = json.loads(raw_text)
        action = str(parsed.get('action') or 'refine_payload')
        if action not in VALID_ACTIONS:
            action = 'refine_payload'
        return CoordinatorDecision(
            action=action,
            rationale=str(parsed.get('rationale') or ''),
            injected_constraints=dict(parsed.get('injected_constraints') or {}),
            abandon=bool(parsed.get('abandon', False)),
        )
    except Exception as exc:
        # LLM call failed — return a safe default
        return CoordinatorDecision(
            action='refine_payload',
            rationale=f'Coordinator LLM call failed ({exc}) — generic retry.',
            injected_constraints={},
        )


def format_constraints_for_prompt(decision: CoordinatorDecision) -> List[str]:
    """Convert CoordinatorDecision.injected_constraints into a list of error strings
    compatible with the existing validation_errors format in _node_refine_pov."""
    errors: List[str] = []
    if decision.rationale:
        errors.append(f'[Coordinator] {decision.rationale}')
    for key, value in (decision.injected_constraints or {}).items():
        if value:
            errors.append(str(value))
    return errors
