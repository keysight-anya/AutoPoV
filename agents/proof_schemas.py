"""
Typed schemas for AutoPoV exploit contracts, proof plans, and runtime results.

Pure-Python dataclasses (no third-party deps) so they work in the container
without Pydantic.  These are additive — no runtime behaviour change until wired
into callers.

Naming convention:
  ExploitContract  — pre-generation, built from static analysis + investigation
  ProofPlan        — model-filled JSON plan, produced during generation
  RuntimeResult    — structured result of PoV execution + oracle evaluation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Shared placeholder/invalid-value sets
# ---------------------------------------------------------------------------

_PLACEHOLDER_MARKERS = {
    '', 'unknown', 'none', 'n/a', 'vulnerable_binary',
    '/path/to/', 'placeholder', '<binary>',
}

# Substring markers for target_binary checks (exclude '' to avoid
# '' in some_string always being True).
_SUBSTRING_MARKERS = {p for p in _PLACEHOLDER_MARKERS if p}

_INVALID_ENTRYPOINTS = {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}

_GENERIC_ORACLE_VALUES = {
    'vulnerability triggered', 'crash', 'error', 'vuln triggered', '',
}


# ---------------------------------------------------------------------------
# ExploitContract
# ---------------------------------------------------------------------------

@dataclass
class ExploitContract:
    """Pre-generation contract built from static analysis + investigation output.

    Fields are populated by the contract builder; the model must not override
    them — it may only fill ProofPlan slots.
    """
    runtime_family: str = ""
    # native | python | node | java | javascript | browser | web | live_app | http

    execution_surface: str = ""
    # cli | repo_script | live_app | browser_dom | function_harness

    target_entrypoint: str = ""
    # function name, route, or binary subcommand

    target_binary: str = ""
    target_route: str = ""
    target_dom_selector: str = ""

    input_mode: str = ""
    # argv | stdin | file | http_request | dom_event

    input_format: str = ""

    trigger_steps: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    setup_requirements: List[str] = field(default_factory=list)
    trigger_requirements: List[str] = field(default_factory=list)
    relevance_anchors: List[str] = field(default_factory=list)

    def is_minimally_usable(self) -> bool:
        """Lightweight early hint used by callers before invoking _contract_gate.

        Returns True when the contract has enough information to be worth
        attempting the full gate check.  _contract_gate() is the canonical
        decision-maker for blocking; this method is a fast pre-check only and
        must not diverge from the gate's per-family rules.
        """
        family = self.runtime_family.strip().lower()
        ep = self.target_entrypoint.strip().lower()

        if family in {'native', 'c', 'cpp', 'binary'}:
            # Three acceptable native targets — any one is sufficient:
            #   1. A resolved function entrypoint (direct harness or traced call)
            #   2. A concrete binary name (CLI invocation proof)
            #   3. execution_surface == 'function_harness' (harness-mode, no binary)
            has_ep = ep not in _INVALID_ENTRYPOINTS
            has_binary = (
                bool(self.target_binary.strip())
                and self.target_binary.strip().lower() not in _SUBSTRING_MARKERS
            )
            has_harness_surface = self.execution_surface.strip().lower() == 'function_harness'
            return has_ep or has_binary or has_harness_surface

        if family in {'python', 'node', 'java', 'javascript'}:
            return ep not in _INVALID_ENTRYPOINTS

        if family in {'browser', 'web'}:
            # Browser proofs need a route/DOM trigger at the contract level
            return bool(self.execution_surface.strip())

        if family in {'live_app', 'http'}:
            # Live-app proofs need a route or startup surface at the contract level
            return bool(self.execution_surface.strip())

        # Unknown family — allow through; gate will catch specifics
        return True


# ---------------------------------------------------------------------------
# ProofPlan
# ---------------------------------------------------------------------------

@dataclass
class ProofPlan:
    """Model-filled proof plan produced during PoV generation (post-generation).

    The model outputs this as a JSON block before writing the PoV script.
    expected_oracle is a *supporting signal only* at runtime — it is never the
    sole basis for confirmation.
    """
    target_binary: str = ""
    target_entrypoint: str = ""
    subcommand: Optional[str] = None
    argv: List[str] = field(default_factory=list)
    stdin_payload: Optional[str] = None
    files_to_create: List[Dict[str, str]] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    expected_oracle: str = ""
    # Model's stated expectation — used as Layer 4 supporting signal only
    why_this_hits_target: str = ""

    def has_placeholders(self) -> bool:
        """Returns True if any required field contains a placeholder value.

        Uses _SUBSTRING_MARKERS (empty string excluded) for substring checks
        to avoid the '' in some_string always-True bug.
        """
        if not self.target_binary or any(
            p in self.target_binary.lower() for p in _SUBSTRING_MARKERS
        ):
            return True
        if not self.target_entrypoint or self.target_entrypoint.lower() in _PLACEHOLDER_MARKERS:
            return True
        if self.expected_oracle.strip().lower() in _GENERIC_ORACLE_VALUES:
            return True
        return False


# ---------------------------------------------------------------------------
# RuntimeResult
# ---------------------------------------------------------------------------

@dataclass
class RuntimeResult:
    """Structured result of PoV execution + oracle evaluation."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    signal_class: str = ""
    # strong | ambiguous | non_evidence

    path_relevant: bool = False
    self_report_only: bool = False
    disqualified: bool = False
    disqualifying_reason: str = ""

    model_oracle_matched: bool = False
    # True when proof_plan.expected_oracle was found in runtime output
    # — supporting signal only, never sole confirmation basis

    triggered: bool = False
    confirmation_reason: str = ""
    # strong_signal+path_relevant | strong_signal+path_relevant+oracle_aligned
    # | path_not_relevant | strong_signal_no_target | ambiguous_signal
    # | non_evidence | disqualified | self_report_only

    matched_evidence_markers: List[str] = field(default_factory=list)
    execution_stage: str = "trigger"
    # setup | baseline | trigger | cleanup
    proof_verdict: str = ""
    # proven | failed | setup_only | unresolved

    def is_confirmable(self) -> bool:
        """True when all three gates are satisfied: strong signal, path relevant,
        not disqualified, not self-report only."""
        return (
            self.signal_class == 'strong'
            and self.path_relevant
            and not self.disqualified
            and not self.self_report_only
        )


# ---------------------------------------------------------------------------
# Setup / Trigger staging
# ---------------------------------------------------------------------------

_EXECUTION_STAGES = frozenset({'setup', 'baseline', 'trigger', 'cleanup'})


@dataclass
class SetupPlan:
    """Deterministic preparation steps that must not count as exploit proof."""
    steps: List[str] = field(default_factory=list)
    files_to_create: List[Dict[str, str]] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class TriggerPlan:
    """The exploit trigger itself; the only stage allowed to confirm proof."""
    execution_surface: str = ""
    input_mode: str = ""
    argv: List[str] = field(default_factory=list)
    stdin_payload: Optional[str] = None
    files_to_create: List[Dict[str, str]] = field(default_factory=list)
    subcommand: Optional[str] = None
    target_entrypoint: str = ""
    target_route: str = ""
    target_dom_selector: str = ""
    http_method: str = ""
    request_param: str = ""


@dataclass
class SetupResult:
    """Observed outcome of deterministic setup/bootstrap steps."""
    stage: str = "setup"
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    artifacts: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class TriggerResult:
    """Observed outcome of the exploit trigger stage."""
    stage: str = "trigger"
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    oracle_reason: str = ""
    path_relevant: bool = False
    matched_evidence_markers: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TargetResolutionResult
# ---------------------------------------------------------------------------

_RESOLUTION_STATUSES = frozenset({'resolved', 'partially_resolved', 'unresolved', 'contradicted'})


@dataclass
class TargetResolutionResult:
    """Output of the deterministic target resolution stage (Layer 2 pre-wire).

    resolution_status values:
      resolved           -- all invariants for the runtime_family are satisfied
      partially_resolved -- at least one target anchor found; gate may still block
      unresolved         -- no usable target found; finding should not reach PoV generation
      contradicted       -- preflight evidence contradicts contract (e.g. entrypoint not found)
    """
    runtime_family: str = ""
    execution_surface: str = ""
    target_entrypoint: str = ""
    target_binary: str = ""
    target_module: str = ""
    target_route: str = ""
    resolution_status: str = "unresolved"  # resolved | partially_resolved | unresolved | contradicted
    derivation_sources: List[str] = field(default_factory=list)
    # e.g. ['static_ast', 'binary_candidates_promoted', 'preflight_observed_binary']
    resolution_note: str = ""
    # Human-readable explanation of why resolution succeeded/failed
