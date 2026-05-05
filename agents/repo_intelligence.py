"""
Repo Intelligence Module
========================
Synthesizes data from recon, probe, and static tool outputs into a structured
RepoProfile.  The profile captures binary protocol, input surface, subcommands,
build system, format hints, and bootstrap requirements — making this intelligence
available to downstream consumers (PoV generation, refinement, strategy planning)
without each module re-deriving it from raw data.

This replaces ad-hoc, hardcoded per-repo logic with a single adaptive distillation
step that runs once per scan and is reused everywhere.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RepoProfile:
    """Distilled intelligence about a target repository."""

    # Identity
    repo_name: str = ''
    project_type: str = ''          # c_library | c_cli | python_package | node_package | web_service | java | unknown
    runtime_family: str = 'native'  # native | python | node | java | web | unknown
    build_system: str = ''          # cmake | make | autoconf | meson | npm | pip | gradle | unknown

    # Binary surface
    primary_binary: str = ''        # resolved binary path or name
    binary_subcommands: List[str] = field(default_factory=list)
    bootstrap_subcommand: str = ''  # keygen / init / setup if detected
    input_surface: str = 'unknown'  # file_argument | stdin | network | argv_only | function_call
    input_format: str = ''          # xml | json | image | archive | audio | pdf | font | html | ''

    # File handling
    accepted_extensions: List[str] = field(default_factory=list)
    rejection_patterns: List[str] = field(default_factory=list)

    # Security-relevant
    known_cwes: List[str] = field(default_factory=list)       # CWEs detected by tools
    known_cves: List[str] = field(default_factory=list)       # CVEs from OSV/recon
    attack_surfaces: List[Dict[str, str]] = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)

    # Protocol intelligence
    needs_key_bootstrap: bool = False
    needs_passphrase: bool = False
    multi_step_protocol: List[str] = field(default_factory=list)  # ordered steps: ['keygen', 'encrypt', 'extract']
    sample_input_files: List[str] = field(default_factory=list)

    # Proof strategy hints
    default_proof_type: str = 'crash_signal'
    default_harness_type: str = 'subprocess_binary'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def synthesize_repo_profile(
    recon_report: Optional[Dict[str, Any]] = None,
    probe_result: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    codebase_path: str = '',
) -> RepoProfile:
    """Build a RepoProfile by merging recon, probe, and finding data.

    Parameters
    ----------
    recon_report : dict
        Output from the recon/discovery phase (attack_surfaces, build_system, etc.)
    probe_result : dict
        Output from probe_runner.ProbeResult.to_dict()
    findings : list
        List of finding dicts from discovery/investigation (for CWE/CVE extraction)
    codebase_path : str
        Path to the codebase on disk (for file-level heuristics)
    """
    rr = recon_report or {}
    pr = probe_result or {}
    profile = RepoProfile()

    # --- Identity ---
    profile.repo_name = (
        str(rr.get('repo_name') or pr.get('repo_name') or '').strip()
        or os.path.basename(codebase_path.rstrip('/\\'))
    )
    profile.project_type = str(rr.get('project_type') or '').strip() or _infer_project_type(pr, codebase_path)
    profile.runtime_family = str(rr.get('runtime_family') or '').strip() or _infer_runtime(pr, profile.project_type)
    profile.build_system = str(rr.get('build_system') or '').strip() or _detect_build_system(codebase_path)

    # --- Binary surface from probe ---
    profile.primary_binary = str(pr.get('probe_binary_path') or '').strip()
    profile.binary_subcommands = list(pr.get('probe_discovered_subcommands') or [])
    profile.bootstrap_subcommand = str(pr.get('probe_bootstrap_subcommand') or '').strip()
    profile.input_surface = str(pr.get('probe_input_surface') or '').strip() or 'unknown'
    profile.input_format = str(pr.get('probe_format_hint') or '').strip()
    profile.accepted_extensions = list(pr.get('probe_inferred_extensions') or [])
    profile.rejection_patterns = list(pr.get('probe_rejection_patterns') or [])

    # --- Merge recon attack surfaces and frameworks ---
    profile.attack_surfaces = list(rr.get('attack_surfaces') or [])
    profile.framework_hints = list(rr.get('framework_hints') or [])
    profile.sample_input_files = list(rr.get('sample_input_files') or [])

    # --- Extract CWEs and CVEs from findings ---
    if findings:
        _cwes = set()
        _cves = set()
        for f in findings:
            cwe = str(f.get('cwe_type') or '').strip()
            if cwe and cwe != 'UNCLASSIFIED' and cwe.startswith('CWE-'):
                _cwes.add(cwe)
            cve = str(f.get('cve_id') or '').strip()
            if cve and cve.startswith('CVE-'):
                _cves.add(cve)
            # Also collect from taxonomy_refs
            for ref in (f.get('taxonomy_refs') or []):
                ref_s = str(ref).strip()
                if ref_s.startswith('CWE-'):
                    _cwes.add(ref_s)
                elif ref_s.startswith('CVE-'):
                    _cves.add(ref_s)
        profile.known_cwes = sorted(_cwes)
        profile.known_cves = sorted(_cves)

    # --- Protocol intelligence ---
    profile.needs_key_bootstrap = bool(profile.bootstrap_subcommand)
    # Detect passphrase requirement from help text
    _help = str(pr.get('probe_help_text') or '').lower()
    profile.needs_passphrase = any(kw in _help for kw in ('passphrase', 'password', 'pin ', '--pass'))

    # Derive multi-step protocol from subcommands
    # Common crypto tool patterns: keygen → encrypt/archive → extract/decrypt
    _STEP_ORDER = {
        'keygen': 0, 'init': 0, 'setup': 0, 'configure': 0,
        'generate-key': 0, 'genkey': 0,
        'encrypt': 1, 'archive': 1, 'seal': 1, 'sign': 1, 'compress': 1,
        'decrypt': 2, 'extract': 2, 'unseal': 2, 'verify': 2, 'decompress': 2,
    }
    _ordered = sorted(
        [(sub, _STEP_ORDER.get(sub.lower(), 5)) for sub in profile.binary_subcommands
         if sub.lower() in _STEP_ORDER],
        key=lambda x: x[1]
    )
    profile.multi_step_protocol = [s[0] for s in _ordered]

    # --- Proof strategy defaults ---
    if profile.runtime_family == 'native':
        profile.default_proof_type = 'crash_signal'
        profile.default_harness_type = 'subprocess_binary'
    elif profile.runtime_family == 'web':
        profile.default_proof_type = 'observable_output'
        profile.default_harness_type = 'http_request'
    elif profile.runtime_family in ('python', 'node'):
        profile.default_proof_type = 'exception'
        profile.default_harness_type = 'direct_import'
    elif profile.project_type in ('c_library',):
        profile.default_proof_type = 'crash_signal'
        profile.default_harness_type = 'compiled_harness'

    # Merge recon proof strategies if available
    _recon_strats = rr.get('proof_strategies') or {}
    if _recon_strats:
        # Use the first recommended strategy
        for _cat, _strat in _recon_strats.items():
            if isinstance(_strat, dict):
                profile.default_proof_type = _strat.get('proof_type', profile.default_proof_type)
                profile.default_harness_type = _strat.get('harness_type', profile.default_harness_type)
                break

    logger.info(
        'RepoProfile synthesized: name=%s type=%s runtime=%s binary=%s format=%s subcmds=%d',
        profile.repo_name, profile.project_type, profile.runtime_family,
        os.path.basename(profile.primary_binary),
        profile.input_format, len(profile.binary_subcommands),
    )
    return profile


def _infer_project_type(probe: Dict[str, Any], codebase_path: str) -> str:
    """Infer project type from probe surface and codebase contents."""
    surface_type = str(probe.get('probe_surface_type') or '').lower()
    if surface_type == 'python_module':
        return 'python_package'
    if surface_type == 'node_module':
        return 'node_package'
    if surface_type == 'web_service':
        return 'web_service'
    if surface_type == 'java_module':
        return 'java'
    if surface_type == 'native_elf':
        binary = str(probe.get('probe_binary_path') or '').lower()
        if probe.get('probe_binary_is_test'):
            return 'c_library'
        return 'c_cli'
    # Fallback: check codebase for telltale files
    if codebase_path and os.path.isdir(codebase_path):
        if os.path.exists(os.path.join(codebase_path, 'CMakeLists.txt')):
            return 'c_cli'
        if os.path.exists(os.path.join(codebase_path, 'Makefile')):
            return 'c_cli'
        if os.path.exists(os.path.join(codebase_path, 'setup.py')) or os.path.exists(os.path.join(codebase_path, 'pyproject.toml')):
            return 'python_package'
        if os.path.exists(os.path.join(codebase_path, 'package.json')):
            return 'node_package'
    return 'unknown'


def _infer_runtime(probe: Dict[str, Any], project_type: str) -> str:
    """Infer runtime family from probe and project type."""
    _TYPE_TO_RUNTIME = {
        'c_cli': 'native', 'c_library': 'native',
        'python_package': 'python', 'node_package': 'node',
        'web_service': 'web', 'java': 'java',
    }
    return _TYPE_TO_RUNTIME.get(project_type, 'unknown')


def _detect_build_system(codebase_path: str) -> str:
    """Detect build system from codebase files."""
    if not codebase_path or not os.path.isdir(codebase_path):
        return 'unknown'
    _markers = [
        ('CMakeLists.txt', 'cmake'),
        ('meson.build', 'meson'),
        ('configure.ac', 'autoconf'),
        ('configure', 'autoconf'),
        ('Makefile', 'make'),
        ('setup.py', 'pip'),
        ('pyproject.toml', 'pip'),
        ('package.json', 'npm'),
        ('build.gradle', 'gradle'),
        ('pom.xml', 'maven'),
        ('Cargo.toml', 'cargo'),
        ('go.mod', 'go'),
    ]
    for marker, system in _markers:
        if os.path.exists(os.path.join(codebase_path, marker)):
            return system
    return 'unknown'


def inject_protocol_into_contract(
    profile: RepoProfile,
    exploit_contract: Dict[str, Any],
) -> Dict[str, Any]:
    """Enrich an exploit contract with repo protocol intelligence.

    Adds multi-step protocol, bootstrap hints, format requirements,
    and proof strategy defaults from the RepoProfile.
    """
    ec = dict(exploit_contract)

    if profile.multi_step_protocol and not ec.get('multi_step_protocol'):
        ec['multi_step_protocol'] = profile.multi_step_protocol

    if profile.bootstrap_subcommand and not ec.get('bootstrap_subcommand'):
        ec['bootstrap_subcommand'] = profile.bootstrap_subcommand

    if profile.needs_key_bootstrap:
        ec.setdefault('needs_key_bootstrap', True)

    if profile.needs_passphrase:
        ec.setdefault('needs_passphrase', True)

    if profile.input_format and not ec.get('probe_format_hint'):
        ec['probe_format_hint'] = profile.input_format

    if profile.accepted_extensions and not ec.get('probe_inferred_extensions'):
        ec['probe_inferred_extensions'] = profile.accepted_extensions

    if profile.rejection_patterns and not ec.get('probe_rejection_patterns'):
        ec['probe_rejection_patterns'] = profile.rejection_patterns

    if profile.binary_subcommands and not ec.get('known_subcommands'):
        ec['known_subcommands'] = profile.binary_subcommands

    if profile.sample_input_files and not ec.get('sample_input_files'):
        ec['sample_input_files'] = profile.sample_input_files

    # Inject protocol hint for prompts
    if profile.multi_step_protocol:
        _protocol_desc = ' → '.join(profile.multi_step_protocol)
        ec['protocol_hint'] = (
            f'This binary uses a multi-step protocol: {_protocol_desc}. '
            f'Your exploit MUST follow this sequence.'
        )

    return ec
