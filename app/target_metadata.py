
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, Optional

_EMPTY = (None, '', [], {})

CURATED_TARGETS = [
    {
        'id': 'jgarzik/picocoin',
        'target_type': 'repo',
        'repo_labels': [
            'jgarzik/picocoin',
            'github.com/jgarzik/picocoin',
            'http://github.com/jgarzik/picocoin',
            'https://github.com/jgarzik/picocoin',
            'picocoin',
        ],
        'path_markers': [
            'include/ccoin/buint.h',
            'include/ccoin/hashtab.h',
            'include/ccoin/parr.h',
        ],
        'repo_hints': {
            'runtime_profile': 'c',
            'inputs': ['Compile and run a focused native harness against the resolved symbol'],
            'preconditions': ['Use repository headers and compile with memory-safety instrumentation when possible'],
            'proof_plan': {
                'runtime_family': 'native',
                'execution_surface': 'function_call',
                'input_mode': 'function',
                'input_format': 'c',
                'oracle': ['crash_signal', 'sanitizer_output', 'stdout_marker'],
                'fallback_strategies': ['deterministic_native_harness_fallback', 'targeted_native_sanitizer_harness'],
            },
            'runtime_hints': {
                'native': {
                    'prefer_function_harness': True,
                    'compiler_flags': ['-fsanitize=address', '-fno-omit-frame-pointer'],
                }
            },
        },
        'path_hints': {
            'include/ccoin/buint.h': {
                'target_entrypoint': 'bu256_new',
                'inputs': ['Pass a crafted init_val into bu256_new through a dedicated harness'],
                'trigger_steps': ['Compile a minimal harness that calls bu256_new', 'Detect null-dereference or sanitizer evidence'],
                'success_indicators': ['VULNERABILITY TRIGGERED', 'AddressSanitizer', 'Segmentation fault', 'SIGSEGV'],
                'proof_plan': {
                    'execution_surface': 'function_call',
                    'input_mode': 'function',
                    'input_format': 'c',
                    'oracle': ['crash_signal', 'sanitizer_output', 'stdout_marker'],
                    'fallback_strategies': ['deterministic_native_harness_fallback', 'targeted_native_sanitizer_harness'],
                },
            },
        },
    },
    {
        'id': 'juliet-dynamic',
        'target_type': 'benchmark',
        'benchmark_ids': ['juliet-dynamic'],
        'repo_hints': {
            'proof_plan': {
                'runtime_family': 'native',
                'fallback_strategies': ['targeted_native_sanitizer_harness'],
            }
        },
    },
    {
        'id': 'owasp-benchmark-python',
        'target_type': 'benchmark',
        'benchmark_ids': ['owasp-benchmark-python'],
        'repo_hints': {
            'runtime_profile': 'python',
            'proof_plan': {
                'runtime_family': 'repo_script',
                'fallback_strategies': ['targeted_python_repo_execution'],
            }
        },
    },
]


def _matches_label(candidate: str, labels: list[str]) -> bool:
    normalized_candidate = _normalize_repo_label(candidate)
    raw_candidate = str(candidate or '').strip().lower()
    for label in labels:
        normalized_label = _normalize_repo_label(label)
        raw_label = str(label or '').strip().lower()
        if normalized_candidate and normalized_candidate == normalized_label:
            return True
        if raw_candidate and raw_candidate == raw_label:
            return True
    return False


def _normalize_repo_label(value: str) -> str:
    raw = str(value or '').strip().lower()
    if not raw:
        return ''
    normalized = raw
    for prefix in ('https://', 'http://', 'git@'):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    if normalized.startswith('github.com/'):
        normalized = normalized[len('github.com/'):]
    elif normalized.startswith('git@github.com:'):
        normalized = normalized[len('git@github.com:'):]
    normalized = normalized.rstrip('/')
    if normalized.endswith('.git'):
        normalized = normalized[:-4]
    return normalized


def _has_marker(codebase_path: str, markers: list[str]) -> bool:
    root = Path(codebase_path or '')
    if not root.exists():
        return False
    for marker in markers:
        if (root / marker).exists():
            return True
    return False


def resolve_curated_target_metadata(
    *,
    target_type: str = 'repo',
    target_label: Optional[str] = None,
    repo_url: Optional[str] = None,
    benchmark_metadata: Optional[Dict[str, Any]] = None,
    codebase_path: Optional[str] = None,
) -> Dict[str, Any]:
    label_candidates = [str(target_label or '').strip(), str(repo_url or '').strip()]
    benchmark_id = str((benchmark_metadata or {}).get('benchmark_id') or '').strip().lower()
    benchmark_family = str((benchmark_metadata or {}).get('benchmark_family') or '').strip().lower()

    for entry in CURATED_TARGETS:
        if entry.get('target_type') == 'benchmark' and target_type == 'benchmark':
            ids = [str(x).lower() for x in (entry.get('benchmark_ids') or []) if str(x).strip()]
            if benchmark_id in ids or benchmark_family in ids:
                return {
                    'id': entry['id'],
                    'matched_by': 'benchmark_id',
                    'repo_hints': copy.deepcopy(entry.get('repo_hints') or {}),
                    'path_hints': copy.deepcopy(entry.get('path_hints') or {}),
                }
        if entry.get('target_type') != 'repo' or target_type != 'repo':
            continue
        if any(label and _matches_label(label, entry.get('repo_labels') or []) for label in label_candidates):
            return {
                'id': entry['id'],
                'matched_by': 'label',
                'repo_hints': copy.deepcopy(entry.get('repo_hints') or {}),
                'path_hints': copy.deepcopy(entry.get('path_hints') or {}),
            }
        if _has_marker(codebase_path or '', entry.get('path_markers') or []):
            return {
                'id': entry['id'],
                'matched_by': 'path_marker',
                'repo_hints': copy.deepcopy(entry.get('repo_hints') or {}),
                'path_hints': copy.deepcopy(entry.get('path_hints') or {}),
            }
    return {}


def path_hints_for(target_metadata: Optional[Dict[str, Any]], filepath: str) -> Dict[str, Any]:
    if not isinstance(target_metadata, dict):
        return {}
    path_hints = target_metadata.get('path_hints') or {}
    rel = str(filepath or '').replace('\\', '/').strip()
    if not rel:
        return {}
    if rel in path_hints:
        return copy.deepcopy(path_hints[rel])
    for key, value in path_hints.items():
        normalized_key = str(key or '').replace('\\', '/').strip()
        if normalized_key and rel.endswith(normalized_key):
            return copy.deepcopy(value)
    return {}


def merge_contract_hints(contract: Optional[Dict[str, Any]], *hint_layers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = copy.deepcopy(contract or {})
    for hints in hint_layers:
        if not isinstance(hints, dict):
            continue
        for key, value in hints.items():
            if value in _EMPTY:
                continue
            if key == 'proof_plan':
                plan = copy.deepcopy(merged.get('proof_plan') or {})
                for plan_key, plan_value in value.items():
                    if plan_value in _EMPTY:
                        continue
                    existing = plan.get(plan_key)
                    if isinstance(plan_value, list):
                        plan[plan_key] = list(dict.fromkeys([*(existing or []), *plan_value]))
                    elif isinstance(plan_value, dict):
                        nested = copy.deepcopy(existing or {})
                        for nested_key, nested_value in plan_value.items():
                            if nested.get(nested_key) in _EMPTY:
                                nested[nested_key] = copy.deepcopy(nested_value)
                        plan[plan_key] = nested
                    elif existing in _EMPTY:
                        plan[plan_key] = copy.deepcopy(plan_value)
                merged['proof_plan'] = plan
                continue
            existing = merged.get(key)
            if isinstance(value, list):
                merged[key] = list(dict.fromkeys([*(existing or []), *value]))
            elif isinstance(value, dict):
                nested = copy.deepcopy(existing or {})
                for nested_key, nested_value in value.items():
                    if nested.get(nested_key) in _EMPTY:
                        nested[nested_key] = copy.deepcopy(nested_value)
                merged[key] = nested
            elif existing in _EMPTY:
                merged[key] = copy.deepcopy(value)
    return merged
