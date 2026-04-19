"""
Heuristic Scout
Generates candidate findings using lightweight pattern matching.
"""

import os
import re
from typing import List, Dict, Any

from app.config import settings


class HeuristicScout:
    """Lightweight heuristics for candidate discovery."""

    def __init__(self):
        self.max_findings = settings.SCOUT_MAX_FINDINGS
        # Confidence values per signal category — higher for patterns that have a
        # tight source→sink correlation (security-critical sinks with concrete triggers)
        # vs broader structural signals that often need taint confirmation.
        self._signal_confidence: dict = {
            'sql_injection_signal': 0.55,
            'xss_signal': 0.50,
            'path_traversal_signal': 0.52,
            'command_injection_signal': 0.60,
            'dynamic_execution_signal': 0.55,
            'unsafe_deserialization_signal': 0.60,
            'memory_corruption_signal': 0.50,
            'integer_overflow_signal': 0.38,
            'lifecycle_misuse_signal': 0.40,
            # Python-specific source signals: medium confidence as they identify
            # input *sources* rather than full source→sink flows.
            'python_cli_taint_signal': 0.42,
            'python_flask_taint_signal': 0.45,
            'python_django_taint_signal': 0.45,
        }
        self._patterns = {
            "sql_injection_signal": [
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*\+", re.IGNORECASE),
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*%s", re.IGNORECASE),
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*format\(", re.IGNORECASE),
                re.compile(r"f[\"\'].*(SELECT|INSERT|UPDATE|DELETE).*\{.*\}", re.IGNORECASE),
            ],
            "xss_signal": [
                re.compile(r"innerHTML\s*=\s*[^\"\']", re.IGNORECASE),
                re.compile(r"document\.write\s*\(", re.IGNORECASE),
                re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
            ],
            "path_traversal_signal": [
                re.compile(r"open\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"\.\.[\\/]", re.IGNORECASE),
                re.compile(r"readFile\s*\(.*req\.", re.IGNORECASE),
            ],
            "command_injection_signal": [
                re.compile(r"os\.system\s*\(", re.IGNORECASE),
                re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True", re.IGNORECASE),
                re.compile(r"child_process\.(exec|spawn)\s*\(.*req\.", re.IGNORECASE),
            ],
            "dynamic_execution_signal": [
                re.compile(r"\beval\s*\(", re.IGNORECASE),
                re.compile(r"\bexec\s*\(", re.IGNORECASE),
                re.compile(r"compile\s*\(.*request\.", re.IGNORECASE),
            ],
            "unsafe_deserialization_signal": [
                re.compile(r"pickle\.loads\s*\(", re.IGNORECASE),
                re.compile(r"yaml\.load\s*\((?!.*Loader)", re.IGNORECASE),
                re.compile(r"unserialize\s*\(", re.IGNORECASE),
            ],
            "memory_corruption_signal": [
                re.compile(r"\bstrcpy\s*\(", re.IGNORECASE),
                re.compile(r"\bgets\s*\(", re.IGNORECASE),
                re.compile(r"\bsprintf\s*\(", re.IGNORECASE),
                re.compile(r"\bmemcpy\s*\(", re.IGNORECASE),
            ],
            "integer_overflow_signal": [
                re.compile(r"\bint\s+\w+\s*=\s*\w+\s*[+*]\s*\w+", re.IGNORECASE),
                re.compile(r"\bsize_t\s+\w+\s*=\s*\w+\s*\*\s*\w+", re.IGNORECASE),
            ],
            "lifecycle_misuse_signal": [
                re.compile(r"\bfree\s*\(\s*\w+\s*\)", re.IGNORECASE),
            ],
            "python_cli_taint_signal": [
                re.compile(r"sys\.argv\[\d+\]", re.IGNORECASE),
                re.compile(r"\.parse_args\(\)\.(\w+)", re.IGNORECASE),
            ],
            "python_flask_taint_signal": [
                re.compile(r"request\.(args|form|values|json|data|get_json)\b", re.IGNORECASE),
                re.compile(r"flask\.request\.(args|form|values|json)\b", re.IGNORECASE),
            ],
            "python_django_taint_signal": [
                re.compile(r"request\.GET\b", re.IGNORECASE),
                re.compile(r"request\.POST\b", re.IGNORECASE),
                re.compile(r"request\.data\b", re.IGNORECASE),
            ],
        }
        self._generic_patterns = [
            {
                "label": "untrusted_input_to_sensitive_sink",
                "confidence": 0.42,
                "patterns": [
                    re.compile(r"(request|req|input|argv|params|query|body).*(exec|system|popen|spawn|eval|render|write|open|query|sql)", re.IGNORECASE),
                    re.compile(r"(exec|system|popen|spawn|eval|render|write|open|query|sql).*(request|req|input|argv|params|query|body)", re.IGNORECASE),
                ],
            },
            {
                "label": "dangerous_memory_or_lifecycle_operation",
                "confidence": 0.48,
                "patterns": [
                    re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy|memmove)\s*\(", re.IGNORECASE),
                    re.compile(r"\bfree\s*\(\s*\w+\s*\)\s*;.*\bfree\s*\(\s*\w+\s*\)", re.IGNORECASE),
                ],
            },
            {
                "label": "unsafe_dynamic_execution_or_loading",
                "confidence": 0.40,
                "patterns": [
                    re.compile(r"\b(eval|exec|compile|__import__|dlopen|LoadLibrary)\b", re.IGNORECASE),
                    re.compile(r"\b(pickle\.loads|yaml\.load|marshal\.loads|ObjectInputStream|unserialize)\b", re.IGNORECASE),
                ],
            },
            {
                "label": "suspicious_auth_or_debug_gap",
                "confidence": 0.36,
                "patterns": [
                    re.compile(r"(allow_anonymous|skip_auth|auth\s*=\s*False|permission_classes\s*=\s*\[\s*\]|authentication_classes\s*=\s*\[\s*\])", re.IGNORECASE),
                    re.compile(r"(DEBUG\s*=\s*True|traceback\.print_exc|printStackTrace)", re.IGNORECASE),
                ],
            },
        ]

    def _is_code_file(self, filepath: str) -> bool:
        ext = os.path.splitext(filepath)[1].lower()
        return ext in {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.cs'}

    def _detect_language(self, filepath: str) -> str:
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.jsx': 'javascript', '.tsx': 'typescript',
            '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.h': 'c', '.hpp': 'cpp', '.go': 'go',
            '.rs': 'rust', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp'
        }
        return lang_map.get(ext, 'unknown')

    def _build_finding(self, rel_path: str, line_idx: int, line: str, language: str, signal_label: str, confidence: float, alert_message: str, source: str) -> Dict[str, Any]:
        return {
            'cwe_type': 'UNCLASSIFIED',
            'taxonomy_refs': [signal_label],
            'filepath': rel_path,
            'line_number': line_idx,
            'code_chunk': line.strip(),
            'llm_verdict': '',
            'llm_explanation': '',
            'confidence': confidence,
            'pov_script': None,
            'pov_path': None,
            'pov_result': None,
            'retry_count': 0,
            'inference_time_s': 0.0,
            'cost_usd': 0.0,
            'final_status': '',
            'alert_message': alert_message,
            'source': source,
            'language': language,
        }

    def scan_directory(self, codebase_path: str, cwes: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(codebase_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for filename in files:
                filepath = os.path.join(root, filename)
                if not self._is_code_file(filepath):
                    continue
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue

                rel_path = os.path.relpath(filepath, codebase_path)
                language = self._detect_language(rel_path)

                for line_idx, line in enumerate(lines, start=1):
                    for label, patterns in self._patterns.items():
                        for pattern in patterns:
                            if pattern.search(line):
                                conf = self._signal_confidence.get(label, 0.38)
                                findings.append(self._build_finding(rel_path, line_idx, line, language, label, conf, f'Heuristic signal: {label}', 'heuristic'))
                                if len(findings) >= self.max_findings:
                                    return findings
                                break
                    for generic in self._generic_patterns:
                        if any(pattern.search(line) for pattern in generic['patterns']):
                            findings.append(self._build_finding(rel_path, line_idx, line, language, generic['label'], generic['confidence'], f"Generic heuristic signal: {generic['label']}", 'heuristic_generic'))
                            if len(findings) >= self.max_findings:
                                return findings
                            break
        return findings


heuristic_scout = HeuristicScout()


def get_heuristic_scout() -> HeuristicScout:
    return heuristic_scout


__all__ = ['HeuristicScout', 'get_heuristic_scout']