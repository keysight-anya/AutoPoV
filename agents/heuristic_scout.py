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
        self._patterns = {
            "CWE-89": [
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*\+", re.IGNORECASE),
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*%s", re.IGNORECASE),
                re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*format\(", re.IGNORECASE),
                re.compile(r"f[\"'].*(SELECT|INSERT|UPDATE|DELETE).*\{.*\}", re.IGNORECASE),
                re.compile(r"execute\s*\(\s*f[\"']", re.IGNORECASE),
                re.compile(r"cursor\.execute\s*\(\s*[^\"']*\+", re.IGNORECASE),
                re.compile(r"\.execute\s*\(\s*f[\"'].*SELECT", re.IGNORECASE),
            ],
            "CWE-119": [
                re.compile(r"\bstrcpy\s*\(", re.IGNORECASE),
                re.compile(r"\bgets\s*\(", re.IGNORECASE),
                re.compile(r"\bsprintf\s*\(", re.IGNORECASE),
                re.compile(r"\bmemcpy\s*\(", re.IGNORECASE),
            ],
            "CWE-190": [
                re.compile(r"\bint\s+\w+\s*=\s*\w+\s*\+\s*\w+", re.IGNORECASE),
                re.compile(r"\bsize_t\s+\w+\s*=\s*\w+\s*\*\s*\w+", re.IGNORECASE),
            ],
            "CWE-416": [
                re.compile(r"\bfree\s*\(\s*\w+\s*\)", re.IGNORECASE),
            ]
        }

    def _is_code_file(self, filepath: str) -> bool:
        ext = os.path.splitext(filepath)[1].lower()
        return ext in {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".cc",
            ".h", ".hpp", ".go", ".rs", ".rb", ".php", ".cs"
        }

    def _detect_language(self, filepath: str) -> str:
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp"
        }
        return lang_map.get(ext, "unknown")

    def scan_directory(self, codebase_path: str, cwes: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(codebase_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for filename in files:
                filepath = os.path.join(root, filename)
                if not self._is_code_file(filepath):
                    continue

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                rel_path = os.path.relpath(filepath, codebase_path)
                language = self._detect_language(rel_path)

                for line_idx, line in enumerate(lines, start=1):
                    for cwe in cwes:
                        patterns = self._patterns.get(cwe, [])
                        for pattern in patterns:
                            if pattern.search(line):
                                findings.append({
                                    "cwe_type": cwe,
                                    "filepath": rel_path,
                                    "line_number": line_idx,
                                    "code_chunk": line.strip(),
                                    "llm_verdict": "",
                                    "llm_explanation": "",
                                    "confidence": 0.35,
                                    "pov_script": None,
                                    "pov_path": None,
                                    "pov_result": None,
                                    "retry_count": 0,
                                    "inference_time_s": 0.0,
                                    "cost_usd": 0.0,
                                    "final_status": "pending",
                                    "alert_message": "Heuristic match",
                                    "source": "heuristic",
                                    "language": language
                                })
                                if len(findings) >= self.max_findings:
                                    return findings

        return findings


heuristic_scout = HeuristicScout()


def get_heuristic_scout() -> HeuristicScout:
    return heuristic_scout
