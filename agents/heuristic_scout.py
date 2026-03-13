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
            "CWE-79": [
                re.compile(r"innerHTML\s*=\s*[^\"']", re.IGNORECASE),
                re.compile(r"document\.write\s*\(", re.IGNORECASE),
                re.compile(r"\.html\s*\(\s*[^\"']", re.IGNORECASE),
                re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
                re.compile(r"render_template_string\s*\(.*request\.", re.IGNORECASE),
            ],
            "CWE-22": [
                re.compile(r"os\.path\.join\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"open\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"\.\.[\\/]", re.IGNORECASE),
                re.compile(r"path\.join\s*\(.*\.\.", re.IGNORECASE),
                re.compile(r"readFile\s*\(.*req\.", re.IGNORECASE),
            ],
            "CWE-78": [
                re.compile(r"os\.system\s*\(", re.IGNORECASE),
                re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True", re.IGNORECASE),
                re.compile(r"exec\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"child_process\.(exec|spawn)\s*\(.*req\.", re.IGNORECASE),
                re.compile(r"Runtime\.exec\s*\(", re.IGNORECASE),
            ],
            "CWE-94": [
                re.compile(r"\beval\s*\(", re.IGNORECASE),
                re.compile(r"\bexec\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"compile\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"__import__\s*\(.*request\.", re.IGNORECASE),
            ],
            "CWE-502": [
                re.compile(r"pickle\.loads\s*\(", re.IGNORECASE),
                re.compile(r"yaml\.load\s*\((?!.*Loader)", re.IGNORECASE),
                re.compile(r"marshal\.loads\s*\(", re.IGNORECASE),
                re.compile(r"ObjectInputStream\s*\(", re.IGNORECASE),
                re.compile(r"unserialize\s*\(", re.IGNORECASE),
            ],
            "CWE-798": [
                re.compile(r"password\s*=\s*[\"'][^\"']{4,}[\"']", re.IGNORECASE),
                re.compile(r"api_key\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE),
                re.compile(r"secret\s*=\s*[\"'][^\"']{4,}[\"']", re.IGNORECASE),
                re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*[\"'][^\"']{8,}[\"']", re.IGNORECASE),
            ],
            "CWE-312": [
                re.compile(r"(password|secret|token|key)\s*=\s*[\"']", re.IGNORECASE),
                re.compile(r"log(ger)?\..*password", re.IGNORECASE),
                re.compile(r"print\s*\(.*password", re.IGNORECASE),
            ],
            "CWE-327": [
                re.compile(r"MD5\s*\(", re.IGNORECASE),
                re.compile(r"SHA1\s*\(", re.IGNORECASE),
                re.compile(r"hashlib\.md5", re.IGNORECASE),
                re.compile(r"hashlib\.sha1\b", re.IGNORECASE),
                re.compile(r"DES\b", re.IGNORECASE),
                re.compile(r"RC4\b", re.IGNORECASE),
            ],
            "CWE-352": [
                re.compile(r"@csrf_exempt", re.IGNORECASE),
                re.compile(r"csrf_token.*false", re.IGNORECASE),
                re.compile(r"CSRFMiddleware.*False", re.IGNORECASE),
                re.compile(r"disable.*csrf", re.IGNORECASE),
            ],
            "CWE-287": [
                re.compile(r"if\s+username\s*==\s*[\"']admin[\"']", re.IGNORECASE),
                re.compile(r"authenticate\s*\(.*skip", re.IGNORECASE),
                re.compile(r"auth\s*=\s*False", re.IGNORECASE),
                re.compile(r"bypass.*auth", re.IGNORECASE),
            ],
            "CWE-306": [
                re.compile(r"@app\.route.*methods.*POST.*\n(?!.*login_required)", re.IGNORECASE),
                re.compile(r"allow_anonymous\s*=\s*True", re.IGNORECASE),
                re.compile(r"authentication_classes\s*=\s*\[\s*\]", re.IGNORECASE),
                re.compile(r"permission_classes\s*=\s*\[\s*\]", re.IGNORECASE),
            ],
            "CWE-601": [
                re.compile(r"redirect\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"HttpResponseRedirect\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"res\.redirect\s*\(.*req\.", re.IGNORECASE),
                re.compile(r"Location.*request\.(GET|POST|args|params)", re.IGNORECASE),
            ],
            "CWE-918": [
                re.compile(r"requests\.(get|post)\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"urllib.*urlopen\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"fetch\s*\(.*req\.", re.IGNORECASE),
                re.compile(r"http\.get\s*\(.*req\.", re.IGNORECASE),
            ],
            "CWE-434": [
                re.compile(r"filename\s*=\s*file\.(filename|name)", re.IGNORECASE),
                re.compile(r"\.save\s*\(.*upload", re.IGNORECASE),
                re.compile(r"move_uploaded_file\s*\(", re.IGNORECASE),
                re.compile(r"MultipartFile.*transfer", re.IGNORECASE),
            ],
            "CWE-611": [
                re.compile(r"XMLParser\s*\(.*resolve_entities\s*=\s*True", re.IGNORECASE),
                re.compile(r"etree\.parse\s*\(", re.IGNORECASE),
                re.compile(r"DocumentBuilderFactory\s*\.", re.IGNORECASE),
                re.compile(r"FEATURE_EXTERNAL_GENERAL_ENTITIES", re.IGNORECASE),
            ],
            "CWE-400": [
                re.compile(r"while\s+True\s*:", re.IGNORECASE),
                re.compile(r"re\.compile\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"time\.sleep\s*\(.*request\.", re.IGNORECASE),
            ],
            "CWE-384": [
                re.compile(r"session\[.*\]\s*=.*request\.", re.IGNORECASE),
                re.compile(r"SESSION_ID\s*=.*request\.", re.IGNORECASE),
                re.compile(r"setSession\s*\(.*request\.", re.IGNORECASE),
            ],
            "CWE-200": [
                re.compile(r"traceback\.print_exc\s*\(", re.IGNORECASE),
                re.compile(r"printStackTrace\s*\(", re.IGNORECASE),
                re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
                re.compile(r"e\.getMessage\s*\(\)\s*\+", re.IGNORECASE),
            ],
            "CWE-20": [
                re.compile(r"int\s*\(\s*request\.", re.IGNORECASE),
                re.compile(r"float\s*\(\s*request\.", re.IGNORECASE),
                re.compile(r"request\.(GET|POST|args|params|body)\s*\[.*\]", re.IGNORECASE),
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


# Export for agentic discovery
__all__ = ['HeuristicScout', 'get_heuristic_scout']
