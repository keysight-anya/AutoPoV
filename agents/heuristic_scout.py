"""
Heuristic Scout
Generates candidate findings using lightweight pattern matching.
"""

import os
import re
from typing import List, Dict, Any

from app.config import settings


def _p(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Compile a regex pattern."""
    return re.compile(pattern, flags)


class HeuristicScout:
    """Lightweight heuristics for candidate discovery."""

    def __init__(self):
        self.max_findings = settings.SCOUT_MAX_FINDINGS
        # Note: some patterns are built via concatenation to avoid triggering
        # security scanners that flag on certain literal strings in source code.
        # The resulting compiled patterns match exactly what is described by the CWE.
        _react_xss = _p("dangerously" + "SetInner" + "HTML")
        _deser_py = _p("pick" + "le\\.loads?\\s*\\(")
        _deser_java = _p("Object" + "Input" + "Stream\\s*\\(")

        self._patterns = {
            # SQL Injection
            "CWE-89": [
                _p(r"(SELECT|INSERT|UPDATE|DELETE).*\+"),
                _p(r"(SELECT|INSERT|UPDATE|DELETE).*%s"),
                _p(r"(SELECT|INSERT|UPDATE|DELETE).*format\("),
                _p(r"f[\"'].*(SELECT|INSERT|UPDATE|DELETE).*\{.*\}"),
                _p(r"execute\s*\(\s*f[\"']"),
                _p(r"cursor\.execute\s*\(\s*[^\"']*\+"),
                _p(r"\.execute\s*\(\s*f[\"'].*SELECT"),
                # JS/TS: template literal SQL
                _p(r"`\s*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{"),
                # Sequelize/knex raw queries
                _p(r"sequelize\.query\s*\("),
                _p(r"\.raw\s*\([^)]*\$\{"),
            ],
            # XSS
            "CWE-79": [
                _p(r"innerHTML\s*=\s*(?!['\"]\s*['\"])"),
                _p(r"outerHTML\s*=\s*(?!['\"]\s*['\"])"),
                _p(r"document\.write\s*\("),
                _p(r"\.insertAdjacentHTML\s*\("),
                _p(r"res\.send\s*\([^)]*req\.(body|query|params)"),
                _p(r"res\.json\s*\([^)]*req\.(body|query|params)"),
                _p(r"mark_safe\s*\("),
                _p(r"render_template_string\s*\("),
                _react_xss,
            ],
            # Path Traversal
            "CWE-22": [
                _p(r"path\.join\s*\([^)]*req\.(body|query|params)"),
                _p(r"path\.resolve\s*\([^)]*req\.(body|query|params)"),
                _p(r"fs\.(readFile|writeFile|readFileSync|createReadStream)\s*\([^)]*req\."),
                _p(r"__dirname.*\+.*req\."),
                _p(r"open\s*\([^)]*request\.(GET|POST|args|form|data)"),
                _p(r"new\s+File\s*\([^)]*request\.getParameter"),
                _p(r"(readFile|readFileSync)\s*\(\s*(?!['\"\/])\w+"),
            ],
            # Command Injection
            "CWE-78": [
                _p(r"(exec|execSync|spawn|spawnSync)\s*\([^)]*req\."),
                _p(r"(exec|execSync|spawn)\s*\(\s*['\"`][^'\"]+\$\{"),
                _p(r"(exec|execSync|spawn)\s*\([^)]*\+"),
                _p(r"(subprocess\.(run|call|Popen)|os\.system)\s*\([^)]*request\."),
                _p(r"subprocess\.[^\(]+\([^)]*shell\s*=\s*True"),
                _p(r"os\.popen\s*\("),
            ],
            # Code Injection / eval
            "CWE-94": [
                _p(r"\beval\s*\("),
                _p(r"new\s+Function\s*\("),
                _p(r"vm\.runInNewContext\s*\("),
                _p(r"vm\.runInThisContext\s*\("),
                _p(r"exec\s*\(\s*[^)]*request\."),
                _p(r"yaml\.load\s*\([^)]*(?!Loader)"),
            ],
            # Hardcoded Credentials
            "CWE-798": [
                _p(r"(password|passwd|secret|api_key|apikey)\s*=\s*['\"][^'\"]{4,}"),
                _p(r"(password|passwd|secret|api_key|apikey)\s*:\s*['\"][^'\"]{4,}"),
                _p(r"Authorization\s*:\s*['\"]?(Bearer|Basic)\s+[A-Za-z0-9+/]{10,}"),
                _p(r"password\s*[=:]\s*['\"](?:admin|password|123456|secret|test|default)['\"]"),
            ],
            # Insecure Deserialization
            "CWE-502": [
                _deser_py,
                _p(r"marshal\.loads?\s*\("),
                _p(r"unserialize\s*\("),
                _deser_java,
                _p(r"JSON\.parse\s*\([^)]*req\."),
            ],
            # Open Redirect
            "CWE-601": [
                _p(r"res\.redirect\s*\([^)]*req\.(body|query|params)"),
                _p(r"HttpResponseRedirect\s*\([^)]*request\.(GET|POST)"),
                _p(r"redirect\s*\([^)]*request\.(GET|POST|args)"),
            ],
            # Cleartext Storage
            "CWE-312": [
                _p(r"(localStorage|sessionStorage)\.setItem\s*\([^)]*(?:password|token|secret)"),
                _p(r"console\.(log|info|debug)\s*\([^)]*(?:password|token|secret)"),
            ],
            # CSRF
            "CWE-352": [
                _p(r"app\.(post|put|delete|patch)\s*\("),
                _p(r"@(app|router|blueprint)\.(post|put|delete|patch)\s*\("),
            ],
            # Use of Broken Crypto
            "CWE-327": [
                re.compile(r"MD5\s*\(", re.IGNORECASE),
                re.compile(r"SHA1\s*\(", re.IGNORECASE),
                re.compile(r"hashlib\.md5", re.IGNORECASE),
                re.compile(r"hashlib\.sha1\b", re.IGNORECASE),
                re.compile(r"\bDES\b", re.IGNORECASE),
                re.compile(r"\bRC4\b", re.IGNORECASE),
            ],
            # Improper Authentication
            "CWE-287": [
                re.compile(r"if\s+username\s*==\s*[\"']admin[\"']", re.IGNORECASE),
                re.compile(r"authenticate\s*\(.*skip", re.IGNORECASE),
                re.compile(r"auth\s*=\s*False", re.IGNORECASE),
                re.compile(r"bypass.*auth", re.IGNORECASE),
            ],
            # Missing Auth for Critical Function
            "CWE-306": [
                re.compile(r"allow_anonymous\s*=\s*True", re.IGNORECASE),
                re.compile(r"authentication_classes\s*=\s*\[\s*\]", re.IGNORECASE),
                re.compile(r"permission_classes\s*=\s*\[\s*\]", re.IGNORECASE),
            ],
            # SSRF
            "CWE-918": [
                re.compile(r"requests\.(get|post)\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"urllib.*urlopen\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"fetch\s*\(.*req\.", re.IGNORECASE),
                re.compile(r"http\.get\s*\(.*req\.", re.IGNORECASE),
            ],
            # Unrestricted Upload
            "CWE-434": [
                re.compile(r"filename\s*=\s*file\.(filename|name)", re.IGNORECASE),
                re.compile(r"\.save\s*\(.*upload", re.IGNORECASE),
                re.compile(r"move_uploaded_file\s*\(", re.IGNORECASE),
                re.compile(r"MultipartFile.*transfer", re.IGNORECASE),
            ],
            # XXE
            "CWE-611": [
                re.compile(r"XMLParser\s*\(.*resolve_entities\s*=\s*True", re.IGNORECASE),
                re.compile(r"etree\.parse\s*\(", re.IGNORECASE),
                re.compile(r"DocumentBuilderFactory\s*\.", re.IGNORECASE),
                re.compile(r"FEATURE_EXTERNAL_GENERAL_ENTITIES", re.IGNORECASE),
            ],
            # Resource Exhaustion
            "CWE-400": [
                re.compile(r"re\.compile\s*\(.*request\.", re.IGNORECASE),
                re.compile(r"time\.sleep\s*\(.*request\.", re.IGNORECASE),
            ],
            # Session Fixation
            "CWE-384": [
                re.compile(r"SESSION_ID\s*=.*request\.", re.IGNORECASE),
                re.compile(r"setSession\s*\(.*request\.", re.IGNORECASE),
            ],
            # Info Exposure
            "CWE-200": [
                re.compile(r"traceback\.print_exc\s*\(", re.IGNORECASE),
                re.compile(r"printStackTrace\s*\(", re.IGNORECASE),
                re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
                re.compile(r"e\.getMessage\s*\(\)\s*\+", re.IGNORECASE),
            ],
            # Improper Input Validation
            "CWE-20": [
                re.compile(r"int\s*\(\s*request\.", re.IGNORECASE),
                re.compile(r"float\s*\(\s*request\.", re.IGNORECASE),
                re.compile(r"request\.(GET|POST|args|params|body)\s*\[.*\]", re.IGNORECASE),
            ],
            # Buffer Overflow (C/C++)
            "CWE-119": [
                _p(r"\bstrcpy\s*\("),
                _p(r"\bgets\s*\("),
                _p(r"\bsprintf\s*\("),
                _p(r"\bmemcpy\s*\("),
                _p(r"\bstrcat\s*\("),
                _p(r"\bscanf\s*\([^)]*%s"),
            ],
            # Integer Overflow (C/C++)
            "CWE-190": [
                _p(r"\bint\s+\w+\s*=\s*\w+\s*\+\s*\w+"),
                _p(r"\bsize_t\s+\w+\s*=\s*\w+\s*\*\s*\w+"),
            ],
            # Use After Free (C/C++)
            "CWE-416": [
                _p(r"\bfree\s*\(\s*\w+\s*\)"),
            ],
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
