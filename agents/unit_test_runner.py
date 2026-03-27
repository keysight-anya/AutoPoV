"""
AutoPoV Unit Test Runner Module
Runs PoV scripts against isolated vulnerable code snippets
"""

import ast
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TestResult:
    """Result of unit test validation"""
    success: bool
    vulnerability_triggered: bool
    execution_time_s: float
    stdout: str
    stderr: str
    exit_code: int
    details: Dict[str, Any]


class UnitTestRunner:
    """Runs PoV scripts against isolated code in unit test style"""

    CWE_ORACLES = {
        "CWE-22": {
            "side_effect_files": ["autopov_traversal_test", "autopov_path_test"],
            "expected_content_patterns": ["root:x:0:0:", "etc/passwd", "windows/system32", "boot.ini"],
            "expected_output_patterns": ["root:", "administrator", "system32", "passwd"],
            "description": "File content from outside intended directory"
        },
        "CWE-78": {
            "side_effect_files": ["autopov_rce", "autopov_cmd_injection"],
            "expected_output_patterns": ["uid=", "gid=", "root", "bin/bash", "cmd.exe", "whoami", "hostname"],
            "description": "Command execution output"
        },
        "CWE-89": {
            "expected_output_patterns": ["MariaDB", "MySQL", "SQLite", "PostgreSQL", "version", "@@version", "table_schema", "information_schema"],
            "timing_threshold_s": 5.0,
            "error_patterns": ["sql syntax", "mysql_fetch", "pg_query", "sqlite3"],
            "description": "Database information disclosure or error"
        },
        "CWE-94": {
            "side_effect_files": ["autopov_code_exec"],
            "expected_output_patterns": ["eval executed", "exec completed", "code injected", "system("],
            "description": "Code execution evidence"
        },
        "CWE-79": {
            "expected_output_patterns": ["<script>", "alert(", "javascript:", "onerror=", "onload=", "document.cookie", "window.location"],
            "dom_patterns": ["innerHTML", "document.write", "eval(", "setTimeout", "setInterval"],
            "description": "JavaScript execution in output"
        },
        "CWE-502": {
            "expected_output_patterns": ["pickle", "unserialize", "ObjectInputStream", "yaml.load", "json.loads"],
            "description": "Unsafe deserialization"
        },
        "CWE-611": {
            "expected_output_patterns": ["<!ENTITY", "SYSTEM", "file://", "http://", "xml version"],
            "description": "XML external entity processing"
        },
    }

    def __init__(self):
        self.test_history = []

    def _normalize_runtime(self, runtime_profile: str = "", filepath: str = "", vulnerable_code: str = "") -> str:
        profile = (runtime_profile or "").strip().lower()
        if profile in {"javascript", "node", "js", "ts", "tsx", "jsx", "typescript"}:
            return "javascript"
        if profile in {"python", "py"}:
            return "python"
        ext = os.path.splitext(filepath or "")[1].lower()
        if ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            return "javascript"
        if ext == ".py":
            return "python"
        if re.search(r"(^|\n)\s*(function\s+|const\s+\w+\s*=\s*\([^)]*\)\s*=>|async\s+function\s+)", vulnerable_code or ""):
            return "javascript"
        return "python"

    def test_vulnerable_function(
        self,
        pov_script: str,
        vulnerable_code: str,
        cwe_type: str,
        scan_id: str,
        exploit_contract: Dict[str, Any] | None = None,
        runtime_profile: str = "python",
        filepath: str = "",
    ) -> TestResult:
        start_time = datetime.utcnow()
        runtime = self._normalize_runtime(runtime_profile, filepath, vulnerable_code)

        try:
            extracted_func = self._extract_function(vulnerable_code, runtime)
            if not extracted_func:
                return TestResult(False, False, 0, "", "Could not extract function from vulnerable code", -1, {"error": "extraction_failed", "runtime_profile": runtime})

            test_harness = self._create_test_harness(
                pov_script=pov_script,
                vulnerable_function=extracted_func,
                cwe_type=cwe_type,
                runtime_profile=runtime,
            )
            result = self._run_isolated_test(test_harness, scan_id, runtime)
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()

            oracle_result = self._evaluate_exploit_oracle(
                cwe_type=cwe_type,
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                execution_time=execution_time,
                exploit_contract=exploit_contract or {},
            )

            test_result = TestResult(
                success=result.get("success", False),
                vulnerability_triggered=oracle_result["triggered"],
                execution_time_s=execution_time,
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                exit_code=result.get("exit_code", -1),
                details={
                    "cwe_type": cwe_type,
                    "extraction_success": True,
                    "test_method": f"isolated_{runtime}",
                    "oracle": oracle_result,
                    "runtime_profile": runtime,
                },
            )
            self.test_history.append(test_result)
            return test_result
        except Exception as e:
            end_time = datetime.utcnow()
            return TestResult(False, False, (end_time - start_time).total_seconds(), "", str(e), -1, {"error": str(e), "runtime_profile": runtime})

    def _extract_function(self, code: str, runtime_profile: str = "python") -> Optional[str]:
        if not code or not code.strip():
            return None
        lines = code.split("\n")
        func_patterns = [r"def\s+(\w+)\s*\(", r"function\s+(\w+)\s*\(", r"(\w+)\s*=\s*function\s*\(", r"const\s+(\w+)\s*=\s*\([^)]*\)\s*=>", r"async\s+function\s+(\w+)"]
        if runtime_profile == "javascript":
            func_patterns = func_patterns[1:]
        elif runtime_profile == "python":
            func_patterns = func_patterns[:1]
        for line in lines:
            for pattern in func_patterns:
                if re.search(pattern, line):
                    return code
        return code

    def _create_test_harness(self, pov_script: str, vulnerable_function: str, cwe_type: str, runtime_profile: str = "python") -> str:
        if runtime_profile == "javascript":
            return self._create_node_test_harness(pov_script, vulnerable_function)
        return self._create_python_test_harness(pov_script, vulnerable_function)

    def _create_python_test_harness(self, pov_script: str, vulnerable_function: str) -> str:
        escaped_vulnerable = vulnerable_function.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
        escaped_pov = pov_script.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
        harness = (
            '#!/usr/bin/env python3\n'
            'import io\n'
            'import sys\n'
            'import traceback\n'
            'from contextlib import redirect_stdout, redirect_stderr\n\n'
            'original_stdout = sys.stdout\n'
            'original_stderr = sys.stderr\n'
            'stdout_buffer = io.StringIO()\n'
            'stderr_buffer = io.StringIO()\n\n'
            'try:\n'
            '    vulnerable_code_context = """__VULNERABLE_CODE__"""\n'
            '    target_url = "http://localhost"\n'
            '    TARGET_URL = target_url\n'
            '    vulnerable_namespace = {}\n'
            '    exec(vulnerable_code_context, vulnerable_namespace)\n'
            '    globals().update(vulnerable_namespace)\n'
            '    pov_code = """__POV_CODE__"""\n'
            '    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):\n'
            '        pov_namespace = {**vulnerable_namespace, "__name__": "__main__", "TARGET_URL": target_url}\n'
            '        exec(pov_code, pov_namespace)\n'
            '    stdout_output = stdout_buffer.getvalue()\n'
            '    stderr_output = stderr_buffer.getvalue()\n'
            '    print(stdout_output, file=original_stdout)\n'
            '    print(stderr_output, file=original_stderr)\n'
            '    all_output = stdout_output + "\\n" + stderr_output\n'
            '    if "VULNERABILITY TRIGGERED" in all_output:\n'
            '        print("\\n[TEST RESULT] Vulnerability successfully triggered", file=original_stdout)\n'
            '        sys.exit(0)\n'
            '    print("\\n[TEST RESULT] Vulnerability not triggered", file=original_stdout)\n'
            '    sys.exit(1)\n'
            'except Exception as e:\n'
            '    error_msg = f"Test harness error: {str(e)}\\n{traceback.format_exc()}"\n'
            '    print(error_msg, file=original_stderr)\n'
            '    sys.exit(2)\n'
        )
        return harness.replace('__VULNERABLE_CODE__', escaped_vulnerable).replace('__POV_CODE__', escaped_pov)

    def _create_node_test_harness(self, pov_script: str, vulnerable_function: str) -> str:
        escaped_vulnerable = vulnerable_function.replace('\\', '\\\\').replace('`', '\\`')
        escaped_pov = pov_script.replace('\\', '\\\\').replace('`', '\\`')
        return """#!/usr/bin/env node
const vm = require(\"vm\");
const stdout = [];
const stderr = [];
const capture = (items) => items.map((item) => typeof item === \"string\" ? item : JSON.stringify(item)).join(\" \");
const context = {
  console: {
    log: (...args) => stdout.push(capture(args)),
    error: (...args) => stderr.push(capture(args)),
    warn: (...args) => stderr.push(capture(args)),
  },
  require,
  process,
  Buffer,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  URL,
  URLSearchParams,
  TARGET_URL: \"http://localhost\",
};
context.global = context;
context.globalThis = context;
try {
  vm.createContext(context);
  vm.runInContext(`__VULNERABLE_CODE__`, context, { timeout: 5000 });
  vm.runInContext(`__POV_CODE__`, context, { timeout: 5000 });
  const combined = stdout.join(\"\\n\") + \"\\n\" + stderr.join(\"\\n\");
  if (stdout.length) process.stdout.write(stdout.join(\"\\n\") + \"\\n\");
  if (stderr.length) process.stderr.write(stderr.join(\"\\n\") + \"\\n\");
  if (combined.includes(\"VULNERABILITY TRIGGERED\")) {
    process.stdout.write(\"\\n[TEST RESULT] Vulnerability successfully triggered\\n\");
    process.exit(0);
  }
  process.stdout.write(\"\\n[TEST RESULT] Vulnerability not triggered\\n\");
  process.exit(1);
} catch (error) {
  process.stderr.write(`Test harness error: ${error && error.stack ? error.stack : String(error)}\\n`);
  process.exit(2);
}
""".replace('__VULNERABLE_CODE__', escaped_vulnerable).replace('__POV_CODE__', escaped_pov)

    def _run_isolated_test(self, test_harness: str, scan_id: str, runtime_profile: str = "python") -> Dict[str, Any]:
        temp_dir = tempfile.mkdtemp(prefix=f"autopov_test_{scan_id}_")
        extension = ".js" if runtime_profile == "javascript" else ".py"
        harness_path = os.path.join(temp_dir, f"test_harness{extension}")
        command = ["node", harness_path] if runtime_profile == "javascript" else ["python3", harness_path]
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "", "NODE_PATH": ""}
        try:
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(test_harness)
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
            return {
                "success": result.returncode == 0,
                "vulnerability_triggered": result.returncode == 0 and "VULNERABILITY TRIGGERED" in (result.stdout + "\n" + result.stderr),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": "Test execution timed out (30s)", "exit_code": -1}
        except Exception as e:
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": f"Test execution failed: {str(e)}", "exit_code": -1}
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_with_mock_data(self, pov_script: str, cwe_type: str, mock_inputs: List[str]) -> List[TestResult]:
        results = []
        for mock_input in mock_inputs:
            test_code = f'\nimport io\nimport sys\nsys.stdin = io.StringIO("""{mock_input}""")\n\n{pov_script}\n'
            result = self._run_isolated_test(test_code, f"mock_{hash(mock_input)}", runtime_profile="python")
            results.append(TestResult(result.get("success", False), result.get("vulnerability_triggered", False), 0, result.get("stdout", ""), result.get("stderr", ""), result.get("exit_code", -1), {"mock_input": mock_input, "test_type": "mock"}))
        return results

    def _evaluate_exploit_oracle(self, cwe_type: str, stdout: str, stderr: str, execution_time: float, exploit_contract: Dict[str, Any] | None = None) -> Dict[str, Any]:
        combined_output = (stdout + stderr).lower()
        evidence = []
        confidence = "low"
        method = None
        if "vulnerability triggered" in combined_output:
            evidence.append("PoV printed 'VULNERABILITY TRIGGERED'")
            confidence = "low"
            method = "string_match"
        exploit_contract = exploit_contract or {}
        oracle = self.CWE_ORACLES.get(cwe_type, {})
        for pattern in exploit_contract.get("success_indicators", []):
            token = str(pattern).strip().lower()
            if token and token in combined_output:
                evidence.append(f"Contract success indicator found: '{pattern}'")
                confidence = "high"
                method = method or "contract_output"
        expected_patterns = list(oracle.get("expected_output_patterns", []))
        expected_patterns.extend([str(x) for x in exploit_contract.get("success_indicators", []) if x])
        for pattern in expected_patterns:
            if str(pattern).lower() in combined_output:
                evidence.append(f"Expected pattern found: '{pattern}'")
                confidence = "high"
                method = method or "output_pattern"
        from app.config import settings
        temp_dir = settings.TEMP_DIR
        content_patterns = list(oracle.get("expected_content_patterns", []))
        content_patterns.extend([str(x) for x in exploit_contract.get("success_indicators", [])])
        side_effect_files = list(oracle.get("side_effect_files", []))
        side_effect_files.extend([str(x) for x in exploit_contract.get("side_effects", []) if x])
        for filename in side_effect_files:
            file_path = os.path.join(temp_dir, filename)
            try:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_content = f.read()
                    if any(str(pattern).lower() in file_content.lower() for pattern in content_patterns if pattern):
                        evidence.append(f"Observed side effect file: {file_path}")
                        confidence = "high"
                        method = method or "side_effect_file"
                    os.remove(file_path)
            except Exception:
                pass
        for pattern in oracle.get("error_patterns", []):
            if pattern.lower() in combined_output:
                evidence.append(f"Error pattern found: '{pattern}'")
                if confidence == "low":
                    confidence = "medium"
                    method = method or "error_pattern"
        for pattern in oracle.get("dom_patterns", []):
            if pattern.lower() in combined_output:
                evidence.append(f"DOM manipulation found: '{pattern}'")
                confidence = "high"
                method = method or "dom_pattern"
        timing_threshold = oracle.get("timing_threshold_s")
        if timing_threshold and execution_time >= timing_threshold:
            evidence.append(f"Time-based detection: {execution_time:.2f}s >= {timing_threshold}s")
            confidence = "medium"
            method = method or "timing"
        generic_indicators = [exploit_contract.get("expected_outcome", ""), exploit_contract.get("goal", ""), *exploit_contract.get("inputs", []), *exploit_contract.get("trigger_steps", [])]
        for indicator in generic_indicators:
            token = str(indicator).strip().lower()
            if token and token in combined_output:
                evidence.append(f"Generic exploit indicator found: '{indicator}'")
                if confidence == "low":
                    confidence = "medium"
                method = method or "generic_contract"
        return {"triggered": len(evidence) > 0, "confidence": confidence, "evidence": evidence, "method": method, "cwe_description": oracle.get("description", "Generic exploit validation"), "exploit_goal": exploit_contract.get("goal", "")}

    def validate_syntax(self, pov_script: str, runtime_profile: str = "python") -> Dict[str, Any]:
        runtime = self._normalize_runtime(runtime_profile)
        if runtime == "javascript":
            if not shutil.which("node"):
                return {"valid": False, "error": "Node.js is not installed", "has_main": False}
            temp_dir = tempfile.mkdtemp(prefix="autopov_syntax_")
            script_path = os.path.join(temp_dir, "syntax_check.js")
            try:
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(pov_script)
                result = subprocess.run(["node", "--check", script_path], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    return {"valid": True, "error": None, "has_main": "VULNERABILITY TRIGGERED" in pov_script}
                return {"valid": False, "error": (result.stderr or result.stdout or "Node.js syntax check failed").strip(), "has_main": False}
            except Exception as e:
                return {"valid": False, "error": str(e), "has_main": False}
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            ast.parse(pov_script)
            return {"valid": True, "error": None, "has_main": "if __name__" in pov_script or "def main" in pov_script}
        except SyntaxError as e:
            return {"valid": False, "error": f"Syntax error at line {e.lineno}: {e.msg}", "has_main": False}


unit_test_runner = UnitTestRunner()


def get_unit_test_runner() -> UnitTestRunner:
    return unit_test_runner
