"""
AutoPoV PoV Tester Module
Tests PoV scripts against running applications and native targets
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime
from agents.app_runner import get_app_runner
from agents.live_app_tester import get_live_app_tester
class PoVTesterError(Exception):
    """Exception raised during PoV testing"""
    pass
class PoVTester:
    INVALID_NATIVE_ENTRYPOINTS = {
        "if", "for", "while", "switch", "return", "sizeof", "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strcmp", "unknown",
    }
    """Tests PoV scripts against running applications and binaries"""
    NATIVE_CRASH_PATTERNS = [
        'addresssanitizer',
        'undefinedbehaviorsanitizer',
        'runtime error:',
        'heap-buffer-overflow',
        'stack-buffer-overflow',
        'global-buffer-overflow',
        'use-after-free',
        'segmentation fault',
        'sigsegv',
        'null pointer',
        'deadlysignal',
        'abort',
    ]
    def _patch_target_refs(self, pov_script: str, target_url: Optional[str] = None, target_binary: Optional[str] = None) -> str:
        if target_url:
            pov_script = pov_script.replace("{{target_url}}", target_url).replace("{target_url}", target_url)
            pov_script = re.sub(r"http://localhost:\d+", target_url, pov_script)
            pov_script = re.sub(r"http://127\.0\.0\.1:\d+", target_url, pov_script)
        if target_binary:
            pov_script = pov_script.replace("{{target_binary}}", target_binary).replace("{target_binary}", target_binary)
        return pov_script
    def _run_script(self, cwd: str, pov_filename: str, language: str, env: Dict[str, str]) -> Dict[str, Any]:
        command = ["python3", pov_filename] if language == "python" else ["node", pov_filename]
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=45, env=env)
            haystack = result.stdout + "\n" + result.stderr
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode, "vulnerability_triggered": "VULNERABILITY TRIGGERED" in haystack}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "PoV execution timed out", "exit_code": -1, "vulnerability_triggered": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "vulnerability_triggered": False}
    def _contract_indicators(self, exploit_contract: Optional[Dict[str, Any]]) -> list[str]:
        indicators = ["VULNERABILITY TRIGGERED"]
        contract = exploit_contract or {}
        indicators.extend(contract.get("success_indicators", []) or [])
        indicators.extend(contract.get("side_effects", []) or [])
        return [str(ind).strip() for ind in indicators if str(ind).strip()]
    def _native_triggered(self, stdout: str, stderr: str, exit_code: int, exploit_contract: Optional[Dict[str, Any]] = None) -> bool:
        haystack = (stdout + "\n" + stderr).lower()
        if any(ind.lower() in haystack for ind in self._contract_indicators(exploit_contract)):
            return True
        if any(pattern in haystack for pattern in self.NATIVE_CRASH_PATTERNS):
            return True
        return exit_code in {134, 139, -11, -6}
    def _run_binary(self, binary_path: str, args: Optional[list[str]] = None, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        try:
            result = subprocess.run([binary_path] + (args or []), capture_output=True, text=True, timeout=30, env=env)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "vulnerability_triggered": False,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Native harness timed out", "exit_code": -1, "vulnerability_triggered": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "vulnerability_triggered": False}
    def _is_binary_native_target(self, target_entrypoint: str, filepath: str = "") -> bool:
        candidate = str(target_entrypoint or "").strip().lower()
        stem = Path(filepath or "").stem.lower()
        if not candidate:
            return False
        if candidate in {"main", "mqjs", "qjs", "mquickjs", "example", "example_stdlib", "mqjs_stdlib"}:
            return True
        if stem and candidate == stem:
            return True
        return False
    def _script_uses_target_binary(self, pov_script: str) -> bool:
        script = str(pov_script or "")
        binary_markers = [
            "TARGET_BINARY",
            "TARGET_BIN",
            "MQJS_BIN",
            "subprocess.run([binary",
            "subprocess.run([binary,",
            "os.environ.get('MQJS_BIN')",
            "os.environ.get('TARGET_BINARY')",
            "os.environ.get('TARGET_BIN')",
        ]
        return any(marker in script for marker in binary_markers)
    def _build_runtime_evidence(self, result: Dict[str, Any], *, validation_method: str, target_binary: Optional[str] = None, target_url: Optional[str] = None) -> Dict[str, Any]:
        stdout = str(result.get("stdout", "") or "")
        stderr = str(result.get("stderr", "") or "")
        exit_code = result.get("exit_code", -1)
        combined = (stdout + "\n" + stderr).strip()
        summary = "Runtime harness executed"
        lowered = combined.lower()
        if 'addresssanitizer' in lowered:
            summary = 'AddressSanitizer reported memory corruption'
        elif 'undefinedbehaviorsanitizer' in lowered:
            summary = 'UndefinedBehaviorSanitizer reported unsafe behavior'
        elif 'assertion `' in lowered or 'assertion failed' in lowered:
            summary = 'Assertion failure observed in vulnerable path'
        elif 'segmentation fault' in lowered or exit_code in {-11, 139}:
            summary = 'Segmentation fault observed during exploit execution'
        elif exit_code in {-6, 134}:
            summary = 'Process aborted during exploit execution'
        elif 'vulnerability triggered' in lowered:
            summary = 'Exploit reported vulnerability triggered'
        excerpt = stderr or stdout
        excerpt = excerpt[:1200]
        return {
            'summary': summary,
            'validation_method': validation_method,
            'target_binary': target_binary,
            'target_url': target_url,
            'exit_code': exit_code,
            'stdout_excerpt': stdout[:1200],
            'stderr_excerpt': stderr[:1200],
            'combined_excerpt': excerpt,
        }
    def _build_targeted_native_harness(self, scan_id: str, cwe_type: str, vulnerable_code: str, exploit_contract: Optional[Dict[str, Any]], language: str) -> Dict[str, Any]:
        exploit_contract = exploit_contract or {}
        target_entrypoint = str(exploit_contract.get("target_entrypoint") or "")
        entry_name = ""
        if re.fullmatch(r"[A-Za-z_]\w*", target_entrypoint) and target_entrypoint.lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
            entry_name = target_entrypoint
        else:
            inferred = re.search(r"(?:static\s+)?(?:[\w\*\s]+)\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", vulnerable_code)
            if inferred and inferred.group(1).lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
                entry_name = inferred.group(1)
            else:
                backticked = re.search(r"`([A-Za-z_]\w*)\s*\(", target_entrypoint)
                if backticked and backticked.group(1).lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
                    entry_name = backticked.group(1)
                elif "main" in target_entrypoint.lower():
                    entry_name = "main"
        if not vulnerable_code.strip() or not entry_name or entry_name.lower() in self.INVALID_NATIVE_ENTRYPOINTS:
            return {"success": False, "error": "No compilable vulnerable snippet or target entrypoint for targeted native harness", "binary_path": None}
        sig_3 = re.search(rf"(?:static\s+)?(?:[\w\*\s]+)\b{re.escape(entry_name)}\s*\(\s*char\s*\*\s*\w+\s*,\s*size_t\s+\w+\s*,\s*const\s+char\s*\*\s*\w+\s*\)", vulnerable_code)
        sig_2 = re.search(rf"(?:static\s+)?(?:[\w\*\s]+)\b{re.escape(entry_name)}\s*\(\s*char\s*\*\s*\w+\s*,\s*const\s+char\s*\*\s*\w+\s*\)", vulnerable_code)
        if not sig_3 and not sig_2:
            return {"success": False, "error": f"No supported native harness signature detected for {entry_name}", "binary_path": None}
        compiler = "gcc" if language == "c" else "g++"
        if not shutil.which(compiler):
            return {"success": False, "error": f"{compiler} is not installed", "binary_path": None}
        temp_dir = tempfile.mkdtemp(prefix=f"autopov_native_harness_{scan_id}_")
        source_path = os.path.join(temp_dir, f"targeted_harness.{'c' if language == 'c' else 'cpp'}")
        binary_path = os.path.join(temp_dir, "targeted_harness")
        main_call = f'{entry_name}(buf, sizeof(buf), payload);' if sig_3 else f'{entry_name}(buf, payload);'
        harness = f"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
{vulnerable_code}
int main(void) {{
    struct {{
        char buf[16];
        unsigned char canary[16];
    }} frame;
    char payload[4096];
    memset(&frame, 0, sizeof(frame));
    memset(frame.canary, 0x5A, sizeof(frame.canary));
    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = 0;
    fprintf(stderr, "[AutoPoV] invoking {entry_name}\\n");
    {main_call.replace('buf', 'frame.buf')}
    for (size_t i = 0; i < sizeof(frame.canary); ++i) {{
        if (frame.canary[i] != 0x5A) {{
            fprintf(stdout, "VULNERABILITY TRIGGERED\\n");
            return 0;
        }}
    }}
    fprintf(stderr, "[AutoPoV] no canary overwrite observed\\n");
    return 2;
}}
"""
        Path(source_path).write_text(harness, encoding='utf-8')
        result = subprocess.run([
            compiler,
            source_path,
            '-O0',
            '-g',
            '-fsanitize=address,undefined',
            '-fno-omit-frame-pointer',
            '-o',
            binary_path,
        ], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"success": False, "error": result.stderr or result.stdout, "binary_path": None}
        return {"success": True, "error": None, "binary_path": binary_path, "build_method": "targeted_native_harness", "temp_dir": temp_dir}
    def test_pov_against_app(self, pov_script: str, scan_id: str, cwe_type: str, target_url: str, language: str = "python", exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        start_time = datetime.utcnow()
        temp_dir = tempfile.mkdtemp(prefix=f"pov_{scan_id}_")
        try:
            pov_filename = "pov.py" if language == "python" else "pov.js"
            patched = self._patch_target_refs(pov_script, target_url=target_url)
            with open(os.path.join(temp_dir, pov_filename), "w") as handle:
                handle.write(patched)
            env = os.environ.copy()
            env["TARGET_URL"] = target_url
            result = self._run_script(temp_dir, pov_filename, language, env)
            haystack = (result.get("stdout", "") + "\n" + result.get("stderr", "")).lower()
            triggered = any(ind.lower() in haystack for ind in self._contract_indicators(exploit_contract)) or bool(result.get("vulnerability_triggered"))
            end_time = datetime.utcnow()
            return {"success": True, "vulnerability_triggered": bool(triggered), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url, "validation_method": "script_against_live_app"}
        except Exception as e:
            end_time = datetime.utcnow()
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": str(e), "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    def test_pov_against_repo(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, language: str = "python", exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        start_time = datetime.utcnow()
        temp_dir = tempfile.mkdtemp(prefix=f"pov_repo_{scan_id}_")
        try:
            pov_filename = "pov.py" if language == "python" else "pov.js"
            pov_path = os.path.join(temp_dir, pov_filename)
            with open(pov_path, "w") as handle:
                handle.write(pov_script)
            env = os.environ.copy()
            env["CODEBASE_PATH"] = codebase_path
            env["TARGET_ENTRYPOINT"] = str((exploit_contract or {}).get("target_entrypoint") or "")
            if language == "python":
                env["PYTHONPATH"] = codebase_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
            else:
                env["NODE_PATH"] = codebase_path + (os.pathsep + env["NODE_PATH"] if env.get("NODE_PATH") else "")
            result = self._run_script(codebase_path, pov_path, language, env)
            haystack = (result.get("stdout", "") + "\n" + result.get("stderr", "")).lower()
            triggered = any(ind.lower() in haystack for ind in self._contract_indicators(exploit_contract)) or bool(result.get("vulnerability_triggered"))
            end_time = datetime.utcnow()
            return {"success": True, "vulnerability_triggered": bool(triggered), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "validation_method": "script_against_repo"}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    def test_binary_target(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, language: str, exploit_contract: Dict[str, Any], vulnerable_code: str = "", filepath: str = "") -> Dict[str, Any]:
        start_time = datetime.utcnow()
        build = get_app_runner().build_native_binary(scan_id, codebase_path, language=language)
        script_result = None
        target_entrypoint = str((exploit_contract or {}).get("target_entrypoint") or "")
        binary_target = self._is_binary_native_target(target_entrypoint, filepath) or self._script_uses_target_binary(pov_script)
        if build.get("success"):
            temp_dir = tempfile.mkdtemp(prefix=f"pov_native_{scan_id}_")
            try:
                script_language = "javascript" if "console.log" in pov_script or "require(" in pov_script else "python"
                pov_filename = "pov.js" if script_language == "javascript" else "pov.py"
                patched = self._patch_target_refs(pov_script, target_binary=build["binary_path"])
                with open(os.path.join(temp_dir, pov_filename), "w") as handle:
                    handle.write(patched)
                env = os.environ.copy()
                env["TARGET_BINARY"] = build["binary_path"]
                env["TARGET_BIN"] = build["binary_path"]
                env["MQJS_BIN"] = build["binary_path"]
                if exploit_contract.get("inputs"):
                    env["TARGET_INPUT"] = str(exploit_contract["inputs"][0])
                script_result = self._run_script(codebase_path, os.path.join(temp_dir, pov_filename), script_language, env)
                triggered = self._native_triggered(script_result.get("stdout", ""), script_result.get("stderr", ""), script_result.get("exit_code", -1), exploit_contract)
                evidence = self._build_runtime_evidence(script_result, validation_method="native_binary_harness", target_binary=build["binary_path"])
                if triggered:
                    end_time = datetime.utcnow()
                    return {"success": True, "vulnerability_triggered": True, "stdout": script_result.get("stdout", ""), "stderr": script_result.get("stderr", ""), "exit_code": script_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": build["binary_path"], "validation_method": "native_binary_harness", "proof_summary": evidence["summary"], "evidence": evidence}
                if binary_target:
                    end_time = datetime.utcnow()
                    return {"success": True, "vulnerability_triggered": False, "stdout": script_result.get("stdout", ""), "stderr": script_result.get("stderr", ""), "exit_code": script_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": build["binary_path"], "validation_method": "native_binary_harness", "proof_summary": evidence["summary"], "evidence": evidence}
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)
        targeted = self._build_targeted_native_harness(scan_id, cwe_type, vulnerable_code, exploit_contract, language)
        if targeted.get("success") and targeted.get("binary_path"):
            try:
                native_result = self._run_binary(targeted["binary_path"])
                triggered = self._native_triggered(native_result.get("stdout", ""), native_result.get("stderr", ""), native_result.get("exit_code", -1), exploit_contract)
                evidence = self._build_runtime_evidence(native_result, validation_method="targeted_native_sanitizer_harness", target_binary=targeted["binary_path"])
                end_time = datetime.utcnow()
                return {"success": True, "vulnerability_triggered": bool(triggered), "stdout": native_result.get("stdout", ""), "stderr": native_result.get("stderr", ""), "exit_code": native_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": targeted["binary_path"], "validation_method": "targeted_native_sanitizer_harness", "proof_summary": evidence["summary"], "evidence": evidence}
            finally:
                shutil.rmtree(targeted.get("temp_dir") or "", ignore_errors=True)
        end_time = datetime.utcnow()
        stderr = (script_result or {}).get("stderr") or targeted.get("error") or build.get("error", "Failed to build target binary")
        failure_result = {"stdout": (script_result or {}).get("stdout", ""), "stderr": stderr, "exit_code": (script_result or {}).get("exit_code", -1)}
        evidence = self._build_runtime_evidence(failure_result, validation_method="native_binary_build", target_binary=build.get("binary_path"))
        proof_infra = bool(build.get("proof_infrastructure_error")) or not build.get("success")
        return {"success": False, "vulnerability_triggered": False, "stdout": failure_result["stdout"], "stderr": stderr, "exit_code": failure_result["exit_code"], "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": datetime.utcnow().isoformat(), "validation_method": "native_binary_build", "proof_infrastructure_error": proof_infra, "proof_summary": evidence["summary"], "evidence": evidence}
    def test_with_contract(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], target_language: str = "python", vulnerable_code: str = "", filepath: str = "") -> Dict[str, Any]:
        exploit_contract = exploit_contract or {}
        runtime_profile = (exploit_contract.get("runtime_profile") or target_language or "python").lower()
        target_entrypoint = str(exploit_contract.get("target_entrypoint") or "")
        if runtime_profile in {"c", "cpp", "binary", "native"} or target_language in {"c", "cpp"}:
            native_language = "c" if target_language == "c" else "cpp"
            return self.test_binary_target(pov_script, scan_id, cwe_type, codebase_path, native_language, exploit_contract, vulnerable_code=vulnerable_code, filepath=filepath)
        if runtime_profile in {"web", "http", "browser"} or target_entrypoint.startswith("/") or target_entrypoint.startswith("http"):
            target_url = exploit_contract.get("target_url") or exploit_contract.get("base_url")
            if target_url:
                live = get_live_app_tester().test_against_live_app(pov_script, cwe_type, {"url": target_url, "method": exploit_contract.get("http_method", "GET")}, scan_id, exploit_contract=exploit_contract)
                return {"success": live.success, "vulnerability_triggered": live.vulnerability_triggered, "stdout": live.response_preview, "stderr": live.error or "", "exit_code": 0 if live.success else -1, "execution_time_s": live.response_time_ms / 1000.0, "timestamp": datetime.utcnow().isoformat(), "target_url": live.target_url, "evidence": live.evidence, "validation_method": "live_app_contract"}
            started = get_app_runner().start_application(scan_id, codebase_path, target_language if target_language in {"python", "javascript", "typescript"} else "javascript")
            if started.get("success"):
                try:
                    live = get_live_app_tester().test_against_live_app(pov_script, cwe_type, {"url": started["url"], "method": exploit_contract.get("http_method", "GET")}, scan_id, exploit_contract=exploit_contract)
                    return {"success": live.success, "vulnerability_triggered": live.vulnerability_triggered, "stdout": live.response_preview, "stderr": live.error or "", "exit_code": 0 if live.success else -1, "execution_time_s": live.response_time_ms / 1000.0, "timestamp": datetime.utcnow().isoformat(), "target_url": live.target_url, "evidence": live.evidence, "validation_method": "live_app_contract"}
                finally:
                    get_app_runner().stop_app(scan_id)
        if runtime_profile in {"python", "javascript", "node", "typescript"}:
            script_language = "javascript" if runtime_profile in {"javascript", "node", "typescript"} else "python"
            return self.test_pov_against_repo(pov_script, scan_id, cwe_type, codebase_path, language=script_language, exploit_contract=exploit_contract)
        script_language = "javascript" if runtime_profile in {"javascript", "node"} else "python"
        target_url = exploit_contract.get("target_url") or exploit_contract.get("base_url") or "http://localhost:3000"
        return self.test_pov_against_app(pov_script, scan_id, cwe_type, target_url, language=script_language, exploit_contract=exploit_contract)
pov_tester = PoVTester()
def get_pov_tester() -> PoVTester:
    """Get the global PoV tester instance"""
    return pov_tester
