"""
AutoPoV PoV Tester Module
Tests PoV scripts against running applications and native targets
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, Optional, Any
from datetime import datetime

from agents.app_runner import get_app_runner
from agents.live_app_tester import get_live_app_tester


class PoVTesterError(Exception):
    """Exception raised during PoV testing"""
    pass


class PoVTester:
    """Tests PoV scripts against running applications and binaries"""

    def _patch_target_refs(self, pov_script: str, target_url: Optional[str] = None, target_binary: Optional[str] = None) -> str:
        if target_url:
            pov_script = pov_script.replace("{{target_url}}", target_url).replace("{target_url}", target_url)
            pov_script = re.sub(r"http://localhost:\d+", target_url, pov_script)
            pov_script = re.sub(r"http://127\.0\.0\.1:\d+", target_url, pov_script)
        if target_binary:
            pov_script = pov_script.replace("{{target_binary}}", target_binary).replace("{target_binary}", target_binary)
        return pov_script

    def _run_script(self, temp_dir: str, pov_filename: str, language: str, env: Dict[str, str]) -> Dict[str, Any]:
        command = ["python3", pov_filename] if language == "python" else ["node", pov_filename]
        try:
            result = subprocess.run(command, cwd=temp_dir, capture_output=True, text=True, timeout=30, env=env)
            haystack = result.stdout + "\n" + result.stderr
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode, "vulnerability_triggered": "VULNERABILITY TRIGGERED" in haystack}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "PoV execution timed out", "exit_code": -1, "vulnerability_triggered": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "vulnerability_triggered": False}

    def test_pov_against_app(self, pov_script: str, scan_id: str, cwe_type: str, target_url: str, language: str = "python") -> Dict[str, Any]:
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
            end_time = datetime.utcnow()
            return {"success": True, "vulnerability_triggered": bool(result.get("vulnerability_triggered")), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url, "validation_method": "script_against_live_app"}
        except Exception as e:
            end_time = datetime.utcnow()
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": str(e), "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_binary_target(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, language: str, exploit_contract: Dict[str, Any]) -> Dict[str, Any]:
        start_time = datetime.utcnow()
        build = get_app_runner().build_native_binary(scan_id, codebase_path, language=language)
        if not build.get("success"):
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": build.get("error", "Failed to build target binary"), "exit_code": -1, "execution_time_s": 0, "timestamp": datetime.utcnow().isoformat(), "validation_method": "native_binary_build"}
        temp_dir = tempfile.mkdtemp(prefix=f"pov_native_{scan_id}_")
        try:
            script_language = "javascript" if "console.log" in pov_script or "require(" in pov_script else "python"
            pov_filename = "pov.js" if script_language == "javascript" else "pov.py"
            patched = self._patch_target_refs(pov_script, target_binary=build["binary_path"])
            with open(os.path.join(temp_dir, pov_filename), "w") as handle:
                handle.write(patched)
            env = os.environ.copy()
            env["TARGET_BINARY"] = build["binary_path"]
            if exploit_contract.get("inputs"):
                env["TARGET_INPUT"] = str(exploit_contract["inputs"][0])
            result = self._run_script(temp_dir, pov_filename, script_language, env)
            indicators = ["VULNERABILITY TRIGGERED"]
            indicators.extend(exploit_contract.get("success_indicators", []) or [])
            indicators.extend(exploit_contract.get("side_effects", []) or [])
            haystack = (result.get("stdout", "") + "\n" + result.get("stderr", "")).lower()
            triggered = any(str(ind).strip().lower() in haystack for ind in indicators if str(ind).strip()) or result.get("vulnerability_triggered", False)
            end_time = datetime.utcnow()
            return {"success": True, "vulnerability_triggered": bool(triggered), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": build["binary_path"], "validation_method": "native_binary_harness"}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_with_contract(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], target_language: str = "python") -> Dict[str, Any]:
        exploit_contract = exploit_contract or {}
        runtime_profile = (exploit_contract.get("runtime_profile") or target_language or "python").lower()
        target_entrypoint = str(exploit_contract.get("target_entrypoint") or "")

        if runtime_profile in {"c", "cpp", "binary", "native"} or target_language in {"c", "cpp"}:
            native_language = "c" if target_language == "c" else "cpp"
            return self.test_binary_target(pov_script, scan_id, cwe_type, codebase_path, native_language, exploit_contract)

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

        script_language = "javascript" if runtime_profile in {"javascript", "node"} else "python"
        target_url = exploit_contract.get("target_url") or exploit_contract.get("base_url") or "http://localhost:3000"
        return self.test_pov_against_app(pov_script, scan_id, cwe_type, target_url, language=script_language)


pov_tester = PoVTester()


def get_pov_tester() -> PoVTester:
    """Get the global PoV tester instance"""
    return pov_tester
