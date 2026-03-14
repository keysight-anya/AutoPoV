"""
AutoPoV Live Application Testing Module
Tests PoV scripts against running web applications
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

import requests


@dataclass
class LiveTestResult:
    """Result of live application testing"""
    success: bool
    vulnerability_triggered: bool
    target_url: str
    response_time_ms: float
    status_code: int
    response_preview: str
    evidence: List[str]
    confidence: str
    error: Optional[str] = None


class LiveAppTester:
    """Tests PoV scripts against live running applications."""

    def __init__(self):
        self.running_containers = {}
        self.test_history = []

    def test_against_live_app(self, pov_script: str, cwe_type: str, target_config: Dict[str, Any], scan_id: str, exploit_contract: Optional[Dict[str, Any]] = None) -> LiveTestResult:
        start_time = datetime.utcnow()
        try:
            exploit_config = self._build_request_config(pov_script, target_config, exploit_contract or {})
            if not exploit_config.get("url") or not exploit_config.get("payload"):
                return LiveTestResult(False, False, target_config.get("url", ""), 0, 0, "", [], "low", "Could not derive live exploit request from exploit contract or PoV")
            result = self._send_exploit_request(exploit_config)
            analysis = self._analyze_response(result, cwe_type, exploit_contract or {})
            end_time = datetime.utcnow()
            test_result = LiveTestResult(
                success=result.get("success", False),
                vulnerability_triggered=analysis["triggered"],
                target_url=exploit_config.get("url", ""),
                response_time_ms=(end_time - start_time).total_seconds() * 1000,
                status_code=result.get("status_code", 0),
                response_preview=result.get("response", "")[:500],
                evidence=analysis["evidence"],
                confidence=analysis["confidence"],
                error=result.get("error"),
            )
            self.test_history.append(test_result)
            return test_result
        except Exception as e:
            return LiveTestResult(False, False, target_config.get("url", ""), 0, 0, "", [], "low", str(e))

    def _build_request_config(self, pov_script: str, target_config: Dict[str, Any], exploit_contract: Dict[str, Any]) -> Dict[str, Any]:
        config = {**target_config}
        route = exploit_contract.get("target_entrypoint") or target_config.get("path") or ""
        base_url = target_config.get("url", "")
        if base_url and route and not route.startswith("http"):
            config["url"] = base_url.rstrip("/") + "/" + route.lstrip("/")
        elif route.startswith("http"):
            config["url"] = route

        inputs = exploit_contract.get("inputs") or []
        payload = None
        param = target_config.get("param") or "input"
        if inputs and isinstance(inputs[0], dict):
            payload = str(inputs[0].get("value") or inputs[0].get("payload") or "")
            param = str(inputs[0].get("name") or param)
        elif inputs:
            payload = str(inputs[0])

        if not payload:
            extracted = self._extract_exploit_config(pov_script)
            payload = extracted.get("payload")
            param = extracted.get("param", param)
            config.setdefault("method", extracted.get("method", "GET"))

        config["payload"] = payload
        config["param"] = param
        config["method"] = (exploit_contract.get("http_method") or target_config.get("method") or config.get("method") or "GET").upper()
        return config

    def _extract_exploit_config(self, pov_script: str) -> Dict[str, Any]:
        config = {"payload": None, "method": "GET", "param": "input"}
        for pattern in [r"[\"']([^\"']*(?:script|alert|SELECT|UNION|\.\./\.\./\.\./|etc/passwd|whoami)[^\"']*)[\"']", r"payload\s*=\s*[\"']([^\"']+)[\"']", r"data\s*=\s*[\"']([^\"']+)[\"']"]:
            match = re.search(pattern, pov_script, re.IGNORECASE)
            if match:
                config["payload"] = match.group(1)
                break
        if "requests.post" in pov_script or "fetch(" in pov_script:
            config["method"] = "POST"
        for pattern in [r"[\"'](\w+)[\"']\s*:\s*[\"'][^\"']+[\"']", r"params\['?([A-Za-z0-9_]+)'?\]", r"data\['?([A-Za-z0-9_]+)'?\]"]:
            match = re.search(pattern, pov_script)
            if match:
                config["param"] = match.group(1)
                break
        return config

    def _send_exploit_request(self, config: Dict[str, Any]) -> Dict[str, Any]:
        url = config.get("url", "")
        method = config.get("method", "GET").upper()
        payload = config.get("payload", "")
        param = config.get("param", "input")
        try:
            if method == "GET":
                separator = "&" if "?" in url else "?"
                full_url = f"{url}{separator}{param}={requests.utils.quote(payload)}"
                response = requests.get(full_url, timeout=10, allow_redirects=True, headers={"User-Agent": "AutoPoV-Test/1.0"})
            else:
                response = requests.post(url, data={param: payload}, timeout=10, allow_redirects=True, headers={"User-Agent": "AutoPoV-Test/1.0", "Content-Type": "application/x-www-form-urlencoded"})
            return {"success": True, "status_code": response.status_code, "response": response.text, "headers": dict(response.headers), "url": response.url}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timed out", "status_code": 0, "response": ""}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Could not connect to target", "status_code": 0, "response": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "status_code": 0, "response": ""}

    def _analyze_response(self, result: Dict[str, Any], cwe_type: str, exploit_contract: Dict[str, Any]) -> Dict[str, Any]:
        response = result.get("response", "")
        status_code = result.get("status_code", 0)
        response_lower = response.lower()
        evidence: List[str] = []
        triggered = False
        confidence = "low"

        for indicator in exploit_contract.get("success_indicators", []) or []:
            if str(indicator).strip() and str(indicator).lower() in response_lower:
                evidence.append(f"Success indicator observed: {indicator}")
                triggered = True
                confidence = "high"
        for effect in exploit_contract.get("side_effects", []) or []:
            if str(effect).strip() and str(effect).lower() in response_lower:
                evidence.append(f"Expected side effect observed: {effect}")
                triggered = True
                confidence = "high"

        if cwe_type == "CWE-79" and ("<script>" in response or "alert(" in response):
            evidence.append("XSS payload reflected in response without encoding")
            triggered = True
            if confidence == "low":
                confidence = "medium"
        elif cwe_type == "CWE-89":
            for error in ["sql syntax", "mysql_fetch", "pg_query", "sqlite3", "ora-", "odbc driver", "jdbc"]:
                if error in response_lower:
                    evidence.append(f"SQL error message detected: {error}")
                    triggered = True
                    confidence = "high"
                    break
        elif cwe_type == "CWE-22":
            for indicator in ["root:x:", "etc/passwd", "boot.ini", "[boot loader]"]:
                if indicator in response_lower:
                    evidence.append(f"File content detected: {indicator}")
                    triggered = True
                    confidence = "high"
                    break
        elif cwe_type == "CWE-78":
            for indicator in ["uid=", "gid=", "root:", "bin/bash", "windows"]:
                if indicator in response_lower:
                    evidence.append(f"Command output detected: {indicator}")
                    triggered = True
                    confidence = "high"
                    break

        if status_code >= 500:
            evidence.append(f"Server error (status {status_code}) - possible crash")
            triggered = True
            if confidence == "low":
                confidence = "medium"

        return {"triggered": triggered, "evidence": evidence, "confidence": confidence}

    def is_target_available(self, url: str) -> bool:
        try:
            response = requests.get(url, timeout=5)
            return response.status_code < 500
        except requests.RequestException:
            return False


live_app_tester = LiveAppTester()


def get_live_app_tester() -> LiveAppTester:
    """Get the global live app tester instance"""
    return live_app_tester
