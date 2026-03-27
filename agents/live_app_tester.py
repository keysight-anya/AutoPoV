"""
AutoPoV Live Application Testing Module
Tests PoV scripts against running web applications
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

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
    """Tests PoV scripts against live running web applications."""

    def __init__(self):
        self.running_containers = {}
        self.test_history = []

    def _coerce_contract_mapping(self, value: Any) -> Dict[str, str]:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items() if v not in (None, "")}
        return {}

    def _build_request_config(self, pov_script: str, target_config: Dict[str, Any], exploit_contract: Dict[str, Any]) -> Dict[str, Any]:
        config: Dict[str, Any] = {**target_config}
        route = str(exploit_contract.get("target_entrypoint") or target_config.get("path") or "")
        base_url = str(target_config.get("url", "") or "")
        if base_url and route and not route.startswith("http"):
            config["url"] = base_url.rstrip("/") + "/" + route.lstrip("/")
        elif route.startswith("http"):
            config["url"] = route

        method = str(exploit_contract.get("http_method") or target_config.get("method") or "GET").upper()
        headers = self._coerce_contract_mapping(exploit_contract.get("headers") or target_config.get("headers") or {})
        cookies = self._coerce_contract_mapping(exploit_contract.get("cookies") or target_config.get("cookies") or {})
        params = self._coerce_contract_mapping(exploit_contract.get("query_params") or target_config.get("query_params") or {})
        form_data = self._coerce_contract_mapping(exploit_contract.get("form_data") or target_config.get("form_data") or {})
        json_body = exploit_contract.get("json_body") if isinstance(exploit_contract.get("json_body"), dict) else None
        raw_body = exploit_contract.get("body") or target_config.get("body")
        param = str(target_config.get("param") or exploit_contract.get("param") or "input")
        payload = None

        inputs = exploit_contract.get("inputs") or []
        if inputs and isinstance(inputs[0], dict):
            first = inputs[0]
            payload = str(first.get("value") or first.get("payload") or first.get("body") or "")
            param = str(first.get("name") or param)
            headers.update(self._coerce_contract_mapping(first.get("headers") or {}))
            cookies.update(self._coerce_contract_mapping(first.get("cookies") or {}))
            if isinstance(first.get("params"), dict):
                params.update(self._coerce_contract_mapping(first.get("params") or {}))
            if isinstance(first.get("json"), dict):
                json_body = {str(k): v for k, v in first.get("json", {}).items()}
            if isinstance(first.get("form"), dict):
                form_data.update(self._coerce_contract_mapping(first.get("form") or {}))
            if first.get("body") and not raw_body:
                raw_body = str(first.get("body"))
        elif inputs:
            payload = str(inputs[0])

        if not payload:
            extracted = self._extract_exploit_config(pov_script)
            payload = extracted.get("payload")
            param = extracted.get("param", param)
            headers.update(extracted.get("headers", {}))
            method = extracted.get("method", method).upper()

        if payload and not json_body and not form_data and not raw_body:
            if method == "GET":
                params[param] = payload
            else:
                form_data[param] = payload

        config.update({
            "payload": payload,
            "param": param,
            "method": method,
            "headers": headers,
            "cookies": cookies,
            "params": params,
            "form_data": form_data,
            "json_body": json_body,
            "body": raw_body,
        })
        return config

    def _extract_exploit_config(self, pov_script: str) -> Dict[str, Any]:
        config: Dict[str, Any] = {"payload": None, "method": "GET", "param": "input", "headers": {}}
        payload_patterns = [
            r"payload\s*=\s*[\"']([^\"']+)[\"']",
            r"data\s*=\s*[\"']([^\"']+)[\"']",
            r"[\"']([^\"']*(?:script|alert|SELECT|UNION|etc/passwd|whoami|onerror=)[^\"']*)[\"']",
        ]
        for pattern in payload_patterns:
            match = re.search(pattern, pov_script, re.IGNORECASE)
            if match:
                config["payload"] = match.group(1)
                break
        if any(token in pov_script for token in ["requests.post", "fetch(", "axios.post", "method: 'POST'", 'method: "POST"']):
            config["method"] = "POST"
        for pattern in [r"[\"'](\w+)[\"']\s*:\s*[\"'][^\"']+[\"']", r"params\[['\"]?([A-Za-z0-9_]+)['\"]?\]", r"data\[['\"]?([A-Za-z0-9_]+)['\"]?\]"]:
            match = re.search(pattern, pov_script)
            if match:
                config["param"] = match.group(1)
                break
        for header_match in re.finditer(r"[\"']([A-Za-z0-9\-]+)[\"']\s*:\s*[\"']([^\"']+)[\"']", pov_script):
            header_name = header_match.group(1)
            header_value = header_match.group(2)
            if header_name.lower() in {"content-type", "authorization", "cookie", "x-csrf-token"}:
                config["headers"][header_name] = header_value
        return config

    def _send_exploit_request(self, config: Dict[str, Any]) -> Dict[str, Any]:
        url = config.get("url", "")
        method = str(config.get("method", "GET") or "GET").upper()
        headers = dict(config.get("headers") or {})
        cookies = dict(config.get("cookies") or {})
        params = dict(config.get("params") or {})
        form_data = dict(config.get("form_data") or {})
        json_body = config.get("json_body") if isinstance(config.get("json_body"), dict) else None
        raw_body = config.get("body")
        if not headers.get("User-Agent"):
            headers["User-Agent"] = "AutoPoV-Test/1.0"
        try:
            session = requests.Session()
            request_kwargs: Dict[str, Any] = {
                "params": params,
                "headers": headers,
                "cookies": cookies,
                "timeout": 10,
                "allow_redirects": True,
            }
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                if json_body is not None:
                    request_kwargs["json"] = json_body
                elif raw_body not in (None, ""):
                    request_kwargs["data"] = raw_body
                else:
                    request_kwargs["data"] = form_data
            response = session.request(method, url, **request_kwargs)
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
        if cwe_type == "CWE-79" and ("<script>" in response or "alert(" in response or "onerror=" in response_lower):
            evidence.append("XSS payload reflected in response without encoding")
            triggered = True
            confidence = "medium" if confidence == "low" else confidence
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

    def test_against_live_app(self, pov_script: str, cwe_type: str, target_config: Dict[str, Any], scan_id: str, exploit_contract: Optional[Dict[str, Any]] = None) -> LiveTestResult:
        start_time = datetime.utcnow()
        try:
            exploit_config = self._build_request_config(pov_script, target_config, exploit_contract or {})
            if not exploit_config.get("url"):
                return LiveTestResult(False, False, target_config.get("url", ""), 0, 0, "", [], "low", "Could not derive live exploit request target")
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

    def is_target_available(self, url: str) -> bool:
        try:
            response = requests.get(url, timeout=5)
            return response.status_code < 500
        except requests.RequestException:
            return False


live_app_tester = LiveAppTester()


def get_live_app_tester() -> LiveAppTester:
    return live_app_tester
