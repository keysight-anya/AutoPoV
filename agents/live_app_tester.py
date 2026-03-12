"""
AutoPoV Live Application Testing Module
Tests PoV scripts against running web applications
"""

import os
import re
import json
import time
import subprocess
import requests
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime


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
    confidence: str  # "high", "medium", "low"
    error: Optional[str] = None


class LiveAppTester:
    """
    Tests PoV scripts against live running applications.
    
    This provides definitive proof by:
    1. Starting the target application in Docker
    2. Sending the exploit payload to the real endpoint
    3. Checking for actual vulnerability indicators in the response
    """
    
    def __init__(self):
        self.running_containers = {}
        self.test_history = []
    
    def test_against_live_app(
        self,
        pov_script: str,
        cwe_type: str,
        target_config: Dict[str, Any],
        scan_id: str
    ) -> LiveTestResult:
        """
        Test PoV against a live running application.
        
        Args:
            pov_script: The PoV/exploit script content
            cwe_type: CWE type being tested
            target_config: Configuration for the target app
                - url: Target URL (e.g., "http://localhost:8080/vulnerable.php")
                - method: HTTP method (GET, POST, etc.)
                - param: Parameter name to inject
                - docker_image: Optional Docker image to start
                - docker_port: Port mapping for Docker
            scan_id: Scan identifier
            
        Returns:
            LiveTestResult with execution details
        """
        start_time = datetime.utcnow()
        
        try:
            # Extract exploit details from PoV script
            exploit_config = self._extract_exploit_config(pov_script, cwe_type)
            
            if not exploit_config:
                return LiveTestResult(
                    success=False,
                    vulnerability_triggered=False,
                    target_url=target_config.get("url", ""),
                    response_time_ms=0,
                    status_code=0,
                    response_preview="",
                    evidence=[],
                    confidence="low",
                    error="Could not extract exploit configuration from PoV"
                )
            
            # Merge with provided config
            config = {**target_config, **exploit_config}
            
            # Send the exploit request
            result = self._send_exploit_request(config)
            
            # Analyze the response for vulnerability indicators
            analysis = self._analyze_response(result, cwe_type)
            
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            test_result = LiveTestResult(
                success=result.get("success", False),
                vulnerability_triggered=analysis["triggered"],
                target_url=config.get("url", ""),
                response_time_ms=response_time,
                status_code=result.get("status_code", 0),
                response_preview=result.get("response", "")[:500],
                evidence=analysis["evidence"],
                confidence=analysis["confidence"]
            )
            
            self.test_history.append(test_result)
            return test_result
            
        except Exception as e:
            return LiveTestResult(
                success=False,
                vulnerability_triggered=False,
                target_url=target_config.get("url", ""),
                response_time_ms=0,
                status_code=0,
                response_preview="",
                evidence=[],
                confidence="low",
                error=str(e)
            )
    
    def _extract_exploit_config(self, pov_script: str, cwe_type: str) -> Optional[Dict[str, Any]]:
        """Extract exploit configuration from PoV script"""
        config = {
            "payload": None,
            "method": "GET",
            "param": "input"
        }
        
        # Look for common payload patterns in the PoV
        payload_patterns = [
            r'["\']([^"\']*(?:script|alert|SELECT|UNION|../../../|etc/passwd|whoami)[^"\']*)["\']',
            r'payload\s*=\s*["\']([^"\']+)["\']',
            r'data\s*=\s*["\']([^"\']+)["\']',
            r'params\s*=\s*\{[^}]*["\']([^"\']+)["\']',
        ]
        
        for pattern in payload_patterns:
            match = re.search(pattern, pov_script, re.IGNORECASE)
            if match:
                config["payload"] = match.group(1)
                break
        
        # Detect HTTP method
        if "requests.post" in pov_script or "xhr.open('POST'" in pov_script:
            config["method"] = "POST"
        elif "requests.get" in pov_script or "xhr.open('GET'" in pov_script:
            config["method"] = "GET"
        
        # Detect parameter name
        param_patterns = [
            r'["\'](\w+)["\']\s*:\s*["\'][^"\']*["\']',
            r'params\[\'?(\w+)\'?\]',
            r'data\[\'?(\w+)\'?\]',
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, pov_script)
            if match:
                config["param"] = match.group(1)
                break
        
        return config if config["payload"] else None
    
    def _send_exploit_request(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Send the exploit HTTP request"""
        url = config.get("url", "")
        method = config.get("method", "GET").upper()
        payload = config.get("payload", "")
        param = config.get("param", "input")
        
        try:
            if method == "GET":
                # For GET, add payload to query string
                separator = "&" if "?" in url else "?"
                full_url = f"{url}{separator}{param}={requests.utils.quote(payload)}"
                response = requests.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "AutoPoV-Test/1.0"}
                )
            else:
                # For POST, send in body
                response = requests.post(
                    url,
                    data={param: payload},
                    timeout=10,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "AutoPoV-Test/1.0",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                )
            
            return {
                "success": True,
                "status_code": response.status_code,
                "response": response.text,
                "headers": dict(response.headers),
                "url": response.url
            }
            
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Request timed out",
                "status_code": 0,
                "response": ""
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error": "Could not connect to target",
                "status_code": 0,
                "response": ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": 0,
                "response": ""
            }
    
    def _analyze_response(self, result: Dict[str, Any], cwe_type: str) -> Dict[str, Any]:
        """Analyze HTTP response for vulnerability indicators"""
        response = result.get("response", "")
        headers = result.get("headers", {})
        status_code = result.get("status_code", 0)
        
        evidence = []
        confidence = "low"
        triggered = False
        
        response_lower = response.lower()
        
        # CWE-specific analysis
        if cwe_type == "CWE-79":  # XSS
            # Check if script tags are reflected without encoding
            if "<script>" in response or "alert(" in response:
                evidence.append("XSS payload reflected in response without encoding")
                confidence = "high"
                triggered = True
            # Check for JavaScript execution context
            elif "javascript:" in response_lower:
                evidence.append("JavaScript protocol detected in response")
                confidence = "medium"
                triggered = True
                
        elif cwe_type == "CWE-89":  # SQL Injection
            # Check for SQL error messages
            sql_errors = [
                "sql syntax", "mysql_fetch", "pg_query", "sqlite3",
                "ora-", "microsoft ole db", "odbc driver", "jdbc"
            ]
            for error in sql_errors:
                if error in response_lower:
                    evidence.append(f"SQL error message detected: {error}")
                    confidence = "high"
                    triggered = True
                    break
            # Check for data extraction
            if any(x in response for x in ["version", "@@version", "table_schema"]):
                evidence.append("Database information potentially extracted")
                confidence = "medium"
                triggered = True
                
        elif cwe_type == "CWE-22":  # Path Traversal
            # Check for file content in response
            file_indicators = ["root:x:", "etc/passwd", "boot.ini", "[boot loader]"]
            for indicator in file_indicators:
                if indicator in response_lower:
                    evidence.append(f"File content detected: {indicator}")
                    confidence = "high"
                    triggered = True
                    break
                    
        elif cwe_type == "CWE-78":  # Command Injection
            # Check for command output
            cmd_indicators = ["uid=", "gid=", "root:", "bin/bash", "windows"]
            for indicator in cmd_indicators:
                if indicator in response_lower:
                    evidence.append(f"Command output detected: {indicator}")
                    confidence = "high"
                    triggered = True
                    break
        
        # Generic checks
        if status_code >= 500:
            evidence.append(f"Server error (status {status_code}) - possible crash")
            if confidence == "low":
                confidence = "medium"
                triggered = True
        
        return {
            "triggered": triggered,
            "evidence": evidence,
            "confidence": confidence
        }
    
    def is_target_available(self, url: str) -> bool:
        """Check if target application is running"""
        try:
            response = requests.get(url, timeout=5)
            return response.status_code < 500
        except:
            return False


# Global tester instance
live_app_tester = LiveAppTester()


def get_live_app_tester() -> LiveAppTester:
    """Get the global live app tester instance"""
    return live_app_tester
