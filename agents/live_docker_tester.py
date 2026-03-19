"""
AutoPoV Live Docker Application Testing Module
Starts target applications in Docker and performs live testing with screenshots
"""

import os
import time
import base64
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


@dataclass
class LiveTestResult:
    success: bool
    vulnerability_triggered: bool
    target_url: str
    container_id: Optional[str]
    response_time_ms: float
    status_code: int
    response_preview: str
    screenshot_path: Optional[str]
    screenshot_base64: Optional[str]
    evidence: List[str]
    confidence: str
    error: Optional[str] = None


class LiveDockerTester:
    VULNERABLE_APP_IMAGES = {
        "dvwa": {"image": "vulnerables/web-dvwa", "port": 80, "env": {"MYSQL_PASS": "dvwa", "MYSQL_USER": "dvwa", "MYSQL_DB": "dvwa"}, "startup_time": 10, "health_check_path": "/login.php"},
        "juice-shop": {"image": "bkimminich/juice-shop", "port": 3000, "env": {}, "startup_time": 5, "health_check_path": "/"},
        "webgoat": {"image": "webgoat/webgoat", "port": 8080, "env": {"WEBGOAT_PORT": "8080"}, "startup_time": 15, "health_check_path": "/WebGoat"},
        "nodegoat": {"image": "nodegoat/nodegoat", "port": 4000, "env": {}, "startup_time": 10, "health_check_path": "/"},
    }

    def __init__(self):
        self._client = None
        self.running_containers = {}
        self.test_history = []

    def _get_client(self):
        if not DOCKER_AVAILABLE:
            raise Exception("docker-py not available. Install docker")
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def is_available(self) -> bool:
        if not DOCKER_AVAILABLE:
            return False
        try:
            self._get_client().ping()
            return True
        except Exception:
            return False

    def start_target_app(self, app_name: str, scan_id: str, custom_image: Optional[str] = None, custom_port: Optional[int] = None, health_path: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
        if not self.is_available():
            return False, "", None
        client = self._get_client()
        if custom_image:
            app_config = {"image": custom_image, "port": custom_port or 80, "env": {}, "startup_time": 10, "health_check_path": health_path or "/"}
        else:
            app_config = self.VULNERABLE_APP_IMAGES.get(app_name)
            if not app_config:
                return False, "", None
            if health_path:
                app_config = {**app_config, "health_check_path": health_path}
        try:
            try:
                client.images.get(app_config["image"])
            except ImageNotFound:
                client.images.pull(app_config["image"])
            host_port = self._find_free_port()
            container_name = f"autopov_target_{scan_id}_{app_name}"
            try:
                old_container = client.containers.get(container_name)
                old_container.stop(timeout=5)
                old_container.remove(force=True)
            except Exception:
                pass
            container = client.containers.run(image=app_config["image"], name=container_name, detach=True, ports={f"{app_config['port']}/tcp": host_port}, environment=app_config.get("env", {}), remove=True)
            time.sleep(app_config.get("startup_time", 10))
            target_url = f"http://localhost:{host_port}"
            if self._wait_for_app(target_url + app_config.get("health_check_path", "/"), timeout=30):
                self.running_containers[scan_id] = {"container_id": container.id, "target_url": target_url, "app_name": app_name, "host_port": host_port}
                return True, target_url, container.id
            container.stop(timeout=5)
            return False, "", None
        except Exception:
            return False, "", None

    def _find_free_port(self) -> int:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("", 0))
            sock.listen(1)
            return sock.getsockname()[1]

    def _wait_for_app(self, url: str, timeout: int = 30) -> bool:
        import requests
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 500:
                    return True
            except requests.RequestException:
                pass
            time.sleep(1)
        return False

    def test_vulnerability(self, scan_id: str, cwe_type: str, target_url: str, exploit_payload: str, target_param: str = "input", http_method: str = "GET", screenshot: bool = True, exploit_contract: Optional[Dict[str, Any]] = None) -> LiveTestResult:
        import requests
        start_time = datetime.utcnow()
        evidence: List[str] = []
        screenshot_path = None
        screenshot_base64 = None
        try:
            request_path = (exploit_contract or {}).get("target_entrypoint") or ""
            if request_path and not request_path.startswith("http"):
                target_url = target_url.rstrip("/") + "/" + request_path.lstrip("/")
            if http_method.upper() == "GET":
                separator = "&" if "?" in target_url else "?"
                full_url = f"{target_url}{separator}{target_param}={requests.utils.quote(exploit_payload)}"
                response = requests.get(full_url, timeout=10, allow_redirects=True, headers={"User-Agent": "AutoPoV-LiveTest/1.0"})
            else:
                full_url = target_url
                response = requests.post(target_url, data={target_param: exploit_payload}, timeout=10, allow_redirects=True, headers={"User-Agent": "AutoPoV-LiveTest/1.0", "Content-Type": "application/x-www-form-urlencoded"})
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            analysis = self._analyze_response(response, cwe_type, exploit_contract or {})
            if screenshot and PLAYWRIGHT_AVAILABLE:
                try:
                    screenshot_path, screenshot_base64 = self._capture_screenshot(full_url)
                    evidence.append(f"Screenshot captured: {screenshot_path}")
                except Exception as e:
                    evidence.append(f"Screenshot failed: {str(e)}")
            confidence = "low"
            if analysis["triggered"]:
                confidence = "high" if len(analysis["evidence"]) >= 2 else "medium"
            result = LiveTestResult(True, analysis["triggered"], target_url, self.running_containers.get(scan_id, {}).get("container_id"), response_time, response.status_code, response.text[:500], screenshot_path, screenshot_base64, analysis["evidence"] + evidence, confidence)
            self.test_history.append(result)
            return result
        except requests.exceptions.Timeout:
            return LiveTestResult(False, False, target_url, self.running_containers.get(scan_id, {}).get("container_id"), 0, 0, "", None, None, ["Request timed out"], "low", "Request timeout")
        except Exception as e:
            return LiveTestResult(False, False, target_url, self.running_containers.get(scan_id, {}).get("container_id"), 0, 0, "", None, None, [], "low", str(e))

    def _analyze_response(self, response, cwe_type: str, exploit_contract: Dict[str, Any]) -> Dict[str, Any]:
        response_text = response.text
        response_lower = response_text.lower()
        evidence: List[str] = []
        triggered = False
        for indicator in exploit_contract.get("success_indicators", []) or []:
            if str(indicator).strip() and str(indicator).lower() in response_lower:
                evidence.append(f"Success indicator observed: {indicator}")
                triggered = True
        for effect in exploit_contract.get("side_effects", []) or []:
            if str(effect).strip() and str(effect).lower() in response_lower:
                evidence.append(f"Expected side effect observed: {effect}")
                triggered = True
        if cwe_type == "CWE-79" and ("<script>" in response_text or "alert(" in response_text):
            evidence.append("XSS payload reflected in response")
            triggered = True
        elif cwe_type == "CWE-89":
            for error in ["sql syntax", "mysql_fetch", "pg_query", "sqlite3", "ora-", "microsoft ole db", "odbc driver"]:
                if error in response_lower:
                    evidence.append(f"SQL error detected: {error}")
                    triggered = True
                    break
        elif cwe_type == "CWE-22":
            for indicator in ["root:x:", "etc/passwd", "boot.ini", "[boot loader]"]:
                if indicator in response_lower:
                    evidence.append(f"File content detected: {indicator}")
                    triggered = True
                    break
        elif cwe_type == "CWE-78":
            for indicator in ["uid=", "gid=", "root:", "bin/bash", "windows"]:
                if indicator in response_lower:
                    evidence.append(f"Command output detected: {indicator}")
                    triggered = True
                    break
        if response.status_code >= 500:
            evidence.append(f"Server error (status {response.status_code})")
            triggered = True
        return {"triggered": triggered, "evidence": evidence}

    def _capture_screenshot(self, url: str) -> Tuple[str, str]:
        if not PLAYWRIGHT_AVAILABLE:
            return None, None
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=10000)
            from app.config import settings
            screenshot_dir = os.path.join(settings.RESULTS_DIR, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            screenshot_path = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
            page.screenshot(path=screenshot_path, full_page=True)
            browser.close()
            with open(screenshot_path, "rb") as handle:
                screenshot_base64 = base64.b64encode(handle.read()).decode("utf-8")
            return screenshot_path, screenshot_base64

    def stop_target_app(self, scan_id: str) -> bool:
        if scan_id not in self.running_containers:
            return False
        container_id = self.running_containers[scan_id].get("container_id")
        if not container_id:
            return False
        try:
            container = self._get_client().containers.get(container_id)
            container.stop(timeout=5)
            del self.running_containers[scan_id]
            return True
        except Exception:
            return False


live_docker_tester = LiveDockerTester()


def get_live_docker_tester() -> LiveDockerTester:
    return live_docker_tester
