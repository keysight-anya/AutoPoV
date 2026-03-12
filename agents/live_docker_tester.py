"""
AutoPoV Live Docker Application Testing Module
Starts target applications in Docker and performs live testing with screenshots
"""

import os
import re
import json
import time
import base64
import tempfile
import subprocess
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

# Try to import playwright for screenshots
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Try to import docker
try:
    import docker
    from docker.errors import DockerException, ContainerError, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


@dataclass
class LiveTestResult:
    """Result of live Docker application testing"""
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
    """
    Tests vulnerabilities against live applications running in Docker.
    
    This provides definitive proof by:
    1. Starting the target application in a Docker container
    2. Waiting for the application to be ready
    3. Sending exploit payloads via HTTP requests
    4. Capturing screenshots of the results
    5. Analyzing responses for vulnerability indicators
    """
    
    # Known vulnerable app Docker images
    VULNERABLE_APP_IMAGES = {
        "dvwa": {
            "image": "vulnerables/web-dvwa",
            "port": 80,
            "env": {"MYSQL_PASS": "dvwa", "MYSQL_USER": "dvwa", "MYSQL_DB": "dvwa"},
            "startup_time": 10,
            "health_check_path": "/login.php"
        },
        "juice-shop": {
            "image": "bkimminich/juice-shop",
            "port": 3000,
            "env": {},
            "startup_time": 5,
            "health_check_path": "/"
        },
        "webgoat": {
            "image": "webgoat/webgoat",
            "port": 8080,
            "env": {"WEBGOAT_PORT": "8080"},
            "startup_time": 15,
            "health_check_path": "/WebGoat"
        },
        "nodegoat": {
            "image": "nodegoat/nodegoat",
            "port": 4000,
            "env": {},
            "startup_time": 10,
            "health_check_path": "/"
        }
    }
    
    def __init__(self):
        self._client = None
        self.running_containers = {}
        self.test_history = []
    
    def _get_client(self):
        """Get Docker client"""
        if not DOCKER_AVAILABLE:
            raise Exception("docker-py not available. Install docker")
        
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as e:
                raise Exception(f"Could not connect to Docker: {e}")
        
        return self._client
    
    def is_available(self) -> bool:
        """Check if Docker is available"""
        if not DOCKER_AVAILABLE:
            return False
        
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception:
            return False
    
    def start_target_app(
        self,
        app_name: str,
        scan_id: str,
        custom_image: Optional[str] = None,
        custom_port: Optional[int] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Start a target application in Docker.
        
        Args:
            app_name: Name of the vulnerable app (dvwa, juice-shop, etc.)
            scan_id: Scan identifier for container naming
            custom_image: Optional custom Docker image
            custom_port: Optional custom port
            
        Returns:
            (success, target_url, container_id)
        """
        if not self.is_available():
            return False, "", None
        
        client = self._get_client()
        
        # Get app configuration
        if custom_image:
            app_config = {
                "image": custom_image,
                "port": custom_port or 80,
                "env": {},
                "startup_time": 10,
                "health_check_path": "/"
            }
        else:
            app_config = self.VULNERABLE_APP_IMAGES.get(app_name)
            if not app_config:
                return False, "", None
        
        try:
            # Check if image exists, pull if needed
            try:
                client.images.get(app_config["image"])
            except ImageNotFound:
                print(f"[LiveDockerTester] Pulling image {app_config['image']}...")
                client.images.pull(app_config["image"])
            
            # Find available host port
            host_port = self._find_free_port()
            
            # Create container
            container_name = f"autopov_target_{scan_id}_{app_name}"
            
            # Stop existing container with same name
            try:
                old_container = client.containers.get(container_name)
                old_container.stop(timeout=5)
                old_container.remove(force=True)
            except:
                pass
            
            # Run new container
            container = client.containers.run(
                image=app_config["image"],
                name=container_name,
                detach=True,
                ports={f"{app_config['port']}/tcp": host_port},
                environment=app_config.get("env", {}),
                remove=True,
                stdout=True,
                stderr=True
            )
            
            # Wait for startup
            startup_time = app_config.get("startup_time", 10)
            print(f"[LiveDockerTester] Waiting {startup_time}s for app to start...")
            time.sleep(startup_time)
            
            # Wait for health check
            target_url = f"http://localhost:{host_port}"
            health_path = app_config.get("health_check_path", "/")
            
            if self._wait_for_app(target_url + health_path, timeout=30):
                self.running_containers[scan_id] = {
                    "container_id": container.id,
                    "target_url": target_url,
                    "app_name": app_name,
                    "host_port": host_port
                }
                return True, target_url, container.id
            else:
                container.stop(timeout=5)
                return False, "", None
                
        except Exception as e:
            print(f"[LiveDockerTester] Error starting app: {e}")
            return False, "", None
    
    def _find_free_port(self) -> int:
        """Find a free port on the host"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def _wait_for_app(self, url: str, timeout: int = 30) -> bool:
        """Wait for application to be ready"""
        import requests
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 500:
                    return True
            except:
                pass
            time.sleep(1)
        
        return False
    
    def test_vulnerability(
        self,
        scan_id: str,
        cwe_type: str,
        target_url: str,
        exploit_payload: str,
        target_param: str = "input",
        http_method: str = "GET",
        screenshot: bool = True
    ) -> LiveTestResult:
        """
        Test a vulnerability against a live application.
        
        Args:
            scan_id: Scan identifier
            cwe_type: CWE type being tested
            target_url: Full URL to vulnerable endpoint
            exploit_payload: The exploit payload
            target_param: Parameter name to inject
            http_method: HTTP method (GET or POST)
            screenshot: Whether to capture screenshot
            
        Returns:
            LiveTestResult with execution details and screenshot
        """
        import requests
        
        start_time = datetime.utcnow()
        evidence = []
        screenshot_path = None
        screenshot_base64 = None
        
        try:
            # Send exploit request
            if http_method.upper() == "GET":
                separator = "&" if "?" in target_url else "?"
                full_url = f"{target_url}{separator}{target_param}={requests.utils.quote(exploit_payload)}"
                response = requests.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "AutoPoV-LiveTest/1.0"}
                )
            else:
                response = requests.post(
                    target_url,
                    data={target_param: exploit_payload},
                    timeout=10,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "AutoPoV-LiveTest/1.0",
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                )
            
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            # Analyze response
            analysis = self._analyze_response(response, cwe_type)
            
            # Capture screenshot if available and requested
            if screenshot and PLAYWRIGHT_AVAILABLE:
                try:
                    screenshot_path, screenshot_base64 = self._capture_screenshot(
                        target_url if http_method.upper() == "POST" else full_url
                    )
                    evidence.append(f"Screenshot captured: {screenshot_path}")
                except Exception as e:
                    evidence.append(f"Screenshot failed: {str(e)}")
            
            # Determine confidence
            confidence = "low"
            if analysis["triggered"]:
                if len(analysis["evidence"]) >= 2:
                    confidence = "high"
                else:
                    confidence = "medium"
            
            result = LiveTestResult(
                success=True,
                vulnerability_triggered=analysis["triggered"],
                target_url=target_url,
                container_id=self.running_containers.get(scan_id, {}).get("container_id"),
                response_time_ms=response_time,
                status_code=response.status_code,
                response_preview=response.text[:500],
                screenshot_path=screenshot_path,
                screenshot_base64=screenshot_base64,
                evidence=analysis["evidence"] + evidence,
                confidence=confidence
            )
            
            self.test_history.append(result)
            return result
            
        except requests.exceptions.Timeout:
            return LiveTestResult(
                success=False,
                vulnerability_triggered=False,
                target_url=target_url,
                container_id=self.running_containers.get(scan_id, {}).get("container_id"),
                response_time_ms=0,
                status_code=0,
                response_preview="",
                screenshot_path=None,
                screenshot_base64=None,
                evidence=["Request timed out"],
                confidence="low",
                error="Request timeout"
            )
        except Exception as e:
            return LiveTestResult(
                success=False,
                vulnerability_triggered=False,
                target_url=target_url,
                container_id=self.running_containers.get(scan_id, {}).get("container_id"),
                response_time_ms=0,
                status_code=0,
                response_preview="",
                screenshot_path=None,
                screenshot_base64=None,
                evidence=[],
                confidence="low",
                error=str(e)
            )
    
    def _analyze_response(self, response, cwe_type: str) -> Dict[str, Any]:
        """Analyze HTTP response for vulnerability indicators"""
        response_text = response.text
        response_lower = response_text.lower()
        evidence = []
        triggered = False
        
        # CWE-specific analysis
        if cwe_type == "CWE-79":  # XSS
            if "<script>" in response_text or "alert(" in response_text:
                evidence.append("XSS payload reflected in response")
                triggered = True
            elif "javascript:" in response_lower:
                evidence.append("JavaScript protocol detected")
                triggered = True
                
        elif cwe_type == "CWE-89":  # SQL Injection
            sql_errors = [
                "sql syntax", "mysql_fetch", "pg_query", "sqlite3",
                "ora-", "microsoft ole db", "odbc driver"
            ]
            for error in sql_errors:
                if error in response_lower:
                    evidence.append(f"SQL error detected: {error}")
                    triggered = True
                    break
                    
        elif cwe_type == "CWE-22":  # Path Traversal
            file_indicators = ["root:x:", "etc/passwd", "boot.ini", "[boot loader]"]
            for indicator in file_indicators:
                if indicator in response_lower:
                    evidence.append(f"File content detected: {indicator}")
                    triggered = True
                    break
                    
        elif cwe_type == "CWE-78":  # Command Injection
            cmd_indicators = ["uid=", "gid=", "root:", "bin/bash", "windows"]
            for indicator in cmd_indicators:
                if indicator in response_lower:
                    evidence.append(f"Command output detected: {indicator}")
                    triggered = True
                    break
        
        # Generic checks
        if response.status_code >= 500:
            evidence.append(f"Server error (status {response.status_code})")
            if not triggered:
                triggered = True
        
        return {
            "triggered": triggered,
            "evidence": evidence
        }
    
    def _capture_screenshot(self, url: str) -> Tuple[str, str]:
        """Capture screenshot of the target URL"""
        if not PLAYWRIGHT_AVAILABLE:
            return None, None
        
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, timeout=10000)
            
            # Create screenshot file
            screenshot_dir = os.path.join(os.getcwd(), "results", "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            screenshot_path = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
            
            page.screenshot(path=screenshot_path, full_page=True)
            browser.close()
            
            # Convert to base64 for embedding
            with open(screenshot_path, "rb") as f:
                screenshot_base64 = base64.b64encode(f.read()).decode("utf-8")
            
            return screenshot_path, screenshot_base64
    
    def stop_target_app(self, scan_id: str) -> bool:
        """Stop the target application container"""
        if scan_id not in self.running_containers:
            return False
        
        container_info = self.running_containers[scan_id]
        container_id = container_info.get("container_id")
        
        if not container_id:
            return False
        
        try:
            client = self._get_client()
            container = client.containers.get(container_id)
            container.stop(timeout=5)
            del self.running_containers[scan_id]
            return True
        except Exception as e:
            print(f"[LiveDockerTester] Error stopping container: {e}")
            return False


# Global tester instance
live_docker_tester = LiveDockerTester()


def get_live_docker_tester() -> LiveDockerTester:
    """Get the global live Docker tester instance"""
    return live_docker_tester
