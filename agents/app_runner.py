"""
AutoPoV Application Runner Module
Manages target application lifecycle for PoV testing
"""

import os
import shutil
import socket
import subprocess
import time
from typing import Dict, Optional, Any
from datetime import datetime

import requests


class AppRunnerError(Exception):
    """Exception raised during application execution"""
    pass


class ApplicationRunner:
    """Runs target applications for PoV testing"""

    def __init__(self):
        self.running_apps = {}

    def _find_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("", 0))
            sock.listen(1)
            return sock.getsockname()[1]

    def _wait_for_http_ready(self, url: str, start_timeout: int) -> bool:
        start_time = time.time()
        while time.time() - start_time < start_timeout:
            try:
                response = requests.get(url, timeout=2)
                if response.status_code < 500:
                    return True
            except requests.RequestException:
                pass
            time.sleep(1)
        return False

    def _register_running_app(self, scan_id: str, process: subprocess.Popen, url: str, port: int, app_path: str, app_type: str) -> Dict[str, Any]:
        app_info = {
            "scan_id": scan_id,
            "process": process,
            "url": url,
            "port": port,
            "app_path": app_path,
            "started_at": datetime.utcnow().isoformat(),
            "type": app_type,
        }
        self.running_apps[scan_id] = app_info
        return {
            "success": True,
            "error": None,
            "url": url,
            "process": process,
            "type": app_type,
        }

    def _detect_python_entrypoint(self, app_path: str) -> Optional[str]:
        for candidate in ["app.py", "main.py", "server.py", "run.py", "manage.py", "wsgi.py"]:
            full = os.path.join(app_path, candidate)
            if os.path.exists(full):
                return full
        return None

    def _detect_native_entry(self, app_path: str, language: str) -> Optional[str]:
        extensions = [".c"] if language == "c" else [".cpp", ".cc", ".cxx", ".c"]
        for stem in ["main", "app", "server"]:
            for ext in extensions:
                full = os.path.join(app_path, stem + ext)
                if os.path.exists(full):
                    return full
        for root, _, files in os.walk(app_path):
            for name in files:
                if any(name.endswith(ext) for ext in extensions):
                    return os.path.join(root, name)
        return None

    def start_nodejs_app(self, scan_id: str, app_path: str, port: int = 3000, start_timeout: int = 60) -> Dict[str, Any]:
        try:
            package_json = os.path.join(app_path, "package.json")
            if not os.path.exists(package_json):
                return {"success": False, "error": f"No package.json found in {app_path}", "url": None, "process": None}
            node_modules = os.path.join(app_path, "node_modules")
            if not os.path.exists(node_modules):
                install_result = subprocess.run(["npm", "install"], cwd=app_path, capture_output=True, text=True, timeout=120)
                if install_result.returncode != 0:
                    return {"success": False, "error": f"npm install failed: {install_result.stderr}", "url": None, "process": None}
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["HOST"] = "0.0.0.0"
            process = subprocess.Popen(["npm", "start"], cwd=app_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            url = f"http://localhost:{port}"
            if not self._wait_for_http_ready(url, start_timeout):
                process.terminate()
                return {"success": False, "error": f"Application failed to start within {start_timeout}s", "url": None, "process": None}
            return self._register_running_app(scan_id, process, url, port, app_path, "nodejs")
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout during npm install", "url": None, "process": None}
        except Exception as e:
            return {"success": False, "error": str(e), "url": None, "process": None}

    def start_python_app(self, scan_id: str, app_path: str, port: int = 8001, start_timeout: int = 60) -> Dict[str, Any]:
        try:
            entry = self._detect_python_entrypoint(app_path)
            if not entry:
                return {"success": False, "error": f"No Python entrypoint found in {app_path}", "url": None, "process": None}
            requirements = os.path.join(app_path, "requirements.txt")
            if os.path.exists(requirements):
                subprocess.run(["python3", "-m", "pip", "install", "-r", requirements], cwd=app_path, capture_output=True, text=True, timeout=180)
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["HOST"] = "0.0.0.0"
            process = subprocess.Popen(["python3", entry], cwd=app_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            url = f"http://localhost:{port}"
            if not self._wait_for_http_ready(url, start_timeout):
                process.terminate()
                return {"success": False, "error": f"Application failed to start within {start_timeout}s", "url": None, "process": None}
            return self._register_running_app(scan_id, process, url, port, app_path, "python")
        except Exception as e:
            return {"success": False, "error": str(e), "url": None, "process": None}

    def build_native_binary(self, scan_id: str, app_path: str, language: str = "c") -> Dict[str, Any]:
        try:
            makefile = os.path.join(app_path, "Makefile")
            if os.path.exists(makefile):
                result = subprocess.run(["make"], cwd=app_path, capture_output=True, text=True, timeout=180)
                if result.returncode != 0:
                    return {"success": False, "error": result.stderr or result.stdout, "binary_path": None}
                for candidate in ["a.out", "main", "app", "server"]:
                    full = os.path.join(app_path, candidate)
                    if os.path.exists(full) and os.access(full, os.X_OK):
                        return {"success": True, "error": None, "binary_path": full}
            source_file = self._detect_native_entry(app_path, language)
            if not source_file:
                return {"success": False, "error": f"No {language} source file found in {app_path}", "binary_path": None}
            compiler = "gcc" if language == "c" else "g++"
            if not shutil.which(compiler):
                return {"success": False, "error": f"{compiler} is not installed", "binary_path": None}
            binary_path = os.path.join("/tmp", f"autopov_{scan_id}_{language}_target")
            result = subprocess.run([compiler, source_file, "-O0", "-g", "-o", binary_path], cwd=app_path, capture_output=True, text=True, timeout=180)
            if result.returncode != 0:
                return {"success": False, "error": result.stderr or result.stdout, "binary_path": None}
            return {"success": True, "error": None, "binary_path": binary_path}
        except Exception as e:
            return {"success": False, "error": str(e), "binary_path": None}

    def start_application(self, scan_id: str, app_path: str, target_language: str, port: Optional[int] = None) -> Dict[str, Any]:
        chosen_port = port or self._find_free_port()
        normalized = (target_language or "").lower()
        if normalized in {"javascript", "typescript", "node"}:
            return self.start_nodejs_app(scan_id, app_path, port=chosen_port)
        if normalized in {"python", "py"}:
            return self.start_python_app(scan_id, app_path, port=chosen_port)
        return {"success": False, "error": f"No live app runner for language: {target_language}", "url": None, "process": None}

    def stop_app(self, scan_id: str) -> bool:
        if scan_id not in self.running_apps:
            return False
        process = self.running_apps[scan_id].get("process")
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception:
                pass
        del self.running_apps[scan_id]
        return True

    def get_app_url(self, scan_id: str) -> Optional[str]:
        if scan_id in self.running_apps:
            return self.running_apps[scan_id].get("url")
        return None

    def is_app_running(self, scan_id: str) -> bool:
        if scan_id not in self.running_apps:
            return False
        process = self.running_apps[scan_id].get("process")
        return bool(process and process.poll() is None)

    def cleanup_all(self):
        for scan_id in list(self.running_apps.keys()):
            self.stop_app(scan_id)


app_runner = ApplicationRunner()


def get_app_runner() -> ApplicationRunner:
    """Get the global application runner instance"""
    return app_runner
