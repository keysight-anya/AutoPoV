"""
AutoPoV Application Runner Module
Manages target application lifecycle for PoV testing
"""
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
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
    def _detect_node_start_command(self, app_path: str) -> Optional[list[str]]:
        package_json = os.path.join(app_path, "package.json")
        if not os.path.exists(package_json):
            return None
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
        except Exception:
            return ["npm", "start"]

        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        for script_name in ["start", "dev", "serve", "preview"]:
            if script_name in scripts:
                return ["npm", "run", script_name]
        return ["npm", "start"]

    def _detect_python_start_commands(self, app_path: str, entry: str, port: int) -> list[list[str]]:
        commands = []
        entry_name = os.path.basename(entry)
        module_name = os.path.splitext(entry_name)[0]
        entry_text = ''
        try:
            with open(entry, 'r', encoding='utf-8', errors='ignore') as f:
                entry_text = f.read()
        except Exception:
            entry_text = ''

        if entry_name == 'manage.py':
            commands.append(["python3", entry, "runserver", f"0.0.0.0:{port}"])
        if 'FastAPI(' in entry_text or 'Starlette(' in entry_text:
            commands.append(["python3", "-m", "uvicorn", f"{module_name}:app", "--host", "0.0.0.0", "--port", str(port)])
        if 'Flask(' in entry_text or 'app = Flask' in entry_text:
            commands.append(["python3", entry])
            commands.append(["python3", "-m", "flask", "--app", entry, "run", "--host", "0.0.0.0", "--port", str(port)])
        if 'app =' in entry_text or 'if __name__ == "__main__"' in entry_text or "if __name__ == '__main__'" in entry_text:
            commands.append(["python3", entry])
        commands.append(["python3", entry])

        seen = set()
        unique_commands = []
        for command in commands:
            key = tuple(command)
            if key not in seen:
                seen.add(key)
                unique_commands.append(command)
        return unique_commands

    def start_nodejs_app(self, scan_id: str, app_path: str, port: int = 3000, start_timeout: int = 60) -> Dict[str, Any]:
        try:
            package_json = os.path.join(app_path, "package.json")
            if not os.path.exists(package_json):
                return {"success": False, "error": f"No package.json found in {app_path}", "url": None, "process": None}
            node_modules = os.path.join(app_path, "node_modules")
            if not os.path.exists(node_modules):
                install_command = ["npm", "ci"] if os.path.exists(os.path.join(app_path, "package-lock.json")) else ["npm", "install"]
                install_result = subprocess.run(install_command, cwd=app_path, capture_output=True, text=True, timeout=180)
                if install_result.returncode != 0:
                    return {"success": False, "error": f"{' '.join(install_command)} failed: {install_result.stderr or install_result.stdout}", "url": None, "process": None}
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["HOST"] = "0.0.0.0"
            command = self._detect_node_start_command(app_path) or ["npm", "start"]
            process = subprocess.Popen(command, cwd=app_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            url = f"http://localhost:{port}"
            if not self._wait_for_http_ready(url, start_timeout):
                process.terminate()
                return {"success": False, "error": f"Application failed to start with {' '.join(command)} within {start_timeout}s", "url": None, "process": None}
            return self._register_running_app(scan_id, process, url, port, app_path, "nodejs")
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout during npm dependency install", "url": None, "process": None}
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
            commands = self._detect_python_start_commands(app_path, entry, port)
            last_error = ""
            url = f"http://localhost:{port}"
            for command in commands:
                process = subprocess.Popen(command, cwd=app_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                if self._wait_for_http_ready(url, start_timeout):
                    return self._register_running_app(scan_id, process, url, port, app_path, "python")
                process.terminate()
                last_error = f"Application failed to start with {' '.join(command)} within {start_timeout}s"
            return {"success": False, "error": last_error or f"Application failed to start within {start_timeout}s", "url": None, "process": None}
        except Exception as e:
            return {"success": False, "error": str(e), "url": None, "process": None}
    def _collect_native_sources(self, app_path: str, language: str) -> list[str]:
        extensions = {".c"} if language == "c" else {".c", ".cc", ".cpp", ".cxx"}
        ignored_dirs = {".git", "node_modules", "venv", ".venv", "results", "data", "dist"}
        sources = []
        for root, dirs, files in os.walk(app_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for name in files:
                if Path(name).suffix.lower() in extensions:
                    sources.append(os.path.join(root, name))
        return sources
    def _find_native_artifacts(self, app_path: str, build_started_at: float | None = None) -> list[str]:
        ignored_dirs = {".git", "node_modules", "venv", ".venv", "results", "data", "dist"}
        ignored_suffixes = {".o", ".obj", ".a", ".so", ".dylib", ".dll", ".lib"}
        repo_name = Path(app_path).name.lower()
        candidates = []
        for root, dirs, files in os.walk(app_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if not os.path.isfile(full) or not os.access(full, os.X_OK):
                    continue
                if Path(name).suffix.lower() in ignored_suffixes:
                    continue
                if build_started_at and st.st_mtime + 1 < build_started_at:
                    continue
                lower_name = name.lower()
                score = 0
                if lower_name in {repo_name, 'a.out', 'main', 'app', 'server'}:
                    score += 10
                if repo_name and repo_name in lower_name:
                    score += 5
                if '/build/' in full.replace('\\', '/'):
                    score += 2
                score += int(st.st_mtime)
                candidates.append((score, full))
        candidates.sort(reverse=True)
        return [full for _, full in candidates]
    def _select_existing_native_binary(self, app_path: str) -> Optional[str]:
        artifacts = self._find_native_artifacts(app_path)
        return artifacts[0] if artifacts else None
    def _run_native_build_command(self, command: list[str], cwd: str, timeout: int = 300, env: Optional[Dict[str, str]] = None) -> tuple[bool, str]:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        output = '\n'.join(part for part in [result.stdout, result.stderr] if part)
        return result.returncode == 0, output
    def _native_sanitizer_env(self, language: str = 'c') -> Dict[str, str]:
        env = os.environ.copy()
        sanitize_flags = '-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
        env['CFLAGS'] = (env.get('CFLAGS', '') + ' ' + sanitize_flags).strip()
        env['CXXFLAGS'] = (env.get('CXXFLAGS', '') + ' ' + sanitize_flags).strip()
        env['LDFLAGS'] = (env.get('LDFLAGS', '') + ' -fsanitize=address,undefined').strip()
        if language == 'c' and shutil.which('gcc'):
            env.setdefault('CC', 'gcc')
        if language in {'cpp', 'c++'} and shutil.which('g++'):
            env.setdefault('CXX', 'g++')
        return env
    def _build_with_project_context(self, app_path: str) -> Dict[str, Any]:
        build_attempts = []
        build_started_at = time.time()
        sanitizer_env = self._native_sanitizer_env()
        sanitize_flags = '-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
        project_commands = []
        if os.path.exists(os.path.join(app_path, 'Makefile')) or os.path.exists(os.path.join(app_path, 'GNUmakefile')):
            project_commands.append((['make', '-j2'], app_path, 'make', sanitizer_env))
        if os.path.exists(os.path.join(app_path, 'CMakeLists.txt')):
            build_dir = os.path.join(app_path, '.autopov-cmake-build')
            project_commands.append(([
                'cmake', '-S', app_path, '-B', build_dir,
                '-DCMAKE_BUILD_TYPE=Debug',
                f'-DCMAKE_C_FLAGS={sanitize_flags}',
                f'-DCMAKE_CXX_FLAGS={sanitize_flags}',
                '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
            ], app_path, 'cmake-configure', sanitizer_env))
            project_commands.append((['cmake', '--build', build_dir, '-j2'], app_path, 'cmake-build', sanitizer_env))
        if os.path.exists(os.path.join(app_path, 'meson.build')):
            build_dir = os.path.join(app_path, '.autopov-meson-build')
            if not os.path.exists(build_dir):
                project_commands.append((['meson', 'setup', build_dir, app_path, '--buildtype', 'debug'], app_path, 'meson-setup', sanitizer_env))
            project_commands.append((['meson', 'compile', '-C', build_dir], app_path, 'meson-compile', sanitizer_env))
        if os.path.exists(os.path.join(app_path, 'build.ninja')):
            project_commands.append((['ninja'], app_path, 'ninja', sanitizer_env))
        for command, cwd, label, env in project_commands:
            if not shutil.which(command[0]):
                build_attempts.append(f'[{label}] skipped: {command[0]} not installed')
                continue
            ok, output = self._run_native_build_command(command, cwd, env=env)
            build_attempts.append(f'[{label}] ' + ('success' if ok else 'failed') + (f'\n{output}' if output else ''))
            if not ok:
                continue
            artifacts = self._find_native_artifacts(app_path, build_started_at)
            if not artifacts:
                artifacts = self._find_native_artifacts(app_path)
            if artifacts:
                return {
                    'success': True,
                    'error': None,
                    'binary_path': artifacts[0],
                    'build_method': label,
                    'build_log': '\n\n'.join(build_attempts),
                    'artifacts': artifacts,
                }
        return {
            'success': False,
            'error': '\n\n'.join(build_attempts) if build_attempts else 'No supported native build system detected',
            'binary_path': None,
            'build_method': None,
            'build_log': '\n\n'.join(build_attempts),
        }
    def build_native_binary(self, scan_id: str, app_path: str, language: str = "c") -> Dict[str, Any]:
        try:
            project_build = self._build_with_project_context(app_path)
            if project_build.get('success'):
                return project_build
            sources = self._collect_native_sources(app_path, language)
            if not sources:
                return {"success": False, "error": f"No {language} source files found in {app_path}", "binary_path": None}
            if len(sources) > 1:
                compiler = 'gcc' if language == 'c' else 'g++'
                if shutil.which(compiler):
                    binary_path = os.path.join('/tmp', f'autopov_{scan_id}_{language}_target')
                    result = subprocess.run(
                        [compiler, *sources, '-O0', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-o', binary_path],
                        cwd=app_path,
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                    if result.returncode == 0:
                        return {
                            'success': True,
                            'error': None,
                            'binary_path': binary_path,
                            'build_method': 'all-sources-compile',
                        }
                existing_binary = self._select_existing_native_binary(app_path)
                if existing_binary:
                    return {
                        'success': True,
                        'error': None,
                        'binary_path': existing_binary,
                        'build_method': 'existing-artifact',
                    }
                return {
                    "success": False,
                    "error": "Multiple native source files detected but no supported build context produced an executable; refusing naive single-file compilation.\n" + (project_build.get('build_log') or ''),
                    "binary_path": None,
                    "proof_infrastructure_error": True,
                }
            source_file = sources[0]
            source_ext = os.path.splitext(source_file)[1].lower()
            compiler = "gcc" if source_ext == ".c" else "g++"
            detected_language = "c" if compiler == "gcc" else "cpp"
            if not shutil.which(compiler):
                return {"success": False, "error": f"{compiler} is not installed", "binary_path": None}
            binary_path = os.path.join("/tmp", f"autopov_{scan_id}_{detected_language}_target")
            result = subprocess.run([compiler, source_file, "-O0", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", binary_path], cwd=app_path, capture_output=True, text=True, timeout=180)
            if result.returncode != 0:
                return {"success": False, "error": result.stderr or result.stdout, "binary_path": None}
            return {"success": True, "error": None, "binary_path": binary_path, "build_method": "single-file-compile"}
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
