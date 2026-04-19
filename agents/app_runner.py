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

try:
    import magic as file_magic
except ImportError:
    file_magic = None
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
    def _iter_app_files(self, app_path: str, suffixes: tuple[str, ...]) -> list[str]:
        ignored_dirs = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', 'results', 'data'}
        collected: list[str] = []
        for root, dirs, files in os.walk(app_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith('.')]
            for name in files:
                if name.endswith(suffixes):
                    collected.append(os.path.join(root, name))
        return collected

    def _is_test_path(self, path: str) -> bool:
        lowered = path.replace('\\', '/').lower()
        markers = ['/src/test/', '/tests/', '/test/', '/__tests__/', '/spec/', '/specs/', 'test_', '_test.', '.spec.', '.test.']
        return any(marker in lowered for marker in markers)

    def _detect_python_entrypoint(self, app_path: str) -> Optional[str]:
        preferred = ["app.py", "main.py", "server.py", "run.py", "manage.py", "wsgi.py", "asgi.py"]
        for candidate in preferred:
            full = os.path.join(app_path, candidate)
            if os.path.exists(full):
                return full

        python_files = self._iter_app_files(app_path, ('.py',))
        scored: list[tuple[int, str]] = []
        for full in python_files:
            rel = os.path.relpath(full, app_path)
            if self._is_test_path(rel):
                continue
            score = 0
            name = os.path.basename(full).lower()
            if name in preferred:
                score += 10
            normalized_rel = rel.replace('\\', '/').lower()
            if '/app/' in normalized_rel or '/src/' in normalized_rel:
                score += 2
            try:
                file_text = Path(full).read_text(encoding='utf-8', errors='ignore')
            except Exception:
                file_text = ''
            if 'FastAPI(' in file_text or 'Flask(' in file_text or 'Starlette(' in file_text:
                score += 8
            if 'if __name__ == "__main__"' in file_text or "if __name__ == '__main__'" in file_text:
                score += 4
            if 'app =' in file_text or 'application =' in file_text:
                score += 2
            scored.append((score, full))
        scored.sort(reverse=True)
        return scored[0][1] if scored else None
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
    def _detect_node_package_manager(self, app_path: str) -> str:
        if os.path.exists(os.path.join(app_path, 'pnpm-lock.yaml')):
            return 'pnpm'
        if os.path.exists(os.path.join(app_path, 'yarn.lock')):
            return 'yarn'
        return 'npm'

    def _detect_node_start_command(self, app_path: str) -> Optional[list[str]]:
        package_json = os.path.join(app_path, "package.json")
        if not os.path.exists(package_json):
            return None
        package_manager = self._detect_node_package_manager(app_path)
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
        except Exception:
            return [package_manager, "start"] if package_manager == 'yarn' else [package_manager, "run", "start"]

        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        for script_name in ["start", "dev", "serve", "preview"]:
            if script_name in scripts:
                if package_manager == 'yarn':
                    return ["yarn", script_name]
                return [package_manager, "run", script_name]
        if package_manager == 'yarn':
            return ["yarn", "start"]
        return [package_manager, "run", "start"]

    def _detect_python_start_commands(self, app_path: str, entry: str, port: int) -> list[list[str]]:
        commands = []
        entry_name = os.path.basename(entry)
        module_name = os.path.splitext(entry_name)[0]
        rel_entry = os.path.relpath(entry, app_path).replace(os.sep, '/')
        module_path = os.path.splitext(rel_entry)[0].replace('/', '.')
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
            commands.append(["python3", "-m", "uvicorn", f"{module_path}:app", "--host", "0.0.0.0", "--port", str(port)])
        if 'Flask(' in entry_text or 'app = Flask' in entry_text:
            commands.append(["python3", entry])
            commands.append(["python3", "-m", "flask", "--app", entry, "run", "--host", "0.0.0.0", "--port", str(port)])
            commands.append(["python3", "-m", "flask", "--app", module_path, "run", "--host", "0.0.0.0", "--port", str(port)])
        if 'app =' in entry_text or 'if __name__ == "__main__"' in entry_text or "if __name__ == '__main__'" in entry_text:
            commands.append(["python3", entry])
            commands.append(["python3", "-m", module_path])
        commands.append(["python3", entry])

        seen = set()
        unique_commands = []
        for command in commands:
            key = tuple(command)
            if key not in seen:
                seen.add(key)
                unique_commands.append(command)
        return unique_commands

    def _install_python_dependencies(self, app_path: str) -> Optional[str]:
        commands: list[list[str]] = []
        if os.path.exists(os.path.join(app_path, 'requirements.txt')):
            commands.append(["python3", "-m", "pip", "install", "-r", "requirements.txt"])
        if os.path.exists(os.path.join(app_path, 'pyproject.toml')):
            if shutil.which('poetry') and os.path.exists(os.path.join(app_path, 'poetry.lock')):
                commands.append(["poetry", "install", "--no-interaction"])
            else:
                commands.append(["python3", "-m", "pip", "install", "."])
        if os.path.exists(os.path.join(app_path, 'Pipfile')) and shutil.which('pipenv'):
            commands.append(["pipenv", "install", "--dev"])

        for command in commands:
            try:
                result = subprocess.run(command, cwd=app_path, capture_output=True, text=True, timeout=240)
            except Exception as exc:
                return f"{' '.join(command)} failed: {exc}"
            if result.returncode != 0:
                return f"{' '.join(command)} failed: {result.stderr or result.stdout}"
        return None

    def _install_node_dependencies(self, app_path: str, package_manager: str) -> Optional[str]:
        if package_manager == 'pnpm':
            commands = [["pnpm", "install", "--frozen-lockfile"], ["pnpm", "install"]]
        elif package_manager == 'yarn':
            commands = [["yarn", "install", "--frozen-lockfile"], ["yarn", "install"]]
        else:
            commands = [["npm", "ci"], ["npm", "install"]]

        last_error = None
        for command in commands:
            executable = command[0]
            if not shutil.which(executable):
                last_error = f"{executable} is not installed"
                continue
            try:
                result = subprocess.run(command, cwd=app_path, capture_output=True, text=True, timeout=240)
            except Exception as exc:
                last_error = f"{' '.join(command)} failed: {exc}"
                continue
            if result.returncode == 0:
                return None
            last_error = f"{' '.join(command)} failed: {result.stderr or result.stdout}"
        return last_error

    def start_nodejs_app(self, scan_id: str, app_path: str, port: int = 3000, start_timeout: int = 60) -> Dict[str, Any]:
        try:
            package_json = os.path.join(app_path, "package.json")
            if not os.path.exists(package_json):
                return {"success": False, "error": f"No package.json found in {app_path}", "url": None, "process": None}
            package_manager = self._detect_node_package_manager(app_path)
            node_modules = os.path.join(app_path, "node_modules")
            if not os.path.exists(node_modules):
                install_error = self._install_node_dependencies(app_path, package_manager)
                if install_error:
                    return {"success": False, "error": install_error, "url": None, "process": None}
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["HOST"] = "0.0.0.0"
            env["BROWSER"] = "none"
            env["CI"] = "true"
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
            install_error = self._install_python_dependencies(app_path)
            if install_error:
                return {"success": False, "error": install_error, "url": None, "process": None}
            env = os.environ.copy()
            env["PORT"] = str(port)
            env["HOST"] = "0.0.0.0"
            env["FLASK_RUN_PORT"] = str(port)
            env["FLASK_RUN_HOST"] = "0.0.0.0"
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

    def _detect_java_start_commands(self, app_path: str, port: int) -> list[list[str]]:
        commands = []
        if os.path.exists(os.path.join(app_path, 'mvnw')):
            commands.append(['./mvnw', '-q', '-DskipTests', 'spring-boot:run'])
        if os.path.exists(os.path.join(app_path, 'pom.xml')):
            commands.append(['mvn', '-q', '-DskipTests', 'spring-boot:run'])
        if os.path.exists(os.path.join(app_path, 'gradlew')):
            commands.append(['./gradlew', 'bootRun', '--no-daemon', '-q'])
            commands.append(['./gradlew', 'run', '--no-daemon', '-q'])
        if os.path.exists(os.path.join(app_path, 'build.gradle')) or os.path.exists(os.path.join(app_path, 'build.gradle.kts')):
            commands.append(['gradle', 'bootRun', '-q'])
            commands.append(['gradle', 'run', '-q'])
        jar_candidates = []
        for jar_dir in [Path(app_path) / 'target', Path(app_path) / 'build' / 'libs']:
            if jar_dir.exists():
                for jar in jar_dir.glob('*.jar'):
                    name = jar.name.lower()
                    if any(token in name for token in ['sources', 'javadoc', 'original', 'tests']):
                        continue
                    jar_candidates.append(str(jar))
        for jar in jar_candidates:
            commands.append(['java', '-jar', jar])
        seen = set()
        unique = []
        for command in commands:
            key = tuple(command)
            if key not in seen:
                seen.add(key)
                unique.append(command)
        return unique

    def start_java_app(self, scan_id: str, app_path: str, port: int = 8080, start_timeout: int = 90) -> Dict[str, Any]:
        try:
            env = os.environ.copy()
            env['PORT'] = str(port)
            env['SERVER_PORT'] = str(port)
            env['HOST'] = '0.0.0.0'
            commands = self._detect_java_start_commands(app_path, port)
            if not commands:
                return {'success': False, 'error': f'No Java entrypoint or build command found in {app_path}', 'url': None, 'process': None}
            last_error = ''
            url = f'http://localhost:{port}'
            for command in commands:
                executable = command[0]
                if executable in {'mvn', 'gradle', 'java'} and not shutil.which(executable):
                    last_error = f'{executable} is not installed'
                    continue
                process = subprocess.Popen(command, cwd=app_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                if self._wait_for_http_ready(url, start_timeout):
                    return self._register_running_app(scan_id, process, url, port, app_path, 'java')
                process.terminate()
                last_error = f"Application failed to start with {' '.join(command)} within {start_timeout}s"
            return {'success': False, 'error': last_error or f'Java application failed to start within {start_timeout}s', 'url': None, 'process': None}
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': None, 'process': None}
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
    def _looks_like_native_binary_file(self, path: str) -> bool:
        try:
            with open(path, 'rb') as f:
                header = f.read(2048)
        except OSError:
            return False
        if header.startswith(b'\x7fELF'):
            return True
        if header.startswith(b'MZ'):
            return True
        if header[:4] in {b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'}:
            return True
        if file_magic is not None:
            try:
                detected = str(file_magic.from_file(path)).lower()
                if any(token in detected for token in ['elf ', 'mach-o', 'pe32', 'executable', 'shared object']):
                    return True
                if any(token in detected for token in ['text', 'ascii', 'unicode text', 'configuration', 'json', 'xml']):
                    return False
            except Exception:
                pass
        if b'\x00' in header:
            return True
        return False

    def _find_native_artifacts(self, app_path: str, build_started_at: float | None = None) -> list[str]:
        ignored_dirs = {".git", "node_modules", "venv", ".venv", "results", "data", "dist"}
        ignored_suffixes = {".o", ".obj", ".a", ".so", ".dylib", ".dll", ".lib", ".sh", ".py", ".pl", ".rb", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".js", ".ts", ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml", ".xml", ".txt"}
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
                if not self._looks_like_native_binary_file(full):
                    continue
                lower_name = name.lower()
                lower_path = full.replace('\\', '/').lower()
                if any(token in lower_name for token in ['config', 'helper']) or '/misc/' in lower_path or '/scripts/' in lower_path or '/docs/' in lower_path:
                    continue
                if build_started_at and st.st_mtime + 1 < build_started_at:
                    continue
                score = 0
                if lower_name in {repo_name, 'a.out', 'main', 'app', 'server'}:
                    score += 10
                if repo_name and repo_name in lower_name:
                    score += 5
                if '/build/' in lower_path or '/src/' in lower_path or '/bin/' in lower_path:
                    score += 2
                score += int(st.st_mtime)
                candidates.append((score, full))
        candidates.sort(reverse=True)
        return [full for _, full in candidates]
    def _select_existing_native_binary(self, app_path: str) -> Optional[str]:
        artifacts = self._find_native_artifacts(app_path)
        return artifacts[0] if artifacts else None

    def _prepare_native_build_context(self, app_path: str) -> None:
        release_path = os.path.join(app_path, 'RELEASE')
        git_dir = os.path.join(app_path, '.git')
        if os.path.exists(git_dir) or os.path.exists(release_path):
            return
        makefile = os.path.join(app_path, 'Makefile')
        gnumakefile = os.path.join(app_path, 'GNUmakefile')
        if not (os.path.exists(makefile) or os.path.exists(gnumakefile)):
            return
        try:
            with open(release_path, 'w', encoding='utf-8') as f:
                f.write('autopov-build\n')
        except OSError:
            pass

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
    def _verify_asan_instrumented(self, binary_path: str) -> bool:
        """Return True if binary contains ASan symbols (i.e. was compiled with -fsanitize=address)."""
        if not binary_path or not os.path.isfile(binary_path):
            return False
        # Try nm first (from binutils), fall back to strings
        for tool, args in [
            ('nm', ['nm', binary_path]),
            ('strings', ['strings', binary_path]),
        ]:
            if not shutil.which(tool):
                continue
            try:
                r = subprocess.run(args, capture_output=True, text=True, timeout=15)
                if '__asan_init' in r.stdout or '__asan_report' in r.stdout or 'AddressSanitizer' in r.stdout:
                    return True
                # If nm succeeded but no asan symbols found, it's definitely not instrumented
                if tool == 'nm' and r.returncode == 0:
                    return False
            except Exception:
                continue
        return False

    def _compile_all_sources_with_asan(self, app_path: str, output_path: str) -> Dict[str, Any]:
        """Compile C/C++ sources with ASan/UBSan as a last-resort fallback.

        Strategy (in order):
        1. Prefer make-based compile with CFLAGS override (handles complex projects like enchive).
        2. Fall back to single primary source file detection.
        3. Last resort: try compiling all .c files together.
        """
        import glob as _glob

        sanitize_flags = '-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
        sanitize_list = sanitize_flags.split()

        # --- Strategy 1: make with CFLAGS override (preferred — respects Makefile defines) ---
        for mf in ['Makefile', 'GNUmakefile']:
            if os.path.exists(os.path.join(app_path, mf)) and shutil.which('make'):
                _s1_started = time.time()
                try:
                    subprocess.run(['make', 'clean'], cwd=app_path, capture_output=True, timeout=60)
                except Exception:
                    pass
                try:
                    r = subprocess.run(
                        ['make', '-j2',
                         f'CFLAGS={sanitize_flags}',
                         f'CXXFLAGS={sanitize_flags}',
                         'LDFLAGS=-fsanitize=address,undefined'],
                        cwd=app_path, capture_output=True, text=True, timeout=300,
                        env={**os.environ,
                             'CFLAGS': sanitize_flags,
                             'CXXFLAGS': sanitize_flags,
                             'LDFLAGS': '-fsanitize=address,undefined'},
                    )
                    if r.returncode == 0:
                        # Find binary produced after we started (5s slack for fast builds)
                        built = self._find_native_artifacts(app_path, _s1_started - 5)
                        if not built:
                            built = self._find_native_artifacts(app_path)
                        if built:
                            return {'success': True, 'binary_path': built[0], 'build_method': 'make-asan-forced'}
                except Exception:
                    pass
                break

        # --- Strategy 2: single primary source file ---
        def _keep(p: str) -> bool:
            lower = p.replace('\\', '/').lower()
            return not any(tok in lower for tok in ['/test/', '/tests/', '/third_party/', '/thirdparty/', '/vendor/', '/.git/', '/example', '/bench', '/fuzz'])

        c_sources = [p for p in _glob.glob(os.path.join(app_path, '**', '*.c'), recursive=True) if _keep(p)]
        cpp_sources = [p for p in _glob.glob(os.path.join(app_path, '**', '*.cpp'), recursive=True) +
                       _glob.glob(os.path.join(app_path, '**', '*.cc'), recursive=True) if _keep(p)]

        if not c_sources and not cpp_sources:
            return {'success': False, 'error': 'No C/C++ sources found'}

        # Collect include dirs (any dir containing .h files)
        h_dirs = set()
        for hp in _glob.glob(os.path.join(app_path, '**', '*.h'), recursive=True):
            h_dirs.add(os.path.dirname(hp))
        include_flags = [f'-I{d}' for d in sorted(h_dirs)]

        compiler = 'g++' if cpp_sources else 'gcc'
        sources = cpp_sources + c_sources if cpp_sources else c_sources

        if not shutil.which(compiler):
            return {'success': False, 'error': f'{compiler} not found'}

        try:
            result = subprocess.run(
                [compiler, *sources, *sanitize_list, *include_flags, '-o', output_path],
                cwd=app_path, capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                return {'success': True, 'binary_path': output_path, 'build_method': 'all-sources-asan-compile'}
            return {'success': False, 'error': result.stderr or result.stdout}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _build_with_project_context(self, app_path: str) -> Dict[str, Any]:
        build_attempts = []
        build_started_at = time.time()
        self._prepare_native_build_context(app_path)
        sanitizer_env = self._native_sanitizer_env()
        sanitize_flags = '-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
        project_commands = []
        if os.path.exists(os.path.join(app_path, 'Makefile')) or os.path.exists(os.path.join(app_path, 'GNUmakefile')):
            # Run 'make clean' first so the subsequent make is not idempotent (forces full recompile with ASan flags)
            if shutil.which('make'):
                try:
                    subprocess.run(['make', 'clean'], cwd=app_path, capture_output=True, timeout=60)
                except Exception:
                    pass
            project_commands.append((
                ['make', '-j2',
                 f'CFLAGS={sanitize_flags}',
                 f'CXXFLAGS={sanitize_flags}',
                 'LDFLAGS=-fsanitize=address,undefined'],
                app_path, 'make', sanitizer_env
            ))
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
            # Use a 5-second slack to tolerate fast builds and low-resolution
            # filesystem timestamps (enchive builds in < 1s, mtime == build_started_at).
            artifacts = self._find_native_artifacts(app_path, build_started_at - 5)
            if not artifacts:
                artifacts = self._find_native_artifacts(app_path)
            if artifacts:
                binary = artifacts[0]
                effective_label = label
                if not self._verify_asan_instrumented(binary):
                    asan_out = os.path.join('/tmp', f'autopov_asan_{os.path.basename(app_path)}')
                    direct = self._compile_all_sources_with_asan(app_path, asan_out)
                    if direct.get('success'):
                        binary = direct['binary_path']
                        effective_label = direct['build_method']
                        build_attempts.append(f'[{effective_label}] ASan fallback compile succeeded')
                    else:
                        build_attempts.append(f'[asan-fallback] failed: {direct.get("error", "")}')
                return {
                    'success': True,
                    'error': None,
                    'binary_path': binary,
                    'build_method': effective_label,
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
        if normalized in {"java"}:
            return self.start_java_app(scan_id, app_path, port=chosen_port)
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
