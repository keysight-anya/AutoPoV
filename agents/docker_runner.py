"""
AutoPoV Docker Runner Module
Executes PoV scripts in isolated Docker containers
"""

import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Optional, Any, List, Tuple
from datetime import datetime

try:
    import docker
    from docker.errors import DockerException, ContainerError, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from app.config import settings


class DockerRunnerError(Exception):
    """Exception raised during Docker execution"""
    pass


class DockerRunner:
    """Runs PoV scripts in Docker containers"""

    def __init__(self):
        self._client = None
        self.image = settings.DOCKER_IMAGE
        self.timeout = settings.DOCKER_TIMEOUT
        self.memory_limit = settings.DOCKER_MEMORY_LIMIT
        self.cpu_limit = settings.DOCKER_CPU_LIMIT
        self.runtime_images = {
            "python": settings.DOCKER_IMAGE,
            "node": settings.DOCKER_NODE_IMAGE,
            "browser": settings.DOCKER_BROWSER_IMAGE,
            "native": settings.DOCKER_NATIVE_IMAGE,
            "php": settings.DOCKER_PHP_IMAGE,
            "ruby": settings.DOCKER_RUBY_IMAGE,
            "go": settings.DOCKER_GO_IMAGE,
            "shell": settings.DOCKER_SHELL_IMAGE,
        }
        self.build_contexts = {
            "python": self._proof_image_dir("python"),
            "node": self._proof_image_dir("node"),
            "browser": self._proof_image_dir("browser"),
            "native": self._proof_image_dir("native"),
            "php": self._proof_image_dir("php"),
            "ruby": self._proof_image_dir("ruby"),
            "go": self._proof_image_dir("go"),
        }

    def _proof_image_dir(self, kind: str) -> Optional[Path]:
        candidate = Path(__file__).resolve().parent.parent / "docker" / "proof-images" / kind
        return candidate if candidate.exists() else None

    def _classify_failure(self, *, infrastructure: bool, reason: str = "") -> Dict[str, Any]:
        category = "infrastructure" if infrastructure else "exploit"
        return {
            "proof_infrastructure_error": infrastructure,
            "failure_category": category,
            "failure_reason": reason,
        }

    def _build_result(
        self,
        *,
        success: bool,
        vulnerability_triggered: bool,
        stdout: str,
        stderr: str,
        exit_code: int,
        execution_time_s: float,
        execution_profile: str,
        runtime_image: str,
        validation_method: str,
        proof_infrastructure_error: bool = False,
        failure_reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = {
            "success": success,
            "vulnerability_triggered": vulnerability_triggered,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "execution_time_s": execution_time_s,
            "timestamp": datetime.utcnow().isoformat(),
            "execution_profile": execution_profile,
            "runtime_image": runtime_image,
            "validation_method": validation_method,
            **self._classify_failure(infrastructure=proof_infrastructure_error, reason=failure_reason),
        }
        if metadata:
            result.update(metadata)
        return result

    def _slugify(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value or "autopov")
        return cleaned.strip("-._")[:80] or "autopov"

    def _detect_script_runtime(self, pov_script: str, execution_profile: Optional[str]) -> str:
        profile = (execution_profile or "").strip().lower()
        script = str(pov_script or "")
        if profile in {"bash", "sh", "shell"}:
            return "shell"
        if profile in {"php"}:
            return "php"
        if profile in {"ruby"}:
            return "ruby"
        if profile in {"go", "golang"}:
            return "go"
        if profile in {"javascript", "node", "typescript", "jsx", "tsx"}:
            return "node"
        if "<?php" in script:
            return "php"
        if script.startswith("#!/bin/bash") or script.startswith("#!/usr/bin/env bash"):
            return "shell"
        if script.startswith("#!/usr/bin/env ruby"):
            return "ruby"
        if script.startswith("#!/usr/bin/env node"):
            return "node"
        if "console.log(" in script or "require(" in script or "process.env" in script:
            return "node"
        if "package main" in script and "func main(" in script:
            return "go"
        return "python"

    def _resolve_environment_kind(self, execution_profile: Optional[str], target_language: Optional[str], exploit_contract: Optional[Dict[str, Any]], script_runtime: str) -> str:
        profile = (execution_profile or "").strip().lower()
        language = (target_language or "").strip().lower()
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get("target_entrypoint") or "").strip().lower()

        if profile in {"browser"}:
            return "browser"
        if profile in {"web", "http"} and contract.get("browser_required"):
            return "browser"
        if language in {"c", "cpp", "c++"} or profile in {"native", "binary", "c", "cpp", "c++"}:
            return "native"
        if script_runtime == "node" and (profile in {"web", "http", "javascript", "node"} or target_entrypoint.startswith("/") or target_entrypoint.startswith("http")):
            if contract.get("browser_required") or contract.get("client_side"):
                return "browser"
            return "node"
        if script_runtime in {"php", "ruby", "go", "shell"}:
            return script_runtime
        return "python"

    def _resolve_runtime(self, pov_script: str, execution_profile: Optional[str], target_language: Optional[str], exploit_contract: Optional[Dict[str, Any]]) -> Tuple[str, str, List[str], str]:
        script_runtime = self._detect_script_runtime(pov_script, execution_profile)
        env_kind = self._resolve_environment_kind(execution_profile, target_language, exploit_contract, script_runtime)
        runtime_image = self.runtime_images.get(env_kind) or self.image
        if script_runtime == "node":
            runtime_command = ["node"]
            pov_filename = "pov.js"
        elif script_runtime == "shell":
            runtime_command = ["bash"]
            pov_filename = "pov.sh"
        elif script_runtime == "php":
            runtime_command = ["php"]
            pov_filename = "pov.php"
        elif script_runtime == "ruby":
            runtime_command = ["ruby"]
            pov_filename = "pov.rb"
        elif script_runtime == "go":
            runtime_command = ["bash", "-lc", "go run /pov/pov.go"]
            pov_filename = "pov.go"
        else:
            runtime_command = ["python3"]
            pov_filename = "pov.py"
        return env_kind, runtime_image, runtime_command, pov_filename

    def _normalize_target_url_for_container(self, target_url: str) -> str:
        url = str(target_url or "").strip()
        if not url:
            return url
        url = url.replace("http://localhost", "http://host.docker.internal")
        url = url.replace("https://localhost", "https://host.docker.internal")
        url = url.replace("http://127.0.0.1", "http://host.docker.internal")
        url = url.replace("https://127.0.0.1", "https://host.docker.internal")
        return url

    def _add_directory_to_archive(self, tar: tarfile.TarFile, source_dir: str, archive_root: str):
        ignored_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "results", "data", ".autopov-cmake-build", ".autopov-meson-build"}
        source_path = Path(source_dir)
        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for name in files:
                full_path = Path(root) / name
                rel_path = full_path.relative_to(source_path)
                tar.add(str(full_path), arcname=str(Path(archive_root) / rel_path))

    def _add_text_to_archive(self, tar: tarfile.TarFile, arcname: str, content: str):
        data = (content or "").encode("utf-8")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        info.mtime = int(datetime.utcnow().timestamp())
        tar.addfile(info, io.BytesIO(data))

    def _collect_fixture_files(self, exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, str]:
        contract = exploit_contract or {}
        files: Dict[str, str] = {}
        fixtures = contract.get("fixtures") or contract.get("test_inputs") or []
        if isinstance(fixtures, dict):
            fixtures = [{"path": key, "content": value} for key, value in fixtures.items()]
        for idx, fixture in enumerate(fixtures):
            if isinstance(fixture, dict):
                path = str(fixture.get("path") or fixture.get("name") or f"fixture_{idx}.txt").lstrip("/")
                content = fixture.get("content")
                if content is None and fixture.get("json") is not None:
                    content = json.dumps(fixture.get("json"), indent=2)
                if content is not None:
                    files[path] = str(content)
            elif fixture is not None:
                files[f"fixture_{idx}.txt"] = str(fixture)
        inputs = contract.get("inputs") or []
        for idx, item in enumerate(inputs):
            if not isinstance(item, dict):
                continue
            mode = str(item.get("mode") or item.get("channel") or "").lower()
            if mode not in {"file", "filepath"}:
                continue
            content = item.get("content")
            if content is None and item.get("json") is not None:
                content = json.dumps(item.get("json"), indent=2)
            if content is None:
                for key in ["value", "payload", "body", "data"]:
                    if item.get(key) not in (None, ""):
                        content = item.get(key)
                        break
            if content is not None:
                name = str(item.get("name") or item.get("filename") or f"input_{idx}.txt").lstrip("/")
                files[name] = str(content)
        return files

    def _get_client(self):
        if not DOCKER_AVAILABLE:
            raise DockerRunnerError("docker-py not available. Install docker")
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as e:
                raise DockerRunnerError(f"Could not connect to Docker: {e}")
        return self._client

    def is_available(self) -> bool:
        if not settings.is_docker_available():
            return False
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception:
            return False

    def _ensure_runtime_image(self, client, env_kind: str, runtime_image: str):
        try:
            client.images.get(runtime_image)
            return
        except ImageNotFound:
            context = self.build_contexts.get(env_kind)
            if context and (context / "Dockerfile").exists():
                client.images.build(path=str(context), tag=runtime_image, rm=True)
                return
            client.images.pull(runtime_image)

    def _build_name(self, scan_id: str, pov_id: str) -> str:
        return f"autopov_{self._slugify(scan_id)}_{self._slugify(pov_id)}"

    def _native_build_commands(self, contract: Dict[str, Any]) -> List[str]:
        build_hints = contract.get("build_commands") or []
        if isinstance(build_hints, str):
            build_hints = [build_hints]
        commands = [str(cmd).strip() for cmd in build_hints if str(cmd).strip()]
        if commands:
            return commands
        return [
            'if [ -f /workspace/codebase/CMakeLists.txt ]; then cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" && cmake --build /workspace/codebase/.autopov-cmake-build -j2; fi',
            'if [ -f /workspace/codebase/meson.build ]; then meson setup /workspace/codebase/.autopov-meson-build /workspace/codebase --buildtype=debug || true; meson compile -C /workspace/codebase/.autopov-meson-build; fi',
            'if [ -f /workspace/codebase/Makefile ] || [ -f /workspace/codebase/GNUmakefile ]; then make -C /workspace/codebase -j2; fi',
            'if [ -f /workspace/codebase/build.ninja ]; then ninja -C /workspace/codebase; fi',
        ]

    def _native_binary_locator_script(self) -> str:
        return """find_binary() {
  python3 - <<'PY'
import os
from pathlib import Path
root = Path('/workspace/codebase')
ignored_suffixes = {'.o', '.obj', '.a', '.so', '.dylib', '.dll', '.lib'}
ignored_dirs = {'.git', 'node_modules', 'venv', '.venv', 'results', 'data', 'dist'}
candidates = []
for current_root, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ignored_dirs]
    for name in files:
        full = Path(current_root) / name
        try:
            st = full.stat()
        except OSError:
            continue
        if not full.is_file() or not os.access(full, os.X_OK):
            continue
        if full.suffix.lower() in ignored_suffixes:
            continue
        score = int(st.st_mtime)
        if '/.autopov-cmake-build/' in str(full):
            score += 15
        if '/.autopov-meson-build/' in str(full):
            score += 15
        if '/build/' in str(full):
            score += 5
        if name.lower() in {'a.out', 'main', 'app', 'server'}:
            score += 20
        candidates.append((score, str(full)))
if not candidates:
    raise SystemExit(1)
candidates.sort(reverse=True)
print(candidates[0][1])
PY
}"""

    def _build_execution_shell(self, env_kind: str, runtime_command: List[str], pov_filename: str, exploit_contract: Dict[str, Any], codebase_path: Optional[str]) -> List[str]:
        contract = exploit_contract or {}
        prelude = [
            'set -e',
            'mkdir -p /pov /workspace /workspace/fixtures',
            'export CODEBASE_PATH="${CODEBASE_PATH:-/workspace/codebase}"',
            'export FIXTURE_ROOT="/workspace/fixtures"',
        ]
        if env_kind == 'native' and codebase_path:
            prelude.extend([
                'export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"',
                'export UBSAN_OPTIONS="print_stacktrace=1"',
                'export CFLAGS="${CFLAGS:-} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export CXXFLAGS="${CXXFLAGS:-} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined"',
            ])
            prelude.extend(self._native_build_commands(contract))
            prelude.append(self._native_binary_locator_script())
            prelude.extend([
                'TARGET_BINARY_CANDIDATE="$(find_binary || true)"',
                'if [ -n "$TARGET_BINARY_CANDIDATE" ]; then export TARGET_BINARY="$TARGET_BINARY_CANDIDATE"; export TARGET_BIN="$TARGET_BINARY_CANDIDATE"; fi',
                'if [ -z "${TARGET_BINARY:-}" ]; then echo "[AutoPoV] infrastructure error: failed to build or locate native target binary" >&2; exit 97; fi',
            ])
        if runtime_command and runtime_command[0] == 'bash':
            run_cmd = f'chmod +x /pov/{pov_filename} && /bin/bash /pov/{pov_filename}'
        elif runtime_command[:2] == ['bash', '-lc']:
            run_cmd = runtime_command[2]
        else:
            run_cmd = ' '.join(runtime_command + [f'/pov/{pov_filename}'])
        prelude.append(run_cmd)
        return ['bash', '-lc', '\n'.join(prelude)]

    def run_pov(
        self,
        pov_script: str,
        scan_id: str,
        pov_id: str,
        extra_files: Optional[Dict[str, str]] = None,
        execution_profile: Optional[str] = None,
        target_language: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None,
        codebase_path: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.is_available():
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout='',
                stderr='Docker not available',
                exit_code=-1,
                execution_time_s=0,
                execution_profile=execution_profile or target_language or 'python',
                runtime_image='unavailable',
                validation_method='generic_container_runtime',
                proof_infrastructure_error=True,
                failure_reason='docker-unavailable',
            )

        temp_dir = tempfile.mkdtemp(prefix=f'autopov_{scan_id}_')
        client = None
        container = None
        env_kind = 'python'
        runtime_image = self.image
        script_runtime = 'python'
        start_time = datetime.utcnow()

        try:
            env_kind, runtime_image, runtime_command, pov_filename = self._resolve_runtime(pov_script, execution_profile, target_language, exploit_contract)
            script_runtime = self._detect_script_runtime(pov_script, execution_profile)
            pov_path = os.path.join(temp_dir, pov_filename)
            with open(pov_path, 'w', encoding='utf-8') as f:
                f.write(pov_script)

            if extra_files:
                for filename, content in extra_files.items():
                    file_path = os.path.join(temp_dir, filename)
                    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)

            client = self._get_client()
            self._ensure_runtime_image(client, env_kind, runtime_image)

            contract = exploit_contract or {}
            raw_target_url = str(contract.get('target_url') or contract.get('base_url') or '')
            target_url = self._normalize_target_url_for_container(raw_target_url)
            network_mode = 'bridge' if target_url else 'none'
            fixture_files = self._collect_fixture_files(contract)
            environment = {
                'TARGET_URL': target_url,
                'CODEBASE_PATH': '/workspace/codebase' if codebase_path else '',
                'TARGET_ENTRYPOINT': str(contract.get('target_entrypoint') or ''),
                'TARGET_HTTP_METHOD': str(contract.get('http_method') or 'GET'),
                'FIXTURE_ROOT': '/workspace/fixtures',
                'AUTOPROOF_ENV_KIND': env_kind,
                'AUTOPROOF_SCRIPT_RUNTIME': script_runtime,
            }
            command = self._build_execution_shell(env_kind, runtime_command, pov_filename, contract, codebase_path)

            container_name = self._build_name(scan_id, pov_id)
            container = client.containers.create(
                image=runtime_image,
                command=command,
                name=container_name,
                working_dir='/',
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                network_mode=network_mode,
                extra_hosts={'host.docker.internal': 'host-gateway'},
                environment=environment,
                detach=True
            )

            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode='w') as tar:
                for name in os.listdir(temp_dir):
                    full_path = os.path.join(temp_dir, name)
                    tar.add(full_path, arcname=f'pov/{name}')
                for rel_name, content in fixture_files.items():
                    self._add_text_to_archive(tar, str(Path('workspace/fixtures') / rel_name), content)
                self._add_text_to_archive(tar, 'workspace/fixtures/manifest.json', json.dumps({
                    'fixtures': sorted(fixture_files.keys()),
                    'scan_id': scan_id,
                    'pov_id': pov_id,
                }, indent=2))
                if codebase_path and os.path.isdir(codebase_path):
                    self._add_directory_to_archive(tar, codebase_path, 'workspace/codebase')
            archive_buffer.seek(0)
            container.put_archive('/', archive_buffer.getvalue())
            container.start()

            timeout_hit = False
            try:
                wait_result = container.wait(timeout=self.timeout)
                exit_code = wait_result.get('StatusCode', -1)
            except Exception as e:
                timeout_hit = True
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = -1
                wait_result = {'Error': str(e)}

            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')
            container.remove(force=True)
            container = None

            execution_time = (datetime.utcnow() - start_time).total_seconds()
            indicators = ['VULNERABILITY TRIGGERED']
            indicators.extend(contract.get('success_indicators', []) or [])
            indicators.extend(contract.get('side_effects', []) or [])
            haystack = (stdout + '\n' + stderr).lower()
            vulnerability_triggered = any(str(ind).strip().lower() in haystack for ind in indicators if str(ind).strip())
            infra_error = timeout_hit or exit_code in {97, 125, 126, 127}
            failure_reason = ''
            if timeout_hit:
                failure_reason = str(wait_result.get('Error') or 'docker-timeout')
            elif infra_error:
                failure_reason = stderr or stdout or 'docker-infrastructure-error'
            elif not vulnerability_triggered and exit_code != 0:
                failure_reason = stderr or stdout or 'exploit-did-not-trigger'

            return self._build_result(
                success=exit_code == 0 or vulnerability_triggered,
                vulnerability_triggered=vulnerability_triggered,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                execution_time_s=execution_time,
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime' if env_kind != 'browser' else 'browser_container_runtime',
                proof_infrastructure_error=infra_error,
                failure_reason=failure_reason,
                metadata={
                    'environment_kind': env_kind,
                    'target_url': target_url or None,
                    'fixture_manifest': sorted(fixture_files.keys()),
                },
            )

        except ContainerError as e:
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout=e.stdout.decode('utf-8', errors='ignore') if e.stdout else '',
                stderr=e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e),
                exit_code=e.exit_status,
                execution_time_s=(datetime.utcnow() - start_time).total_seconds(),
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime',
                proof_infrastructure_error=e.exit_status in {97, 125, 126, 127},
                failure_reason=str(e),
                metadata={'environment_kind': env_kind},
            )
        except Exception as e:
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout='',
                stderr=str(e),
                exit_code=-1,
                execution_time_s=(datetime.utcnow() - start_time).total_seconds(),
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime',
                proof_infrastructure_error=True,
                failure_reason=str(e),
                metadata={'environment_kind': env_kind},
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            self._cleanup_pov_resources(scan_id, pov_id)

    def _cleanup_pov_resources(self, scan_id: str, pov_id: str):
        try:
            client = self._get_client()
            container_pattern = f"autopov_{self._slugify(scan_id)}_{self._slugify(pov_id)}"
            containers = client.containers.list(all=True, filters={"name": container_pattern})
            for container in containers:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            try:
                client.volumes.prune()
            except Exception:
                pass
        except Exception:
            pass

    def cleanup_all_pov_resources(self, scan_id: Optional[str] = None):
        try:
            client = self._get_client()
            pattern = f"autopov_{self._slugify(scan_id)}" if scan_id else "autopov_"
            containers = client.containers.list(all=True, filters={"name": pattern})
            for container in containers:
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception:
                    pass
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            try:
                client.api.prune_builds()
            except Exception:
                pass
        except Exception as e:
            print(f"Warning: Docker cleanup failed: {e}")

    def run_with_input(self, pov_script: str, input_data: str, scan_id: str, pov_id: str) -> Dict[str, Any]:
        extra_files = {
            'input_data.txt': input_data,
            'pov_script.py': pov_script,
        }
        wrapper_script = """
import sys
exec(open('/pov/pov_script.py').read())
"""
        extra_files['wrapper.py'] = wrapper_script
        return self.run_pov(wrapper_script, scan_id, pov_id, extra_files=extra_files)

    def run_binary_pov(self, pov_script: str, binary_data: bytes, scan_id: str, pov_id: str, exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        temp_dir = tempfile.mkdtemp(prefix=f'autopov_{scan_id}_')
        try:
            binary_path = os.path.join(temp_dir, 'input.bin')
            with open(binary_path, 'wb') as f:
                f.write(binary_data)
            return self.run_pov(
                pov_script=pov_script,
                scan_id=scan_id,
                pov_id=pov_id,
                extra_files={'input.bin': ''},
                exploit_contract=exploit_contract,
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._cleanup_pov_resources(scan_id, pov_id)

    def batch_run(self, pov_scripts: List[Dict[str, Any]], scan_id: str, progress_callback: Optional[callable] = None) -> List[Dict[str, Any]]:
        results = []
        for i, pov_info in enumerate(pov_scripts):
            result = self.run_pov(
                pov_script=pov_info['script'],
                scan_id=scan_id,
                pov_id=pov_info.get('id', str(i)),
                execution_profile=pov_info.get('execution_profile'),
                target_language=pov_info.get('target_language'),
                exploit_contract=pov_info.get('exploit_contract'),
                codebase_path=pov_info.get('codebase_path'),
            )
            results.append(result)
            if progress_callback:
                progress_callback(i + 1, len(pov_scripts), result)
        return results

    def get_stats(self) -> Dict[str, Any]:
        if not self.is_available():
            return {'available': False}
        try:
            client = self._get_client()
            info = client.info()
            return {
                'available': True,
                'version': info.get('ServerVersion', 'unknown'),
                'containers_running': info.get('ContainersRunning', 0),
                'containers_total': info.get('Containers', 0),
                'images': info.get('Images', 0),
            }
        except Exception as e:
            return {'available': False, 'error': str(e)}


docker_runner = DockerRunner()


def get_docker_runner() -> DockerRunner:
    """Get the global Docker runner instance"""
    return docker_runner
