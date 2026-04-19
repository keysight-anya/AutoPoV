"""
AutoPoV Docker Runner Module
Executes PoV scripts in isolated Docker containers
"""

import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Optional, Any, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

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


class DockerImagePreparationError(DockerRunnerError):
    """Exception raised while preparing Docker runtime images."""
    pass


class DockerRunner:
    """Runs PoV scripts in Docker containers"""

    GENERIC_SELF_REPORTED_MARKERS = {"vulnerability triggered"}
    # Exception markers are only excluded from corroboration when the exploit contract
    # does NOT explicitly declare 'exception' as an oracle type.  Declaring it promotes
    # controlled Python/JS exceptions to valid corroborating evidence.
    GENERIC_EXCEPTION_MARKERS = {"traceback", "referenceerror", "typeerror", "valueerror", "exception"}
    RUNTIME_CRASH_PATTERNS = [
        'addresssanitizer',
        'undefinedbehaviorsanitizer',
        'runtime error:',
        'heap-buffer-overflow',
        'stack-buffer-overflow',
        'global-buffer-overflow',
        'use-after-free',
        'segmentation fault',
        'sigsegv',
        'sigabrt',
        'bus error',
        'core dumped',
        'deadlysignal',
        'abort',
        'null pointer',
    ]

    # Patterns indicating the binary rejected our payload for format/magic reasons
    # BEFORE reaching vulnerable code.  When matched after a failed run, we retry
    # with structurally correct format-aware payloads (Task 0b).
    _FORMAT_REJECTION_RE = re.compile(
        r'unhandled file type'
        r'|premature end of file'
        r'|bad png chunk'
        r'|not a jpeg'
        r'|invalid jpeg'
        r'|not a valid'
        r'|unsupported format'
        r'|cannot open'
        r'|not recognized'
        r'|file format not recognized'
        r'|unknown file type'
        r'|invalid file'
        # jhead-specific: oversized IFD or bad pointer caught before reaching vulnerable loop
        r'|illegally sized exif'
        r'|illegal value pointer'
        r'|bad components count',
        re.IGNORECASE,
    )

    # Map binary name fragments -> preferred file extension for payload selection.
    _BINARY_EXT_MAP = {
        'jhead': '.jpg', 'exiftool': '.jpg', 'tiff': '.tif',
        'convert': '.jpg', 'identify': '.jpg', 'mogrify': '.jpg',
        'ffmpeg': '.jpg', 'ffprobe': '.jpg',
        'mp3': '.mp3', 'pdf': '.pdf',
        'gif': '.gif', 'png': '.png', 'bmp': '.bmp', 'webp': '.webp',
        # XML parsers / well-formedness checkers — payloads must be XML
        'xmlwf': '.xml', 'xmllint': '.xml', 'xmlto': '.xml', 'xml2': '.xml',
        'expat': '.xml', 'libxml': '.xml', 'saxparser': '.xml',
        # JSON parsers
        'cjson': '.json', 'json_check': '.json', 'json_verify': '.json',
        'jansson': '.json', 'jq': '.json', 'json-c': '.json',
        # Archive/compression tools
        'enchive': '.enc', 'gpg': '.enc', 'openssl': '.bin',
        'zip': '.zip', 'unzip': '.zip', 'tar': '.tar', 'gzip': '.gz',
        'zlib': '.gz', 'bzip': '.bz2', 'lz4': '.lz4', 'zstd': '.zst',
    }

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
            "java": settings.DOCKER_JAVA_IMAGE,
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
            "java": self._proof_image_dir("java"),
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
        oracle_reason = 'oracle_matched' if vulnerability_triggered else (failure_reason if failure_reason else 'no_oracle_match')
        # Extract oracle_result from metadata before updating result so it becomes
        # a top-level key (consumed by agent_graph._ensure_staged_runtime_result).
        _oracle_result = (metadata or {}).pop('oracle_result', None) if metadata else None
        _path_relevant = bool((_oracle_result or {}).get('path_relevant', vulnerability_triggered))
        _matched_markers = list((_oracle_result or {}).get('matched_evidence_markers', []))
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
            "execution_stage": "trigger",
            "proof_verdict": "proven" if vulnerability_triggered else "failed",
            "oracle_result": _oracle_result,
            "setup_result": {
                "stage": "setup",
                "success": not proof_infrastructure_error,
                "stdout": "",
                "stderr": failure_reason if proof_infrastructure_error else "",
                "exit_code": 0 if not proof_infrastructure_error else -1,
                "artifacts": [runtime_image] if runtime_image else [],
                "notes": ["generic container runtime prepared"] if not proof_infrastructure_error else ["generic container runtime failed before trigger execution"],
            },
            "trigger_result": {
                "stage": "trigger",
                "success": vulnerability_triggered,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "oracle_reason": oracle_reason,
                "path_relevant": _path_relevant,
                "matched_evidence_markers": _matched_markers,
            },
            **self._classify_failure(infrastructure=proof_infrastructure_error, reason=failure_reason),
        }
        if metadata:
            result.update(metadata)
        return result

    def _slugify(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value or "autopov")
        return cleaned.strip("-._")[:80] or "autopov"

    def _contract_indicators(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        indicators = ["VULNERABILITY TRIGGERED"]
        contract = exploit_contract or {}
        indicators.extend(contract.get("success_indicators", []) or [])
        indicators.extend(contract.get("side_effects", []) or [])
        return [str(ind).strip() for ind in indicators if str(ind).strip()]

    def _extract_structured_runtime_evidence(self, stdout: str, stderr: str) -> Dict[str, Any]:
        combined_lines = [line.strip() for line in (str(stdout or '') + '\n' + str(stderr or '')).splitlines() if line.strip()]
        for line in reversed(combined_lines):
            if not (line.startswith('{') and line.endswith('}')):
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            evidence = [str(item).lower() for item in (payload.get('evidence') or []) if str(item).strip()]
            child_crash = False
            # Check any key whose name contains 'returncode' or 'exit_code' for negative values
            # (covers both the canonical 'returncode' key and harness-specific keys like
            # 'client_returncode', 'child_exit_code', etc. emitted by inline C harnesses).
            for k, v in payload.items():
                k_norm = k.lower().replace('-', '_')
                if ('returncode' in k_norm or 'exit_code' in k_norm) and isinstance(v, int) and v < 0:
                    child_crash = True
                    break
            if any(item.startswith('signal=') for item in evidence):
                child_crash = True
            if any(token in ' '.join(evidence) for token in ['sanitizer_output', 'segfault_text']):
                child_crash = True
            return {'payload': payload, 'child_crash': child_crash, 'evidence': evidence}
        return {'payload': None, 'child_crash': False, 'evidence': []}

    def _exception_oracle_declared(self, exploit_contract: Optional[Dict[str, Any]]) -> bool:
        """Return True when the exploit contract explicitly declares 'exception' as an oracle type."""
        contract = exploit_contract or {}
        proof_plan = contract.get('proof_plan') or {}
        oracles = [str(x).lower() for x in (proof_plan.get('oracle') or []) if str(x).strip()]
        return 'exception' in oracles

    def _normalize_oracle_reason(self, oracle: Dict[str, Any], *, infrastructure: bool = False, timeout_hit: bool = False) -> str:
        if infrastructure:
            return 'timeout' if timeout_hit else 'infrastructure_failure'
        reason = str((oracle or {}).get('reason') or '').strip().lower()
        allowed = {
            'oracle_matched',
            'structured_runtime_crash',
            'runtime_crash_signal',
            'self_report_only',
            'no_oracle_match',
            'environment_failure',
        }
        return reason if reason in allowed else 'no_oracle_match'

    def _evaluate_runtime_oracle(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        exploit_contract: Optional[Dict[str, Any]] = None,
        *,
        asan_disabled: bool = False,
        baseline_exit_code: int = -1,
        baseline_stderr: str = '',
        pov_script: str = '',
    ) -> Dict[str, Any]:
        """Delegate to oracle_policy.evaluate_proof_outcome for taxonomy-agnostic evaluation.

        Adds path relevance, self-report blocking, and asan_disabled baseline comparison
        on top of the legacy RUNTIME_CRASH_PATTERNS list.  The structured-runtime-evidence
        JSON envelope (from inline harness wrappers) is checked as a supplementary signal
        and can promote triggered=True when oracle_policy did not see strong evidence.
        """
        import agents.oracle_policy as _oracle_policy
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
        if target_entrypoint.lower() in {'unknown', 'none', 'n/a', ''}:
            target_entrypoint = ''
        target_binary = str(contract.get('target_binary') or '').strip()
        filepath = str(contract.get('filepath') or '').strip()
        plan = contract.get('proof_plan') or {}
        expected_oracle = str(plan.get('expected_oracle') or '').strip()
        relevance_anchors = [
            str(x).strip()
            for x in (contract.get('relevance_anchors') or [])
            if str(x).strip()
        ]
        # Add probe_binary_name as a fallback relevance anchor so that a real crash
        # whose stacktrace references the binary name still confirms even when
        # target_entrypoint, target_binary, and filepath are all empty/unknown.
        _probe_bin_name = str(contract.get('probe_binary_name') or '').strip()
        if _probe_bin_name and _probe_bin_name not in relevance_anchors:
            relevance_anchors = list(relevance_anchors) + [_probe_bin_name]

        execution_surface = str(
            contract.get('execution_surface') or
            (contract.get('proof_plan') or {}).get('execution_surface') or ''
        ).strip().lower()

        op = _oracle_policy.evaluate_proof_outcome(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            target_entrypoint=target_entrypoint,
            filepath=filepath,
            pov_script=pov_script,  # enables self-report blocking
            expected_oracle=expected_oracle,
            target_binary=target_binary,
            stage='trigger',
            relevance_anchors=relevance_anchors,
            asan_disabled=asan_disabled,
            baseline_exit_code=baseline_exit_code,
            baseline_stderr=baseline_stderr,
            execution_surface=execution_surface,
        )
        # Task 6: For c_library_harness surface, also evaluate behavioral oracle
        # (routes to evaluate_proof_outcome internally for c_library_harness)
        if execution_surface == 'c_library_harness' and not op.get('triggered'):
            _beh_op = _oracle_policy.evaluate_behavioral_proof_outcome(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                execution_surface=execution_surface,
                target_entrypoint=target_entrypoint,
                filepath=filepath,
                pov_script=pov_script,
                expected_oracle=expected_oracle,
                target_binary=target_binary,
                relevance_anchors=relevance_anchors,
            )
            if _beh_op.get('triggered'):
                op = _beh_op

        triggered = op['triggered']
        reason = op['reason']
        self_report_only = op.get('self_report_only', False)

        # Structured runtime evidence: JSON envelope emitted by inline C harness wrappers.
        # If oracle_policy did not confirm but the harness signals a child crash,
        # promote to triggered so this path is not silently swallowed.
        structured_runtime = self._extract_structured_runtime_evidence(stdout, stderr)
        if structured_runtime.get('child_crash') and not triggered:
            triggered = True
            reason = 'structured_runtime_crash'

        return {
            'triggered': triggered,
            'matched_markers': op.get('matched_evidence_markers', []),
            'reason': reason,
            'self_report_only': self_report_only,
            'structured_runtime_evidence': structured_runtime.get('payload'),
            # Full oracle_policy result — consumed by _build_result → oracle_result top-level key
            'oracle_result': op,
        }

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
        if profile in {"java"}:
            return "java"
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
        if "public class " in script and "public static void main" in script:
            return "java"
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
        # Task 4C: C library harness — execution_surface or probe_surface_type signals a pure C lib.
        # EXCEPTION: if a real binary path is already known (probe_binary_path / target_binary),
        # route as 'native' so we use the full binary-locator+build path, not the harness.
        _exec_surf = str(contract.get('execution_surface') or '').strip().lower()
        _repo_surf = str(contract.get('repo_surface_class') or '').strip().lower()
        _known_bin = (
            str(contract.get('probe_binary_path') or '').strip()
            or str(contract.get('probe_binary_name') or '').strip()
            or str(contract.get('target_binary') or '').strip()
        )
        if (_exec_surf == 'c_library_harness' or _repo_surf == 'library_c') and not _known_bin:
            return 'c_library_harness'
        if language in {"c", "cpp", "c++"} or profile in {"native", "binary", "c", "cpp", "c++"}:
            return "native"
        if language in {"java"} or profile in {"java"}:
            return "java"
        if script_runtime == "java":
            return "java"
        if script_runtime == "node" and (profile in {"web", "http", "javascript", "node", "typescript"} or language in {"javascript", "typescript", "node"} or target_entrypoint.startswith("/") or target_entrypoint.startswith("http") or not profile):
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
        # Task 4C: c_library_harness uses the native image
        if env_kind == 'c_library_harness':
            runtime_image = self.runtime_images.get('native') or self.runtime_images.get('c_library_harness') or self.image
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
        elif script_runtime == "java":
            # Compile and run the PoV; class name is derived from the public class declaration.
            # The PoV generator is instructed to name the class 'AutoPoV'.
            runtime_command = ["bash", "-lc", "cd /pov && javac pov.java && java AutoPoV"]
            pov_filename = "pov.java"
        else:
            runtime_command = ["python3"]
            pov_filename = "pov.py"
        return env_kind, runtime_image, runtime_command, pov_filename

    def _repair_runtime_script(self, pov_script: str, *, script_runtime: str, env_kind: str) -> str:
        script = str(pov_script or '')
        if script_runtime != 'python' or not script:
            return script
        if '.stdin.close()' in script and '.communicate(' in script:
            script = re.sub(r'(?m)^[ \t]*\w+\.stdin\.close\(\)[ \t]*$', '# AutoPoV repaired closed-stdin before communicate', script)
        return script

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
                self._prepare_runtime_image_with_cli(
                    ["docker", "build", "-t", runtime_image, str(context)],
                    runtime_image=runtime_image,
                    action="build",
                )
                return
            self._prepare_runtime_image_with_cli(
                ["docker", "pull", runtime_image],
                runtime_image=runtime_image,
                action="pull",
            )

    def _prepare_runtime_image_with_cli(self, command: List[str], *, runtime_image: str, action: str) -> None:
        timeout_s = max(1, int(settings.DOCKER_IMAGE_PREP_TIMEOUT))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DockerImagePreparationError(
                f"Docker image {action} timed out after {timeout_s}s for {runtime_image}"
            ) from exc
        except FileNotFoundError as exc:
            raise DockerImagePreparationError(
                f"Docker CLI is not available for runtime image {action}: {runtime_image}"
            ) from exc

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            stdout = (completed.stdout or "").strip()
            detail = stderr or stdout or f"docker {action} failed with exit code {completed.returncode}"
            raise DockerImagePreparationError(
                f"Failed to {action} runtime image {runtime_image}: {detail}"
            )

    def _parse_subcommands_from_help_text(self, help_text: str) -> List[str]:
        """Parse CLI subcommands from a binary's --help / usage output.
        Looks for a 'Commands:' section and collects the first word of each entry.
        Same logic as verifier._extract_subcommands_from_surface but self-contained.
        """
        if not help_text or 'command' not in help_text.lower():
            return []
        found: List[str] = []
        collecting = False
        for line in help_text.splitlines():
            m = re.search(r'commands?\s*(?:\([^)]*\))?\s*:(.*)', line, re.IGNORECASE)
            if m:
                raw = re.split(r'[\s,]+', m.group(1))
                inline = [t.strip().strip(',') for t in raw if t.strip() and not t.strip().startswith('-')]
                if inline:
                    return inline
                collecting = True
                continue
            if collecting:
                stripped = line.strip()
                if not stripped or stripped.startswith('[') or stripped.startswith('('):
                    break
                if stripped.startswith('-'):
                    continue
                tok = stripped.split()[0].strip(',').strip()
                if tok and not tok.startswith('-') and not tok.endswith(':'):
                    found.append(tok)
        return found

    def _extract_help_text_from_stdout(self, stdout: str) -> str:
        """Extract the CLI --help output captured between AUTOPOV_HELP_TEXT sentinels."""
        begin_marker = 'AUTOPOV_HELP_TEXT_BEGIN'
        end_marker = 'AUTOPOV_HELP_TEXT_END'
        lines = (stdout or '').splitlines()
        try:
            start = next(i for i, l in enumerate(lines) if l.strip() == begin_marker)
            end = next(i for i, l in enumerate(lines) if i > start and l.strip() == end_marker)
            return '\n'.join(lines[start + 1:end]).strip()
        except StopIteration:
            return ''

    def _extract_preflight_surface_from_stdout(self, stdout: str) -> str:
        """Parse the AUTOPOV_PREFLIGHT_SURFACE=<value> sentinel line from container stdout."""
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_PREFLIGHT_SURFACE='):
                return line[len('AUTOPOV_PREFLIGHT_SURFACE='):].strip()
        return ''

    def _extract_binary_path_from_stdout(self, stdout: str) -> str:
        """Parse the AUTOPOV_BINARY=<path> sentinel line emitted by the container prelude.
        Returns the resolved absolute binary path, or '' if not found.
        """
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_BINARY='):
                return line[len('AUTOPOV_BINARY='):].strip()
        return ''

    def _extract_build_status_from_stdout(self, stdout: str) -> Dict[str, Any]:
        """Parse AUTOPOV_BUILD_STATUS, AUTOPOV_BUILD_LOG and AUTOPOV_ASAN_DISABLED sentinels.

        Returns a dict with keys:
          - 'build_status':  'success' | 'failed' | 'unknown'
          - 'build_log':     last N lines of build output (pipe-separated, '' when absent)
          - 'asan_disabled': True when AUTOPOV_ASAN_DISABLED=1 sentinel is present
        """
        status = 'unknown'
        log = ''
        asan_disabled = False
        for line in (stdout or '').splitlines():
            line = line.strip()
            if line.startswith('AUTOPOV_BUILD_STATUS='):
                status = line[len('AUTOPOV_BUILD_STATUS='):].strip()
            elif line.startswith('AUTOPOV_BUILD_LOG='):
                log = line[len('AUTOPOV_BUILD_LOG='):].strip().replace('|', '\n')
            elif line.startswith('AUTOPOV_ASAN_DISABLED='):
                asan_disabled = line[len('AUTOPOV_ASAN_DISABLED='):].strip() == '1'
        return {'build_status': status, 'build_log': log, 'asan_disabled': asan_disabled}

    def _strip_help_text_sentinels(self, stdout: str) -> str:
        """Remove the AUTOPOV_HELP_TEXT sentinel block, the AUTOPOV_BINARY sentinel line,
        and the AUTOPOV_BUILD_STATUS/AUTOPOV_BUILD_LOG sentinel lines from stdout so the
        PoV oracle only sees actual exploit output."""
        import re
        # Strip the help-text block
        cleaned = re.sub(
            r'AUTOPOV_HELP_TEXT_BEGIN\n.*?\nAUTOPOV_HELP_TEXT_END\n?',
            '',
            stdout or '',
            flags=re.DOTALL,
        )
        # Strip the binary-path sentinel line
        cleaned = re.sub(r'^AUTOPOV_BINARY=.*\n?', '', cleaned, flags=re.MULTILINE)
        # Strip build-status sentinel lines
        cleaned = re.sub(r'^AUTOPOV_BUILD_STATUS=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_BUILD_LOG=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_ASAN_DISABLED=.*\n?', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'^AUTOPOV_PREFLIGHT_SURFACE=.*\n?', '', cleaned, flags=re.MULTILINE)
        return cleaned

    def _build_name(self, scan_id: str, pov_id: str) -> str:
        return f"autopov_{self._slugify(scan_id)}_{self._slugify(pov_id)}"

    def _native_auto_dep_resolver(self) -> str:
        """
        Returns a shell fragment that auto-installs missing C/C++ build
        dependencies by scanning the codebase's #include directives and
        using apt-file to map headers → packages, then apt-get installing
        anything not already present.  Runs silently; never aborts the build
        if resolution fails (all errors are suppressed with || true).
        """
        return r"""
# ── AutoPoV: automatic C/C++ dependency resolution ─────────────────────────
_autopov_resolve_deps() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 0
  # Collect all unique system headers used in C/C++ source files
  local HEADERS
  HEADERS=$(grep -rh '^#include[[:space:]]*<' "$CB" --include='*.c' --include='*.h' \
    --include='*.cpp' --include='*.cc' --include='*.cxx' --include='*.hpp' 2>/dev/null \
    | sed 's/.*<\([^>]*\)>.*/\1/' | sort -u)
  [ -z "$HEADERS" ] && return 0
  # Check if apt-file is available (it is in autopov/proof-native)
  command -v apt-file >/dev/null 2>&1 || return 0
  # Cap to 20 unique headers to prevent slow apt-file lookups for large codebases
  HEADERS=$(echo "$HEADERS" | head -20)
  local MISSING_PKGS=""
  while IFS= read -r HEADER; do
    [ -z "$HEADER" ] && continue
    # Skip headers that already exist on the system
    if python3 -c "import ctypes.util; import os; \
      found = any(os.path.exists(p+'/'+\"$HEADER\") \
        for p in ['/usr/include','/usr/local/include','/usr/include/x86_64-linux-gnu']); \
      exit(0 if found else 1)" 2>/dev/null; then
      continue
    fi
    # Use apt-file to find which package provides this header
    local PKG
    PKG=$(timeout 5 apt-file search --fixed-string "$HEADER" 2>/dev/null \
      | grep -E '^[a-z][^:]+: /usr/include/' \
      | grep -v '\-dbg\|\-doc\|\-examples\|lib32\|lib64\|libx32' \
      | head -1 | cut -d: -f1 | tr -d ' ')
    [ -z "$PKG" ] && continue
    # Only queue -dev packages or packages ending in -dev
    echo "$PKG" | grep -qE '\-dev$|^lib.*-dev' || continue
    MISSING_PKGS="$MISSING_PKGS $PKG"
  done <<< "$HEADERS"
  if [ -n "$MISSING_PKGS" ]; then
    echo "[AutoPoV] Installing missing C/C++ dependencies:$MISSING_PKGS" >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $MISSING_PKGS >/dev/null 2>&1 || true
  fi
}
_autopov_resolve_deps || true
# ────────────────────────────────────────────────────────────────────────────
"""

    def _native_build_tool_resolver(self) -> str:
        """
        Returns a shell fragment that auto-installs missing BUILD TOOLS (flex,
        bison, python3-dev, nasm, etc.) by scanning the codebase's CMakeLists.txt,
        Makefile, and configure.ac for explicit build-tool invocations.

        Complements _native_auto_dep_resolver() which handles -dev header packages
        discovered via #include scanning.  This resolver handles tools that must be
        present on PATH before cmake/make can even configure (e.g. flex, bison).
        Runs silently; never aborts the build (all errors suppressed with || true).
        """
        return r"""
# ── AutoPoV: build-tool dependency resolver ─────────────────────────────────
_autopov_build_tool_resolver() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 0
  local PKGS=""
  # Read all common build manifests at once
  local CONTENT
  CONTENT=$(cat "$CB/CMakeLists.txt" "$CB/Makefile" "$CB/configure.ac" \
               "$CB/configure.in" "$CB/Makefile.am" 2>/dev/null || true)
  [ -z "$CONTENT" ] && return 0
  # flex / lex
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(FLEX|FLEX_TARGET|AC_PROG_LEX' \
    && ! command -v flex >/dev/null 2>&1 && PKGS="$PKGS flex"
  # bison / yacc
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(BISON|BISON_TARGET|AC_PROG_YACC' \
    && ! command -v bison >/dev/null 2>&1 && PKGS="$PKGS bison"
  # python3-dev (needed when CMake probes Python headers)
  echo "$CONTENT" | grep -qiE 'FindPython3|python3-config|Python3_INCLUDE|python-dev' \
    && ! dpkg -s python3-dev >/dev/null 2>&1 && PKGS="$PKGS python3-dev"
  # nasm
  echo "$CONTENT" | grep -qiE '\bnasm\b' \
    && ! command -v nasm >/dev/null 2>&1 && PKGS="$PKGS nasm"
  # yasm
  echo "$CONTENT" | grep -qiE '\byasm\b' \
    && ! command -v yasm >/dev/null 2>&1 && PKGS="$PKGS yasm"
  # gettext / intltool
  echo "$CONTENT" | grep -qiE 'AC_PROG_INTLTOOL|AM_GNU_GETTEXT' \
    && ! command -v autopoint >/dev/null 2>&1 && PKGS="$PKGS gettext"
  # pkg-config
  echo "$CONTENT" | grep -qiE 'PKG_CHECK_MODULES|pkg-config' \
    && ! command -v pkg-config >/dev/null 2>&1 && PKGS="$PKGS pkg-config"
  # autotools (autoreconf / automake)
  echo "$CONTENT" | grep -qiE 'AM_INIT_AUTOMAKE|autoreconf' \
    && ! command -v autoreconf >/dev/null 2>&1 && PKGS="$PKGS dh-autoreconf"
  [ -z "$PKGS" ] && return 0
  echo "[AutoPoV] Installing missing build tools:$PKGS" >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS \
    >/dev/null 2>&1 || true
}
_autopov_build_tool_resolver || true
# ─────────────────────────────────────────────────────────────────────────────
"""

    def _infer_ext_from_contract(self, contract: Dict[str, Any]) -> str:
        """Infer a file extension hint from binary name or contract for format-payload selection."""
        binary_name = (
            str(contract.get('probe_binary_name') or '')
            or str(contract.get('target_binary') or '')
            or str(contract.get('target_entrypoint') or '')
        ).lower()
        for fragment, ext in self._BINARY_EXT_MAP.items():
            if fragment in binary_name:
                return ext
        return '.bin'

    def _run_with_format_aware_payloads(
        self,
        binary_path: str,
        ext: str,
        contract: Optional[Dict[str, Any]],
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """Re-run the binary with structurally valid format-aware payloads.

        This method runs the binary DIRECTLY on the host (via subprocess).  It is
        intended for use only when the binary is accessible on the host file system
        (e.g., in a shared volume / WSL mount path).  For container-internal binaries,
        the retry is instead injected into the generated PoV script by verifier.py
        (Task 0 / Task 0b of the plan).

        Returns a dict with at least 'triggered' (bool) and 'reason' (str).
        If no payload triggers, returns triggered=False, reason='format_retry_exhausted'.
        """
        import agents.verifier as _verifier
        payloads = _verifier.get_format_payloads(ext)
        crash_codes = {134, 139, -11, -6}
        for payload in payloads:
            try:
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as _tf:
                    _tf.write(payload)
                    payload_path = _tf.name
                try:
                    r = subprocess.run(
                        [binary_path, payload_path],
                        capture_output=True,
                        timeout=timeout,
                    )
                    oracle = self._evaluate_runtime_oracle(
                        r.stdout.decode('utf-8', errors='replace') if r.stdout else '',
                        r.stderr.decode('utf-8', errors='replace') if r.stderr else '',
                        r.returncode,
                        contract,
                    )
                    if oracle.get('triggered') or r.returncode in crash_codes:
                        oracle['triggered'] = True
                        oracle['reason'] = oracle.get('reason') or 'format_corrected_crash'
                        return oracle
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    try:
                        os.unlink(payload_path)
                    except OSError:
                        pass
            except Exception:
                continue
        # For JPEG targets: also try argv-based exploits that require specific flags.
        # jhead CVE-2021-3496 / imgfile.c:448 sprintf stack overflow:
        #   jhead -n%99i <file>  =>  sprintf(num/*16*/, "%99d", 1) = stack-buffer-overflow
        if ext in ('.jpg', '.jpeg'):
            import agents.verifier as _verifier2
            argv_payloads = _verifier2.get_format_payloads(ext)
            argv_flags_list = ['-n%99i', '-n%9999i']
            for _argv_flags in argv_flags_list:
                for _payload in argv_payloads[:2]:  # only need a few valid JPEGs
                    try:
                        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as _tf:
                            _tf.write(_payload)
                            _ppath = _tf.name
                        try:
                            _r = subprocess.run(
                                [binary_path, _argv_flags, _ppath],
                                capture_output=True,
                                timeout=timeout,
                            )
                            _oracle = self._evaluate_runtime_oracle(
                                _r.stdout.decode('utf-8', errors='replace') if _r.stdout else '',
                                _r.stderr.decode('utf-8', errors='replace') if _r.stderr else '',
                                _r.returncode,
                                contract,
                            )
                            if _oracle.get('triggered') or _r.returncode in crash_codes:
                                _oracle['triggered'] = True
                                _oracle['reason'] = _oracle.get('reason') or 'argv_stack_overflow'
                                return _oracle
                        except subprocess.TimeoutExpired:
                            pass
                        finally:
                            try:
                                os.unlink(_ppath)
                            except OSError:
                                pass
                    except Exception:
                        continue
        return {'triggered': False, 'reason': 'format_retry_exhausted', 'signal_class': 'non_evidence'}

    def _build_tiered_confirmation_pov(
        self,
        binary_path: str,
        ext: str,
        contract: Optional[Dict[str, Any]],
        run_valgrind: bool = True,
        run_repeated_crash: bool = True,
    ) -> str:
        """Build a minimal Python PoV script that runs the tiered confirmation stack.

        Used by the tiered-confirmation tier in run_pov() to spin up a second container
        run after the first attempt fails.  The script:
          1. Iterates over format-aware payloads for *ext*.
          2. Re-runs under Valgrind if available (Task 1).
          3. Runs 3x for consistent crash confirmation (Task 3).
        The script emits 'VULNERABILITY TRIGGERED' on success and returns 0.
        """
        import agents.verifier as _verifier
        payloads = _verifier.get_format_payloads(ext)
        # Serialize payloads as a Python list literal for embedding in the script.
        payload_reprs = ', '.join(repr(p) for p in payloads)
        crash_codes_str = '(134, 139, -11, -6)'
        run_valgrind_str = str(run_valgrind)
        run_repeated_crash_str = str(run_repeated_crash)
        return f'''import os, subprocess, sys, tempfile

TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') or {binary_path!r}
CRASH_CODES = {crash_codes_str}
RUNTIME_CRASH_MARKERS = (
    'heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free',
    'double-free', 'runtime error:', 'Segmentation fault', 'SIGSEGV',
    '==ERROR: AddressSanitizer', 'SUMMARY: AddressSanitizer',
    'Invalid read of size', 'Invalid write of size', 'Use of uninitialised',
)

def _is_crash(stdout, stderr, rc):
    combined = (stdout or '') + (stderr or '')
    return rc in CRASH_CODES or any(m.lower() in combined.lower() for m in RUNTIME_CRASH_MARKERS)

PAYLOADS = [{payload_reprs}]

def main():
    binary = TARGET_BINARY
    if not binary or not os.path.isfile(binary):
        sys.stderr.write('[AutoPoV-tier] binary not found: ' + repr(binary) + '\\n')
        return 1
    best_payload = None
    for payload in PAYLOADS:
        with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as tf:
            tf.write(payload)
            ppath = tf.name
        try:
            r = subprocess.run([binary, ppath], capture_output=True, timeout=15)
            stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
            stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
            if _is_crash(stdout, stderr, r.returncode):
                sys.stdout.write(stdout)
                sys.stderr.write(stderr)
                print('VULNERABILITY TRIGGERED')
                return 0
            # Keep best payload (first that didn't get rejected by format check)
            from_fmt_rejection = any(p in stdout+stderr for p in [
                'Unhandled file type', 'Premature end of file', 'bad PNG chunk',
                'Not a JPEG', 'invalid jpeg', 'not a valid', 'unsupported format',
            ])
            if not from_fmt_rejection and best_payload is None:
                best_payload = (payload, ppath)
                ppath = None  # don't unlink yet
        except subprocess.TimeoutExpired:
            pass
        finally:
            if ppath:
                try: os.unlink(ppath)
                except OSError: pass
    # For JPEG targets: try argv-based stack overflow via -n format flag.
    # imgfile.c:448: sprintf(num[16], pat, ++RenameSequence) where pat="%99d" from "-n%99i"
    # This gives a deterministic stack-buffer-overflow on any valid JPEG with ASan build.
    if {ext!r} in ('.jpg', '.jpeg'):
        for _flags in ('-n%99i', '-n%9999i'):
            for _p in (PAYLOADS[0],) + (tuple(PAYLOADS[1:2]) if len(PAYLOADS) > 1 else ()):
                with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as _tf:
                    _tf.write(_p)
                    _pp = _tf.name
                try:
                    _r = subprocess.run([binary, _flags, _pp], capture_output=True, timeout=15)
                    _out = _r.stdout.decode('utf-8', errors='replace') if _r.stdout else ''
                    _err = _r.stderr.decode('utf-8', errors='replace') if _r.stderr else ''
                    if _is_crash(_out, _err, _r.returncode):
                        sys.stdout.write(_out)
                        sys.stderr.write(_err)
                        print('VULNERABILITY TRIGGERED')
                        return 0
                except subprocess.TimeoutExpired:
                    pass
                finally:
                    try: os.unlink(_pp)
                    except OSError: pass
    if best_payload is None:
        # All payloads were format-rejected; use first payload regardless
        best_payload = (PAYLOADS[0], None)
    payload_bytes, payload_file = best_payload
    if payload_file is None:
        with tempfile.NamedTemporaryFile(suffix={ext!r}, delete=False) as tf:
            tf.write(payload_bytes)
            payload_file = tf.name
    try:
        # Tier 1: Valgrind
        if {run_valgrind_str} and subprocess.run(['which', 'valgrind'], capture_output=True).returncode == 0:
            vg = subprocess.run(
                ['valgrind', '--error-exitcode=42', '--track-origins=yes',
                 '--leak-check=no', binary, payload_file],
                capture_output=True, timeout=90
            )
            vg_out = vg.stdout.decode('utf-8', errors='replace') if vg.stdout else ''
            vg_err = vg.stderr.decode('utf-8', errors='replace') if vg.stderr else ''
            if _is_crash(vg_out, vg_err, vg.returncode):
                sys.stdout.write(vg_out)
                sys.stderr.write(vg_err)
                print('VULNERABILITY TRIGGERED')
                return 0
        # Tier 3: Repeated crash
        if {run_repeated_crash_str}:
            hits = 0
            for _ in range(3):
                try:
                    rr = subprocess.run([binary, payload_file], capture_output=True, timeout=15)
                    if rr.returncode in CRASH_CODES:
                        hits += 1
                except subprocess.TimeoutExpired:
                    pass
            if hits == 3:
                print('VULNERABILITY TRIGGERED')
                return 0
    finally:
        try: os.unlink(payload_file)
        except OSError: pass
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''

    def _run_pov_with_valgrind(
        self,
        binary_path: str,
        payload_path: str,
        contract: Optional[Dict[str, Any]],
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Re-run binary under Valgrind memcheck and return an oracle result dict.

        Valgrind emits structured error lines (==PID== Invalid read of size N)
        to stderr.  The oracle_policy _SANITIZER_STRUCTURAL regex recognises
        these as 'strong' evidence (Task 2).  Called when the first run returned
        ambiguous_signal (Task 1).

        Note: binary_path and payload_path must be accessible on the calling host
        (not container-internal paths).  This method is used when the DockerRunner
        runs locally (e.g., integration tests) or via the tiered PoV script approach.
        """
        if not shutil.which('valgrind'):
            return {'triggered': False, 'reason': 'valgrind_not_available', 'signal_class': 'non_evidence'}
        cmd = [
            'valgrind',
            '--error-exitcode=42',
            '--track-origins=yes',
            '--leak-check=no',  # faster; we want mem errors not leaks
            binary_path,
            payload_path,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            vg_stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
            vg_stderr = r.stderr.decode('utf-8', errors='replace') if r.stderr else ''
            oracle = self._evaluate_runtime_oracle(vg_stdout, vg_stderr, r.returncode, contract)
            if oracle.get('triggered'):
                oracle['reason'] = 'valgrind_confirmed'
            return oracle
        except subprocess.TimeoutExpired:
            return {'triggered': False, 'reason': 'valgrind_timeout', 'signal_class': 'ambiguous'}
        except Exception:
            return {'triggered': False, 'reason': 'valgrind_error', 'signal_class': 'non_evidence'}

    def _confirm_by_repeated_crash(
        self,
        binary_path: str,
        payload_path: str,
        contract: Optional[Dict[str, Any]],
        crash_codes: Tuple[int, ...] = (134, 139, -11, -6),
        n: int = 3,
        timeout: int = 15,
    ) -> bool:
        """Run the binary N times with the same payload and check for consistent crash exit codes.

        3 independent SIGSEGV/SIGABRT results is strong evidence of a real crash
        (not a flaky environment exit).  Called as last resort when Valgrind produces
        no structured errors (Task 3).

        Note: binary_path and payload_path must be accessible on the calling host
        (not container-internal paths).  Used by _build_tiered_confirmation_pov() for
        in-container execution.
        """
        hits = 0
        for _ in range(n):
            try:
                r = subprocess.run(
                    [binary_path, payload_path],
                    capture_output=True,
                    timeout=timeout,
                )
                if r.returncode in crash_codes:
                    hits += 1
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        return hits == n

    def _native_build_commands(self, contract: Dict[str, Any]) -> List[str]:
        build_hints = contract.get("build_commands") or []
        if isinstance(build_hints, str):
            build_hints = [build_hints]
        commands = [str(cmd).strip() for cmd in build_hints if str(cmd).strip()]
        if commands:
            return commands
        return [
            # Step -1: ensure Valgrind is available for non-ASan crash confirmation fallback.
            # Already in the Dockerfile but this guards against stale proof images.
            'command -v valgrind >/dev/null 2>&1 || apt-get install -y --no-install-recommends valgrind 2>/dev/null || true',
            # Step 0: auto-install any missing C/C++ library headers before building
            self._native_auto_dep_resolver(),
            # Step 0e: auto-install missing build tools (flex/bison/python3-dev/nasm/etc.)
            # by scanning CMakeLists.txt/Makefile/configure.ac for build-tool invocations.
            # Complements _native_auto_dep_resolver() which only handles -dev header pkgs.
            self._native_build_tool_resolver(),
            # Step 0b: stub a RELEASE or VERSION file when the repo generates its version
            # string from VCS metadata that is absent in the container snapshot.  Generic
            # heuristic: any repo that has neither .git nor a RELEASE/VERSION file and
            # uses a configure/Makefile-based build may fail on version-file generation.
            'if [ ! -d /workspace/codebase/.git ] && [ ! -f /workspace/codebase/RELEASE ] && [ ! -f /workspace/codebase/VERSION ]; then echo "autopov-stub" > /workspace/codebase/RELEASE; fi',
            # Step 0c: initialise submodules when the repo depends on them
            'if [ -f /workspace/codebase/.gitmodules ]; then git -C /workspace/codebase submodule update --init --recursive 2>/dev/null || true; fi',
            # Step 0d: run autoconf / autogen.sh when configure does not yet exist
            '([ -f /workspace/codebase/configure ] || ! [ -f /workspace/codebase/Makefile.am ]) || (cd /workspace/codebase && ([ -x ./autogen.sh ] && ./autogen.sh 2>/dev/null || autoconf 2>/dev/null || autoreconf -i 2>/dev/null) || true)',
            # CMake: prefer clang for sanitizer builds (better ASan compatibility than gcc on Ubuntu 24.04)
            'if [ -f /workspace/codebase/CMakeLists.txt ]; then'
            '  cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '    -DCMAKE_BUILD_TYPE=Debug'
            '    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++'
            '    -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"'
            '    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"'
            '  && cmake --build /workspace/codebase/.autopov-cmake-build -j2'
            '  || cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
            '       -DCMAKE_BUILD_TYPE=Debug'
            '  && cmake --build /workspace/codebase/.autopov-cmake-build -j2; fi',
            'if [ -f /workspace/codebase/meson.build ]; then meson setup /workspace/codebase/.autopov-meson-build /workspace/codebase --buildtype=debug -Db_sanitize=address,undefined || true; meson compile -C /workspace/codebase/.autopov-meson-build; fi',
            # Patch Makefile to use ?= so command-line CFLAGS/CC/LDFLAGS overrides are not ignored
            # by projects that define these variables with = (immediate assignment) rather than ?=.
            # Also strip -Werror from any hardcoded CFLAGS/CXXFLAGS in the Makefile so that
            # injected ASan/sanitizer flags don't cause warnings-as-errors build failures
            # (e.g. kore uses -Werror + -fstack-protector-all which conflicts with ASan).
            # The sed is idempotent: running it twice on a ?= line is a no-op.
            # After patching, run 'make clean' to force a full rebuild with the new flags.
            # Detect Makefile under any common casing (Makefile, makefile, GNUmakefile)
            '_MF=""; for _MF_TRY in /workspace/codebase/Makefile /workspace/codebase/makefile /workspace/codebase/GNUmakefile; do [ -f "$_MF_TRY" ] && _MF="$_MF_TRY" && break; done',
            'if [ -n "$_MF" ]; then'
            '  sed -i "s/^\\(CFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CXXFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CC[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(CXX[[:space:]]*\\):*=[[:space:]]*/\\1?= /g;'
            '         s/^\\(LDFLAGS[[:space:]]*\\):*=[[:space:]]*/\\1?= /g" "$_MF" || true;'
            '  sed -i "s/-Werror[^ ]*//g" "$_MF" || true; fi',
            'if [ -n "$_MF" ]; then make -C /workspace/codebase clean 2>/dev/null || true; fi',
            # ASan build strategy for Makefile projects:
            # 1. Use clang (better ASan ABI than gcc on Ubuntu 24.04 — avoids the
            #    __asan_option_detect_stack_use_after_return relocation error in .text).
            # 2. Strip -fstack-protector-all from CFLAGS before injecting ASan because
            #    that flag conflicts with ASan's stack redzoning on some projects.
            # 3. Fall back to gcc-based ASan build, then finally a clean no-sanitizer
            #    build so we always get a runnable binary.
            # 4. Emit AUTOPOV_BUILD_STATUS=success|failed so run_pov can detect build
            #    failures early and skip PoV execution with a clear infra error.
            # IMPORTANT: use a temp-file sentinel (/tmp/_autopov_build_ok) instead of a shell
            # variable to propagate build success across subshells.  Shell variable assignments
            # inside (...) subshells do NOT affect the parent shell, so _AUTOPOV_BUILD_OK=1
            # inside a fallback-chain subshell was silently lost, making every build appear
            # to fail even when the binary was successfully produced.
            # Also wrap the entire chain in `set +e` / `set -e` brackets so individual
            # fallback attempts don't abort the script under `set -e`.
            'if [ -n "$_MF" ]; then'
            '  _STRIPPED_CFLAGS=$(echo "${CFLAGS:-}" | sed "s/-fstack-protector[^ ]*//g");'
            '  rm -f /tmp/_autopov_build_ok;'
            '  set +e;'
            '  export CC="${CC:-clang}";'
            '  export CXX="${CXX:-clang++}";'
            '  export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '  export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '  export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined";'
            '  export ASAN=1;'
            '  make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_asan_clang.log'
            '  && touch /tmp/_autopov_build_ok;'
            '  if [ ! -f /tmp/_autopov_build_ok ]; then'
            '    make -C /workspace/codebase clean 2>/dev/null || true;'
            '    export CC=gcc; export CXX=g++;'
            '    export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '    export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer";'
            '    make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_asan_gcc.log'
            '    && touch /tmp/_autopov_build_ok;'
            '  fi;'
            '  if [ ! -f /tmp/_autopov_build_ok ]; then'
            '    make -C /workspace/codebase clean 2>/dev/null || true;'
            '    unset CC CXX ASAN;'
            '    export CFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fno-omit-frame-pointer";'
            '    export CXXFLAGS="${_STRIPPED_CFLAGS} -O0 -g -fno-omit-frame-pointer";'
            '    unset LDFLAGS;'
            '    make -B -C /workspace/codebase -j2 2>/tmp/_autopov_build_nosan.log'
            '    && touch /tmp/_autopov_build_ok'
            '    && echo "AUTOPOV_ASAN_DISABLED=1";'
            '  fi;'
            '  set -e;'
            '  if [ -f /tmp/_autopov_build_ok ]; then'
            '    echo "AUTOPOV_BUILD_STATUS=success";'
            '  else'
            '    _BUILD_LOG=$(tail -40 /tmp/_autopov_build_nosan.log /tmp/_autopov_build_asan_gcc.log /tmp/_autopov_build_asan_clang.log 2>/dev/null | head -50 | tr "\n" "|");'
            '    echo "AUTOPOV_BUILD_STATUS=failed";'
            '    echo "AUTOPOV_BUILD_LOG=${_BUILD_LOG}";'
            '  fi; fi',
            'if [ -f /workspace/codebase/build.ninja ]; then ninja -C /workspace/codebase; fi',
            # 3a: Cargo.toml — best-effort Rust build (no ASan injection; Rust uses its own sanitizer flags)
            'if [ ! -f /tmp/_autopov_build_ok ] && [ -f /workspace/codebase/Cargo.toml ]; then'
            '  cd /workspace/codebase && cargo build --release 2>/tmp/_autopov_build_cargo.log'
            '  && touch /tmp/_autopov_build_ok || true; fi',
            # 3c: custom build script fallback (build.sh / compile.sh) for non-standard builders
            'if [ ! -f /tmp/_autopov_build_ok ] && ([ -f /workspace/codebase/build.sh ] || [ -f /workspace/codebase/compile.sh ]); then'
            '  _BS="/workspace/codebase/build.sh"; [ -f "$_BS" ] || _BS="/workspace/codebase/compile.sh";'
            '  chmod +x "$_BS" && "$_BS" 2>/tmp/_autopov_build_custom.log && touch /tmp/_autopov_build_ok || true; fi',
            # Step N: post-build ldd check — detect missing shared libraries and try to
            # install them automatically so the binary can actually run.
            # Runs silently; never aborts the build pipeline (|| true everywhere).
            r"""
_autopov_ldd_fix() {
  local BIN="${TARGET_BINARY:-}"
  [ -n "$BIN" ] || BIN="$(find /workspace/codebase -maxdepth 4 -type f -executable ! -name '*.sh' ! -name '*.py' 2>/dev/null | head -1)"
  [ -n "$BIN" ] || return 0
  command -v ldd >/dev/null 2>&1 || return 0
  local MISSING
  MISSING=$(ldd "$BIN" 2>&1 | grep 'not found' | awk '{print $1}') || return 0
  [ -n "$MISSING" ] || return 0
  command -v apt-file >/dev/null 2>&1 || return 0
  local PKGS=""
  for LIB in $MISSING; do
    local P
    P=$(timeout 5 apt-file search --fixed-string "$LIB" 2>/dev/null | grep -v 'dbg\|doc\|dev\|lib32\|lib64\|libx32' | head -1 | cut -d: -f1 | tr -d ' ') || true
    [ -n "$P" ] && PKGS="$PKGS $P"
  done
  [ -n "$PKGS" ] || return 0
  echo "[AutoPoV] Installing missing runtime libs:$PKGS" >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS >/dev/null 2>&1 || true
}
_autopov_ldd_fix || true
""",
        ]

    def _native_binary_locator_script(self) -> str:
        return """find_binary() {
  python3 - <<'PY'
import os
import re
import json
import subprocess
from pathlib import Path

root = Path('/workspace/codebase')
cmake_build = root / '.autopov-cmake-build'
meson_build = root / '.autopov-meson-build'

ignored_suffixes = {'.o', '.obj', '.a', '.so', '.dylib', '.dll', '.lib',
                    '.sh', '.py', '.rb', '.pl', '.js', '.php', '.lua', '.tcl',
                    '.bat', '.cmd', '.ps1'}
ignored_dirs = {'.git', 'node_modules', 'venv', '.venv', 'results', 'data', 'dist'}

# Known helper/tool binary names that should not be selected as the main target.
_TOOL_BINARY_NAMES = {
    'install', 'setup', 'configure', 'autogen', 'libtool',
    'config', 'compat', 'mkinstalldirs', 'depcomp', 'missing', 'compile',
    'ltmain', 'bootstrap', 'aclocal',
}

# ── Build authoritative test-binary deny-set from build system metadata ──────
# These are the exact executables registered as tests by the build system.
# They get score=-999 and can never beat a real target binary.
test_binary_paths = set()  # absolute resolved path strings

# 1. CMake: parse every CTestTestfile.cmake generated after cmake --build
#    Format: add_test(NAME foo COMMAND /abs/path/to/binary [args...])
_CTEST_CMD_RE = re.compile(
    r'add_test\s*\(\s*(?:NAME\s+\S+\s+)?COMMAND\s+([^\s)]+)',
    re.IGNORECASE,
)
if cmake_build.exists():
    for ctest_file in cmake_build.rglob('CTestTestfile.cmake'):
        try:
            text = ctest_file.read_text(errors='replace')
        except OSError:
            continue
        for m in _CTEST_CMD_RE.finditer(text):
            p = Path(m.group(1))
            if not p.is_absolute():
                p = cmake_build / p
            try:
                test_binary_paths.add(str(p.resolve()))
            except OSError:
                test_binary_paths.add(str(p))

# 2. Meson: meson introspect --tests returns JSON list of test executables
if (meson_build / 'meson-info').exists():
    try:
        out = subprocess.check_output(
            ['meson', 'introspect', '--tests', str(meson_build)],
            stderr=subprocess.DEVNULL, timeout=10,
        )
        for entry in json.loads(out):
            cmd = entry.get('cmd', []) or entry.get('exe', [])
            if cmd:
                p = Path(cmd[0])
                try:
                    test_binary_paths.add(str(p.resolve()))
                except OSError:
                    test_binary_paths.add(str(p))
    except Exception:
        pass

# 3. Make: extract TESTS = ... variable from the top-level Makefile
makefile = root / 'Makefile'
if makefile.exists():
    _TESTS_VAR_RE = re.compile(r'^\s*TESTS\s*[+:]?=\s*(.+)', re.MULTILINE)
    try:
        mf_text = makefile.read_text(errors='replace')
        for m in _TESTS_VAR_RE.finditer(mf_text):
            for tok in m.group(1).split():
                if tok.startswith('$') or tok.startswith('#'):
                    continue
                for base in (root, cmake_build, meson_build):
                    candidate = base / tok
                    if candidate.exists():
                        try:
                            test_binary_paths.add(str(candidate.resolve()))
                        except OSError:
                            test_binary_paths.add(str(candidate))
    except OSError:
        pass

# Repo name from env var set by AutoPoV (e.g. 'kore' for jorisvink/kore)
repo_name = os.environ.get('AUTOPOV_REPO_NAME', root.name).lower()
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
        # Block standard suffixes AND versioned shared-object names like
        # libfoo.so.1.7.19 (where Path.suffix == '.19', not '.so').
        _all_suffixes = {s.lower() for s in full.suffixes}
        if full.suffix.lower() in ignored_suffixes or '.so' in _all_suffixes:
            continue
        if '.so' in name.lower():
            continue
        # ── Build-system deny-set: exact match, authoritative, no guessing ──
        try:
            resolved = str(full.resolve())
        except OSError:
            resolved = str(full)
        if resolved in test_binary_paths:
            candidates.append((-999, str(full)))
            continue
        score = int(st.st_mtime)
        if '/.autopov-cmake-build/' in str(full):
            score += 15
        if '/.autopov-meson-build/' in str(full):
            score += 15
        if '/build/' in str(full):
            score += 5
        if name.lower() in {'a.out', 'main', 'app', 'server'}:
            # Only reward generic names when NOT inside a CodeQL/CMake compiler-test dir
            _parts_lower = [p.lower() for p in str(full.relative_to(root)).split(os.sep)]
            if not any(p in ('_codeql_build_dir', 'cmakefiles', 'compilerid', 'compileridcxx', 'compilerc') for p in _parts_lower):
                score += 20
        # Reward binary named after the repo (e.g. 'kore' in jorisvink/kore)
        if name.lower() == repo_name:
            score += 30
        # Penalise binaries whose own name matches a known tool/helper name
        if name.lower() in _TOOL_BINARY_NAMES:
            score -= 40
        # Penalise binaries inside tool/helper subdirs (kodev, tools, scripts, etc.)
        rel = str(full.relative_to(root))
        depth = rel.count(os.sep)
        if depth >= 2:
            score -= 10  # nested deeper than one subdir
        # Penalise known tool/helper subdirectory names
        parts = rel.split(os.sep)
        if any(p.lower() in {'tools', 'scripts', 'contrib', 'util', 'utils', 'test', 'tests', 'examples', 'samples', 'helper', 'helpers', 'build-aux'} for p in parts[:-1]):
            score -= 20
        # Penalise CodeQL intermediate build directory and CMake compiler-test artifacts.
        if any(p in ('_codeql_build_dir', 'CMakeFiles', 'CompilerIdC', 'CompilerIdCXX') for p in parts):
            score -= 60
        # Belt-and-suspenders: penalise autotools helper scripts by filename
        if name.lower() in {'ltmain', 'ltmain.sh'}:
            score -= 60
        candidates.append((score, str(full)))
if not candidates:
    raise SystemExit(1)
candidates.sort(reverse=True)
# If the best candidate has a negative score (only test harnesses / deny-set found),
# emit nothing so the caller falls back to the c_library_harness path.
if candidates[0][0] < 0:
    raise SystemExit(1)
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
        # ── Task 3: surface-adaptive entry-command injection ────────────────────
        # Regardless of env_kind, propagate probe-discovered entry command and base URL
        # into env vars so PoV scripts can use them without guessing.
        _probe_entry = str(contract.get('probe_entry_command') or '').strip()
        _probe_base_url = str(contract.get('probe_base_url') or '').strip()
        _probe_surface = str(contract.get('probe_surface_type') or '').strip().lower()
        if _probe_entry:
            prelude.append(f'export AUTOPOV_ENTRY={_probe_entry!r}')
        if _probe_base_url:
            prelude.append(f'export AUTOPOV_BASE_URL={_probe_base_url!r}')
        if env_kind == 'native' and codebase_path:
            prelude.extend([
                'export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stacktrace=1"',
                'export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"',
                # Prefer clang for ASan builds; it handles fstack-protector-all better
                # than gcc on Ubuntu 24.04 (avoids relocation-in-.text linker error).
                'export CC="${CC:-clang}"',
                'export CXX="${CXX:-clang++}"',
                # Strip -fstack-protector variants before injecting ASan flags
                '_STRIPPED="$(echo "${CFLAGS:-}" | sed \'s/-fstack-protector[^ ]*//g\')"',
                'export CFLAGS="${_STRIPPED} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export CXXFLAGS="${_STRIPPED} -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"',
                'export LDFLAGS="${LDFLAGS:-} -fsanitize=address,undefined"',
            ])
            prelude.extend(self._native_build_commands(contract))
            prelude.append(self._native_binary_locator_script())
            prelude.extend([
                'TARGET_BINARY_CANDIDATE="$(find_binary || true)"',
                'if [ -n "$TARGET_BINARY_CANDIDATE" ]; then export TARGET_BINARY="$TARGET_BINARY_CANDIDATE"; export TARGET_BIN="$TARGET_BINARY_CANDIDATE"; fi',
                # If the probe identified the exact binary, prefer it over the locator result
                'if [ -n "${AUTOPOV_PROBE_BINARY:-}" ] && [ -x "$AUTOPOV_PROBE_BINARY" ]; then export TARGET_BINARY="$AUTOPOV_PROBE_BINARY"; export TARGET_BIN="$AUTOPOV_PROBE_BINARY"; fi',
                # If no real binary found (only test harnesses), fall back to library harness mode
                # so the PoV can still compile an inline C harness against the library.
                'if [ -z "${TARGET_BINARY:-}" ]; then export AUTOPOV_MODE=c_library_harness; export LIB_INCLUDE_PATH="/workspace/codebase"; export LIB_SRC_PATH="/workspace/codebase"; LIB_HEADER=$(find /workspace/codebase -maxdepth 3 -name "*.h" ! -path "*/.git/*" ! -path "*/CMakeFiles/*" | head -5 | tr "\n" ":"); export LIB_HEADERS="${LIB_HEADER%:}"; echo "[AutoPoV] no real CLI binary found — switching to c_library_harness mode" >&2; fi',
                'if [ -z "${TARGET_BINARY:-}" ] && [ "${AUTOPOV_MODE:-}" != "c_library_harness" ]; then echo "[AutoPoV] infrastructure error: failed to build or locate native target binary" >&2; exit 97; fi',
                # Add the binary\'s parent directory to PATH so scripts using the bare
                # binary name (e.g. TARGET_BINARY = \'enchive\') resolve correctly
                # regardless of where the model chose to look it up.
                'export PATH="$(dirname "$TARGET_BINARY"):$PATH"',
                # Emit the resolved binary path so run_pov can parse it from stdout
                # and propagate target_binary_path back to agent_graph / exploit_contract.
                'echo "AUTOPOV_BINARY=$TARGET_BINARY"',
                # Run the binary with no args (most CLI tools print usage/help that way).
                # Falls back to --help for tools that require an explicit flag.
                # Output is captured between sentinels; stripped from oracle stdout.
                'echo "AUTOPOV_HELP_TEXT_BEGIN"',
                '"$TARGET_BINARY" 2>&1 | head -80 || "$TARGET_BINARY" --help 2>&1 | head -80 || true',
                'echo "AUTOPOV_HELP_TEXT_END"',
                # ── Preflight sanity guard (3 s) ────────────────────────────────
                # Run the binary with a tiny random payload to determine the real
                # input surface BEFORE the PoV runs. Emit AUTOPOV_PREFLIGHT_SURFACE
                # so the coordinator can override the PoV generation prompt.
                '_PF_TMPF=$(mktemp /tmp/pf_XXXXXX)',
                'printf "AAAAAAAAAAAAAAAA\\x00BBBBBBBB" > "$_PF_TMPF"',
                # Try file argument first
                '_PF_FILE_OUT=$(timeout 3 "$TARGET_BINARY" "$_PF_TMPF" 2>&1 || true)',
                '_PF_STDIN_OUT=$(printf "AAAAAAAAAAAAAAAA\\x00BBBBBBBB" | timeout 3 "$TARGET_BINARY" 2>&1 || true)',
                # Detect surface: if binary opened the file → file_argument
                '_PF_USAGE_KW="usage:\\|--help\\|no files\\|expects a\\|missing file\\|requires a"',
                'if echo "$_PF_STDIN_OUT" | grep -qi "$_PF_USAGE_KW" && ! echo "$_PF_FILE_OUT" | grep -qi "$_PF_USAGE_KW"; then',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=file_argument"',
                'elif echo "$_PF_FILE_OUT" | grep -qi "$_PF_USAGE_KW" && ! echo "$_PF_STDIN_OUT" | grep -qi "$_PF_USAGE_KW"; then',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=stdin"',
                'else',
                '  echo "AUTOPOV_PREFLIGHT_SURFACE=unknown"',
                'fi',
                'rm -f "$_PF_TMPF"',
            ])
        elif env_kind == 'c_library_harness' and codebase_path:
            # Task 4C: C library harness environment.
            # No binary to locate -- the PoV script compiles its own harness inline.
            # Set up ASan flags + codebase path so the PoV can find headers/libs.
            prelude.extend([
                'export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stacktrace=1"',
                'export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"',
                'export CC="${CC:-clang}"',
                'export CXX="${CXX:-clang++}"',
                'export LIB_INCLUDE_PATH="/workspace/codebase"',
                'export LIB_SRC_PATH="/workspace/codebase"',
                'LIB_HEADER=$(find /workspace/codebase -maxdepth 3 -name "*.h"'
                '  ! -path "*/.git/*" ! -path "*/CMakeFiles/*"'
                '  | head -5 | tr "\n" ":")',
                'export LIB_HEADERS="${LIB_HEADER%:}"',
                # Build the library with ASan so the PoV harness can link against it
                'if [ -f /workspace/codebase/CMakeLists.txt ]; then'
                '  mkdir -p /workspace/codebase/.autopov-cmake-build &&'
                '  cmake -S /workspace/codebase -B /workspace/codebase/.autopov-cmake-build'
                '    -DCMAKE_BUILD_TYPE=RelWithDebInfo'
                '    -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined"'
                '    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"'
                '    -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF -q 2>/dev/null &&'
                '  cmake --build /workspace/codebase/.autopov-cmake-build --parallel 4 2>/dev/null || true;'
                '  export LD_LIBRARY_PATH="/workspace/codebase/.autopov-cmake-build:${LD_LIBRARY_PATH:-}"; fi',
                'if [ -z "${LD_LIBRARY_PATH:-}" ] && [ -f /workspace/codebase/Makefile ]; then'
                '  make -C /workspace/codebase -j4 2>/dev/null || true; fi',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'python' and codebase_path:
            # Auto-install Python dependencies from requirements files found in the codebase.
            # This allows PoVs that import project packages (requests, yaml, jinja2, etc.)
            # to run without pre-baking every possible package into the proof image.
            prelude.append(
                'if [ -d /workspace/codebase ]; then'
                '  for _RF in /workspace/codebase/requirements*.txt /workspace/codebase/requirements/*.txt; do'
                '    [ -f "$_RF" ] && pip3 install --quiet --no-cache-dir --break-system-packages -r "$_RF" 2>/dev/null || true;'
                '  done;'
                '  if [ -f /workspace/codebase/setup.py ] && ! pip3 show "$(python3 -c \"import tomllib,sys; d=tomllib.load(open(\\"/workspace/codebase/pyproject.toml\\",\\"rb\\")); print(d[\\"project\\"][\\"name\\"])\" 2>/dev/null || echo \"__none__\")" >/dev/null 2>&1; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages -e /workspace/codebase 2>/dev/null || true;'
                '  fi;'
                '  if [ -f /workspace/codebase/pyproject.toml ] || [ -f /workspace/codebase/setup.cfg ]; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages -e /workspace/codebase 2>/dev/null || true;'
                '  fi;'
                # Fallback: install by repo name (e.g. 'cherrypy', 'flask', 'httpie').
                # pip install is a no-op when already installed, so this is always safe.
                '  _REPO_PKG=$(basename "${CODEBASE_PATH:-/workspace/codebase}" | tr \'[:upper:]\' \'[:lower:]\' | tr \'_\' \'-\');'
                '  if [ -n "$_REPO_PKG" ] && [ "$_REPO_PKG" != "codebase" ]; then'
                '    pip3 install --quiet --no-cache-dir --break-system-packages "$_REPO_PKG" 2>/dev/null || true;'
                '  fi; fi'
            )
            # Task 3: For web_service surface, auto-start the Python web app before the PoV runs.
            if _probe_surface == 'web_service':
                _ws_port = '8000'
                if _probe_base_url and ':' in _probe_base_url:
                    _port_part = _probe_base_url.rstrip('/').rsplit(':', 1)[-1]
                    if _port_part.isdigit():
                        _ws_port = _port_part
                if _probe_entry:
                    _ws_entry_cmds = [f'_WS_ENTRY={_probe_entry!r}']
                else:
                    _ws_entry_cmds = [
                        '_WS_ENTRY=""',
                        'for _F in /workspace/codebase/app.py /workspace/codebase/server.py /workspace/codebase/main.py /workspace/codebase/run.py /workspace/codebase/wsgi.py; do [ -f "$_F" ] && _WS_ENTRY="$_F" && break || true; done',
                    ]
                prelude.extend(_ws_entry_cmds)
                prelude.extend([
                    f'export PORT={_ws_port!r}',
                    f'export APP_URL="http://localhost:{_ws_port}"',
                    'if [ -n "${_WS_ENTRY:-}" ]; then',
                    '  python3 "$_WS_ENTRY" &',
                    '  _WS_PID=$!',
                    '  _TRIES=0; while [ $_TRIES -lt 20 ]; do',
                    f'    curl -sf "http://localhost:{_ws_port}" -o /dev/null 2>/dev/null && break || true',
                    '    sleep 1; _TRIES=$((_TRIES+1)); done',
                    '  export AUTOPOV_BASE_URL="$APP_URL"',
                    '  export SERVER_PID=$_WS_PID',
                    'fi',
                ])
        elif env_kind == 'java' and codebase_path:
            # Build the Java project inside the container so TARGET_BINARY points to
            # the assembled jar.  Falls back gracefully when no build file is found.
            prelude.extend([
                # Maven build
                'if [ -f /workspace/codebase/pom.xml ]; then'
                '  mvn -f /workspace/codebase/pom.xml package -DskipTests -q'
                '  && JAVA_JAR="$(find /workspace/codebase/target -maxdepth 2 -name "*.jar" ! -name "*-sources.jar" | sort -V | tail -1)"'
                '  && export TARGET_BINARY="$JAVA_JAR"; export TARGET_BIN="$JAVA_JAR"; fi',
                # Gradle build
                'if [ -z "${TARGET_BINARY:-}" ] && ([ -f /workspace/codebase/build.gradle ] || [ -f /workspace/codebase/build.gradle.kts ]); then'
                '  gradle -p /workspace/codebase build -x test -q'
                '  && JAVA_JAR="$(find /workspace/codebase/build/libs -maxdepth 2 -name "*.jar" ! -name "*-sources.jar" | sort -V | tail -1)"'
                '  && export TARGET_BINARY="$JAVA_JAR"; export TARGET_BIN="$JAVA_JAR"; fi',
                # Expose jar for PoV scripts via env
                'export CODEBASE_PATH=/workspace/codebase',
                'if [ -n "${TARGET_BINARY:-}" ]; then export TARGET_JAR="$TARGET_BINARY"; fi',
            ])
        elif env_kind == 'node' and codebase_path:
            # Task 5a/5b: detect JS surface type and set up the environment accordingly.
            # probe_input_surface is carried on exploit_contract from the preflight probe.
            _js_surface = str(contract.get('probe_input_surface') or '').strip().lower()
            # GAP-6: also accept probe_surface_type=web_service as network surface
            if not _js_surface and str(contract.get('probe_surface_type') or '').lower() == 'web_service':
                _js_surface = 'network'

            # Install deps always
            prelude.append(
                'if [ -f /workspace/codebase/package.json ]; then'
                '  cd /workspace/codebase && npm install --silent 2>/dev/null || true;'
                '  if node -e "const s=(require(\'./package.json\').scripts||{}); process.exit(s.build?0:1);" 2>/dev/null; then'
                '    npm run build --silent 2>/dev/null || true; fi; fi'
            )

            if _js_surface == 'network':
                # 5a: HTTP-server repo — auto-detect entrypoint and start server
                prelude.extend([
                    # Find server entrypoint: server.js > app.js > index.js
                    '_JS_ENTRY=""',
                    'for _F in /workspace/codebase/server.js /workspace/codebase/app.js /workspace/codebase/src/server.js /workspace/codebase/src/app.js /workspace/codebase/index.js; do',
                    '  [ -f "$_F" ] && _JS_ENTRY="$_F" && break || true; done',
                    # Fall back to main field in package.json
                    'if [ -z "$_JS_ENTRY" ] && [ -f /workspace/codebase/package.json ]; then',
                    '  _PKG_MAIN=$(node -e "try{console.log(require(\'/workspace/codebase/package.json\').main||\'\')}catch(e){}" 2>/dev/null || true)',
                    '  [ -n "$_PKG_MAIN" ] && _JS_ENTRY="/workspace/codebase/$_PKG_MAIN"; fi',
                    # Start the server in background
                    'if [ -n "$_JS_ENTRY" ]; then',
                    '  export PORT="${PORT:-3000}"',
                    '  export APP_URL="http://localhost:${PORT}"',
                    '  node "$_JS_ENTRY" &',
                    '  _SRV_PID=$!',
                    '  _TRIES=0; while [ $_TRIES -lt 15 ]; do',
                    '    curl -sf "$APP_URL" -o /dev/null 2>/dev/null && break || true',
                    '    sleep 1; _TRIES=$((_TRIES+1)); done',
                    '  export SERVER_PID=$_SRV_PID',
                    'fi',
                ])
            elif _js_surface == 'function_call':
                # 5b: Library repo — expose require path; no server started
                prelude.extend([
                    'export LIB_REQUIRE_PATH="/workspace/codebase"',
                    'export CODEBASE_PATH="/workspace/codebase"',
                ])
            # default: npm install already done above, nothing extra needed
        # GAP-2: Go / Ruby / PHP dep auto-install
        elif env_kind == 'go' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/go.mod ]; then'
                '  export GOPATH=/tmp/autopov-gopath;'
                '  export GOMODCACHE="$GOPATH/pkg/mod";'
                '  cd /workspace/codebase && go mod download 2>/dev/null || true; fi',
                'export GOPATH="${GOPATH:-/tmp/autopov-gopath}"',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'ruby' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/Gemfile ]; then'
                '  cd /workspace/codebase && bundle install --quiet 2>/dev/null || true; fi',
                'export CODEBASE_PATH="/workspace/codebase"',
            ])
        elif env_kind == 'php' and codebase_path:
            prelude.extend([
                'if [ -f /workspace/codebase/composer.json ]; then'
                '  cd /workspace/codebase && composer install --no-interaction --quiet 2>/dev/null || true; fi',
                'export CODEBASE_PATH="/workspace/codebase"',
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
            pov_script = self._repair_runtime_script(pov_script, script_runtime=script_runtime, env_kind=env_kind)
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
            try:
                self._ensure_runtime_image(client, env_kind, runtime_image)
            except DockerImagePreparationError as e:
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
                    failure_reason='docker-image-prep-failed',
                    metadata={'environment_kind': env_kind},
                )

            contract = exploit_contract or {}
            raw_target_url = str(contract.get('target_url') or contract.get('base_url') or '')
            target_url = self._normalize_target_url_for_container(raw_target_url)
            # GAP-1: web_service and http_request surfaces need bridge mode so the PoV
            # can reach the in-container web server or make outbound HTTP requests.
            _needs_network = (
                bool(target_url)
                or str(contract.get('execution_surface') or '').lower() in {'http_request', 'browser_dom'}
                or str(contract.get('proof_plan', {}).get('execution_surface') or '').lower() in {'http_request', 'browser_dom'}
                or str(contract.get('probe_surface_type') or '').lower() == 'web_service'
                or str(contract.get('probe_input_surface') or '').lower() == 'network'
            )
            network_mode = 'bridge' if _needs_network else 'none'
            fixture_files = self._collect_fixture_files(contract)
            environment = {
                'TARGET_URL': target_url,
                'CODEBASE_PATH': '/workspace/codebase' if codebase_path else '',
                'TARGET_ENTRYPOINT': str(contract.get('target_entrypoint') or ''),
                'TARGET_HTTP_METHOD': str(contract.get('http_method') or 'GET'),
                'FIXTURE_ROOT': '/workspace/fixtures',
                'AUTOPROOF_ENV_KIND': env_kind,
                'AUTOPROOF_SCRIPT_RUNTIME': script_runtime,
                # Pass repo name for binary locator heuristics (from exploit_contract or basename of codebase path)
                'AUTOPOV_REPO_NAME': (contract.get('repo_name') or os.path.basename(codebase_path.rstrip('/\\')) if codebase_path else '').lower(),
            }
            # If the preflight probe discovered the binary path, pass it through so
            # the binary locator inside the container can skip scoring heuristics.
            _probe_bin = contract.get('probe_binary_path') or ''
            if _probe_bin:
                environment['AUTOPOV_PROBE_BINARY'] = _probe_bin
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

            # Extract CLI help text captured during preflight and strip sentinel markers
            # from stdout so the PoV oracle only sees actual exploit output.
            preflight_help_text = self._extract_help_text_from_stdout(stdout)
            preflight_subcommands = self._parse_subcommands_from_help_text(preflight_help_text) if preflight_help_text else []
            # Extract the resolved binary path before stripping sentinels
            target_binary_path = self._extract_binary_path_from_stdout(stdout)
            # Extract preflight surface detection result
            preflight_detected_surface = self._extract_preflight_surface_from_stdout(stdout)
            # Extract build status before stripping sentinels
            build_info = self._extract_build_status_from_stdout(stdout)
            stdout = self._strip_help_text_sentinels(stdout)

            # --- Build failure gate ---
            # If the container emitted AUTOPOV_BUILD_STATUS=failed, the binary was never
            # produced.  Return a clear infrastructure error immediately so the pipeline
            # can give the LLM an actionable hint instead of burning a retry on a missing
            # binary.
            if build_info.get('build_status') == 'failed':
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                build_log_snippet = (build_info.get('build_log') or '').strip()[-1500:]
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout=stdout,
                    stderr=f"[AutoPoV] Build failed inside container.\n{build_log_snippet}",
                    exit_code=97,
                    execution_time_s=execution_time,
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='build_failed',
                    metadata={
                        'environment_kind': env_kind,
                        'build_status': 'failed',
                        'build_log': build_log_snippet,
                        'preflight_help_text': preflight_help_text or None,
                        'preflight_subcommands': preflight_subcommands or None,
                    },
                )

            execution_time = (datetime.utcnow() - start_time).total_seconds()
            # build_info was already extracted above for the build failure gate.
            # Derive asan_disabled from it here before evaluating the oracle.
            asan_disabled = build_info.get('asan_disabled', False)
            # Probe-captured baseline (injected into exploit_contract by agent_graph).
            _baseline_ec = int((contract.get('probe_baseline_exit_code') or -1))
            _baseline_err = str(contract.get('probe_baseline_stderr') or '')
            oracle = self._evaluate_runtime_oracle(
                stdout, stderr, exit_code, contract,
                asan_disabled=asan_disabled,
                baseline_exit_code=_baseline_ec,
                baseline_stderr=_baseline_err,
                pov_script=pov_script,
            )

            # ----------------------------------------------------------------
            # Tiered confirmation stack (Tasks 0b, 1, 3)
            # Only runs when the first oracle pass did NOT confirm the vuln.
            # Tiers are tried in order; first success short-circuits the rest.
            # ----------------------------------------------------------------
            # Skip tiered confirmation if the build never completed (build_status unknown
            # means the container timed out before emitting the sentinel — a second
            # container would also time out, wasting time without adding signal).
            _first_build_status = build_info.get('build_status', 'unknown')
            _build_completed = _first_build_status in ('success', 'failed', 'asan_disabled')
            if not oracle.get('triggered') and env_kind == 'native' and not timeout_hit and _build_completed:
                _combined_output = (stdout or '') + '\n' + (stderr or '')
                # Infer file extension from the binary name in the contract.
                # Falls back to .jpg when the binary is a known image-processing tool.
                _inferred_ext = self._infer_ext_from_contract(contract)
                # If the contract doesn't name the binary, try extracting it from
                # the resolved binary path (e.g. '/workspace/codebase/jhead' -> '.jpg').
                if _inferred_ext == '.bin' and target_binary_path:
                    import os as _os_tier
                    _bin_basename = _os_tier.path.basename(target_binary_path).lower()
                    for _frag, _fext in self._BINARY_EXT_MAP.items():
                        if _frag in _bin_basename:
                            _inferred_ext = _fext
                            break
                _target_bin_in_container = target_binary_path or str(contract.get('probe_binary_path') or '')

                # Determine whether to run the tiered confirmation script.
                # Conditions: (a) format-rejection detected OR (b) signal is ambiguous/asan_disabled.
                _sig_cls = (oracle.get('oracle_result') or {}).get('signal_class', '')
                _fmt_rejected = bool(self._FORMAT_REJECTION_RE.search(_combined_output))
                _should_tier = _fmt_rejected or _sig_cls == 'ambiguous' or asan_disabled

                logger.debug(
                    '[tier] env_kind=%s timeout_hit=%s sig_cls=%r fmt_rejected=%s '
                    'asan_disabled=%s should_tier=%s bin=%r ext=%r',
                    env_kind, timeout_hit, _sig_cls, _fmt_rejected,
                    asan_disabled, _should_tier, _target_bin_in_container, _inferred_ext,
                )

                if _should_tier and _target_bin_in_container:
                    try:
                        _tier_script = self._build_tiered_confirmation_pov(
                            binary_path=_target_bin_in_container,
                            ext=_inferred_ext,
                            contract=contract,
                            run_valgrind=True,
                            run_repeated_crash=True,
                        )
                        # Run the tier script in a fresh container using the same image.
                        # It will have access to the codebase (already built in the first run).
                        logger.debug('[tier] launching tiered confirmation container for pov_id=%s', pov_id)
                        _tier_result = self.run_pov(
                            pov_script=_tier_script,
                            scan_id=scan_id,
                            pov_id=pov_id + '_tier',
                            execution_profile='c',  # native
                            target_language='c',
                            exploit_contract=contract,
                            codebase_path=codebase_path,
                        )
                        logger.debug('[tier] tier result: triggered=%s reason=%r',
                                     _tier_result.get('vulnerability_triggered'),
                                     _tier_result.get('failure_reason'))
                        if _tier_result.get('vulnerability_triggered'):
                            # Promote tier result: keep oracle metadata but mark triggered
                            oracle['triggered'] = True
                            oracle['reason'] = 'tiered_confirmation'
                            if isinstance(oracle.get('oracle_result'), dict):
                                oracle['oracle_result']['triggered'] = True
                                oracle['oracle_result']['signal_class'] = 'strong'
                    except Exception as _tier_exc:
                        logger.warning('[tier] tiered confirmation raised: %s', _tier_exc, exc_info=True)
            # ----------------------------------------------------------------

            vulnerability_triggered = oracle['triggered']
            infra_error = timeout_hit or exit_code in {97, 125, 126, 127}
            failure_reason = self._normalize_oracle_reason(oracle, infrastructure=infra_error, timeout_hit=timeout_hit)
            if oracle.get('self_report_only'):
                failure_reason = 'self_report_only'

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
                    'oracle_reason': oracle.get('reason'),
                    'matched_markers': oracle.get('matched_markers', []),
                    'preflight_help_text': preflight_help_text or None,
                    'preflight_subcommands': preflight_subcommands or None,
                    'target_binary_path': target_binary_path or None,
                    'target_binary': os.path.basename(target_binary_path) if target_binary_path else None,
                    'preflight_detected_surface': preflight_detected_surface or None,
                    'build_status': build_info.get('build_status') or 'unknown',
                    'build_log': (build_info.get('build_log') or '').strip()[-1500:] or None,
                    'asan_disabled': asan_disabled,
                    'oracle_result': oracle.get('oracle_result'),
                },
            )

        except ContainerError as e:
            ce_stdout = e.stdout.decode('utf-8', errors='ignore') if e.stdout else ''
            ce_stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e)
            ce_build_info = self._extract_build_status_from_stdout(ce_stdout)
            ce_stdout_clean = self._strip_help_text_sentinels(ce_stdout)
            ce_infra = e.exit_status in {97, 125, 126, 127}
            ce_reason = 'build_failed' if ce_build_info.get('build_status') == 'failed' else str(e)
            if ce_build_info.get('build_status') == 'failed':
                build_log_snippet = (ce_build_info.get('build_log') or '').strip()[-1500:]
                return self._build_result(
                    success=False,
                    vulnerability_triggered=False,
                    stdout=ce_stdout_clean,
                    stderr=f'[AutoPoV] Build failed inside container.\n{build_log_snippet}',
                    exit_code=e.exit_status,
                    execution_time_s=(datetime.utcnow() - start_time).total_seconds(),
                    execution_profile=execution_profile or target_language or script_runtime,
                    runtime_image=runtime_image,
                    validation_method='generic_container_runtime',
                    proof_infrastructure_error=True,
                    failure_reason='build_failed',
                    metadata={
                        'environment_kind': env_kind,
                        'build_status': 'failed',
                        'build_log': build_log_snippet,
                        'preflight_help_text': preflight_help_text or None,
                        'preflight_subcommands': preflight_subcommands or None,
                    },
                )
            return self._build_result(
                success=False,
                vulnerability_triggered=False,
                stdout=ce_stdout_clean,
                stderr=ce_stderr,
                exit_code=e.exit_status,
                execution_time_s=(datetime.utcnow() - start_time).total_seconds(),
                execution_profile=execution_profile or target_language or script_runtime,
                runtime_image=runtime_image,
                validation_method='generic_container_runtime',
                proof_infrastructure_error=ce_infra,
                failure_reason=ce_reason,
                metadata={
                    'environment_kind': env_kind,
                    'build_status': ce_build_info.get('build_status') or 'unknown',
                    'build_log': (ce_build_info.get('build_log') or '').strip()[-1500:] or None,
                    'preflight_help_text': preflight_help_text or None,
                    'preflight_subcommands': preflight_subcommands or None,
                },
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

