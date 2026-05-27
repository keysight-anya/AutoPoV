
"""Managed benchmark source installation and discovery."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

from app.config import settings


@dataclass(frozen=True)
class BuiltinBenchmark:
    benchmark_id: str
    benchmark_family: str
    display_name: str
    repo_url: str
    default_branch: str
    language: str
    description: str


BUILTIN_BENCHMARKS: Dict[str, BuiltinBenchmark] = {
    'juliet-dynamic': BuiltinBenchmark(
        benchmark_id='juliet-dynamic',
        benchmark_family='juliet_dynamic',
        display_name='Juliet Dynamic',
        repo_url='https://github.com/ispras/juliet-dynamic.git',
        default_branch='master',
        language='c/c++',
        description='Managed Juliet C/C++ dynamic benchmark suite',
    ),
    'owasp-benchmark-python': BuiltinBenchmark(
        benchmark_id='owasp-benchmark-python',
        benchmark_family='owasp_benchmark_python',
        display_name='OWASP Benchmark Python',
        repo_url='https://github.com/OWASP-Benchmark/BenchmarkPython.git',
        default_branch='main',
        language='python',
        description='Managed OWASP Benchmark Python suite',
    ),
}


class BenchmarkManager:
    def __init__(self) -> None:
        self._root = Path(settings.BENCHMARK_SOURCES_DIR).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def list_benchmarks(self) -> List[Dict[str, object]]:
        return [self.get_benchmark_status(benchmark_id) for benchmark_id in sorted(BUILTIN_BENCHMARKS)]

    def get_benchmark_status(self, benchmark_id: str) -> Dict[str, object]:
        benchmark = self._get_builtin(benchmark_id)
        install_path = self._install_path(benchmark_id)
        installed = install_path.exists() and (install_path / '.git').exists()
        return {
            **asdict(benchmark),
            'install_path': str(install_path),
            'installed': installed,
        }

    def ensure_installed(self, benchmark_id: str) -> str:
        benchmark = self._get_builtin(benchmark_id)
        install_path = self._install_path(benchmark_id)
        with self._lock:
            if install_path.exists() and (install_path / '.git').exists():
                return str(install_path)
            self._install_builtin(benchmark, install_path)
        return str(install_path)

    def _install_builtin(self, benchmark: BuiltinBenchmark, install_path: Path) -> None:
        if install_path.exists():
            shutil.rmtree(install_path, ignore_errors=True)
        install_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                [
                    'git', 'clone', '--depth', '1', '--branch', benchmark.default_branch,
                    benchmark.repo_url, str(install_path)
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=900,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or '').strip()
            raise RuntimeError(f"Failed to install benchmark '{benchmark.benchmark_id}': {stderr or exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Timed out installing benchmark '{benchmark.benchmark_id}'") from exc

    def _get_builtin(self, benchmark_id: str) -> BuiltinBenchmark:
        benchmark = BUILTIN_BENCHMARKS.get(benchmark_id)
        if not benchmark:
            known = ', '.join(sorted(BUILTIN_BENCHMARKS))
            raise ValueError(f"Unknown benchmark_id '{benchmark_id}'. Known benchmarks: {known}")
        return benchmark

    def _install_path(self, benchmark_id: str) -> Path:
        return self._root / benchmark_id


_benchmark_manager: Optional[BenchmarkManager] = None


def get_benchmark_manager() -> BenchmarkManager:
    global _benchmark_manager
    if _benchmark_manager is None:
        _benchmark_manager = BenchmarkManager()
    return _benchmark_manager
