
from pathlib import Path

from app import benchmark_manager as benchmark_manager_module
from app.benchmark_manager import BenchmarkManager


def test_list_benchmarks_reports_install_status(monkeypatch, tmp_path):
    monkeypatch.setattr(benchmark_manager_module.settings, 'BENCHMARK_SOURCES_DIR', str(tmp_path))
    manager = BenchmarkManager()

    statuses = manager.list_benchmarks()

    assert {item['benchmark_id'] for item in statuses} == {'juliet-dynamic', 'owasp-benchmark-python'}
    assert all(item['installed'] is False for item in statuses)


def test_ensure_installed_clones_builtin(monkeypatch, tmp_path):
    monkeypatch.setattr(benchmark_manager_module.settings, 'BENCHMARK_SOURCES_DIR', str(tmp_path))
    manager = BenchmarkManager()
    calls = []

    def fake_run(cmd, check, capture_output, text, timeout):
        calls.append(cmd)
        target = Path(cmd[-1])
        target.mkdir(parents=True, exist_ok=True)
        (target / '.git').mkdir(exist_ok=True)
        return None

    monkeypatch.setattr(benchmark_manager_module.subprocess, 'run', fake_run)

    install_path = manager.ensure_installed('juliet-dynamic')

    assert Path(install_path).exists()
    assert (Path(install_path) / '.git').exists()
    assert calls and calls[0][:4] == ['git', 'clone', '--depth', '1']


def test_ensure_installed_reuses_existing_install(monkeypatch, tmp_path):
    monkeypatch.setattr(benchmark_manager_module.settings, 'BENCHMARK_SOURCES_DIR', str(tmp_path))
    manager = BenchmarkManager()
    install_path = Path(tmp_path) / 'juliet-dynamic'
    install_path.mkdir(parents=True)
    (install_path / '.git').mkdir()

    def fake_run(*args, **kwargs):
        raise AssertionError('git clone should not be called when benchmark is already installed')

    monkeypatch.setattr(benchmark_manager_module.subprocess, 'run', fake_run)

    assert manager.ensure_installed('juliet-dynamic') == str(install_path)
