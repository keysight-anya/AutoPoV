"""Tests for agentic discovery CodeQL fallback behavior."""

import subprocess
from pathlib import Path

from agents.agentic_discovery import AgenticDiscovery


class TestAgenticDiscoveryCodeQLFallback:
    def test_candidate_codeql_build_commands_include_autogen_and_make_for_cpp_repo(self, tmp_path):
        (tmp_path / 'autogen.sh').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        (tmp_path / 'Makefile').write_text('all:\n\t@true\n', encoding='utf-8')

        discovery = AgenticDiscovery()
        commands = discovery._candidate_codeql_build_commands(str(tmp_path), 'cpp')

        assert any('./autogen.sh' in command for command in commands)
        assert any('make -j' in command for command in commands)
        assert any(command.startswith('python3 ') for command in commands)

    def test_candidate_codeql_build_commands_include_helper_and_optional_java_build_tools_for_java_repo(self, tmp_path):
        (tmp_path / 'pom.xml').write_text('<project/>', encoding='utf-8')
        (tmp_path / 'mvnw').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        (tmp_path / 'gradlew').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')

        discovery = AgenticDiscovery()
        commands = discovery._candidate_codeql_build_commands(str(tmp_path), 'java')

        assert any(command.startswith('python3 ') for command in commands)
        assert any('./mvnw -q -DskipTests compile' in command for command in commands)
        assert any('./gradlew --no-daemon compileJava classes -q' in command for command in commands)

    def test_try_codeql_retries_with_manual_build_after_autobuild_failure(self, monkeypatch, tmp_path):
        (tmp_path / 'autogen.sh').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        state = {'logs': [], 'scan_id': 'scan-1'}
        discovery = AgenticDiscovery()

        calls = []

        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            calls.append(cmd)
            if cmd[1:3] == ['database', 'create'] and not any(arg.startswith('--command=') for arg in cmd):
                return subprocess.CompletedProcess(cmd, 2, '', 'autobuild failed')
            if cmd[1:3] == ['database', 'create'] and any(arg.startswith('--command=') for arg in cmd):
                return subprocess.CompletedProcess(cmd, 0, '', '')
            raise AssertionError(f'unexpected subprocess call: {cmd}')

        monkeypatch.setattr(subprocess, 'run', fake_run)
        monkeypatch.setattr(discovery, '_get_codeql_suite', lambda lang, state=None: '/tmp/fake-suite.qls')
        monkeypatch.setattr(discovery, '_run_codeql_analyze', lambda *args, **kwargs: [])

        result = discovery._try_codeql(str(tmp_path), 'c', 'scan-1', state)

        assert result.success is True
        assert result.metadata['build_strategy'] == 'manual'
        assert any(any(arg.startswith('--command=') for arg in cmd) for cmd in calls if cmd[1:3] == ['database', 'create'])

    def test_build_codeql_create_cmd_prefers_wrapper_script_for_manual_builds(self):
        discovery = AgenticDiscovery()

        cmd = discovery._build_codeql_create_cmd(
            '/tmp/codeql-db',
            '/tmp/repo',
            'cpp',
            build_wrapper_path='/tmp/codeql-build.sh',
        )

        assert '--command=/bin/sh /tmp/codeql-build.sh' in cmd

    def test_write_codeql_manual_build_wrapper_preserves_shell_command_text(self, tmp_path):
        discovery = AgenticDiscovery()

        wrapper = discovery._write_codeql_manual_build_wrapper(str(tmp_path), 'cmake -S . -B build && cmake --build build -j4', 'scan-x', 1)
        content = Path(wrapper).read_text(encoding='utf-8')

        assert 'cd ' in content
        assert 'cmake -S . -B build && cmake --build build -j4' in content

    def test_try_codeql_reports_autobuild_failure_when_no_manual_fallback_exists(self, monkeypatch, tmp_path):
        state = {'logs': [], 'scan_id': 'scan-2'}
        discovery = AgenticDiscovery()

        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            return subprocess.CompletedProcess(cmd, 2, '', 'autobuild failed')

        monkeypatch.setattr(subprocess, 'run', fake_run)
        monkeypatch.setattr(discovery, '_get_codeql_suite', lambda lang, state=None: '/tmp/fake-suite.qls')

        result = discovery._try_codeql(str(tmp_path), 'python', 'scan-2', state)

        assert result.success is False
        assert 'Database creation failed' in (result.error or '')


    def test_filter_test_findings_removes_test_code_paths(self):
        discovery = AgenticDiscovery()
        findings = [
            {'filepath': 'src/test/java/com/example/AuthTest.java', 'line_number': 10},
            {'filepath': 'src/main/java/com/example/AuthService.java', 'line_number': 20},
            {'filepath': 'tests/test_login.py', 'line_number': 30},
        ]

        filtered = discovery._filter_test_findings(findings)

        assert filtered == [{'filepath': 'src/main/java/com/example/AuthService.java', 'line_number': 20}]


    def test_native_heuristic_scout_finds_unchecked_allocation_use(self, tmp_path):
        """Heuristic scout was removed; this test is now a no-op placeholder."""
        import pytest
        pytest.skip("_run_native_heuristic_scout removed (heuristic discovery disabled)")
