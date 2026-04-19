import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.pov_tester import PoVTester


def test_repair_native_runtime_script_removes_target_binary_rebinding():
    tester = PoVTester()
    script = """import os
TARGET_BINARY = os.environ.get("TARGET_BINARY")

def _find_binary(name, codebase):
    return "/tmp/bin"

def main() -> int:
    global TARGET_BINARY
    if not TARGET_BINARY:
        TARGET_BINARY = _find_binary("enchive", "/tmp")
    if not os.path.isfile(TARGET_BINARY):
        return 1
    return _run_exploit(TARGET_BINARY)
"""
    repaired = tester._repair_native_runtime_script(script)
    assert "global TARGET_BINARY" not in repaired
    assert "if not TARGET_BINARY:" not in repaired
    assert "TARGET_BINARY = _find_binary" not in repaired
    assert "if not binary:" in repaired
    assert "return _run_exploit(binary)" in repaired


def test_prepare_native_runtime_env_sets_binary_and_codebase():
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix="autopov_test_env_")
    env = tester._prepare_native_runtime_env({}, temp_dir, "/tmp/enchive", "/tmp/codebase", {"known_subcommands": ["archive", "keygen"]})
    assert env["TARGET_BINARY"] == "/tmp/enchive"
    assert env["TARGET_BIN"] == "/tmp/enchive"
    assert env["CODEBASE_PATH"] == "/tmp/codebase"
    assert env["MQJS_BIN"] == "/tmp/enchive"
    assert env["HOME"].startswith(temp_dir)
    assert Path(env["HOME"]).exists()


def test_binary_cli_contract_counts_as_binary_target_even_for_internal_symbol_name():
    tester = PoVTester()
    contract = {
        "target_binary": "/tmp/enchive",
        "proof_plan": {"execution_surface": "binary_cli"},
    }
    assert tester._is_binary_native_target("agent_run", "src/enchive.c", contract) is True


def test_build_targeted_native_harness_renames_embedded_main_for_internal_symbol():
    tester = PoVTester()
    vulnerable_code = """
int helper(const char *payload) {
    return payload ? 0 : 1;
}
int main(void) {
    return 0;
}
"""
    result = tester._build_targeted_native_harness("scan", "CWE-787", vulnerable_code, {"target_entrypoint": "helper"}, "c")
    try:
        assert result["success"] is True
    finally:
        import shutil
        shutil.rmtree(result.get("temp_dir") or "", ignore_errors=True)


def test_build_targeted_native_harness_can_fall_back_to_inferred_function_symbol():
    tester = PoVTester()
    vulnerable_code = """
int helper(const char *payload) {
    return payload ? 0 : 1;
}
"""
    result = tester._build_targeted_native_harness("scan", "CWE-787", vulnerable_code, {"target_entrypoint": "agent_run"}, "c")
    try:
        assert result["success"] is True
    finally:
        import shutil
        shutil.rmtree(result.get("temp_dir") or "", ignore_errors=True)


def test_evaluate_proof_outcome_marks_setup_stage_only():
    tester = PoVTester()
    result = tester._evaluate_proof_outcome(
        stdout="",
        stderr="src/enchive.c:1404: runtime error: left shift of negative value\n#5 0xdead in command_extract",
        exit_code=1,
        exploit_contract={"target_entrypoint": "command_extract", "target_binary": "enchive", "relevance_anchors": ["command_extract"]},
        execution_stage='setup',
    )
    assert result['triggered'] is False
    assert result['reason'] == 'setup_stage_only'
    assert result['proof_verdict'] == 'setup_only'


def test_run_native_setup_plugins_noop_when_not_required():
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix="autopov_setup_plugins_")
    env = tester._prepare_native_runtime_env({}, temp_dir, "/tmp/tool", "/tmp/codebase", {})
    result = tester._run_native_setup_plugins("/tmp/tool", env, {})
    assert result["stage"] == "setup"
    assert result["success"] is True
    assert "no native setup plugins required" in result["notes"]


def test_run_native_setup_plugins_bootstraps_enchive(monkeypatch):
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix="autopov_setup_plugins_enchive_")
    env = tester._prepare_native_runtime_env({}, temp_dir, "/tmp/enchive", "/tmp/codebase", {"known_subcommands": ["keygen", "extract"]})
    pub = Path(env["HOME"]) / ".config" / "enchive" / "enchive.pub"
    sec = Path(env["HOME"]) / ".config" / "enchive" / "enchive.sec"

    class _Result:
        returncode = 0
        stdout = "bootstrapped"
        stderr = ""

    def _fake_run(*args, **kwargs):
        pub.parent.mkdir(parents=True, exist_ok=True)
        pub.write_text("pub")
        sec.write_text("sec")
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = tester._run_native_setup_plugins("/tmp/enchive", env, {"known_subcommands": ["keygen", "extract"], "setup_requirements": ["bootstrap key material before trigger execution"]})
    assert result["success"] is True
    assert str(pub) in result["artifacts"]
    assert str(sec) in result["artifacts"]


class _FakeLiveResult:
    def __init__(self, *, success=True, vulnerability_triggered=False, target_url='http://target', response_time_ms=25.0, response_preview='preview', evidence=None, error=None):
        self.success = success
        self.vulnerability_triggered = vulnerability_triggered
        self.target_url = target_url
        self.response_time_ms = response_time_ms
        self.response_preview = response_preview
        self.evidence = list(evidence or [])
        self.error = error


def test_failure_category_maps_setup_stage_only_to_setup_crashed_unrelated():
    tester = PoVTester()
    assert tester._failure_category_from_outcome(setup_success=True, triggered=False, oracle_reason='setup_stage_only') == 'setup_crashed_unrelated'


def test_format_live_test_result_includes_stage_artifacts():
    tester = PoVTester()
    setup_result = tester._build_setup_result(stage='setup', success=True, artifacts=['http://target'], notes=['external_target_url_provided'])
    live = _FakeLiveResult(success=True, vulnerability_triggered=False, evidence=['no marker'])
    result = tester._format_live_test_result(live_result=live, validation_method='live_app_contract', setup_result=setup_result, target_url='http://target')
    assert result['setup_result']['stage'] == 'setup'
    assert result['trigger_result']['stage'] == 'trigger'
    assert result['proof_verdict'] == 'failed'
    assert result['failure_category'] == 'trigger_not_reached'


def test_test_with_contract_live_app_start_failure_returns_setup_failed(monkeypatch):
    tester = PoVTester()

    class _FakeRunner:
        def start_application(self, *args, **kwargs):
            return {'success': False, 'error': 'boot failed'}

    monkeypatch.setattr('agents.pov_tester.get_app_runner', lambda: _FakeRunner())
    result = tester.test_with_contract(
        pov_script='print(1)',
        scan_id='scan',
        cwe_type='CWE-79',
        codebase_path='/tmp/codebase',
        exploit_contract={'runtime_profile': 'web', 'target_entrypoint': '/search'},
        target_language='python',
    )
    assert result['failure_category'] == 'setup_failed'
    assert result['setup_result']['stage'] == 'setup'
    assert result['oracle_result']['reason'] == 'setup_failed'



def test_run_script_setup_plugins_applies_setup_environment_and_requirements():
    tester = PoVTester()
    env = tester._apply_setup_environment({'BASE': '1'}, {'setup_environment': {'TOKEN': 'abc'}, 'setup_requirements': ['seed fixtures']})
    result = tester._run_script_setup_plugins(env, '/tmp/codebase', {'setup_requirements': ['seed fixtures']})
    assert env['TOKEN'] == 'abc'
    assert result['success'] is True
    assert 'seed fixtures' in result['notes']
    assert '/tmp/codebase' in result['artifacts']


def test_run_live_setup_plugins_records_target_url_artifact():
    tester = PoVTester()
    result = tester._run_live_setup_plugins({'setup_requirements': ['warm session']}, target_url='http://target')
    assert result['success'] is True
    assert 'http://target' in result['artifacts']
    assert 'warm session' in result['notes']


def test_test_binary_target_binary_cli_failure_includes_stage_artifacts(monkeypatch):
    tester = PoVTester()

    class _FakeRunner:
        def build_native_binary(self, *args, **kwargs):
            return {"success": True, "binary_path": "/tmp/enchive"}

    monkeypatch.setattr('agents.pov_tester.get_app_runner', lambda: _FakeRunner())
    monkeypatch.setattr(tester, '_native_preflight', lambda *args, **kwargs: {
        'ok': True,
        'checks': [{'check': 'binary_present', 'ok': True}],
        'issues': [],
        'effective_contract': {'target_binary': '/tmp/enchive', 'target_entrypoint': 'extract', 'proof_plan': {'execution_surface': 'binary_cli'}},
    })
    monkeypatch.setattr(tester, '_run_native_binary_with_contract', lambda *args, **kwargs: {
        'stdout': '',
        'stderr': 'no crash',
        'exit_code': 1,
        'selected_binary': '/tmp/enchive',
        'surface': {'commands': ['extract']},
        'baseline_result': {},
        'setup_result': tester._build_setup_result(stage='setup', success=True, artifacts=['/tmp/enchive'], notes=['native setup complete']),
        'effective_contract': {'target_binary': '/tmp/enchive', 'target_entrypoint': 'extract', 'proof_plan': {'execution_surface': 'binary_cli'}},
        'path_exercised': False,
    })
    monkeypatch.setattr(tester, '_evaluate_proof_outcome', lambda *args, **kwargs: {'triggered': False, 'reason': 'no_oracle_match', 'proof_verdict': 'failed', 'path_relevant': False, 'matched_evidence_markers': []})
    monkeypatch.setattr(tester, '_run_script', lambda *args, **kwargs: {'stdout': '', 'stderr': 'no crash', 'exit_code': 1})
    monkeypatch.setattr(tester, '_repair_native_runtime_script', lambda script: script)
    monkeypatch.setattr(tester, '_patch_target_refs', lambda script, **kwargs: script)
    monkeypatch.setattr(tester, '_native_script_guardrail_issues', lambda *args, **kwargs: [])
    monkeypatch.setattr(tester, '_build_runtime_evidence', lambda *args, **kwargs: {'summary': 'Runtime harness executed'})

    result = tester.test_binary_target(
        pov_script='print(1)',
        scan_id='scan',
        cwe_type='CWE-416',
        codebase_path='/tmp/codebase',
        language='c',
        exploit_contract={'target_binary': '/tmp/enchive', 'target_entrypoint': 'extract', 'proof_plan': {'execution_surface': 'binary_cli'}},
    )

    assert result['setup_result']['stage'] == 'setup'
    assert result['trigger_result']['stage'] == 'trigger'
    assert result['proof_verdict'] == 'failed'


def test_test_binary_target_build_failure_includes_stage_artifacts(monkeypatch):
    tester = PoVTester()

    class _FakeRunner:
        def build_native_binary(self, *args, **kwargs):
            return {'success': False, 'error': 'compile failed'}

    monkeypatch.setattr('agents.pov_tester.get_app_runner', lambda: _FakeRunner())

    result = tester.test_binary_target(
        pov_script='print(1)',
        scan_id='scan',
        cwe_type='CWE-416',
        codebase_path='/tmp/codebase',
        language='c',
        exploit_contract={'target_binary': '/tmp/enchive', 'target_entrypoint': 'extract', 'proof_plan': {'execution_surface': 'binary_cli'}},
    )

    assert result['setup_result']['success'] is False
    assert result['trigger_result']['stage'] == 'trigger'
    assert result['proof_verdict'] == 'failed'


def test_run_native_setup_plugins_uses_setup_requirements_for_key_material(monkeypatch):
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix="autopov_setup_plugins_requirements_")
    env = tester._prepare_native_runtime_env({}, temp_dir, "/tmp/not_enchive", "/tmp/codebase", {"known_subcommands": ["keygen", "extract"], "setup_requirements": ["bootstrap key material before trigger execution"]})

    called = {"value": False}

    def _fake_bootstrap(binary_path, local_env):
        called["value"] = True
        return tester._build_setup_result(stage='setup', success=True, artifacts=['/tmp/key'], notes=['bootstrapped from setup requirements'])

    monkeypatch.setattr(tester, '_bootstrap_key_material_via_keygen', lambda *args, **kwargs: _fake_bootstrap(*args, **kwargs))
    result = tester._run_native_setup_plugins('/tmp/not_enchive', env, {"known_subcommands": ["keygen", "extract"], "setup_requirements": ["bootstrap key material before trigger execution"]})

    assert called['value'] is True
    assert result['success'] is True
    assert 'bootstrapped from setup requirements' in result['notes']


def test_native_trigger_requirement_issues_flags_missing_entrypoint_and_subcommand():
    tester = PoVTester()
    contract = {
        'target_entrypoint': 'command_extract',
        'trigger_requirements': ['reach target entrypoint: command_extract', 'use trigger subcommand: extract'],
        'proof_plan': {'runtime_family': 'c', 'subcommand': 'extract'},
    }
    issues = tester._native_trigger_requirement_issues('print("hello")', contract)
    assert any('reach target entrypoint: command_extract' in issue for issue in issues)
    assert any('use trigger subcommand: extract' in issue for issue in issues)


def test_native_script_guardrail_issues_include_trigger_requirements():
    tester = PoVTester()
    contract = {
        'runtime_profile': 'c',
        'target_entrypoint': 'command_extract',
        'trigger_requirements': ['reach target entrypoint: command_extract', 'use trigger subcommand: extract'],
        'proof_plan': {'runtime_family': 'c', 'subcommand': 'extract'},
    }
    issues = tester._native_script_guardrail_issues('print("extract only")', contract, {})
    assert any('reach target entrypoint: command_extract' in issue for issue in issues)


def test_build_setup_and_trigger_plan_capture_contract_fields():
    tester = PoVTester()
    contract = {
        'setup_requirements': ['seed fixtures'],
        'setup_environment': {'TOKEN': 'abc'},
        'setup_files': [{'path': 'fixtures/token.txt', 'content': 'abc'}],
        'target_route': '/search',
        'proof_plan': {'execution_surface': 'live_app', 'input_mode': 'request', 'subcommand': 'extract', 'argv': ['extract', 'payload']},
        'target_entrypoint': 'command_extract',
    }
    setup_plan = tester._build_setup_plan(contract, base_dir='/tmp/codebase', target_url='http://target')
    trigger_plan = tester._build_trigger_plan(contract)
    assert setup_plan.environment['TOKEN'] == 'abc'
    assert setup_plan.files_to_create[0]['path'] == 'fixtures/token.txt'
    assert trigger_plan.execution_surface == 'live_app'
    assert trigger_plan.subcommand == 'extract'


def test_run_script_setup_plugins_materializes_setup_plan_files():
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix='autopov_setup_plan_files_')
    env = {}
    contract = {'setup_files': [{'path': 'fixtures/data.txt', 'content': 'hello'}], 'setup_requirements': ['seed fixtures']}
    result = tester._run_script_setup_plugins(env, temp_dir, contract)
    assert Path(temp_dir, 'fixtures', 'data.txt').read_text() == 'hello'
    assert str(Path(temp_dir, 'fixtures', 'data.txt')) in result['artifacts']


def test_failure_category_maps_strong_signal_no_target_to_target_unresolved():
    tester = PoVTester()
    assert tester._failure_category_from_outcome(setup_success=True, triggered=False, oracle_reason='strong_signal_no_target') == 'target_unresolved'


def test_apply_deterministic_script_skeleton_populates_repo_context():
    tester = PoVTester()
    script = tester._apply_deterministic_script_skeleton('print(payload)', language='python', mode='repo_script', exploit_contract={
        'target_entrypoint': 'run_query',
        'target_route': '/search',
        'proof_plan': {'execution_surface': 'repo_script', 'input_mode': 'stdin', 'argv': ['run_query', 'AAAA']},
    }, codebase_path='/tmp/codebase')
    assert 'AUTOPOV_DETERMINISTIC_SKELETON' in script
    assert 'TARGET_ROUTE = "/search"' in script
    assert 'CODEBASE_PATH = os.environ.get' in script


def test_format_live_test_result_uses_richer_http_taxonomy():
    tester = PoVTester()
    setup_result = tester._build_setup_result(stage='setup', success=True)
    live = _FakeLiveResult(success=True, vulnerability_triggered=True, evidence=['Server error (status 500)'])
    result = tester._format_live_test_result(live_result=live, validation_method='live_app_contract', setup_result=setup_result, target_url='http://target', exploit_contract={'target_route': '/search'})
    assert result['oracle_result']['reason'] == 'http_status_evidence'


def test_format_live_test_result_uses_dom_selector_taxonomy():
    tester = PoVTester()
    setup_result = tester._build_setup_result(stage='setup', success=True)
    live = _FakeLiveResult(success=True, vulnerability_triggered=True, response_preview='<div id="result">boom</div>', evidence=['Success indicator observed in DOM: boom'])
    result = tester._format_live_test_result(live_result=live, validation_method='browser_live_contract', setup_result=setup_result, target_url='http://target', exploit_contract={'target_dom_selector': '#result'})
    assert result['oracle_result']['reason'] == 'browser_dom_selector_evidence'


def test_run_native_setup_plugins_uses_generic_key_material_plugin(monkeypatch):
    tester = PoVTester()
    temp_dir = tempfile.mkdtemp(prefix='autopov_setup_plugins_generic_')
    env = tester._prepare_native_runtime_env({}, temp_dir, '/tmp/tool', '/tmp/codebase', {'known_subcommands': ['keygen'], 'setup_requirements': ['bootstrap key material before trigger execution']})
    called = {'value': False}
    def _fake(binary_path, local_env, **kwargs):
        called['value'] = True
        return tester._build_setup_result(stage='setup', success=True, notes=['generic key bootstrap'])
    monkeypatch.setattr(tester, '_bootstrap_key_material_via_keygen', _fake)
    result = tester._run_native_setup_plugins('/tmp/tool', env, {'known_subcommands': ['keygen'], 'setup_requirements': ['bootstrap key material before trigger execution']})
    assert called['value'] is True
    assert 'generic key bootstrap' in result['notes']


def test_apply_deterministic_script_skeleton_populates_js_context():
    tester = PoVTester()
    script = tester._apply_deterministic_script_skeleton('console.log(payload)', language='javascript', mode='browser_dom', exploit_contract={
        'target_route': '/search',
        'target_dom_selector': '#result',
        'proof_plan': {'execution_surface': 'browser_dom', 'input_mode': 'request'},
    }, target_url='http://target')
    assert 'const AUTOPOV_CONTEXT =' in script
    assert 'const TARGET_DOM_SELECTOR = "#result";' in script
    assert 'const TARGET_URL = process.env.TARGET_URL || "http://target";' in script


def test_build_trigger_plan_captures_http_and_dom_fields():
    tester = PoVTester()
    trigger_plan = tester._build_trigger_plan({
        'target_route': '/search',
        'target_dom_selector': '#result',
        'http_method': 'POST',
        'param': 'q',
        'proof_plan': {'execution_surface': 'browser_dom', 'input_mode': 'request'},
    })
    assert trigger_plan.target_route == '/search'
    assert trigger_plan.target_dom_selector == '#result'
    assert trigger_plan.http_method == 'POST'
    assert trigger_plan.request_param == 'q'


def test_setup_plugin_capabilities_detect_key_and_live_artifacts():
    tester = PoVTester()
    contract = {
        'known_subcommands': ['keygen'],
        'setup_requirements': ['bootstrap key material before trigger execution'],
        'setup_files': [{'path': 'fixtures/a.txt', 'content': 'x'}],
        'target_url': 'http://target',
    }
    assert 'key_material_bootstrap' in tester._setup_plugin_capabilities(contract, 'native')
    assert 'materialize_setup_files' in tester._setup_plugin_capabilities(contract, 'script')
    assert 'external_target_url' in tester._setup_plugin_capabilities(contract, 'live')


def test_is_live_path_relevant_uses_dom_selector():
    tester = PoVTester()
    live = _FakeLiveResult(success=True, vulnerability_triggered=True, response_preview='<div id="result">boom</div>', evidence=[])
    assert tester._is_live_path_relevant(live_result=live, validation_method='browser_live_contract', exploit_contract={'target_dom_selector': '#result'}, target_url='http://target') is True


def test_is_live_path_relevant_false_when_route_does_not_match():
    tester = PoVTester()
    live = _FakeLiveResult(success=True, vulnerability_triggered=True, response_preview='ok', evidence=['body returned ok'])
    assert tester._is_live_path_relevant(live_result=live, validation_method='live_app_contract', exploit_contract={'target_route': '/search'}, target_url='http://target') is False


def test_classify_live_oracle_reason_variants():
    tester = PoVTester()
    live_header = _FakeLiveResult(success=True, vulnerability_triggered=True, evidence=['Header reflected: X-Test'])
    assert tester._classify_live_oracle_reason(live_result=live_header, validation_method='live_app_contract', exploit_contract={'target_route': '/search'}, target_url='http://target') == 'http_header_evidence'
    live_side = _FakeLiveResult(success=True, vulnerability_triggered=True, evidence=['Expected side effect observed: file written'])
    assert tester._classify_live_oracle_reason(live_result=live_side, validation_method='live_app_contract', exploit_contract={'target_route': '/search'}, target_url='http://target') == 'http_side_effect_evidence'
    live_route = _FakeLiveResult(success=True, vulnerability_triggered=True, response_preview='GET /search ok', evidence=[])
    assert tester._classify_live_oracle_reason(live_result=live_route, validation_method='live_app_contract', exploit_contract={'target_route': '/search'}, target_url='http://target') == 'http_route_evidence'
    live_body = _FakeLiveResult(success=True, vulnerability_triggered=True, response_preview='plain body', evidence=[])
    assert tester._classify_live_oracle_reason(live_result=live_body, validation_method='live_app_contract', exploit_contract={'target_route': '/search'}, target_url='http://target') == 'http_body_evidence'


def test_live_format_result_rejects_self_report_only():
    tester = PoVTester()
    setup_result = tester._build_setup_result(stage='setup', success=True)
    live = _FakeLiveResult(success=True, vulnerability_triggered=True, evidence=['script executed'])
    result = tester._format_live_test_result(live_result=live, validation_method='browser_live_contract', setup_result=setup_result, target_url='http://target', exploit_contract={'target_dom_selector': '#result'}, pov_script='console.log("script executed")')
    assert result['oracle_result']['reason'] == 'self_report_only'
    assert result['proof_verdict'] == 'failed'


# ---------------------------------------------------------------------------
# _non_native_script_guardrail_issues
# ---------------------------------------------------------------------------

def test_non_native_guardrail_flags_hardcoded_localhost_live_app():
    tester = PoVTester()
    script = 'import requests\nrequests.get("http://localhost:8080/search")'
    issues = tester._non_native_script_guardrail_issues(script, {}, mode='live_app')
    assert any('hardcoded localhost' in issue.lower() for issue in issues)


def test_non_native_guardrail_flags_127_hardcoded_live_app():
    tester = PoVTester()
    script = 'import requests\nrequests.post("http://127.0.0.1:3000/api")'
    issues = tester._non_native_script_guardrail_issues(script, {}, mode='live_app')
    assert any('hardcoded localhost' in issue.lower() for issue in issues)


def test_non_native_guardrail_clean_live_app_no_issues():
    tester = PoVTester()
    script = '# AUTOPOV_DETERMINISTIC_SKELETON\nTARGET_URL = "http://target"\nrequests.get(TARGET_URL + "/search")'
    issues = tester._non_native_script_guardrail_issues(script, {'target_route': '/search'}, mode='live_app')
    assert issues == []


def test_non_native_guardrail_flags_missing_route_reference_live_app():
    tester = PoVTester()
    # Script has skeleton but doesn't reference the declared route at all
    script = '# AUTOPOV_DETERMINISTIC_SKELETON\nTARGET_URL = "http://target"\nrequests.get(TARGET_URL)'
    issues = tester._non_native_script_guardrail_issues(script, {'target_route': '/admin/secret'}, mode='live_app')
    assert any('target_route' in issue for issue in issues)


def test_non_native_guardrail_repo_script_flags_missing_entrypoint():
    tester = PoVTester()
    script = 'import subprocess\nsubprocess.run(["python3", "run.py"])'
    issues = tester._non_native_script_guardrail_issues(
        script, {'target_entrypoint': 'parse_input'}, mode='repo_script'
    )
    assert any('parse_input' in issue for issue in issues)


def test_non_native_guardrail_repo_script_codebase_path_satisfies():
    tester = PoVTester()
    script = 'CODEBASE_PATH = "/tmp/repo"\nimport subprocess\nsubprocess.run([CODEBASE_PATH])'
    issues = tester._non_native_script_guardrail_issues(
        script, {'target_entrypoint': 'parse_input'}, mode='repo_script'
    )
    assert issues == []


def test_non_native_guardrail_empty_script_no_issues():
    tester = PoVTester()
    assert tester._non_native_script_guardrail_issues('', {}, mode='live_app') == []
    assert tester._non_native_script_guardrail_issues('', {}, mode='repo_script') == []


def test_non_native_guardrail_unknown_entrypoint_no_issues():
    tester = PoVTester()
    script = 'import subprocess\nsubprocess.run(["run.py"])'
    # 'unknown' entrypoints should not trigger guardrail
    issues = tester._non_native_script_guardrail_issues(
        script, {'target_entrypoint': 'unknown'}, mode='repo_script'
    )
    assert issues == []


# ---------------------------------------------------------------------------
# _write_pinentry_stub and _bootstrap_key_material_via_keygen pinentry ordering
# ---------------------------------------------------------------------------

def test_write_pinentry_stub_creates_executable_file(tmp_path):
    tester = PoVTester()
    stub_path = tester._write_pinentry_stub(str(tmp_path))
    assert os.path.isfile(stub_path)
    assert os.access(stub_path, os.X_OK)
    content = Path(stub_path).read_text()
    assert '#!/usr/bin/env python3' in content
    assert 'GETPIN' in content
    assert 'autopov-passphrase' in content
    assert 'BYE' in content


def test_write_pinentry_stub_custom_passphrase(tmp_path):
    tester = PoVTester()
    stub_path = tester._write_pinentry_stub(str(tmp_path), passphrase='mysecret')
    content = Path(stub_path).read_text()
    assert 'mysecret' in content


def test_write_pinentry_stub_creates_dir_if_missing(tmp_path):
    tester = PoVTester()
    target = str(tmp_path / 'nested' / 'dir')
    stub_path = tester._write_pinentry_stub(target)
    assert os.path.isfile(stub_path)


def test_bootstrap_key_material_pinentry_stub_created_before_early_return(monkeypatch, tmp_path):
    # Simulate keys already existing — pinentry_stub must be defined (no NameError)
    tester = PoVTester()
    home = tmp_path / 'home'
    home.mkdir()
    binary_name = 'mytool'
    config_dir = home / '.config' / binary_name
    config_dir.mkdir(parents=True)
    (config_dir / f'{binary_name}.pub').write_text('pub')
    (config_dir / f'{binary_name}.sec').write_text('sec')
    # Should not raise NameError
    result = tester._bootstrap_key_material_via_keygen(
        f'/tmp/{binary_name}', {'HOME': str(home)}, config_name=binary_name
    )
    assert result['success'] is True
    assert any('key material already present' in n for n in result.get('notes', []))
    # pinentry stub should be listed in artifacts
    assert any('autopov_pinentry_stub.py' in str(a) for a in result.get('artifacts', []))


def test_bootstrap_key_material_prefers_pinentry_equals_form(monkeypatch, tmp_path):
    tester = PoVTester()
    home = tmp_path / 'home'
    home.mkdir()
    calls = []
    def _fake_run(command, **kwargs):
        calls.append(command)
        class R:
            returncode = 1
            stdout = ''
            stderr = ''
        return R()
    monkeypatch.setattr('subprocess.run', _fake_run)
    tester._bootstrap_key_material_via_keygen('/tmp/enchive', {'HOME': str(home)})
    # First attempt must use --pinentry= form
    assert calls, 'subprocess.run was never called'
    assert any(str(part).startswith('--pinentry=') for part in calls[0])
