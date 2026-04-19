"""
Tests for agent components
"""

import os
import pytest
from agents.docker_runner import DockerRunner
from agents.static_validator import StaticValidator
from agents.verifier import VulnerabilityVerifier
from agents.pov_tester import PoVTester
from agents.app_runner import ApplicationRunner
from app.agent_graph import AgentGraph
from prompts import (
    format_pov_generation_prompt,
    format_pov_generation_prompt_offline,
    format_pov_refinement_prompt,
    format_pov_refinement_prompt_offline,
    format_pov_validation_prompt,
    format_pov_validation_prompt_offline,
)


class TestVulnerabilityVerifier:
    """Test PoV verifier"""
    
    @pytest.fixture
    def verifier(self):
        """Create verifier instance"""
        return VulnerabilityVerifier()
    
    def test_validate_pov_syntax_error(self, verifier):
        """Test validation catches syntax errors"""
        invalid_script = "def broken(:\n    pass"
        
        result = verifier.validate_pov(
            invalid_script,
            "CWE-89",
            "test.py",
            1
        )
        
        assert result["is_valid"] is False
        assert any("Syntax error" in issue for issue in result["issues"])
    
    def test_validate_pov_missing_trigger(self, verifier):
        """Test validation requires VULNERABILITY TRIGGERED"""
        script = "print('hello')"
        
        result = verifier.validate_pov(
            script,
            "CWE-89",
            "test.py",
            1
        )
        
        assert result["is_valid"] is False
        assert any("VULNERABILITY TRIGGERED" in issue for issue in result["issues"])
    
    def test_validate_pov_valid(self, verifier):
        """Test validation accepts valid script"""
        script = """
import sys
print("VULNERABILITY TRIGGERED")
sys.exit(0)
"""
        
        result = verifier.validate_pov(
            script,
            "CWE-89",
            "test.py",
            1
        )
        
        # Should be valid (no syntax errors, has trigger)
        assert result["is_valid"] is True
    
    def test_stdlib_modules(self, verifier):
        """Test stdlib module detection"""
        stdlib = verifier._get_stdlib_modules()
        
        assert "os" in stdlib
        assert "sys" in stdlib
        assert "json" in stdlib
        assert "requests" not in stdlib  # Not stdlib
    def test_normalize_exploit_contract_adds_proof_plan_for_native(self, verifier):
        contract = verifier._normalize_exploit_contract({}, 'CWE-476', 'Possible null dereference in mqjs loader', 'eval_str = (char *)load_file(filename, NULL);', filepath='mqjs.c')
        plan = contract.get('proof_plan') or {}
        assert plan.get('runtime_family') == 'native'
        assert plan.get('execution_surface') == 'binary_cli'
        assert plan.get('oracle')

    def test_normalize_exploit_contract_prefers_file_input_for_js_engine_targets(self, verifier):
        seed = {
            'target_entrypoint': 'mqjs',
            'runtime_profile': 'c',
            'inputs': ['A JavaScript file containing: load("missing.js")'],
        }
        contract = verifier._normalize_exploit_contract(seed, 'CWE-476', 'mqjs null dereference', 'eval_str = (char *)load_file(filename, NULL);', filepath='mqjs.c')
        plan = contract.get('proof_plan') or {}
        assert plan.get('input_mode') == 'file'
        assert plan.get('input_format') == 'javascript'

    def test_audit_handoff_rejects_missing_native_target(self, verifier):
        audit = verifier.audit_handoff(
            {
                'runtime_profile': 'c',
                'proof_plan': {
                    'runtime_family': 'native',
                    'execution_surface': 'binary_cli',
                    'oracle': ['crash_signal'],
                },
            },
            'CWE-120',
            'native cli overflow',
            'char buf[8];',
            filepath='src/cli.c',
        )
        assert audit['is_ready'] is False
        assert any('missing a concrete binary or entrypoint' in issue for issue in audit['issues'])

    def test_audit_handoff_allows_repo_script_without_explicit_entrypoint(self, verifier):
        audit = verifier.audit_handoff(
            {
                'runtime_profile': 'python',
                'proof_plan': {
                    'runtime_family': 'python',
                    'execution_surface': 'repo_script',
                    'oracle': ['exception'],
                    'preflight_checks': ['module_importable'],
                },
                'inputs': ['payload'],
            },
            'CWE-94',
            'python repo proof',
            'import demo',
            filepath='app/main.py',
        )
        assert audit['is_ready'] is True
        assert any('does not have a concrete entrypoint' in warning for warning in audit['warnings'])

    def test_audit_handoff_rejects_source_like_runtime_target(self, verifier):
        audit = verifier.audit_handoff(
            {
                'runtime_profile': 'c',
                'proof_plan': {
                    'runtime_family': 'native',
                    'execution_surface': 'binary_cli',
                    'oracle': ['crash_signal'],
                    'binary_candidates': ['demo'],
                },
                'runtime_feedback': {
                    'runtime': {
                        'target_binary': '/tmp/demo/examples/websocket/src/websocket.c',
                    }
                },
            },
            'CWE-78',
            'native target drift',
            'int main(void) { return 0; }',
            filepath='src/cli.c',
        )
        assert audit['is_ready'] is False
        assert any('source file' in issue for issue in audit['issues'])

    def test_normalize_exploit_contract_applies_nested_runtime_feedback_to_proof_plan(self, verifier):
        seed = {
            'target_entrypoint': 'quickjs',
            'runtime_profile': 'c',
            'proof_plan': {
                'runtime_family': 'native',
                'execution_surface': 'binary_cli',
                'input_mode': 'file',
                'candidate_input_modes': ['file', 'stdin'],
                'binary_candidates': ['quickjs'],
            },
            'runtime_feedback': {
                'runtime': {
                    'target_binary': '/tmp/autopov/examples/hello_module',
                    'recommended_input_mode': 'argv',
                    'supported_input_modes': ['argv', 'stdin'],
                    'observed_surface': {
                        'options': [],
                        'supports_positional_file': False,
                        'eval_option': None,
                        'include_option': None,
                    },
                }
            },
        }
        contract = verifier._normalize_exploit_contract(seed, 'CWE-787', 'native cli drift', 'int main(void) { return 0; }', filepath='quickjs.c')
        plan = contract.get('proof_plan') or {}
        assert plan.get('input_mode') == 'argv'
        assert 'argv' in (plan.get('candidate_input_modes') or [])
        assert (plan.get('binary_candidates') or [])[0] == 'hello_module'
        assert contract.get('target_entrypoint') == 'hello_module'

    def test_validate_pov_rejects_missing_file_native_trigger(self, verifier):
        script = '''
import subprocess
subprocess.run(["mqjs", "/tmp/definitely_missing.js"])
print("VULNERABILITY TRIGGERED")
'''
        contract = {
            'target_entrypoint': 'mqjs',
            'runtime_profile': 'c',
            'proof_plan': {
                'runtime_family': 'native',
                'input_mode': 'file',
                'input_format': 'javascript',
            },
        }
        result = verifier.validate_pov(script, 'CWE-476', 'mqjs.c', 44, exploit_contract=contract)
        assert result['is_valid'] is False
        assert any('missing-file path' in issue for issue in result['issues'])

    def test_validate_pov_rejects_invalid_native_eval_payload(self, verifier):
        script = '''
import subprocess
subprocess.run(["mqjs", "-e", "'use strict';;const S = 'A'.repeat(8);;}};"])
print("VULNERABILITY TRIGGERED")
'''
        contract = {
            'target_entrypoint': 'mqjs',
            'runtime_profile': 'c',
            'proof_plan': {
                'runtime_family': 'native',
                'input_mode': 'argv',
                'input_format': 'javascript',
            },
        }
        result = verifier.validate_pov(script, 'CWE-476', 'mqjs.c', 44, exploit_contract=contract)
        assert result['is_valid'] is False
        assert any('invalid JavaScript syntax' in issue for issue in result['issues'])
    def test_validate_pov_rejects_generated_c_harness_with_single_backslash_newlines(self, verifier):
        script = '''
from pathlib import Path
harness_c = Path("harness.c")
harness_c.write_text("""
#include <stdio.h>
int main(void) {
  fprintf(stderr, "usage: %s\n", "demo");
  printf("HARNESS_DONE\n");
  return 0;
}
""", encoding="utf-8")
print("VULNERABILITY TRIGGERED")
'''
        contract = {
            'target_entrypoint': 'unknown',
            'runtime_profile': 'c',
            'proof_plan': {
                'runtime_family': 'native',
                'input_mode': 'argv',
                'input_format': 'text',
            },
        }
        result = verifier.validate_pov(script, 'CWE-22', 'docs/examples/ftp-wildcard.c', 1, exploit_contract=contract)
        assert result['is_valid'] is False
        assert any('malformed C source' in issue for issue in result['issues'])

    def test_pov_generation_prompts_are_harmonized_between_online_and_offline(self, verifier):
        online = format_pov_generation_prompt(
            cwe_type='CWE-476',
            filepath='mqjs.c',
            line_number=44,
            vulnerable_code='eval_str = load_file(filename, NULL);',
            explanation='Possible null dereference',
            code_context='int main(void) { return 0; }',
            target_language='c',
            pov_language='python',
            exploit_contract={'target_entrypoint': 'mqjs'},
            runtime_feedback='{}',
        )
        offline = format_pov_generation_prompt_offline(
            cwe_type='CWE-476',
            filepath='mqjs.c',
            line_number=44,
            vulnerable_code='eval_str = load_file(filename, NULL);',
            explanation='Possible null dereference',
            code_context='int main(void) { return 0; }',
            target_language='c',
            pov_language='python',
            exploit_contract={'target_entrypoint': 'mqjs'},
            runtime_feedback='{}',
        )
        assert online == offline

    def test_pov_validation_prompts_are_harmonized_between_online_and_offline(self, verifier):
        online = format_pov_validation_prompt('print("VULNERABILITY TRIGGERED")', 'CWE-476', 'mqjs.c', 44, exploit_contract={'goal': 'prove crash'})
        offline = format_pov_validation_prompt_offline('print("VULNERABILITY TRIGGERED")', 'CWE-476', 'mqjs.c', 44, exploit_contract={'goal': 'prove crash'})
        assert online == offline

    def test_pov_refinement_prompts_are_harmonized_between_online_and_offline(self, verifier):
        online = format_pov_refinement_prompt(
            cwe_type='CWE-476',
            filepath='mqjs.c',
            line_number=44,
            vulnerable_code='eval_str = load_file(filename, NULL);',
            explanation='Possible null dereference',
            code_context='int main(void) { return 0; }',
            failed_pov='print(1)',
            validation_errors=['oracle_not_observed'],
            attempt_number=2,
            target_language='c',
            exploit_contract={'target_entrypoint': 'mqjs'},
            runtime_feedback='{}',
        )
        offline = format_pov_refinement_prompt_offline(
            cwe_type='CWE-476',
            filepath='mqjs.c',
            line_number=44,
            vulnerable_code='eval_str = load_file(filename, NULL);',
            explanation='Possible null dereference',
            code_context='int main(void) { return 0; }',
            failed_pov='print(1)',
            validation_errors=['oracle_not_observed'],
            attempt_number=2,
            target_language='c',
            exploit_contract={'target_entrypoint': 'mqjs'},
            runtime_feedback='{}',
        )
        assert online == offline


class TestAgentGraphProofHandoff:
    def test_attach_feedback_to_contract_preserves_validation_and_runtime(self):
        graph = AgentGraph()
        finding = {
            "exploit_contract": {"target_entrypoint": "mqjs"},
        }

        validation_result = {
            "is_valid": False,
            "issues": ["PoV may not directly address the vulnerable code or exploit contract"],
            "suggestions": ["Use the observed binary surface"],
            "will_trigger": "NO",
            "validation_method": "native_guardrails",
        }
        runtime_result = {
            "failure_category": "oracle_not_observed",
            "validation_method": "native_binary_harness",
            "oracle_result": {"reason": "self_report_only", "matched_markers": ["vulnerability triggered"], "self_report_only": True},
            "recommended_input_mode": "file",
            "supported_input_modes": ["file", "stdin"],
            "surface": {"options": ["--eval", "--memory-limit"], "supports_positional_file": True},
            "stdout": "VULNERABILITY TRIGGERED",
            "stderr": "",
            "exit_code": 0,
        }

        contract = graph._attach_feedback_to_contract(finding, validation_result=validation_result, runtime_result=runtime_result)

        assert contract["runtime_feedback"]["validation"]["issues"] == validation_result["issues"]
        assert contract["runtime_feedback"]["runtime"]["failure_category"] == "oracle_not_observed"
        assert contract["runtime_feedback"]["runtime"]["recommended_input_mode"] == "file"
        assert contract["runtime_feedback"]["runtime"]["oracle_reason"] == "self_report_only"

    def test_derive_refinement_errors_from_runtime_when_validation_is_empty(self):
        graph = AgentGraph()
        runtime_result = {
            "failure_category": "oracle_not_observed",
            "oracle_result": {"reason": "self_report_only", "self_report_only": True},
            "recommended_input_mode": "file",
            "supported_input_modes": ["file", "stdin"],
            "selected_variant": "argv_payload",
            "surface": {"options": ["--eval", "--memory-limit"]},
            "stderr": "path exercised but no crash",
        }

        issues = graph._derive_refinement_errors({}, runtime_result)

        assert any("Runtime failure category: oracle_not_observed" in issue for issue in issues)
        assert any("self-reported success" in issue for issue in issues)
        assert any("recommends input mode: file" in issue for issue in issues)
        assert any("argv_payload" in issue for issue in issues)

class TestStaticValidator:
    def test_validate_allows_native_binary_pov_when_entrypoint_is_unknown(self):
        validator = StaticValidator()
        script = '''
import os
import subprocess
binary = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN")
subprocess.run([binary, "payload"], check=False)
print("VULNERABILITY TRIGGERED")
'''
        contract = {
            'target_entrypoint': 'unknown',
            'runtime_profile': 'c',
            'proof_plan': {
                'runtime_family': 'native',
                'input_mode': 'argv',
                'input_format': 'text',
            },
        }

        result = validator.validate(script, 'CWE-22', '', 'docs/examples/ftp-wildcard.c', 1, exploit_contract=contract)

        assert result.is_valid is True
        assert 'PoV does not reference the target entrypoint from the exploit contract' not in result.issues


    def test_validate_handles_dict_shaped_contract_lists_without_crashing(self):
        validator = StaticValidator()
        script = '''
print("VULNERABILITY TRIGGERED")
SPECIAL_MARKER = 1
'''
        contract = {
            'target_entrypoint': 'unknown',
            'runtime_profile': 'c',
            'success_indicators': {'marker': 'SPECIAL_MARKER'},
            'inputs': {'mode': 'argv'},
            'side_effects': {'artifact': 'output.txt'},
            'proof_plan': {
                'runtime_family': 'native',
                'input_mode': 'argv',
                'input_format': 'text',
            },
        }

        result = validator.validate(script, 'CWE-22', '', 'docs/examples/ftp-wildcard.c', 1, exploit_contract=contract)

        assert isinstance(result.issues, list)
        assert any('SPECIAL_MARKER' in pattern for pattern in result.matched_patterns)

class TestPoVTester:
    @pytest.fixture
    def tester(self):
        return PoVTester()

    def test_evaluate_proof_outcome_uses_contract_markers(self, tester):
        contract = {
            'success_indicators': ['SPECIAL_MARKER'],
            'proof_plan': {'oracle': ['response_marker']},
        }
        result = tester._evaluate_proof_outcome('ok SPECIAL_MARKER', '', 0, contract)
        assert result['triggered'] is True
        assert 'special_marker' in result['matched_markers']

    def test_evaluate_proof_outcome_detects_native_crash_oracle(self, tester):
        contract = {
            'proof_plan': {'oracle': ['crash_signal', 'sanitizer_output']},
        }
        result = tester._evaluate_proof_outcome('', 'AddressSanitizer: heap-buffer-overflow', 1, contract)
        assert result['triggered'] is True

    def test_evaluate_proof_outcome_rejects_self_report_only_marker(self, tester):
        result = tester._evaluate_proof_outcome('VULNERABILITY TRIGGERED', '', 0, {})
        assert result['triggered'] is False
        assert result['reason'] == 'self_report_only'
        assert result['self_report_only'] is True

    def test_evaluate_proof_outcome_accepts_contract_specific_marker(self, tester):
        contract = {
            'success_indicators': ['SPECIAL_MARKER'],
            'proof_plan': {'oracle': ['response_marker']},
        }
        result = tester._evaluate_proof_outcome('SPECIAL_MARKER\nVULNERABILITY TRIGGERED', '', 0, contract)
        assert result['triggered'] is True
        assert result['reason'] == 'oracle_matched'

    def test_evaluate_proof_outcome_rejects_generic_traceback_setup_failure(self, tester):
        contract = {
            'proof_plan': {'oracle': ['exception']},
        }
        stderr = "Traceback (most recent call last):\nModuleNotFoundError: No module named 'more_itertools'"
        result = tester._evaluate_proof_outcome('', stderr, 1, contract)
        assert result['triggered'] is False
        assert result['reason'] == 'environment_failure'
        assert result['setup_failure_detected'] is True

    def test_evaluate_proof_outcome_accepts_structured_native_crash(self, tester):
        contract = {
            'proof_plan': {'oracle': ['crash_signal', 'sanitizer_output']},
        }
        stdout = 'VULNERABILITY TRIGGERED\n{"limit_kb": 1024, "returncode": -11, "evidence": ["signal=11"]}\n'
        result = tester._evaluate_proof_outcome(stdout, '', 0, contract)
        assert result['triggered'] is True
        assert result['reason'] in {'oracle_matched', 'structured_native_crash', 'native_crash_signal'}
        assert 'signal=11' in result['matched_markers']
        assert result['self_report_only'] is False





class TestApplicationRunnerCrossLanguage:
    def test_detect_node_package_manager_prefers_lockfiles(self, tmp_path):
        runner = ApplicationRunner()
        (tmp_path / 'pnpm-lock.yaml').write_text('lockfileVersion: 9', encoding='utf-8')
        assert runner._detect_node_package_manager(str(tmp_path)) == 'pnpm'
        (tmp_path / 'pnpm-lock.yaml').unlink()
        (tmp_path / 'yarn.lock').write_text('# yarn lockfile', encoding='utf-8')
        assert runner._detect_node_package_manager(str(tmp_path)) == 'yarn'

    def test_detect_python_entrypoint_skips_test_paths(self, tmp_path):
        runner = ApplicationRunner()
        tests_dir = tmp_path / 'tests'
        tests_dir.mkdir()
        (tests_dir / 'app.py').write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding='utf-8')
        src_dir = tmp_path / 'src'
        src_dir.mkdir()
        real_entry = src_dir / 'server.py'
        real_entry.write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding='utf-8')
        assert runner._detect_python_entrypoint(str(tmp_path)) == str(real_entry)


class TestNativeLibraryFallback:
    def test_extract_target_entrypoint_handles_inline_native_function(self):
        verifier = VulnerabilityVerifier()
        code = """static inline bu256_t *bu256_new(const bu256_t *init_val)
{
    return 0;
}
"""
        assert verifier._extract_target_entrypoint(code, 'include/ccoin/buint.h') == 'bu256_new'

    def test_generate_pov_falls_back_for_native_library_finding(self):
        verifier = VulnerabilityVerifier()
        contract = {
            'runtime_profile': 'c',
            'target_entrypoint': 'unknown',
            'proof_plan': {
                'runtime_family': 'native',
                'execution_surface': 'binary_cli',
                'input_mode': 'argv',
                'input_format': 'text',
                'oracle': ['crash_signal'],
                'preflight_checks': ['binary_exists'],
            },
        }
        result = verifier._synthesize_native_library_fallback_pov(
            'CWE-476',
            'include/ccoin/buint.h',
            """static inline bu256_t *bu256_new(const bu256_t *init_val)
{
    bu256_t *v;
    v = (bu256_t *)malloc(sizeof(bu256_t));
    bu256_copy(v, init_val);
    return v;
}
""",
            'Unchecked allocation failure leads to null dereference',
            contract,
        )
        assert result is not None
        assert result['success'] is True
        assert 'VULNERABILITY TRIGGERED' in result['pov_script']
        assert result['exploit_contract']['target_entrypoint'] == 'bu256_new'
        assert result['exploit_contract']['proof_plan']['execution_surface'] == 'function_call'

    def test_generate_pov_native_library_fallback_escapes_newlines(self):
        verifier = VulnerabilityVerifier()
        contract = {
            'runtime_profile': 'c',
            'target_entrypoint': 'unknown',
            'proof_plan': {
                'runtime_family': 'native',
                'execution_surface': 'binary_cli',
                'input_mode': 'argv',
                'input_format': 'text',
                'oracle': ['crash_signal'],
                'preflight_checks': ['binary_exists'],
            },
        }
        result = verifier._synthesize_native_library_fallback_pov(
            'CWE-476',
            'include/ccoin/buint.h',
            """static inline bu256_t *bu256_new(const bu256_t *init_val)
{
    bu256_t *v;
    v = (bu256_t *)malloc(sizeof(bu256_t));
    bu256_copy(v, init_val);
    return v;
}
""",
            'Unchecked allocation failure leads to null dereference',
            contract,
        )
        script = result['pov_script']
        assert "\\n" in script
        assert "Awaiting native harness fallback" in script
        compile(script, '<generated-pov>', 'exec')
