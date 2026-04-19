"""
7-layer repo-independent regression suite for oracle_policy and proof_schemas.

No real repo, no network, no Docker required.  All inputs are synthetic strings.

Layer 1 — Signal classifier logic
Layer 2 — Path relevance
Layer 3 — Self-report blocking
Layer 4 — Full decision (evaluate_proof_outcome)
Layer 5 — Contract gate (_contract_gate)
Layer 6 — Proof plan validation (_validate_proof_plan)
Layer 7 — ProofPlan.has_placeholders() unit check
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from agents.oracle_policy import (
    classify_signal,
    evaluate_proof_outcome,
    is_path_relevant,
    is_self_report_only,
    validate_expected_oracle,
)
from agents.proof_schemas import ExploitContract, ProofPlan, RuntimeResult


# ===========================================================================
# Layer 1 — Signal classifier logic
# ===========================================================================

class TestClassifySignal:
    def test_non_evidence_unknown_command(self):
        assert classify_signal('', 'enchive: unknown command', 1) == 'non_evidence'

    def test_non_evidence_missing_command(self):
        assert classify_signal('missing command\n', '', 1) == 'non_evidence'

    def test_non_evidence_clean_exit(self):
        assert classify_signal('output ok', '', 0) == 'non_evidence'

    def test_non_evidence_usage_text(self):
        assert classify_signal('', 'usage: enchive [options]\ntry --help', 1) == 'non_evidence'

    def test_strong_asan_banner(self):
        stderr = '==12345== ERROR: AddressSanitizer: heap-use-after-free on address 0x...'
        assert classify_signal('', stderr, 1) == 'strong'

    def test_strong_heap_use_after_free_keyword(self):
        assert classify_signal('', 'heap-use-after-free at 0xdeadbeef', 1) == 'strong'

    def test_strong_beats_non_evidence(self):
        # Binary prints usage first, then crashes with ASan — strong wins
        combined_stderr = 'usage: enchive\n==1234== ERROR: AddressSanitizer: heap-buffer-overflow'
        assert classify_signal('', combined_stderr, 1) == 'strong'

    def test_non_evidence_usage_without_strong(self):
        assert classify_signal('', 'usage: enchive [options]', 1) == 'non_evidence'

    def test_ambiguous_generic_abort(self):
        # "abort" alone, no sanitizer banner
        assert classify_signal('', 'Aborted (core dumped)', 134) == 'ambiguous'

    def test_strong_stack_buffer_overflow(self):
        assert classify_signal('', 'SUMMARY: AddressSanitizer: stack-buffer-overflow', 1) == 'strong'

    def test_strong_ubsan_runtime_error(self):
        assert classify_signal('', 'runtime error: signed integer overflow: .c:42', 1) == 'strong'

    def test_strong_stack_frame(self):
        assert classify_signal('', '#0 0xdeadbeef in command_extract /src/enchive.c:1574', 1) == 'strong'

    def test_validate_expected_oracle_rejects_generic(self):
        assert not validate_expected_oracle('vulnerability triggered')
        assert not validate_expected_oracle('crash')
        assert not validate_expected_oracle('error')
        assert not validate_expected_oracle('')

    def test_validate_expected_oracle_accepts_specific(self):
        assert validate_expected_oracle('heap-use-after-free')
        assert validate_expected_oracle('==1234== ERROR: heap-buffer-overflow')
        assert validate_expected_oracle('stack-buffer-overflow on address')


# ===========================================================================
# Layer 2 — Path relevance
# ===========================================================================

class TestIsPathRelevant:
    def test_entrypoint_in_stack_trace(self):
        output = '#0 0xdeadbeef in command_extract /src/enchive.c:1574'
        assert is_path_relevant(output, 'command_extract', '/src/enchive.c')

    def test_filepath_basename_in_output(self):
        output = 'READ of size 8 at 0x... by thread T0\n#0 enchive.c:1591'
        assert is_path_relevant(output, '', '/src/enchive.c')

    def test_neither_present_returns_false(self):
        output = '==1234== ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...'
        assert not is_path_relevant(output, 'command_extract', '/src/enchive.c')

    def test_empty_target_and_filepath(self):
        output = 'heap-use-after-free'
        assert not is_path_relevant(output, '', '')

    def test_case_insensitive_match(self):
        output = 'in COMMAND_EXTRACT at line 1574'
        assert is_path_relevant(output, 'command_extract', '')


# ===========================================================================
# Layer 3 — Self-report blocking
# ===========================================================================

class TestIsSelfReportOnly:
    _script_with_print = 'import subprocess\nprint("VULNERABILITY TRIGGERED")\n'
    _script_without_print = 'import subprocess\nresult = subprocess.run(["./enchive"])\n'

    def test_self_report_only_when_only_marker(self):
        evidence = ['vulnerability triggered']
        assert is_self_report_only(self._script_with_print, evidence)

    def test_not_self_report_when_asan_present(self):
        evidence = ['vulnerability triggered', 'heap-use-after-free']
        assert not is_self_report_only(self._script_with_print, evidence)

    def test_not_self_report_when_non_self_report_marker(self):
        evidence = ['heap-use-after-free']
        assert not is_self_report_only(self._script_without_print, evidence)

    def test_empty_markers_returns_false(self):
        assert not is_self_report_only(self._script_with_print, [])

    def test_self_report_string_not_in_script_returns_false(self):
        # Marker says "vulnerability triggered" but script does not contain it
        evidence = ['vulnerability triggered']
        assert not is_self_report_only(self._script_without_print, evidence)


# ===========================================================================
# Layer 4 — Full decision (evaluate_proof_outcome)
# ===========================================================================

_ASAN_STDERR = (
    '==1234== ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef\n'
    '#0 0xdeadbeef in command_extract /src/enchive.c:1591\n'
    '#1 0xdeadbeef in main /src/enchive.c:42\n'
)


class TestEvaluateProofOutcome:
    def test_confirmed_strong_path_relevant(self):
        result = evaluate_proof_outcome(
            '', _ASAN_STDERR, 1,
            target_entrypoint='command_extract',
            filepath='/src/enchive.c',
        )
        assert result['triggered'] is True
        assert 'strong_signal' in result['reason']
        assert result['path_relevant'] is True

    def test_not_confirmed_path_not_relevant(self):
        # Strong signal but target_entrypoint not in output
        result = evaluate_proof_outcome(
            '', _ASAN_STDERR, 1,
            target_entrypoint='some_other_function',
            filepath='/other/file.c',
        )
        assert result['triggered'] is False
        assert result['reason'] == 'path_not_relevant'

    def test_not_confirmed_strong_no_target(self):
        # Strong signal but no target_entrypoint, no target_binary, no filepath
        # — must NOT auto-confirm; has_any_target is False
        result = evaluate_proof_outcome(
            '', _ASAN_STDERR, 1,
            target_entrypoint='',
            filepath='',
            target_binary='',
        )
        assert result['triggered'] is False
        assert result['reason'] == 'strong_signal_no_target'

    def test_confirmed_binary_name_relevance(self):
        # Strong signal + no target_entrypoint + target_binary name appears in crash output
        # — CLI-style native proof: gate admits it, oracle must confirm via binary-name path
        asan_with_binary = _ASAN_STDERR + '\nenchive: heap-use-after-free near enchive+0x42\n'
        result = evaluate_proof_outcome(
            '', asan_with_binary, 1,
            target_entrypoint='',
            filepath='',
            target_binary='enchive',
        )
        assert result['triggered'] is True
        assert 'strong_signal' in result['reason']
        assert result['path_relevant'] is True

    def test_not_confirmed_binary_name_absent(self):
        # Strong signal + no target_entrypoint + target_binary name NOT in crash output
        # — binary-name path cannot confirm; must return path_not_relevant
        result = evaluate_proof_outcome(
            '', _ASAN_STDERR, 1,
            target_entrypoint='',
            filepath='',
            target_binary='other_binary',
        )
        assert result['triggered'] is False
        assert result['reason'] == 'path_not_relevant'

    def test_not_confirmed_non_evidence(self):
        result = evaluate_proof_outcome(
            '', 'enchive: unknown command', 1,
            target_entrypoint='command_extract',
        )
        assert result['triggered'] is False
        assert result['reason'] == 'non_evidence'
        assert result['disqualified'] is True

    def test_not_confirmed_self_report_only(self):
        # PoV exits with error (exit_code=1) but only prints a self-report success string.
        # classify_signal returns 'ambiguous' (no strong crash pattern, no non-evidence pattern).
        # is_self_report_only should then block confirmation.
        script = 'import os\nprint("VULNERABILITY TRIGGERED")\nsys.exit(1)\n'
        result = evaluate_proof_outcome(
            'VULNERABILITY TRIGGERED\n', '', 1,
            target_entrypoint='command_extract',
            pov_script=script,
        )
        assert result['triggered'] is False
        assert result['reason'] == 'self_report_only'

    def test_not_confirmed_ambiguous(self):
        result = evaluate_proof_outcome(
            '', 'Aborted (core dumped)', 134,
            target_entrypoint='command_extract',
            filepath='/src/enchive.c',
        )
        assert result['triggered'] is False
        assert result['reason'] == 'ambiguous_signal'

    def test_model_oracle_matched_supporting_signal(self):
        # expected_oracle matches but cannot alone set triggered=True
        # (here signal is ambiguous so it should remain not confirmed)
        result = evaluate_proof_outcome(
            '', 'heap-use-after-free something generic', 134,
            target_entrypoint='',
            expected_oracle='heap-use-after-free',
        )
        # signal is 'strong' here (keyword present), but no target -> unresolved
        assert result['model_oracle_matched'] is True
        assert result['triggered'] is False  # no target known

    def test_oracle_aligned_in_reason_when_confirmed(self):
        result = evaluate_proof_outcome(
            '', _ASAN_STDERR, 1,
            target_entrypoint='command_extract',
            filepath='/src/enchive.c',
            expected_oracle='heap-use-after-free',
        )
        assert result['triggered'] is True
        assert 'oracle_aligned' in result['reason']

    def test_backward_compat_keys_present(self):
        result = evaluate_proof_outcome('', _ASAN_STDERR, 1)
        assert 'matched_markers' in result
        assert 'setup_failure_detected' in result


# ===========================================================================
# Layer 5 — Contract gate (_contract_gate)
# ===========================================================================

# Import the gate via the verifier module
try:
    from agents.verifier import VulnerabilityVerifier
    _verifier = VulnerabilityVerifier()
    _HAS_VERIFIER = True
except Exception:
    _HAS_VERIFIER = False


@pytest.mark.skipif(not _HAS_VERIFIER, reason='VulnerabilityVerifier not importable')
class TestContractGate:
    def _gate(self, contract, family, preflight=None):
        return _verifier._contract_gate(contract, family, preflight or {})

    def test_native_blocks_all_unresolved(self):
        contract = {}
        issues = self._gate(contract, 'native')
        assert any('unresolved' in i for i in issues)

    def test_native_passes_with_target_binary_only(self):
        contract = {'target_binary': 'enchive'}
        issues = self._gate(contract, 'native')
        assert not any('target_entrypoint' in i or 'unresolved' in i for i in issues)

    def test_native_passes_with_function_harness_surface(self):
        contract = {'execution_surface': 'function_harness'}
        issues = self._gate(contract, 'native')
        assert not any('unresolved' in i for i in issues)

    def test_python_blocks_unknown_entrypoint(self):
        contract = {'target_entrypoint': 'unknown'}
        issues = self._gate(contract, 'python')
        assert any('target_entrypoint' in i for i in issues)

    def test_browser_blocks_missing_execution_surface(self):
        contract = {}
        issues = self._gate(contract, 'browser')
        assert any('execution_surface' in i for i in issues)

    def test_live_app_blocks_missing_execution_surface(self):
        contract = {}
        issues = self._gate(contract, 'live_app')
        assert any('execution_surface' in i for i in issues)

    def test_blocks_when_no_pre_gen_oracle(self):
        contract = {'target_binary': 'enchive', 'target_entrypoint': 'archive'}
        issues = self._gate(contract, 'native')
        assert any('success' in i or 'oracle' in i for i in issues)

    def test_passes_with_success_indicators(self):
        contract = {
            'target_binary': 'enchive',
            'target_entrypoint': 'archive',
            'success_indicators': ['heap-use-after-free'],
        }
        issues = self._gate(contract, 'native')
        assert not any('success' in i or 'oracle' in i for i in issues)

    def test_preflight_issues_block(self):
        contract = {
            'target_binary': 'enchive',
            'target_entrypoint': 'archive',
            'success_indicators': ['heap-use-after-free'],
        }
        preflight = {'issues': ['binary not found in codebase']}
        issues = self._gate(contract, 'native', preflight)
        assert any('preflight' in i for i in issues)

    def test_clean_native_contract_passes(self):
        contract = {
            'target_entrypoint': 'command_extract',
            'target_binary': 'enchive',
            'success_indicators': ['heap-use-after-free'],
        }
        issues = self._gate(contract, 'native')
        assert issues == []


# ===========================================================================
# Layer 6 — Proof plan validation (_validate_proof_plan)
# ===========================================================================

@pytest.mark.skipif(not _HAS_VERIFIER, reason='VulnerabilityVerifier not importable')
class TestValidateProofPlan:
    def _validate(self, plan_dict, contract=None):
        return _verifier._validate_proof_plan(plan_dict, contract or {})

    def _clean_plan(self):
        return {
            'target_binary': 'enchive',
            'target_entrypoint': 'command_extract',
            'argv': ['archive', '-k', 'key.sec', 'file.enc'],
            'expected_oracle': 'heap-use-after-free',
            'why_this_hits_target': 'archive subcommand calls command_extract which frees key',
        }

    def test_rejects_placeholder_target_binary(self):
        plan = self._clean_plan()
        plan['target_binary'] = '/path/to/binary'
        issues = self._validate(plan)
        assert issues

    def test_rejects_angle_bracket_target_binary(self):
        plan = self._clean_plan()
        plan['target_binary'] = '<binary>'
        issues = self._validate(plan)
        assert issues

    def test_rejects_generic_expected_oracle(self):
        plan = self._clean_plan()
        plan['expected_oracle'] = 'vulnerability triggered'
        issues = self._validate(plan)
        assert issues

    def test_rejects_empty_expected_oracle(self):
        plan = self._clean_plan()
        plan['expected_oracle'] = ''
        issues = self._validate(plan)
        assert issues

    def test_accepts_well_formed_plan(self):
        issues = self._validate(self._clean_plan())
        assert issues == []

    def test_rejects_argv_with_angle_bracket_tokens(self):
        plan = self._clean_plan()
        plan['argv'] = ['<arg1>', '<arg2>']
        issues = self._validate(plan)
        assert issues

    def test_rejects_argv_with_path_to_token(self):
        plan = self._clean_plan()
        plan['argv'] = ['archive', '/path/to/file']
        issues = self._validate(plan)
        assert issues

    def test_accepts_standalone_repeated_char_payload(self):
        # AAAA... alone — legitimate overflow payload, must NOT be blocked
        plan = self._clean_plan()
        plan['argv'] = ['archive', 'AAAAAAAAAAAAAAAA']
        issues = self._validate(plan)
        assert issues == []

    def test_rejects_repeated_char_with_scaffold_smell(self):
        # AAAA... co-occurring with <arg1> — scaffold smell combination
        plan = self._clean_plan()
        plan['argv'] = ['<arg1>', 'AAAAAAAAAAAAAAAA']
        issues = self._validate(plan)
        assert issues

    def test_function_harness_without_binary_passes(self):
        # function_harness surface does not require target_binary
        plan = {
            'target_binary': '',
            'target_entrypoint': 'command_extract',
            'execution_surface': 'function_harness',
            'argv': [],
            'expected_oracle': 'heap-use-after-free',
            'why_this_hits_target': 'harness calls command_extract directly',
        }
        contract = {'execution_surface': 'function_harness', 'runtime_profile': 'native'}
        issues = self._validate(plan, contract)
        # Should have no target_binary error
        assert not any('target_binary is empty' in i for i in issues)

    def test_non_native_family_without_binary_passes(self):
        # Python family does not require target_binary
        plan = {
            'target_binary': '',
            'target_entrypoint': 'parse_input',
            'argv': [],
            'expected_oracle': 'runtime error: index out of range',
            'why_this_hits_target': 'calls parse_input with oversized payload',
        }
        contract = {'runtime_profile': 'python'}
        issues = self._validate(plan, contract)
        assert not any('target_binary is empty' in i for i in issues)


# ===========================================================================
# Layer 7 — ProofPlan.has_placeholders() unit check
# ===========================================================================

class TestProofPlanHasPlaceholders:
    def test_clean_plan_returns_false(self):
        p = ProofPlan(
            target_binary='enchive',
            target_entrypoint='command_extract',
            expected_oracle='heap-use-after-free',
        )
        assert p.has_placeholders() is False

    def test_placeholder_target_binary_returns_true(self):
        p = ProofPlan(
            target_binary='/path/to/enchive',
            target_entrypoint='command_extract',
            expected_oracle='heap-use-after-free',
        )
        assert p.has_placeholders() is True

    def test_generic_oracle_returns_true(self):
        p = ProofPlan(
            target_binary='enchive',
            target_entrypoint='command_extract',
            expected_oracle='crash',
        )
        assert p.has_placeholders() is True

    def test_real_entrypoint_returns_false(self):
        p = ProofPlan(
            target_binary='enchive',
            target_entrypoint='key_derive',
            expected_oracle='runtime error: signed integer overflow',
        )
        assert p.has_placeholders() is False

    def test_empty_target_binary_returns_true(self):
        p = ProofPlan(target_binary='', target_entrypoint='func', expected_oracle='heap-use-after-free')
        assert p.has_placeholders() is True

    def test_no_empty_string_false_positive(self):
        # '' in _PLACEHOLDER_MARKERS must not cause has_placeholders() to return True
        # for a legitimate non-empty target_binary
        p = ProofPlan(
            target_binary='enchive',
            target_entrypoint='archive',
            expected_oracle='heap-buffer-overflow',
        )
        assert p.has_placeholders() is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


class TestPathRelevanceStrictTarget:
    def test_known_entrypoint_dominates_file_and_binary_match(self):
        combined = "src/enchive.c:1404 runtime error: left shift of negative value\n#5 0xdead in command_keygen\n/tmp/autopov/enchive"
        assert is_path_relevant(combined, "command_extract", "src/enchive.c", "enchive") is False

    def test_evaluate_proof_outcome_rejects_unrelated_setup_crash(self):
        stderr = "src/enchive.c:1404: runtime error: left shift of negative value\n#5 0xdead in command_keygen\n/tmp/autopov/enchive"
        result = evaluate_proof_outcome("", stderr, 1, target_entrypoint="command_extract", filepath="src/enchive.c", target_binary="enchive")
        assert result["triggered"] is False
        assert result["reason"] == "path_not_relevant"


def test_strong_setup_stage_does_not_confirm():
    stderr = "src/enchive.c:1404: runtime error: left shift of negative value\n#5 0xdead in command_extract"
    result = evaluate_proof_outcome("", stderr, 1, target_entrypoint="command_extract", filepath="src/enchive.c", target_binary="enchive", stage="setup")
    assert result["triggered"] is False
    assert result["reason"] == "setup_stage_only"


def test_relevance_anchor_overrides_file_level_match():
    stderr = "src/enchive.c:1404: runtime error: left shift of negative value\n#5 0xdead in command_keygen"
    result = evaluate_proof_outcome("", stderr, 1, target_entrypoint="command_extract", filepath="src/enchive.c", target_binary="enchive", relevance_anchors=["command_extract"])
    assert result["triggered"] is False
    assert result["reason"] == "path_not_relevant"



def test_evaluate_live_proof_outcome_rejects_self_report_only_browser():
    import agents.oracle_policy as oracle_policy
    result = oracle_policy.evaluate_live_proof_outcome(
        ['script executed'],
        target_dom_selector='#result',
        target_url='http://target',
        pov_script='console.log("script executed")',
        stage='trigger',
        runtime_family='browser',
    )
    assert result['triggered'] is False
    assert result['reason'] == 'self_report_only'


def test_evaluate_live_proof_outcome_honors_stage_guard():
    import agents.oracle_policy as oracle_policy
    result = oracle_policy.evaluate_live_proof_outcome(
        ['Success indicator observed in DOM: boom'],
        target_dom_selector='#result',
        target_url='http://target',
        stage='setup',
        runtime_family='browser',
    )
    assert result['triggered'] is False
    assert result['reason'] == 'setup_stage_only'


def test_evaluate_proof_outcome_ignores_non_crash_target_mentions_for_relevance():
    stdout = "running enchive extract with crafted archive\n"
    stderr = (
        "curve25519-donna.c:304: runtime error: left shift of negative value -54871\n"
        "    #0 0xdeadbeef in command_keygen /src/enchive.c:999\n"
    )
    result = evaluate_proof_outcome(
        stdout=stdout,
        stderr=stderr,
        exit_code=2,
        target_entrypoint='command_extract',
        filepath='src/enchive.c',
        target_binary='enchive',
        relevance_anchors=['command_extract', 'extract'],
        stage='trigger',
    )
    assert result['signal_class'] == 'strong'
    assert result['path_relevant'] is False
    assert result['triggered'] is False
    assert result['reason'] == 'path_not_relevant'
