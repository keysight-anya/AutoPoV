"""
Synthetic unit tests for Layer 1 Target Resolution fixes.

Tests cover:
  1. Binary anchor promotion (preflight > candidates > no-op)
  2. Subcommand extraction from various help-text formats
  3. resolution_status derivation from gate blocking reasons
  4. argv[0] subcommand enforcement in _validate_proof_plan
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.verifier import VulnerabilityVerifier, _resolution_status_from_gate, _GATE_CODE_MAP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_verifier():
    return VulnerabilityVerifier()


def _normalize(verifier, contract, cwe_type='CWE-787', explanation='heap overflow',
               vulnerable_code='void f(){}', filepath='target.c', runtime_feedback=None):
    """Thin wrapper around _normalize_exploit_contract that injects runtime_feedback."""
    if runtime_feedback is not None:
        contract = dict(contract)
        contract['runtime_feedback'] = runtime_feedback
    return verifier._normalize_exploit_contract(
        contract, cwe_type, explanation, vulnerable_code, filepath=filepath
    )


def _validate(verifier, plan, contract=None):
    return verifier._validate_proof_plan(plan, exploit_contract=contract or {})


# ---------------------------------------------------------------------------
# TestBinaryCandidatesPromotion
# ---------------------------------------------------------------------------

class TestBinaryCandidatesPromotion:

    def test_binary_candidates_promoted_to_target_binary(self):
        v = _make_verifier()
        contract = {'runtime_profile': 'native', 'proof_plan': {'binary_candidates': ['enchive']}}
        result = _normalize(v, contract)
        assert result['target_binary'] == 'enchive'

    def test_preflight_observed_binary_takes_priority(self):
        """observed_target_binary beats binary_candidates[0]."""
        v = _make_verifier()
        contract = {'runtime_profile': 'native', 'proof_plan': {'binary_candidates': ['other_tool']}}
        rf = {'target_binary': 'enchive', 'observed_surface': {}}
        result = _normalize(v, contract, runtime_feedback=rf)
        assert result['target_binary'] == 'enchive'

    def test_source_file_not_promoted(self):
        """A source file in binary_candidates must not be promoted."""
        v = _make_verifier()
        contract = {'runtime_profile': 'native', 'proof_plan': {'binary_candidates': ['enchive.c']}}
        result = _normalize(v, contract)
        # target_binary should remain unset (empty or the default)
        tb = result.get('target_binary', '')
        assert tb == '' or tb.lower() in {'', 'unknown', 'none', 'n/a'}

    def test_placeholder_not_promoted(self):
        """Placeholder values must not be promoted."""
        v = _make_verifier()
        contract = {'runtime_profile': 'native', 'proof_plan': {'binary_candidates': ['unknown']}}
        result = _normalize(v, contract)
        tb = result.get('target_binary', '')
        assert tb == '' or tb.lower() in {'unknown', 'none', 'n/a', ''}

    def test_existing_target_binary_not_overwritten(self):
        """If target_binary is already set and valid, it must not be changed."""
        v = _make_verifier()
        contract = {
            'runtime_profile': 'native',
            'target_binary': 'enchive',
            'proof_plan': {'binary_candidates': ['different_tool']},
        }
        result = _normalize(v, contract)
        assert result['target_binary'] == 'enchive'

    def test_non_native_family_not_promoted(self):
        """Promotion must not run for non-native families."""
        v = _make_verifier()
        contract = {'runtime_profile': 'python', 'proof_plan': {'binary_candidates': ['myscript']}}
        result = _normalize(v, contract, filepath='target.py')
        # target_binary should not be set for python
        assert not result.get('target_binary')

    def test_function_symbol_not_promoted_to_target_binary(self):
        """A function-like native symbol must not be promoted as the target binary."""
        v = _make_verifier()
        contract = {
            'runtime_profile': 'native',
            'target_entrypoint': 'optparse_arg',
            'proof_plan': {'binary_candidates': ['optparse_arg']},
        }
        result = _normalize(v, contract, filepath='enchive.c')
        tb = result.get('target_binary', '')
        assert tb == '' or tb.lower() in {'', 'unknown', 'none', 'n/a'}

    def test_build_handoff_payload_persists_runtime_feedback_subcommands(self):
        v = _make_verifier()
        contract = {'runtime_profile': 'native', 'proof_plan': {'execution_surface': 'binary_cli'}}
        runtime_feedback = {
            'target_binary': 'enchive',
            'observed_surface': {
                'help_text': 'Commands: archive, extract, keygen, fingerprint'
            },
        }
        payload = v.build_handoff_payload(
            contract,
            'CWE-787',
            'heap overflow',
            'void f(){}',
            filepath='enchive.c',
            runtime_feedback=runtime_feedback,
        )
        assert payload['contract'].get('runtime_feedback')
        assert payload['contract'].get('known_subcommands') == ['archive', 'extract', 'keygen', 'fingerprint']


# ---------------------------------------------------------------------------
# TestSubcommandExtraction
# ---------------------------------------------------------------------------

class TestSubcommandExtraction:

    def _extract(self, runtime_feedback):
        v = _make_verifier()
        return v._extract_subcommands_from_surface(runtime_feedback)

    def test_extracts_from_help_text_same_line_comma(self):
        """Enchive-style: 'Commands (unique prefixes accepted): keygen, archive, extract, fingerprint'"""
        rf = {
            'observed_surface': {
                'help_text': (
                    'Usage: enchive [options] <command>\n'
                    'Commands (unique prefixes accepted): keygen, archive, extract, fingerprint\n'
                    'Options:\n'
                    '  --verbose   be verbose\n'
                )
            }
        }
        result = self._extract(rf)
        assert result == ['keygen', 'archive', 'extract', 'fingerprint']

    def test_extracts_from_help_text_same_line_space(self):
        """Space-separated variant without commas."""
        rf = {
            'observed_surface': {
                'help_text': 'commands: start stop restart\n'
            }
        }
        result = self._extract(rf)
        assert result == ['start', 'stop', 'restart']

    def test_extracts_from_commands_field(self):
        """Direct structured list takes priority."""
        rf = {
            'observed_surface': {
                'commands': ['archive', 'extract', 'keygen'],
                'help_text': 'Commands: something_else',
            }
        }
        result = self._extract(rf)
        assert result == ['archive', 'extract', 'keygen']

    def test_extracts_from_subcommands_field(self):
        rf = {'observed_surface': {'subcommands': ['init', 'push', 'pull']}}
        result = self._extract(rf)
        assert result == ['init', 'push', 'pull']

    def test_returns_empty_when_no_commands(self):
        rf = {'observed_surface': {'help_text': 'Usage: tool [options]\n  --help  show help\n'}}
        result = self._extract(rf)
        assert result == []

    def test_returns_empty_when_no_surface(self):
        assert self._extract({}) == []
        assert self._extract(None) == []

    def test_multiline_block(self):
        """Multi-line Commands block (header only, tokens on separate lines)."""
        rf = {
            'observed_surface': {
                'help_text': (
                    'Available commands:\n'
                    'init      initialise repository\n'
                    'commit    commit changes\n'
                    'push      push to remote\n'
                    '\n'
                    'Options:\n'
                )
            }
        }
        result = self._extract(rf)
        assert 'init' in result
        assert 'commit' in result
        assert 'push' in result
        # Must NOT include option lines
        assert not any(r.startswith('-') for r in result)

    def test_no_false_positives_before_header(self):
        """Lines before the Commands: header must not be collected."""
        rf = {
            'observed_surface': {
                'help_text': (
                    'foo bar baz\n'
                    'qux quux\n'
                    'Commands: keygen, archive\n'
                )
            }
        }
        result = self._extract(rf)
        assert result == ['keygen', 'archive']
        assert 'foo' not in result
        assert 'baz' not in result


# ---------------------------------------------------------------------------
# TestResolutionStatus
# ---------------------------------------------------------------------------

class TestResolutionStatus:

    def test_gate_unresolved_on_missing_native_target(self):
        reasons = [
            'native target: target_entrypoint, target_binary, and execution_surface '
            'are all unresolved -- cannot generate a targeted PoV'
        ]
        assert _resolution_status_from_gate(reasons) == 'unresolved'

    def test_gate_contradicted_on_preflight(self):
        reasons = ['preflight: entrypoint not found in binary']
        assert _resolution_status_from_gate(reasons) == 'contradicted'

    def test_gate_partially_resolved_on_missing_signal(self):
        reasons = [
            'contract is missing a pre-generation success signal -- '
            'set success_indicators or expected_outcome before PoV generation'
        ]
        assert _resolution_status_from_gate(reasons) == 'partially_resolved'

    def test_gate_unresolved_on_python_target(self):
        reasons = ['python target: target_entrypoint is unknown']
        assert _resolution_status_from_gate(reasons) == 'unresolved'

    def test_gate_unresolved_on_browser_target(self):
        reasons = ['browser target: execution_surface must be set on the contract']
        assert _resolution_status_from_gate(reasons) == 'unresolved'

    def test_empty_blocking_list_defaults_unresolved(self):
        assert _resolution_status_from_gate([]) == 'unresolved'

    def test_contradicted_wins_first_match(self):
        """When multiple reasons present, first match (preflight) wins."""
        reasons = [
            'preflight: stale binary path',
            'native target: target_binary empty',
        ]
        assert _resolution_status_from_gate(reasons) == 'contradicted'


# ---------------------------------------------------------------------------
# TestSubcommandValidation
# ---------------------------------------------------------------------------

class TestSubcommandValidation:

    def _plan(self, argv, binary='enchive'):
        return {
            'target_binary': binary,
            'target_entrypoint': 'archive_command',
            'argv': argv,
            'expected_oracle': 'heap-use-after-free',
            'why_this_hits_target': 'archive_command processes the argv payload',
        }

    def _contract(self, known_subcommands=None):
        c = {
            'runtime_profile': 'native',
            'execution_surface': 'binary_cli',
            'success_indicators': ['AddressSanitizer'],
        }
        if known_subcommands is not None:
            c['known_subcommands'] = known_subcommands
        return c

    def test_argv_subcommand_enforced_when_known(self):
        v = _make_verifier()
        plan = self._plan(argv=['AAAA' * 20])
        contract = self._contract(known_subcommands=['archive', 'extract'])
        issues = _validate(v, plan, contract)
        assert any('argv[0] must be one of the known subcommands' in i for i in issues)

    def test_argv_subcommand_passes_when_correct(self):
        v = _make_verifier()
        plan = self._plan(argv=['archive', 'AAAA' * 20])
        contract = self._contract(known_subcommands=['archive', 'extract'])
        issues = _validate(v, plan, contract)
        assert not any('argv[0] must be one of the known subcommands' in i for i in issues)

    def test_argv_subcommand_skipped_when_none_known(self):
        """No known_subcommands => enforcement does not fire."""
        v = _make_verifier()
        plan = self._plan(argv=['AAAA' * 20])
        contract = self._contract(known_subcommands=None)
        issues = _validate(v, plan, contract)
        assert not any('argv[0] must be one of the known subcommands' in i for i in issues)

    def test_argv_subcommand_case_insensitive(self):
        """Subcommand comparison is case-insensitive."""
        v = _make_verifier()
        plan = self._plan(argv=['ARCHIVE', 'payload'])
        contract = self._contract(known_subcommands=['archive', 'extract'])
        issues = _validate(v, plan, contract)
        assert not any('argv[0] must be one of the known subcommands' in i for i in issues)



def test_merge_refined_contract_preserves_native_anchors():
    v = _make_verifier()
    base = {
        'runtime_profile': 'native',
        'target_binary': 'enchive',
        'target_entrypoint': 'command_archive',
        'known_subcommands': ['archive', 'extract'],
        'runtime_feedback': {
            'target_binary': 'enchive',
            'observed_surface': {'help_text': 'Commands: archive, extract'}
        },
        'proof_plan': {
            'runtime_family': 'native',
            'execution_surface': 'binary_cli',
            'binary_candidates': ['enchive'],
            'observed_subcommands': ['archive', 'extract'],
        },
    }
    refined = {
        'target_binary': 'unknown',
        'target_entrypoint': 'unknown',
        'proof_plan': {
            'runtime_family': 'native',
            'execution_surface': 'binary_cli',
            'expected_oracle': 'heap-buffer-overflow',
        },
    }
    merged = v._merge_refined_contract(base, refined)
    assert merged['target_binary'] == 'enchive'
    assert merged['target_entrypoint'] == 'command_archive'
    assert merged['known_subcommands'] == ['archive', 'extract']
    assert merged['proof_plan']['observed_subcommands'] == ['archive', 'extract']
    assert merged['proof_plan']['expected_oracle'] == 'heap-buffer-overflow'


def test_merge_refined_contract_function_harness_drops_stale_cli_plan_fields():
    v = _make_verifier()
    base = {
        'runtime_profile': 'native',
        'execution_surface': 'function_harness',
        'target_binary': 'enchive',
        'target_entrypoint': 'dupstr',
        'known_subcommands': ['archive', 'extract'],
        'proof_plan': {
            'runtime_family': 'native',
            'execution_surface': 'function_call',
            'target_entrypoint': 'dupstr',
            'observed_subcommands': ['archive', 'extract'],
        },
    }
    refined = {
        'proof_plan': {
            'execution_surface': 'function_call',
            'target_entrypoint': 'command_archive',
            'subcommand': 'archive',
            'route_shape': 'enchive archive <outfile>',
            'payload_mode': 'empty_string',
        },
    }
    merged = v._merge_refined_contract(base, refined)
    assert merged['proof_plan']['target_entrypoint'] == 'dupstr'
    assert 'subcommand' not in merged['proof_plan'] or not merged['proof_plan']['subcommand']
    assert 'route_shape' not in merged['proof_plan'] or not merged['proof_plan']['route_shape']
    assert 'payload_mode' not in merged['proof_plan'] or not merged['proof_plan']['payload_mode']


def test_normalize_native_cli_handler_preserves_binary_cli_and_target_subcommand():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'command_extract',
        'target_binary': 'enchive',
        'proof_plan': {'execution_surface': 'binary_cli'},
    }
    runtime_feedback = {
        'target_binary': 'enchive',
        'observed_surface': {'help_text': 'Commands: keygen, archive, extract, fingerprint'},
    }
    result = _normalize(v, contract, filepath='enchive.c', runtime_feedback=runtime_feedback)
    assert result['proof_plan']['execution_surface'] == 'binary_cli'
    assert result['proof_plan']['subcommand'] == 'extract'
    assert result['target_binary'] == 'enchive'
    assert result['known_subcommands'] == ['keygen', 'archive', 'extract', 'fingerprint']


def test_normalize_internal_native_symbol_switches_to_function_call():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'optparse_arg',
        'target_binary': 'enchive',
        'proof_plan': {'execution_surface': 'binary_cli'},
    }
    runtime_feedback = {
        'target_binary': 'enchive',
        'observed_surface': {'help_text': 'Commands: keygen, archive, extract, fingerprint'},
    }
    result = _normalize(v, contract, filepath='enchive.c', runtime_feedback=runtime_feedback)
    assert result['proof_plan']['execution_surface'] == 'function_call'
    assert result['proof_plan']['input_mode'] == 'function'
    assert result['execution_surface'] == 'function_harness'
    assert result['proof_plan'].get('subcommand') in (None, '')


def test_function_call_native_plan_clears_stale_subcommand():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'optparse_arg',
        'target_binary': 'enchive',
        'proof_plan': {
            'execution_surface': 'binary_cli',
            'subcommand': 'extract',
        },
    }
    runtime_feedback = {
        'target_binary': 'enchive',
        'observed_surface': {'help_text': 'Commands: keygen, archive, extract, fingerprint'},
    }
    result = _normalize(v, contract, filepath='enchive.c', runtime_feedback=runtime_feedback)
    assert result['proof_plan']['execution_surface'] == 'function_call'
    assert 'subcommand' not in result['proof_plan'] or not result['proof_plan']['subcommand']


def test_function_call_native_plan_rebinds_target_entrypoint_and_clears_cli_metadata():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'dupstr',
        'target_binary': 'enchive',
        'proof_plan': {
            'execution_surface': 'binary_cli',
            'target_entrypoint': 'command_archive',
            'subcommand': 'archive',
            'route_shape': 'enchive archive <outfile>',
            'trigger_shape': 'missing outfile argument',
            'payload_mode': 'empty_string',
        },
    }
    runtime_feedback = {
        'target_binary': 'enchive',
        'observed_surface': {'help_text': 'Commands: keygen, archive, extract, fingerprint'},
    }
    result = _normalize(v, contract, filepath='enchive.c', runtime_feedback=runtime_feedback)
    assert result['proof_plan']['execution_surface'] == 'function_call'
    assert result['proof_plan']['target_entrypoint'] == 'dupstr'
    for stale_key in ('subcommand', 'route_shape', 'trigger_shape', 'payload_mode'):
        assert stale_key not in result['proof_plan'] or not result['proof_plan'][stale_key]


def test_native_fallback_script_uses_local_binary_variable_not_global_assignment():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'command_extract',
        'target_binary': 'enchive',
        'known_subcommands': ['archive', 'extract'],
        'proof_plan': {'execution_surface': 'binary_cli'},
    }
    result = v._synthesize_native_library_fallback_pov(
        'CWE-787',
        'enchive.c',
        'void f(){}',
        'heap overflow',
        contract,
        runtime_feedback={'target_binary': 'enchive', 'observed_surface': {'help_text': 'Commands: archive, extract'}},
    )
    script = result['pov_script']
    assert 'binary = TARGET_BINARY' in script
    assert 'if not binary and CODEBASE_PATH:' in script
    assert 'glob.glob' in script
    assert 'if not TARGET_BINARY and CODEBASE_PATH and TARGET_SYMBOL:' not in script
    assert 'TARGET_BINARY = _find_binary(TARGET_SYMBOL, CODEBASE_PATH)' not in script


def test_native_fallback_script_invokes_safe_probe_args():
    v = _make_verifier()
    contract = {
        'runtime_profile': 'native',
        'target_entrypoint': 'command_extract',
        'target_binary': 'enchive',
        'known_subcommands': ['archive', 'extract'],
        'proof_plan': {'execution_surface': 'binary_cli'},
    }
    result = v._synthesize_native_library_fallback_pov(
        'CWE-787',
        'enchive.c',
        'void f(){}',
        'heap overflow',
        contract,
        runtime_feedback={'target_binary': 'enchive', 'observed_surface': {'help_text': 'Commands: archive, extract'}},
    )
    script = result['pov_script']
    assert '[binary, ' in script
    assert '"A" * 256' in script or "'A' * 256" in script
    assert '[TARGET_BINARY,' not in script


def test_build_handoff_payload_populates_stage_requirements_and_relevance_anchors():
    from agents.verifier import verifier
    payload = verifier.build_handoff_payload(
        exploit_contract={
            'runtime_profile': 'c',
            'target_entrypoint': 'command_extract',
            'target_binary': 'enchive',
            'known_subcommands': ['keygen', 'extract'],
            'proof_plan': {'runtime_family': 'native', 'execution_surface': 'binary_cli', 'input_mode': 'argv', 'subcommand': 'extract'},
        },
        cwe_type='CWE-787',
        explanation='x',
        vulnerable_code='int command_extract(int argc, char **argv) { return argc + (argv != 0); }',
        filepath='src/enchive.c',
    )
    contract = payload['contract']
    assert 'bootstrap key material before trigger execution' in contract['setup_requirements']
    assert 'reach target entrypoint: command_extract' in contract['trigger_requirements']
    assert 'command_extract' in contract['relevance_anchors']
    assert 'extract' in contract['relevance_anchors']


def test_build_handoff_payload_infers_native_subcommand_into_anchors_and_plan():
    verifier = VulnerabilityVerifier()
    contract = {
        'runtime_profile': 'c',
        'target_entrypoint': 'command_extract',
        'known_subcommands': ['keygen', 'archive', 'extract', 'fingerprint'],
        'proof_plan': {'runtime_family': 'c', 'execution_surface': 'binary_cli'},
    }
    payload = verifier.build_handoff_payload(contract, 'CWE-416', 'desc', 'int x;', filepath='src/enchive.c')
    normalized = payload['contract']
    assert normalized['proof_plan']['subcommand'] == 'extract'
    assert 'use trigger subcommand: extract' in normalized['trigger_requirements']
    assert 'extract' in normalized['relevance_anchors']


def test_exploit_contract_schema_supports_route_and_dom_fields():
    from agents.proof_schemas import ExploitContract
    contract = ExploitContract(target_route='/search', target_dom_selector='#search', execution_surface='browser_dom')
    assert contract.target_route == '/search'
    assert contract.target_dom_selector == '#search'
