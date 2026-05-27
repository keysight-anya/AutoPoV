
from app.target_metadata import merge_contract_hints, path_hints_for, resolve_curated_target_metadata


def test_resolve_curated_target_metadata_for_picocoin_by_repo_label(tmp_path):
    (tmp_path / 'include' / 'ccoin').mkdir(parents=True)
    (tmp_path / 'include' / 'ccoin' / 'buint.h').write_text('header', encoding='utf-8')
    metadata = resolve_curated_target_metadata(
        target_type='repo',
        target_label='https://github.com/jgarzik/picocoin',
        repo_url='https://github.com/jgarzik/picocoin',
        codebase_path=str(tmp_path),
    )
    assert metadata['id'] == 'jgarzik/picocoin'
    assert metadata['repo_hints']['runtime_profile'] == 'c'


def test_path_hints_for_buint_header():
    metadata = resolve_curated_target_metadata(
        target_type='repo',
        target_label='jgarzik/picocoin',
        repo_url='https://github.com/jgarzik/picocoin',
        codebase_path='.',
    )
    hints = path_hints_for(metadata, 'include/ccoin/buint.h')
    assert hints['target_entrypoint'] == 'bu256_new'
    assert 'function_call' == hints['proof_plan']['execution_surface']


def test_merge_contract_hints_preserves_existing_values_and_adds_fallbacks():
    contract = {
        'runtime_profile': 'c',
        'proof_plan': {
            'runtime_family': 'native',
            'oracle': ['crash_signal'],
        },
        'inputs': ['existing input'],
    }
    hints = {
        'target_entrypoint': 'bu256_new',
        'inputs': ['metadata input'],
        'proof_plan': {
            'oracle': ['sanitizer_output', 'stdout_marker'],
            'fallback_strategies': ['deterministic_native_harness_fallback'],
        },
    }
    merged = merge_contract_hints(contract, hints)
    assert merged['target_entrypoint'] == 'bu256_new'
    assert merged['inputs'] == ['existing input', 'metadata input']
    assert merged['proof_plan']['oracle'] == ['crash_signal', 'sanitizer_output', 'stdout_marker']
    assert merged['proof_plan']['fallback_strategies'] == ['deterministic_native_harness_fallback']


def test_resolve_curated_target_metadata_does_not_match_substring_repo_name(tmp_path):
    (tmp_path / 'src').mkdir(parents=True)
    metadata = resolve_curated_target_metadata(
        target_type='repo',
        target_label='https://example.com/not-picocoin-fork',
        repo_url='https://example.com/not-picocoin-fork',
        codebase_path=str(tmp_path),
    )
    assert metadata == {}
