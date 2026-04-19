import json
from pathlib import Path

from app.benchmark_registry import BenchmarkRegistry


def test_preview_and_materialize_manifest(tmp_path):
    source_root = tmp_path / 'source'
    case_dir = source_root / 'suite' / 'case1'
    case_dir.mkdir(parents=True)
    (case_dir / 'bad.c').write_text('int main(void) { return 0; }\n', encoding='utf-8')

    manifest = {
        'benchmark_family': 'juliet',
        'benchmark_id': 'juliet-sample',
        'language': 'c',
        'source_root': str(source_root),
        'cases': [
            {
                'case_id': 'case-bad',
                'source_path': 'suite/case1',
                'expected_vulnerable': True,
                'cwes': ['CWE-121'],
            }
        ],
    }
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')

    registry = BenchmarkRegistry()
    preview = registry.preview_manifest(manifest_path=str(manifest_path), case_ids=['case-bad'])
    assert preview['benchmark_id'] == 'juliet-sample'
    assert preview['selected_case_ids'] == ['case-bad']

    materialized = registry.materialize(scan_id='test-scan', manifest_path=str(manifest_path), case_ids=['case-bad'])
    assert Path(materialized.codebase_path).exists()
    assert (Path(materialized.codebase_path) / 'suite' / 'case1' / 'bad.c').exists()
    assert materialized.benchmark_metadata['cases'][0]['workspace_paths'] == ['suite/case1']


def test_auto_detects_juliet_dynamic_root(tmp_path):
    root = tmp_path / 'juliet-dynamic'
    (root / 'testcases' / 'CWE121').mkdir(parents=True)
    (root / 'testcasesupport').mkdir(parents=True)
    (root / 'test_juliet.py').write_text('# runner\n', encoding='utf-8')
    (root / 'Makefile').write_text('all:\n\t@true\n', encoding='utf-8')
    testcase = root / 'testcases' / 'CWE121' / 'CWE121_bad_01.c'
    testcase.write_text('int main(void) { return 0; }\n', encoding='utf-8')

    registry = BenchmarkRegistry()
    preview = registry.preview_manifest(benchmark_root=str(root))

    assert preview['benchmark_family'] == 'juliet_dynamic'
    assert preview['cases_total'] == 1
    assert preview['cases'][0]['case_id'] == 'CWE121_bad_01'
    assert preview['cases'][0]['cwes'] == ['CWE-121']


def test_auto_detects_owasp_benchmark_python_root(tmp_path):
    root = tmp_path / 'BenchmarkPython'
    (root / 'data').mkdir(parents=True)
    (root / 'testcode').mkdir(parents=True)
    (root / 'helpers').mkdir(parents=True)
    (root / 'templates').mkdir(parents=True)
    (root / 'app.py').write_text('print(1)\n', encoding='utf-8')
    (root / 'requirements.txt').write_text('flask\n', encoding='utf-8')
    (root / 'testcode' / 'BenchmarkTest00001.py').write_text('def handler():\n    return True\n', encoding='utf-8')
    payload = {
        'cases': [
            {
                'test_id': 'BenchmarkTest00001',
                'route': '/sql/test',
                'expected_vulnerable': True,
                'cwes': ['CWE-89'],
            }
        ]
    }
    (root / 'data' / 'cases.json').write_text(json.dumps(payload), encoding='utf-8')

    registry = BenchmarkRegistry()
    preview = registry.preview_manifest(benchmark_root=str(root))

    assert preview['benchmark_family'] == 'owasp_benchmark_python'
    assert preview['language'] == 'python'
    assert preview['cases_total'] == 1
    assert preview['cases'][0]['case_id'] == 'BenchmarkTest00001'
    assert preview['cases'][0]['cwes'] == ['CWE-89']
    assert preview['cases'][0]['copy_paths'] == ['testcode/BenchmarkTest00001.py']


def test_score_findings_uses_case_mapping():
    registry = BenchmarkRegistry()
    metadata = {
        'benchmark_family': 'juliet',
        'benchmark_id': 'juliet-sample',
        'language': 'c',
        'cases': [
            {
                'case_id': 'bad-case',
                'expected_vulnerable': True,
                'cwes': ['CWE-121'],
                'workspace_paths': ['suite/bad'],
            },
            {
                'case_id': 'good-case',
                'expected_vulnerable': False,
                'cwes': ['CWE-121'],
                'workspace_paths': ['suite/good'],
            },
        ],
    }
    findings = [
        {
            'filepath': 'suite/bad/example.c',
            'llm_verdict': 'REAL',
            'final_status': 'confirmed',
        },
        {
            'filepath': 'suite/good/example.c',
            'llm_verdict': 'FALSE_POSITIVE',
            'final_status': 'unproven',
        },
    ]

    score = registry.score_findings(metadata, findings)
    assert score['detection']['true_positive_cases'] == 1
    assert score['detection']['false_positive_cases'] == 0
    assert score['proof']['true_positive_cases'] == 1
    assert score['proof']['false_positive_cases'] == 0
    assert score['cases'][0]['detected'] is True
    assert score['cases'][0]['proved'] is True
    assert score['cases'][1]['detected'] is False


def test_auto_imported_cases_are_normalized_for_materialize(tmp_path):
    root = tmp_path / 'juliet-dynamic'
    case_dir = root / 'testcases' / 'CWE121'
    support_dir = root / 'testcasesupport'
    case_dir.mkdir(parents=True)
    support_dir.mkdir(parents=True)
    (root / 'test_juliet.py').write_text('# runner\n', encoding='utf-8')
    (root / 'Makefile').write_text('all:\n\t@true\n', encoding='utf-8')
    (case_dir / 'Makefile').write_text('all:\n\t@true\n', encoding='utf-8')
    (support_dir / 'io.c').write_text('int io(void) { return 0; }\n', encoding='utf-8')
    (case_dir / 'CWE121_bad_01.c').write_text('int main(void) { return helper(); }\n', encoding='utf-8')
    (case_dir / 'CWE121_01a.c').write_text('int helper(void) { return 0; }\n', encoding='utf-8')

    registry = BenchmarkRegistry()
    materialized = registry.materialize(scan_id='bench-normalize', benchmark_root=str(root))
    workspace = Path(materialized.codebase_path)

    assert (workspace / 'testcases' / 'CWE121' / 'CWE121_bad_01.c').exists()
    assert (workspace / 'testcases' / 'CWE121' / 'Makefile').exists()
    assert (workspace / 'testcasesupport' / 'io.c').exists()
    assert (workspace / '.autopov-benchmark.json').exists()
    assert (workspace / '.autopov-benchmark-build.py').exists()
    metadata = json.loads((workspace / '.autopov-benchmark.json').read_text(encoding='utf-8'))
    assert metadata['codeql_build_commands'][0] == 'python .autopov-benchmark-build.py'
    case = next(case for case in materialized.benchmark_metadata['cases'] if case['case_id'] == 'CWE121_bad_01')
    assert case['copy_paths'] == ['testcases/CWE121/CWE121_bad_01.c']
    assert case['workspace_paths'] == ['testcases/CWE121/CWE121_bad_01.c']
