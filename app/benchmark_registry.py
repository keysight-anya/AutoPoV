
"""Benchmark manifest loading, auto-import, materialization, and scoring."""

from __future__ import annotations

import csv
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MaterializedBenchmark:
    codebase_path: str
    benchmark_metadata: Dict[str, Any]


class BenchmarkRegistry:
    """Loads benchmark manifests and maps them into normal scan workspaces."""

    def load_target(
        self,
        benchmark_root: Optional[str] = None,
        manifest_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        if manifest_path:
            manifest = self.load_manifest(manifest_path)
        elif benchmark_root:
            manifest = self.load_auto_manifest(benchmark_root)
        else:
            raise ValueError("Either manifest_path or benchmark_root must be provided")
        return self._normalize_manifest(manifest)

    def load_auto_manifest(self, benchmark_root: str) -> Dict[str, Any]:
        root = Path(benchmark_root).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Benchmark root not found: {benchmark_root}")

        detector = self._detect_builtin_benchmark(root)
        if detector == 'juliet_dynamic':
            return self._build_juliet_dynamic_manifest(root)
        if detector == 'owasp_benchmark_python':
            return self._build_owasp_benchmark_python_manifest(root)

        raise ValueError(
            "Could not recognize benchmark root. Supported auto-imports are "
            "juliet-dynamic and OWASP Benchmark Python. You can still use a custom manifest."
        )

    def _normalize_manifest(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        cases = manifest.get('cases')
        if not isinstance(cases, list) or not cases:
            raise ValueError("Benchmark manifest must define a non-empty 'cases' array")

        normalized_cases = []
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                raise ValueError(f"Benchmark case at index {index} must be an object")
            case_id = str(case.get('case_id') or '').strip()
            if not case_id:
                raise ValueError(f"Benchmark case at index {index} is missing case_id")

            copy_paths = case.get('copy_paths')
            if not copy_paths:
                source_path = case.get('source_path')
                if not source_path:
                    raise ValueError(f"Benchmark case '{case_id}' must define source_path or copy_paths")
                copy_paths = [source_path]
            if not isinstance(copy_paths, list) or not all(isinstance(item, str) and str(item).strip() for item in copy_paths):
                raise ValueError(f"Benchmark case '{case_id}' copy_paths must be a list of non-empty strings")

            normalized_case = dict(case)
            normalized_case['case_id'] = case_id
            normalized_case['copy_paths'] = [str(item).strip() for item in copy_paths]
            normalized_case['support_copy_paths'] = [str(item).strip() for item in (case.get('support_copy_paths') or []) if str(item).strip()]
            normalized_case['expected_vulnerable'] = bool(case.get('expected_vulnerable', True))
            normalized_case['cwes'] = [str(cwe) for cwe in (case.get('cwes') or [])]
            normalized_cases.append(normalized_case)

        normalized_manifest = dict(manifest)
        normalized_manifest['cases'] = normalized_cases
        return normalized_manifest

    def load_manifest(self, manifest_path: str) -> Dict[str, Any]:
        manifest_file = Path(manifest_path).expanduser().resolve()
        if not manifest_file.exists() or not manifest_file.is_file():
            raise FileNotFoundError(f"Benchmark manifest not found: {manifest_path}")

        with manifest_file.open('r', encoding='utf-8') as handle:
            manifest = json.load(handle)

        if not isinstance(manifest, dict):
            raise ValueError("Benchmark manifest must be a JSON object")

        manifest.setdefault('benchmark_id', manifest_file.stem)
        manifest.setdefault('benchmark_family', 'custom')
        manifest.setdefault('language', 'unknown')
        manifest['manifest_path'] = str(manifest_file)

        source_root = manifest.get('source_root')
        if not source_root:
            raise ValueError("Benchmark manifest must define 'source_root'")
        source_root_path = Path(source_root).expanduser()
        if not source_root_path.is_absolute():
            source_root_path = (manifest_file.parent / source_root_path).resolve()
        if not source_root_path.exists() or not source_root_path.is_dir():
            raise ValueError(f"Benchmark source_root does not exist: {source_root_path}")
        manifest['source_root'] = str(source_root_path)

        cases = manifest.get('cases')
        if not isinstance(cases, list) or not cases:
            raise ValueError("Benchmark manifest must define a non-empty 'cases' array")

        return self._normalize_manifest(manifest)

    def preview_manifest(
        self,
        manifest_path: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        benchmark_root: Optional[str] = None,
    ) -> Dict[str, Any]:
        manifest = self.load_target(benchmark_root=benchmark_root, manifest_path=manifest_path)
        selected_cases = self._select_cases(manifest, case_ids)
        return self._build_benchmark_metadata(manifest, selected_cases, workspace_root=None)

    def materialize(
        self,
        scan_id: str,
        manifest_path: Optional[str] = None,
        case_ids: Optional[List[str]] = None,
        benchmark_root: Optional[str] = None,
    ) -> MaterializedBenchmark:
        manifest = self.load_target(benchmark_root=benchmark_root, manifest_path=manifest_path)
        selected_cases = self._select_cases(manifest, case_ids)
        workspace_root = Path(f'/tmp/autopov/{scan_id}/benchmark').resolve()
        if workspace_root.exists():
            shutil.rmtree(workspace_root, ignore_errors=True)
        workspace_root.mkdir(parents=True, exist_ok=True)

        source_root = Path(manifest['source_root']).resolve()
        case_workspace_paths: Dict[str, List[str]] = {}

        for support_path in manifest.get('support_paths') or []:
            support_source = (source_root / support_path).resolve()
            if not support_source.exists():
                continue
            self._copy_into_workspace(source_root, workspace_root, support_path, benchmark_id=manifest.get('benchmark_id') or 'benchmark')

        for case in selected_cases:
            copied_paths: List[str] = []
            all_paths = list(case['copy_paths']) + list(case.get('support_copy_paths') or [])
            seen_paths = set()
            for copy_path in all_paths:
                if copy_path in seen_paths:
                    continue
                seen_paths.add(copy_path)
                rel_path = self._copy_into_workspace(source_root, workspace_root, copy_path, benchmark_id=case['case_id'])
                if copy_path in case['copy_paths']:
                    copied_paths.append(rel_path)
            case_workspace_paths[case['case_id']] = copied_paths

        self._write_workspace_metadata(workspace_root, manifest, selected_cases)
        metadata = self._build_benchmark_metadata(manifest, selected_cases, workspace_root=workspace_root)
        for case in metadata['cases']:
            case['workspace_paths'] = case_workspace_paths.get(case['case_id'], [])

        return MaterializedBenchmark(codebase_path=str(workspace_root), benchmark_metadata=metadata)

    def _copy_into_workspace(self, source_root: Path, workspace_root: Path, copy_path: str, benchmark_id: str) -> str:
        src = (source_root / copy_path).resolve()
        if not src.exists():
            raise ValueError(f"Benchmark case '{benchmark_id}' copy path does not exist: {copy_path}")
        try:
            rel_path = src.relative_to(source_root)
        except ValueError as exc:
            raise ValueError(f"Benchmark case '{benchmark_id}' path escapes source_root: {copy_path}") from exc

        dest = workspace_root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dest)
        return rel_path.as_posix()

    def _write_workspace_metadata(self, workspace_root: Path, manifest: Dict[str, Any], selected_cases: List[Dict[str, Any]]) -> None:
        payload: Dict[str, Any] = {
            'benchmark_family': manifest.get('benchmark_family'),
            'benchmark_id': manifest.get('benchmark_id'),
            'selected_case_ids': [case['case_id'] for case in selected_cases],
        }
        build_script_relpath = self._write_workspace_build_script(workspace_root, manifest)
        codeql_build_commands = self._benchmark_codeql_build_commands(manifest, selected_cases, build_script_relpath)
        if codeql_build_commands:
            payload['codeql_build_commands'] = codeql_build_commands
        metadata_path = workspace_root / '.autopov-benchmark.json'
        metadata_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')

    def _write_workspace_build_script(self, workspace_root: Path, manifest: Dict[str, Any]) -> Optional[str]:
        family = manifest.get('benchmark_family')
        if family != 'juliet_dynamic':
            return None

        script_relpath = '.autopov-benchmark-build.py'
        script_path = workspace_root / script_relpath
        script_path.write_text(
            """from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent
build_dir = root / '.autopov-codeql-objs'
build_dir.mkdir(exist_ok=True)

cc = shutil.which('clang') or shutil.which('gcc') or shutil.which('cc')
cxx = shutil.which('clang++') or shutil.which('g++') or shutil.which('c++')
if not cc or not cxx:
    raise SystemExit('No C/C++ compiler found for Juliet benchmark build helper')

sources = []
for base_name in ('testcases', 'testcasesupport'):
    base = root / base_name
    if not base.exists():
        continue
    for source in sorted(base.rglob('*')):
        if source.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}:
            sources.append(source)

if not sources:
    raise SystemExit('No Juliet benchmark sources found to compile')

include_flags = []
support_dir = root / 'testcasesupport'
if support_dir.exists():
    include_flags.extend(['-I', str(support_dir)])
include_flags.extend(['-I', str(root)])

successes = 0
failures = []
for source in sources:
    suffix = source.suffix.lower()
    compiler = cxx if suffix in {'.cc', '.cpp', '.cxx'} else cc
    cmd = [compiler, '-c', '-g']
    if compiler == cxx:
        cmd.append('-std=c++11')
    cmd.extend(include_flags)
    obj_name = source.relative_to(root).as_posix().replace('/', '__') + '.o'
    cmd.extend([str(source), '-o', str(build_dir / obj_name)])
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode == 0:
        successes += 1
        continue
    failures.append((source.as_posix(), completed.stderr or completed.stdout or 'compile failed'))

if successes == 0:
    for source, error in failures[:10]:
        sys.stderr.write(f'[juliet-build] {source}: {error}\n')
    raise SystemExit(1)

if failures:
    sys.stderr.write(f'[juliet-build] compiled {successes} source files; ignored {len(failures)} compile failures during extraction\n')
""",
            encoding='utf-8',
        )
        return script_relpath

    def _benchmark_codeql_build_commands(self, manifest: Dict[str, Any], selected_cases: List[Dict[str, Any]], build_script_relpath: Optional[str] = None) -> List[str]:
        family = manifest.get('benchmark_family')
        if family == 'juliet_dynamic':
            commands: List[str] = []
            if build_script_relpath:
                commands.append(f"python {build_script_relpath}")
            cwe_dirs = sorted({Path(case['copy_paths'][0]).parts[1] for case in selected_cases if len(Path(case['copy_paths'][0]).parts) > 1})
            commands.extend(f"make -C testcases/{cwe_dir} BUILD_ALL=0" for cwe_dir in cwe_dirs)
            return commands
        return []

    def score_findings(self, benchmark_metadata: Optional[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not benchmark_metadata:
            return None

        cases = benchmark_metadata.get('cases') or []
        if not cases:
            return None

        findings = findings or []
        case_results = []
        detection_tp = detection_fp = detection_fn = detection_tn = 0
        proof_tp = proof_fp = proof_fn = proof_tn = 0

        for case in cases:
            matched = self._match_case_findings(case, findings)
            expected_vulnerable = bool(case.get('expected_vulnerable'))
            detected = any((f.get('llm_verdict') == 'REAL') or (f.get('final_status') in {'confirmed', 'failed'}) for f in matched)
            proved = any(f.get('final_status') == 'confirmed' for f in matched)

            if expected_vulnerable:
                detection_tp += int(detected)
                detection_fn += int(not detected)
                proof_tp += int(proved)
                proof_fn += int(not proved)
            else:
                detection_fp += int(detected)
                detection_tn += int(not detected)
                proof_fp += int(proved)
                proof_tn += int(not proved)

            case_results.append({
                'case_id': case.get('case_id'),
                'expected_vulnerable': expected_vulnerable,
                'expected_cwes': list(case.get('cwes') or []),
                'matched_findings': len(matched),
                'detected': detected,
                'proved': proved,
                'matched_files': sorted({str(f.get('filepath') or '') for f in matched if f.get('filepath')}),
            })

        vulnerable_cases = sum(1 for case in cases if case.get('expected_vulnerable'))
        safe_cases = len(cases) - vulnerable_cases

        return {
            'benchmark_family': benchmark_metadata.get('benchmark_family'),
            'benchmark_id': benchmark_metadata.get('benchmark_id'),
            'language': benchmark_metadata.get('language'),
            'cases_total': len(cases),
            'vulnerable_cases': vulnerable_cases,
            'safe_cases': safe_cases,
            'detection': {
                'true_positive_cases': detection_tp,
                'false_positive_cases': detection_fp,
                'false_negative_cases': detection_fn,
                'true_negative_cases': detection_tn,
                'precision': self._ratio(detection_tp, detection_tp + detection_fp),
                'recall': self._ratio(detection_tp, detection_tp + detection_fn),
            },
            'proof': {
                'true_positive_cases': proof_tp,
                'false_positive_cases': proof_fp,
                'false_negative_cases': proof_fn,
                'true_negative_cases': proof_tn,
                'precision': self._ratio(proof_tp, proof_tp + proof_fp),
                'recall': self._ratio(proof_tp, proof_tp + proof_fn),
            },
            'cases': case_results,
        }

    def _detect_builtin_benchmark(self, root: Path) -> Optional[str]:
        if (root / 'test_juliet.py').exists() and (root / 'testcases').exists() and (root / 'testcasesupport').exists():
            return 'juliet_dynamic'
        if (root / 'requirements.txt').exists() and ((root / 'testcode').exists() or (root / 'data').exists() or (root / 'benchmarkData').exists()):
            return 'owasp_benchmark_python'
        return None

    def _build_juliet_dynamic_manifest(self, root: Path) -> Dict[str, Any]:
        cases: List[Dict[str, Any]] = []
        juliet_root = root / 'testcases'
        for testcase in sorted(juliet_root.rglob('*')):
            if not testcase.is_file():
                continue
            suffix = testcase.suffix.lower()
            if suffix not in {'.c', '.cpp', '.cc', '.cxx'}:
                continue

            rel_path = testcase.relative_to(root).as_posix()
            case_id = testcase.stem
            cwes = self._extract_cwes_from_name(case_id)
            language = 'cpp' if suffix in {'.cpp', '.cc', '.cxx'} else 'c'
            cases.append({
                'case_id': case_id,
                'source_path': rel_path,
                'support_copy_paths': self._juliet_case_support_copy_paths(root, testcase),
                'expected_vulnerable': True,
                'cwes': cwes,
                'entrypoint_hint': 'main',
                'oracle_hint': 'juliet-dynamic sanitizer-backed runtime confirmation',
                'build': {'runner': 'test_juliet.py'},
                'run': {'runner': 'test_juliet.py'},
                'language': language,
            })

        if not cases:
            raise ValueError(f"No Juliet Dynamic cases found under: {root}")

        return {
            'benchmark_family': 'juliet_dynamic',
            'benchmark_id': root.name,
            'benchmark_name': 'Juliet Dynamic',
            'language': self._majority_language(cases),
            'source_root': str(root),
            'support_paths': ['Makefile', 'test_juliet.py', 'testcasesupport', 'inputs'],
            'cases': cases,
        }

    def _build_owasp_benchmark_python_manifest(self, root: Path) -> Dict[str, Any]:
        cases: List[Dict[str, Any]] = []
        benchmark_data_root = root / 'benchmarkData' if (root / 'benchmarkData').exists() else root / 'data'
        source_dirs = [root / 'benchmark', root / 'testcode', root / 'src', root / 'app']

        data_files: List[Path] = []
        if benchmark_data_root.exists():
            data_files.extend(
                path for path in benchmark_data_root.rglob('*')
                if path.is_file() and path.suffix.lower() in {'.json', '.csv'}
            )
        data_files.extend(
            path for path in root.glob('expectedresults*.csv')
            if path.is_file()
        )

        for data_file in sorted({path.resolve(): path for path in data_files}.values()):

            case_entries = self._load_owasp_python_case_entries(data_file)
            if not case_entries:
                continue

            for entry in case_entries:
                route = entry.get('route') or entry.get('path') or entry.get('endpoint')
                case_id = str(entry.get('test_id') or entry.get('name') or route or data_file.stem).strip()
                expected_vulnerable = bool(entry.get('expected_vulnerable', entry.get('vulnerable', True)))
                cwes = [str(cwe) for cwe in (entry.get('cwes') or self._extract_cwes_from_name(case_id))]
                exact_testcode = root / 'testcode' / f'{case_id}.py'
                if exact_testcode.exists():
                    copy_paths = [exact_testcode.relative_to(root).as_posix()]
                else:
                    copy_paths = self._resolve_owasp_python_copy_paths(source_dirs, route)
                if not copy_paths:
                    copy_paths = [self._normalize_relpath(data_file.relative_to(root).as_posix())]
                cases.append({
                    'case_id': case_id,
                    'copy_paths': copy_paths,
                    'expected_vulnerable': expected_vulnerable,
                    'cwes': cwes,
                    'entrypoint_hint': route,
                    'oracle_hint': 'OWASP Benchmark Python expected vulnerable endpoint behavior',
                    'build': {'framework': 'owasp_benchmark_python'},
                    'run': {'route': route},
                    'language': 'python',
                })

        if not cases:
            py_files = sorted((root / 'benchmark').rglob('*.py')) if (root / 'benchmark').exists() else []
            for py_file in py_files:
                rel_path = py_file.relative_to(root).as_posix()
                case_id = py_file.stem
                cases.append({
                    'case_id': case_id,
                    'source_path': rel_path,
                    'expected_vulnerable': True,
                    'cwes': self._extract_cwes_from_name(case_id),
                    'entrypoint_hint': py_file.stem,
                    'oracle_hint': 'OWASP Benchmark Python fallback import from benchmark source tree',
                    'language': 'python',
                })

        if not cases:
            raise ValueError(f"No OWASP Benchmark Python cases found under: {root}")

        return {
            'benchmark_family': 'owasp_benchmark_python',
            'benchmark_id': root.name,
            'benchmark_name': 'OWASP Benchmark Python',
            'language': 'python',
            'source_root': str(root),
            'support_paths': ['app.py', 'requirements.txt', 'helpers', 'templates', 'data'],
            'cases': cases,
        }

    def _juliet_case_support_copy_paths(self, root: Path, testcase: Path) -> List[str]:
        support_paths: List[str] = []
        testcase_rel = testcase.relative_to(root).as_posix()
        support_paths.append(str(testcase.parent.relative_to(root) / 'Makefile').replace('\\', '/'))

        stem = testcase.stem
        family_base = re.sub(r'_(?:bad|goodG2B|goodB2G|good|a|b|c|d|e)$', '', stem)
        if family_base == stem:
            family_base = re.sub(r'_[a-e]$', '', stem)

        for sibling in testcase.parent.iterdir():
            if not sibling.is_file():
                continue
            if sibling.suffix.lower() not in {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'}:
                continue
            if sibling.stem.startswith(family_base) and sibling.name != testcase.name:
                support_paths.append(sibling.relative_to(root).as_posix())

        return sorted(dict.fromkeys(support_paths))

    def _load_owasp_python_case_entries(self, data_file: Path) -> List[Dict[str, Any]]:
        try:
            if data_file.suffix.lower() == '.json':
                payload = json.loads(data_file.read_text(encoding='utf-8'))
                if isinstance(payload, list):
                    return [item for item in payload if isinstance(item, dict)]
                if isinstance(payload, dict):
                    for key in ('cases', 'tests', 'data'):
                        value = payload.get(key)
                        if isinstance(value, list):
                            return [item for item in value if isinstance(item, dict)]
            if data_file.suffix.lower() == '.csv':
                rows: List[Dict[str, Any]] = []
                with data_file.open('r', encoding='utf-8') as handle:
                    reader = csv.reader(handle)
                    for row in reader:
                        if not row or not row[0] or row[0].startswith('#'):
                            continue
                        if len(row) < 4:
                            continue
                        rows.append({
                            'test_id': row[0].strip(),
                            'route': row[1].strip() if len(row) > 1 else '',
                            'expected_vulnerable': (row[2].strip().lower() == 'true') if len(row) > 2 else True,
                            'cwes': [f"CWE-{row[3].strip()}"] if len(row) > 3 and row[3].strip() else [],
                        })
                return rows
            return []
        except Exception:
            return []

    def _resolve_owasp_python_copy_paths(self, source_dirs: List[Path], route: Optional[str]) -> List[str]:
        if not route:
            return []
        tokens = [token for token in re.split(r'[^A-Za-z0-9_]+', str(route)) if token]
        if not tokens:
            return []

        copy_paths: List[str] = []
        for source_dir in source_dirs:
            if not source_dir.exists():
                continue
            for py_file in source_dir.rglob('*.py'):
                lowered = py_file.stem.lower()
                if any(token.lower() in lowered for token in tokens):
                    copy_paths.append(py_file.relative_to(source_dir.parent).as_posix())
        return sorted(set(copy_paths))

    def _extract_cwes_from_name(self, value: str) -> List[str]:
        matches = re.findall(r'CWE[-_]?(\d+)', str(value or ''), flags=re.IGNORECASE)
        return [f'CWE-{match}' for match in matches]

    def _majority_language(self, cases: List[Dict[str, Any]]) -> str:
        counts: Dict[str, int] = {}
        for case in cases:
            language = str(case.get('language') or 'unknown')
            counts[language] = counts.get(language, 0) + 1
        return max(counts.items(), key=lambda item: item[1])[0] if counts else 'unknown'

    def _select_cases(self, manifest: Dict[str, Any], case_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
        cases = manifest['cases']
        if not case_ids:
            return cases
        requested = {str(case_id).strip() for case_id in case_ids if str(case_id).strip()}
        selected = [case for case in cases if case['case_id'] in requested]
        missing = sorted(requested - {case['case_id'] for case in selected})
        if missing:
            raise ValueError(f"Benchmark case ids not found in manifest: {', '.join(missing)}")
        if not selected:
            raise ValueError("No benchmark cases selected")
        return selected

    def _build_benchmark_metadata(self, manifest: Dict[str, Any], selected_cases: List[Dict[str, Any]], workspace_root: Optional[Path]) -> Dict[str, Any]:
        return {
            'benchmark_family': manifest.get('benchmark_family'),
            'benchmark_id': manifest.get('benchmark_id'),
            'benchmark_name': manifest.get('benchmark_name') or manifest.get('benchmark_id'),
            'language': manifest.get('language'),
            'manifest_path': manifest.get('manifest_path'),
            'source_root': manifest.get('source_root'),
            'workspace_root': str(workspace_root) if workspace_root else None,
            'selected_case_ids': [case['case_id'] for case in selected_cases],
            'cases_total': len(selected_cases),
            'cases': [
                {
                    'case_id': case['case_id'],
                    'expected_vulnerable': bool(case.get('expected_vulnerable', True)),
                    'cwes': list(case.get('cwes') or []),
                    'copy_paths': list(case.get('copy_paths') or []),
                    'entrypoint_hint': case.get('entrypoint_hint'),
                    'oracle_hint': case.get('oracle_hint'),
                    'build': dict(case.get('build') or {}),
                    'run': dict(case.get('run') or {}),
                }
                for case in selected_cases
            ],
        }

    def _match_case_findings(self, case: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        workspace_paths = [self._normalize_relpath(path) for path in (case.get('workspace_paths') or [])]
        if not workspace_paths:
            return []
        matched = []
        for finding in findings:
            filepath = str(finding.get('filepath') or '')
            if not filepath:
                continue
            normalized = filepath.replace('\\', '/').lstrip('./')
            if any(normalized == path or normalized.startswith(f"{path}/") for path in workspace_paths):
                matched.append(finding)
        return matched

    def _normalize_relpath(self, value: str) -> str:
        return str(value or '').replace('\\', '/').lstrip('./')

    def _ratio(self, numerator: int, denominator: int) -> Optional[float]:
        if denominator <= 0:
            return None
        return round(float(numerator) / float(denominator), 4)


_benchmark_registry: Optional[BenchmarkRegistry] = None


def get_benchmark_registry() -> BenchmarkRegistry:
    global _benchmark_registry
    if _benchmark_registry is None:
        _benchmark_registry = BenchmarkRegistry()
    return _benchmark_registry
