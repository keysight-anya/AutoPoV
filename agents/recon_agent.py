"""
Reconnaissance Agent — LLM-driven analysis of target repositories.

Runs ONCE per scan (before discovery and investigation) to produce a
ReconReport that guides all downstream decisions: proof strategy selection,
Docker image choice, oracle evaluation, and PoV generation prompts.

This replaces hardcoded CWE-specific logic, fixed proof type defaults, and
static language/framework assumptions with dynamic, per-repo intelligence.
"""

import os
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ReconReport dataclass — the output of the recon phase
# ---------------------------------------------------------------------------

@dataclass
class ReconReport:
    """Dynamic intelligence about a target repository, produced once per scan."""

    # Project classification
    project_type: str = "unknown"
    # Values: cli_tool, library, web_app, api_server, parser, framework,
    #         desktop_app, daemon, plugin, test_suite, unknown

    languages: List[str] = field(default_factory=list)
    # Primary languages detected (e.g. ["c", "python"])

    language_counts: Dict[str, int] = field(default_factory=dict)
    # Full language -> file count mapping from project structure scan

    build_system: str = "unknown"
    # cmake, make, autotools, meson, maven, gradle, npm, pip, cargo, go_mod, etc.

    build_commands: List[str] = field(default_factory=list)
    # Exact commands to build the project (e.g. ["mkdir build && cd build && cmake .. && make"])

    attack_surfaces: List[Dict[str, str]] = field(default_factory=list)
    # [{type: "file_input", format: "yaml", entry: "yaml_load"}, ...]

    runtime_family: str = "native"
    # native, python, node, java, ruby, php, go, rust, shell

    docker_image: str = ""
    # Recommended Docker image (e.g. "autopov/proof-native:latest")

    docker_extra_deps: List[str] = field(default_factory=list)
    # Additional packages to install (apt, pip, npm)

    proof_strategies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Mapping of vulnerability category -> recommended proof approach
    # e.g. {"memory_corruption": {"proof_type": "crash_signal", "harness_type": "subprocess_binary"}}

    binary_candidates: List[str] = field(default_factory=list)
    # Built executables to target (e.g. ["enchive", "libyaml-test"])

    entrypoints: List[Dict[str, str]] = field(default_factory=list)
    # [{name: "yaml_parser_parse", type: "function", file: "src/parser.c", how_to_invoke: "..."}]

    framework_hints: List[str] = field(default_factory=list)
    # ["uses libexpat", "Flask web framework", "Node.js Express"]

    # Default proof type for this project when the LLM fails to specify one
    default_proof_type: str = "crash_signal"
    default_harness_type: str = "subprocess_binary"

    # Observable evidence patterns specific to this project
    default_observable_evidence: List[str] = field(default_factory=list)

    # Known CVE findings detected from dependency manifests
    known_cve_findings: List[Dict[str, Any]] = field(default_factory=list)

    # Entry-point candidates discovered from project structure
    entry_point_candidates: List[Dict[str, str]] = field(default_factory=list)
    # [{"name": "main", "file": "src/main.c", "type": "function"}, ...]

    # Sample input files found in test/fixture directories
    sample_input_files: List[str] = field(default_factory=list)

    # Inferred input format hints (e.g. ["xml", "json", "binary"])
    input_format_hints: List[str] = field(default_factory=list)

    # Whether the repo exposes an HTTP/web surface
    has_web_surface: bool = False

    # Detected web frameworks (e.g. ["flask", "express"])
    web_frameworks: List[str] = field(default_factory=list)

    # Repo surface classification (library_c, cli_tool_c, python_module, etc.)
    repo_surface_class: str = "unknown"

    # Database requirements detected from manifests/code
    # e.g. [{"db_type": "postgresql", "orm": "sqlalchemy", "substitute": "sqlite"}]
    detected_databases: List[Dict[str, str]] = field(default_factory=list)

    # DB substitution env vars for docker containers
    # e.g. {"DATABASE_URL": "sqlite:///autopov_test.db", "DB_ENGINE": "sqlite3"}
    db_substitution_env: Dict[str, str] = field(default_factory=dict)

    # Files identified as high-value targets from git history analysis
    # Ranked by security-commit frequency and recency.
    # [{file, reason, commit_count, last_security_commit}]
    high_value_files: List[Dict[str, Any]] = field(default_factory=list)

    # Recent security-related commit summaries (last 50 matching commits)
    # [{hash, message, date, files_changed}]
    security_commits: List[Dict[str, Any]] = field(default_factory=list)

    # Vulnerability types seen in commit history
    # e.g. ["buffer overflow", "sql injection", "use-after-free"]
    historical_vuln_types: List[str] = field(default_factory=list)

    # Repository age and activity metadata
    # {first_commit_date, last_commit_date, total_commits, is_active}
    repo_activity: Dict[str, Any] = field(default_factory=dict)

    # GitHub security intelligence (when repo_url is github.com)
    # [{cve, severity, package, description, source}]
    github_security_findings: List[Dict[str, Any]] = field(default_factory=list)

    # SECURITY.md and CHANGELOG content (first 3KB each)
    security_policy: str = ""
    changelog_excerpt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReconReport':
        if not data:
            return cls()
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def get_default_proof_strategy(self) -> Dict[str, Any]:
        """Return the fallback proof_strategy dict for this project."""
        return {
            'proof_type': self.default_proof_type,
            'observable_evidence': self.default_observable_evidence,
            'harness_type': self.default_harness_type,
        }

    def resolve_docker_image(self) -> str:
        """Return the best Docker image for this project."""
        if self.docker_image:
            return self.docker_image
        family = self.runtime_family.lower()
        image_map = {
            'python': settings.DOCKER_IMAGE,
            'node': settings.DOCKER_NODE_IMAGE,
            'javascript': settings.DOCKER_NODE_IMAGE,
            'java': settings.DOCKER_JAVA_IMAGE,
            'ruby': settings.DOCKER_RUBY_IMAGE,
            'php': settings.DOCKER_PHP_IMAGE,
            'go': settings.DOCKER_GO_IMAGE,
            'native': settings.DOCKER_NATIVE_IMAGE,
            'c': settings.DOCKER_NATIVE_IMAGE,
            'cpp': settings.DOCKER_NATIVE_IMAGE,
        }
        return image_map.get(family, settings.DOCKER_NATIVE_IMAGE)


# ---------------------------------------------------------------------------
# Filesystem scanning utilities (no LLM needed)
# ---------------------------------------------------------------------------

_BUILD_FILES = {
    'CMakeLists.txt': 'cmake',
    'Makefile': 'make',
    'configure.ac': 'autotools',
    'configure': 'autotools',
    'meson.build': 'meson',
    'pom.xml': 'maven',
    'build.gradle': 'gradle',
    'build.gradle.kts': 'gradle',
    'package.json': 'npm',
    'setup.py': 'pip',
    'setup.cfg': 'pip',
    'pyproject.toml': 'pip',
    'Cargo.toml': 'cargo',
    'go.mod': 'go_mod',
    'Gemfile': 'bundler',
    'composer.json': 'composer',
}

_LANG_EXTS = {
    '.c': 'c', '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp',
    '.hpp': 'cpp', '.hh': 'cpp',
    '.py': 'python', '.pyx': 'python',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript',
    '.java': 'java', '.kt': 'kotlin',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.cs': 'csharp',
    '.swift': 'swift',
    '.scala': 'scala',
}

_RUNTIME_FAMILY_MAP = {
    'c': 'native', 'cpp': 'native', 'rust': 'native', 'go': 'native',
    'python': 'python', 'javascript': 'node', 'typescript': 'node',
    'java': 'java', 'kotlin': 'java', 'scala': 'java',
    'ruby': 'ruby', 'php': 'php', 'csharp': 'native',
    'swift': 'native',
}


def _scan_project_structure(codebase_path: str) -> Dict[str, Any]:
    """Scan the project directory for build files, languages, and structure.
    
    This is a fast, deterministic scan with no LLM calls.
    Returns raw data for the LLM to analyze.
    """
    result = {
        'build_files': [],
        'language_counts': {},
        'total_files': 0,
        'key_files': [],
        'has_tests': False,
        'has_docs': False,
        'top_level_dirs': [],
        'package_manifests': {},
        'entry_point_candidates': [],
        'sample_input_files': [],
        'input_format_hints': set(),
        'has_web_surface': False,
        'web_frameworks': [],
        'has_main_function': False,
        'is_library': False,
    }

    if not codebase_path or not os.path.isdir(codebase_path):
        return result

    # Walk the codebase (limit depth to avoid huge repos)
    max_files = 5000
    file_count = 0
    for root, dirs, files in os.walk(codebase_path):
        # Skip hidden dirs, vendor, node_modules, etc.
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and d not in ('node_modules', 'vendor', '.git', '__pycache__',
                                 'build', 'dist', 'target', '.tox', 'venv', 'env')]

        rel_root = os.path.relpath(root, codebase_path)
        if rel_root == '.':
            result['top_level_dirs'] = sorted(dirs)

        for fname in files:
            file_count += 1
            if file_count > max_files:
                break

            # Build files
            if fname in _BUILD_FILES:
                result['build_files'].append({
                    'name': fname,
                    'build_system': _BUILD_FILES[fname],
                    'path': os.path.join(rel_root, fname) if rel_root != '.' else fname,
                })

            # Language detection
            ext = os.path.splitext(fname)[1].lower()
            if ext in _LANG_EXTS:
                lang = _LANG_EXTS[ext]
                result['language_counts'][lang] = result['language_counts'].get(lang, 0) + 1

            # Key files
            if fname.lower() in ('readme.md', 'readme.rst', 'readme.txt', 'readme'):
                result['has_docs'] = True

            # Test detection
            if 'test' in rel_root.lower() or fname.lower().startswith('test_'):
                result['has_tests'] = True

        # Read package manifests (first 8KB — pom.xml can easily exceed 2KB)
        for fname in files:
            if fname in ('package.json', 'pom.xml', 'Cargo.toml', 'setup.py',
                         'pyproject.toml', 'go.mod', 'CMakeLists.txt', 'Makefile',
                         'requirements.txt', 'requirements-dev.txt',
                         'requirements-prod.txt', 'requirements-test.txt',
                         'composer.json', 'Gemfile.lock'):
                fpath = os.path.join(root, fname)
                if rel_root == '.' or rel_root.count(os.sep) < 2:
                    try:
                        with open(fpath, 'r', errors='replace') as f:
                            # 16KB default; CMakeLists/Makefile only need 2KB
                            _read_limit = 2048 if fname in ('CMakeLists.txt', 'Makefile') else 16384
                            content = f.read(_read_limit)
                        # Use relative path as key for multi-module projects
                        # (e.g. Maven multi-module: root pom.xml + submodule pom.xml)
                        manifest_key = os.path.join(rel_root, fname) if rel_root != '.' else fname
                        result['package_manifests'][manifest_key] = content
                    except (OSError, PermissionError):
                        pass

        if file_count > max_files:
            break

    result['total_files'] = file_count

    # Post-scan: detect entry points (main() in C/C++, if __name__ in Python)
    import re as _re_scan
    _MAIN_RE = _re_scan.compile(r'\bint\s+main\s*\(', _re_scan.MULTILINE)
    _PY_MAIN_RE = _re_scan.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]")
    _WEB_IMPORTS = _re_scan.compile(
        r'(?:import|from)\s+(?:flask|django|aiohttp|tornado|fastapi|starlette|'
        r'express|fastify|koa|hapi|bottle|cherrypy)',
        _re_scan.IGNORECASE,
    )
    _INPUT_EXT_MAP = {
        '.xml': 'xml', '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml',
        '.csv': 'csv', '.bin': 'binary', '.dat': 'binary', '.raw': 'binary',
        '.txt': 'text', '.html': 'html', '.htm': 'html',
    }
    _FIXTURE_DIRS = {
        'test', 'tests', 'test-data', 'testdata', 'test_data',
        'fixtures', 'fixture', 'samples', 'sample', 'examples', 'example',
        'data', 'resources', 'testfiles', 'testcases',
    }
    _format_hints: set = result['input_format_hints']  # alias to the set

    for root, dirs, files in os.walk(codebase_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and d not in ('node_modules', 'vendor', '.git', '__pycache__',
                                 'build', 'dist', 'target', '.tox', 'venv', 'env')]
        rel_root = os.path.relpath(root, codebase_path)
        _parts = set(os.path.normpath(rel_root).split(os.sep))

        # Collect sample input files from fixture directories
        if _parts & _FIXTURE_DIRS:
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _INPUT_EXT_MAP:
                    if len(result['sample_input_files']) < 15:
                        result['sample_input_files'].append(
                            os.path.join(rel_root, fname) if rel_root != '.' else fname
                        )
                    _format_hints.add(_INPUT_EXT_MAP[ext])

        # Scan source files for entry points and web frameworks
        _depth = 0 if rel_root == '.' else rel_root.count(os.sep) + 1
        if _depth > 3:
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            # C/C++ main()
            if ext in ('.c', '.cpp', '.cc', '.cxx'):
                try:
                    _src = open(fpath, 'r', errors='ignore').read(8192)
                    if _MAIN_RE.search(_src):
                        result['has_main_function'] = True
                        result['entry_point_candidates'].append({
                            'name': 'main',
                            'file': os.path.join(rel_root, fname) if rel_root != '.' else fname,
                            'type': 'function',
                        })
                except OSError:
                    pass
            # Python entry points
            elif ext == '.py':
                try:
                    _src = open(fpath, 'r', errors='ignore').read(4096)
                    if _PY_MAIN_RE.search(_src):
                        result['entry_point_candidates'].append({
                            'name': fname,
                            'file': os.path.join(rel_root, fname) if rel_root != '.' else fname,
                            'type': 'script',
                        })
                    if _WEB_IMPORTS.search(_src):
                        result['has_web_surface'] = True
                        # Extract framework name
                        for _wm in _re_scan.finditer(r'(?:import|from)\s+(flask|django|aiohttp|tornado|fastapi|starlette|express|fastify|koa|bottle)', _src, _re_scan.IGNORECASE):
                            _fw = _wm.group(1).lower()
                            if _fw not in result['web_frameworks']:
                                result['web_frameworks'].append(_fw)
                except OSError:
                    pass
            # JS/TS web frameworks in source
            elif ext in ('.js', '.ts', '.mjs'):
                try:
                    _src = open(fpath, 'r', errors='ignore').read(4096)
                    for _fw_name in ('express', 'fastify', 'koa', 'hapi'):
                        if f"require('{_fw_name}'" in _src or f'from "{_fw_name}"' in _src or f"from '{_fw_name}'" in _src:
                            result['has_web_surface'] = True
                            if _fw_name not in result['web_frameworks']:
                                result['web_frameworks'].append(_fw_name)
                except OSError:
                    pass

    # Determine is_library: has public headers / setup.py but no main()
    if not result['has_main_function']:
        _has_public_api = any(
            bf['build_system'] in ('cmake', 'make', 'autotools', 'meson')
            for bf in result['build_files']
        ) or any(
            m in result.get('package_manifests', {})
            for m in ('setup.py', 'pyproject.toml', 'Cargo.toml')
        )
        if _has_public_api:
            result['is_library'] = True

    # Convert set to sorted list for JSON serialization
    result['input_format_hints'] = sorted(_format_hints)

    return result


# ---------------------------------------------------------------------------
# Dependency CVE scanning
# ---------------------------------------------------------------------------

# _load_advisory_db — REMOVED: replaced by agents/cve_lookup.py OSV queries


def _parse_dependency_versions(structure: Dict[str, Any]) -> List[Dict[str, str]]:
    """Parse dependency names and versions from package manifests.

    Returns a list of dicts: [{name, version, ecosystem}, ...]
    """
    import re as _re
    deps: List[Dict[str, str]] = []
    manifests = structure.get('package_manifests', {})

    # --- pip: requirements.txt and all requirements-*.txt variants ---
    for _req_name, _content in manifests.items():
        if not (_req_name == 'requirements.txt' or
                (_req_name.startswith('requirements') and
                 _req_name.endswith('.txt'))):
            continue
        if not _content:
            continue
        for line in _content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            m = _re.match(r'^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*([\d.]+\S*))?', line)
            if m:
                deps.append({'name': m.group(1), 'version': m.group(2) or '', 'ecosystem': 'pip'})

    _pyproject = manifests.get('pyproject.toml', '')
    if _pyproject:
        for line in _pyproject.splitlines():
            m = _re.match(r'^\s*"?([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*([\d.]+))?', line)
            if m and m.group(1) not in ('name', 'version', 'description', 'python_requires', 'requires-python'):
                deps.append({'name': m.group(1), 'version': m.group(2) or '', 'ecosystem': 'pip'})

    # --- npm: package.json ---
    _pkg_json_raw = manifests.get('package.json', '')
    if _pkg_json_raw:
        try:
            import json as _json
            _pkg = _json.loads(_pkg_json_raw)
            for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                for name, ver_spec in (_pkg.get(section) or {}).items():
                    ver = _re.sub(r'[^\d.]', '', str(ver_spec)).lstrip('.')
                    deps.append({'name': name, 'version': ver, 'ecosystem': 'npm'})
        except (ValueError, AttributeError):
            pass

    # --- maven: pom.xml (collect from all pom.xml manifests) ---
    _pom_parts = [v for k, v in manifests.items() if k == 'pom.xml' or k.endswith('/pom.xml') or k.endswith('\\pom.xml')]
    _pom = '\n'.join(_pom_parts)
    if _pom:
        # Parse each <dependency> block atomically to avoid mispairing
        # artifactIds with unrelated version elements (parent, plugin, etc.)
        _dep_blocks = _re.findall(r'<dependency>(.*?)</dependency>', _pom, _re.DOTALL)
        for _block in _dep_blocks:
            _art_m = _re.search(r'<artifactId>\s*([^<]+?)\s*</artifactId>', _block)
            # Skip versions that are Maven property references (${...})
            _ver_m = _re.search(r'<version>\s*([^<$][^<]*?)\s*</version>', _block)
            if _art_m:
                deps.append({
                    'name': _art_m.group(1).strip(),
                    'version': _ver_m.group(1).strip() if _ver_m else '',
                    'ecosystem': 'maven',
                })

    # --- go.mod ---
    _gomod = manifests.get('go.mod', '')
    if _gomod:
        for line in _gomod.splitlines():
            m = _re.match(r'^\s+([\w./-]+)\s+v([\d.]+)', line)
            if m:
                # Store both full module path and last segment for matching
                full_path = m.group(1)
                _parts = full_path.rsplit('/', 1)
                short_name = _parts[-1] if _parts else full_path
                deps.append({'name': full_path, 'version': m.group(2), 'ecosystem': 'go'})
                # Also add short name for stdlib-style packages (net/http -> net/http)
                if short_name != full_path:
                    deps.append({'name': short_name, 'version': m.group(2), 'ecosystem': 'go'})

    # --- Cargo.toml ---
    _cargo = manifests.get('Cargo.toml', '')
    if _cargo:
        for line in _cargo.splitlines():
            m = _re.match(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([\d.]+)"', line)
            if m:
                deps.append({'name': m.group(1), 'version': m.group(2), 'ecosystem': 'cargo'})

    # --- composer.json (PHP) ---
    _composer_raw = manifests.get('composer.json', '')
    if _composer_raw:
        try:
            import json as _json_c
            _composer = _json_c.loads(_composer_raw)
            for section in ('require', 'require-dev'):
                for name, ver_spec in (_composer.get(section) or {}).items():
                    if name == 'php' or name.startswith('ext-'):
                        continue  # skip PHP version and extension requirements
                    ver = _re.sub(r'[^\d.]', '', str(ver_spec)).lstrip('.')
                    deps.append({'name': name, 'version': ver, 'ecosystem': 'composer'})
        except (ValueError, AttributeError):
            pass

    # --- Gemfile.lock (Ruby) ---
    _gemlock = manifests.get('Gemfile.lock', '')
    if _gemlock:
        _in_specs = False
        for line in _gemlock.splitlines():
            stripped = line.strip()
            if stripped == 'specs:':
                _in_specs = True
                continue
            if _in_specs:
                m = _re.match(r'^\s{4}([A-Za-z0-9_-]+)\s+\(([\d.]+)', line)
                if m:
                    deps.append({'name': m.group(1), 'version': m.group(2), 'ecosystem': 'gem'})
                elif not line.startswith('    '):
                    _in_specs = False  # left the specs section

    return deps


# _version_lt, _match_known_cves, scan_dependencies_for_cves — REMOVED
# Replaced by agents/cve_lookup.py (OSV live queries with cache fallback)


# ---------------------------------------------------------------------------
# Syft SBOM discovery — catches vendored deps, fat JARs, etc.
# ---------------------------------------------------------------------------

def _run_syft_sbom(codebase_path: str) -> List[Dict[str, str]]:
    """Run Syft SBOM scan to discover dependencies missed by manifest parsing.

    Returns a list of dep dicts compatible with cve_lookup.query_cves_for_dependencies.
    Falls back gracefully if syft is not installed or errors out.
    """
    import shutil
    if not shutil.which('syft'):
        logger.debug('_run_syft_sbom: syft not found on PATH — skipping')
        return []

    import subprocess as _sp
    import json as _json

    try:
        proc = _sp.run(
            ['syft', f'dir:{codebase_path}', '-o', 'json', '--quiet'],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            logger.debug('_run_syft_sbom: syft returned %d', proc.returncode)
            return []

        sbom = _json.loads(proc.stdout)
    except (OSError, _json.JSONDecodeError, _sp.TimeoutExpired) as exc:
        logger.debug('_run_syft_sbom: failed: %s', exc)
        return []

    # Map Syft ecosystem types to our canonical ecosystem names
    _ECO_MAP = {
        'java-archive': 'maven', 'maven': 'maven',
        'npm': 'npm', 'node': 'npm',
        'python': 'pypi', 'pip': 'pypi', 'pypi': 'pypi',
        'gem': 'gem', 'ruby': 'gem',
        'go-module': 'go', 'go': 'go',
        'rust-crate': 'cargo', 'cargo': 'cargo',
        'composer': 'composer', 'php': 'composer',
        'apk': 'native', 'deb': 'native', 'rpm': 'native',
    }

    deps: List[Dict[str, str]] = []
    for artifact in sbom.get('artifacts', []):
        name = artifact.get('name', '')
        version = artifact.get('version', '')
        if not name or not version:
            continue
        syft_type = (artifact.get('type') or '').lower()
        ecosystem = _ECO_MAP.get(syft_type, '')
        if not ecosystem:
            # Try language field
            lang = (artifact.get('language') or '').lower()
            ecosystem = _ECO_MAP.get(lang, '')
        if not ecosystem:
            continue
        deps.append({'name': name, 'version': version, 'ecosystem': ecosystem})

    logger.info('_run_syft_sbom: discovered %d packages via Syft', len(deps))
    return deps


# ---------------------------------------------------------------------------
# Git history analysis — local .git only, no external dependencies
# ---------------------------------------------------------------------------

_SECURITY_KEYWORDS = [
    # Vulnerability types
    'overflow', 'buffer overflow', 'heap overflow', 'stack overflow',
    'use-after-free', 'use after free', 'uaf', 'double free',
    'null pointer', 'null dereference', 'out-of-bounds', 'oob',
    'integer overflow', 'integer underflow',
    'injection', 'sql injection', 'command injection', 'code injection',
    'xss', 'cross-site scripting', 'csrf',
    'path traversal', 'directory traversal', 'lfi', 'rfi',
    'deserialization', 'insecure deserialization',
    'ssrf', 'xxe', 'xml injection',
    'prototype pollution',
    'race condition', 'toctou',
    'memory leak', 'memory corruption',
    # Fix vocabulary
    'security', 'vuln', 'vulnerability', 'cve', 'exploit',
    'fix', 'patch', 'sanitize', 'sanitise', 'validate',
    'bypass', 'auth bypass', 'authentication bypass',
    'privilege escalation', 'escalation',
    'disclosure', 'information disclosure',
]


def _analyse_git_history(codebase_path: str) -> Dict[str, Any]:
    """Analyse the git history of a cloned repo for security intelligence.

    Uses subprocess git commands — no gitpython dependency needed.
    Falls back gracefully if .git directory does not exist (zip uploads).

    Returns a dict with:
      security_commits: list of security-related commits
      high_value_files: files ranked by security-commit involvement
      historical_vuln_types: vulnerability types seen in commit messages
      repo_activity: age and maintenance metadata
    """
    result: Dict[str, Any] = {
        'security_commits': [],
        'high_value_files': [],
        'historical_vuln_types': [],
        'repo_activity': {},
    }

    git_dir = os.path.join(codebase_path, '.git')
    if not os.path.isdir(git_dir):
        logger.debug("_analyse_git_history: no .git directory — skipping")
        return result

    import subprocess as _sp
    import re as _re  # noqa: F811
    from datetime import datetime as _dt
    from collections import defaultdict as _dd

    def _git(args: list, timeout: int = 15) -> str:
        """Run a git command, return stdout or empty string on error."""
        try:
            r = _sp.run(
                ['git'] + args,
                cwd=codebase_path,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return r.stdout.strip() if r.returncode == 0 else ''
        except Exception:
            return ''

    # ── 1. Repo activity metadata ──────────────────────────────────────────
    age_days: Optional[int] = None
    try:
        first_date = _git(['log', '--reverse', '--format=%ci', '--max-count=1'])
        last_date = _git(['log', '--format=%ci', '--max-count=1'])
        total_str = _git(['rev-list', '--count', 'HEAD'])
        total_commits = int(total_str) if total_str.isdigit() else 0

        last_dt = None
        if last_date:
            try:
                last_dt = _dt.fromisoformat(last_date[:10])
            except ValueError:
                pass

        is_active = False
        if last_dt:
            age_days = (_dt.utcnow() - last_dt).days
            is_active = age_days < 365

        result['repo_activity'] = {
            'first_commit_date': first_date[:10] if first_date else '',
            'last_commit_date': last_date[:10] if last_date else '',
            'total_commits': total_commits,
            'is_active': is_active,
            'days_since_last_commit': age_days,
        }
    except Exception as e:
        logger.debug("_analyse_git_history: activity metadata failed: %s", e)

    # ── 2. Security-related commits ────────────────────────────────────────
    log_output = _git([
        'log',
        '--format=%H|%ci|%s',
        '--max-count=200',
    ])

    if not log_output:
        return result

    _file_security_count: Dict[str, int] = {}
    _file_last_sec_date: Dict[str, str] = {}
    vuln_types_seen: set = set()

    _vuln_kw_map = {
        'overflow': 'buffer overflow',
        'buffer overflow': 'buffer overflow',
        'heap overflow': 'buffer overflow',
        'use-after-free': 'use-after-free',
        'use after free': 'use-after-free',
        'uaf': 'use-after-free',
        'injection': 'injection',
        'sql injection': 'sql injection',
        'xss': 'xss',
        'path traversal': 'path traversal',
        'directory traversal': 'path traversal',
        'deserialization': 'deserialization',
        'race condition': 'race condition',
        'memory leak': 'memory leak',
        'integer overflow': 'integer overflow',
        'ssrf': 'ssrf',
        'xxe': 'xxe',
        'prototype pollution': 'prototype pollution',
        'command injection': 'command injection',
    }

    for line in log_output.splitlines():
        parts = line.split('|', 2)
        if len(parts) < 3:
            continue
        commit_hash, commit_date, subject = parts
        subject_lower = subject.lower()

        matched_keywords = [
            kw for kw in _SECURITY_KEYWORDS
            if kw in subject_lower
        ]
        if not matched_keywords:
            continue

        files_raw = _git(['diff-tree', '--no-commit-id', '-r', '--name-only', commit_hash])
        changed_files = [
            f for f in files_raw.splitlines()
            if f and not f.startswith('test') and not f.startswith('docs')
            and not f.endswith('.md') and not f.endswith('.txt')
        ]

        result['security_commits'].append({
            'hash': commit_hash[:8],
            'date': commit_date[:10],
            'message': subject[:120],
            'files_changed': changed_files[:10],
            'keywords': matched_keywords[:5],
        })

        for f in changed_files:
            _file_security_count[f] = _file_security_count.get(f, 0) + 1
            if f not in _file_last_sec_date or commit_date > _file_last_sec_date[f]:
                _file_last_sec_date[f] = commit_date[:10]

        for kw in matched_keywords:
            if kw in _vuln_kw_map:
                vuln_types_seen.add(_vuln_kw_map[kw])

    # ── 3. Rank high-value files ───────────────────────────────────────────
    ranked = sorted(
        _file_security_count.items(),
        key=lambda x: (x[1], _file_last_sec_date.get(x[0], '')),
        reverse=True
    )
    result['high_value_files'] = [
        {
            'file': f,
            'security_commit_count': count,
            'last_security_commit': _file_last_sec_date.get(f, ''),
            'reason': f'Involved in {count} security-related commit(s)',
        }
        for f, count in ranked[:20]
    ]

    result['historical_vuln_types'] = sorted(vuln_types_seen)

    logger.info(
        "_analyse_git_history: %d security commits, %d high-value files, types: %s",
        len(result['security_commits']),
        len(result['high_value_files']),
        result['historical_vuln_types'],
    )
    return result


def _read_security_docs(codebase_path: str) -> Dict[str, str]:
    """Read SECURITY.md and CHANGELOG if present.

    These files explicitly document past vulnerabilities and responsible
    disclosure — direct intelligence for the LLM recon prompt.
    """
    docs: Dict[str, str] = {'security_policy': '', 'changelog_excerpt': ''}
    cb = Path(codebase_path)

    # SECURITY.md / SECURITY.rst / SECURITY.txt
    for name in ('SECURITY.md', 'SECURITY.rst', 'SECURITY.txt', 'SECURITY',
                 '.github/SECURITY.md'):
        p = cb / name
        if p.is_file():
            try:
                docs['security_policy'] = p.read_text(
                    encoding='utf-8', errors='ignore')[:3000]
                break
            except OSError:
                pass

    # CHANGELOG / CHANGES / HISTORY
    for name in ('CHANGELOG.md', 'CHANGELOG.rst', 'CHANGELOG', 'CHANGES.md',
                 'CHANGES', 'HISTORY.md', 'HISTORY.rst', 'NEWS.md', 'NEWS'):
        p = cb / name
        if p.is_file():
            try:
                docs['changelog_excerpt'] = p.read_text(
                    encoding='utf-8', errors='ignore')[:3000]
                break
            except OSError:
                pass

    return docs


def _query_github_security(repo_url: str, github_token: str = '') -> List[Dict[str, Any]]:
    """Query GitHub security APIs for advisories and Dependabot alerts.

    Only runs when:
      - repo_url contains github.com
      - GITHUB_TOKEN is available (or passed explicitly)

    Returns a list of CVE-like finding dicts compatible with the
    known_cve_findings format for injection as pre-confirmed findings.

    Falls back gracefully — returns [] on any error.
    """
    if 'github.com' not in (repo_url or '').lower():
        return []
    token = github_token or settings.GITHUB_TOKEN
    if not token:
        logger.debug("_query_github_security: no GITHUB_TOKEN — skipping")
        return []

    import re as _re  # noqa: F811
    import requests as _req

    # Extract owner/repo from URL
    m = _re.search(r'github\.com[/:]([^/]+)/([^/\s.]+)', repo_url)
    if not m:
        return []
    owner, repo = m.group(1), m.group(2).rstrip('.git')

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    findings: List[Dict[str, Any]] = []
    seen_cves: set = set()

    # Import proof derivation functions for accurate proof_type assignment
    try:
        from agents.cve_lookup import _derive_proof_type, _derive_proof_hint
    except ImportError:
        _derive_proof_type = None  # type: ignore[assignment]
        _derive_proof_hint = None  # type: ignore[assignment]

    # ── 1. Repository security advisories ──────────────────────────────────
    try:
        resp = _req.get(
            f'https://api.github.com/repos/{owner}/{repo}/security-advisories',
            headers=headers,
            timeout=8,
            params={'per_page': 20},
        )
        if resp.status_code == 200:
            for adv in resp.json():
                for vuln in (adv.get('vulnerabilities') or []):
                    pkg = vuln.get('package') or {}
                    cve_id = adv.get('cve_id') or adv.get('ghsa_id') or ''
                    if cve_id and cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        severity = adv.get('severity', 'unknown')
                        patched = vuln.get('patched_versions') or ''
                        if isinstance(patched, list):
                            patched = patched[0] if patched else ''
                        # Derive proof_type/hint from description (same logic as OSV)
                        _vuln_dict = {'summary': adv.get('summary', ''), 'details': adv.get('description', '')}
                        _dep_dict = {'name': pkg.get('name', '')}
                        _pt = _derive_proof_type(_vuln_dict) if _derive_proof_type else 'observable_output'
                        _ph = _derive_proof_hint(_vuln_dict, _dep_dict) if _derive_proof_hint else adv.get('summary', '')
                        findings.append({
                            'package': pkg.get('name', ''),
                            'ecosystem': pkg.get('ecosystem', '').lower(),
                            'installed_version': '',
                            'fix_version': str(patched),
                            'cve': cve_id,
                            'cwe': '',
                            'severity': severity,
                            'cvss': _severity_to_cvss(severity),
                            'description': adv.get('summary', ''),
                            'proof_hint': _ph,
                            'proof_type': _pt,
                            'osv_id': adv.get('ghsa_id', ''),
                            'aliases': [adv.get('ghsa_id', '')],
                            'source': 'github_advisory',
                        })
        elif resp.status_code == 404:
            logger.debug("_query_github_security: advisories not accessible")
    except Exception as e:
        logger.debug("_query_github_security: advisories query failed: %s", e)

    # ── 2. Dependabot alerts ──────────────────────────────────────────
    try:
        resp = _req.get(
            f'https://api.github.com/repos/{owner}/{repo}/dependabot/alerts',
            headers=headers,
            timeout=8,
            params={'per_page': 30, 'state': 'open'},
        )
        if resp.status_code == 200:
            for alert in resp.json():
                adv = alert.get('security_advisory') or {}
                dep = alert.get('dependency') or {}
                pkg = dep.get('package') or {}
                cve_id = adv.get('cve_id') or adv.get('ghsa_id') or ''
                if not cve_id or cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                severity = adv.get('severity', 'unknown')
                patched = adv.get('patched_versions') or ''
                if isinstance(patched, list):
                    patched = patched[0] if patched else ''
                # Derive proof_type/hint from description (same logic as OSV)
                _vuln_dict = {'summary': adv.get('summary', ''), 'details': adv.get('description', '')}
                _dep_dict = {'name': pkg.get('name', '')}
                _pt = _derive_proof_type(_vuln_dict) if _derive_proof_type else 'observable_output'
                _ph = _derive_proof_hint(_vuln_dict, _dep_dict) if _derive_proof_hint else adv.get('summary', '')
                findings.append({
                    'package': pkg.get('name', ''),
                    'ecosystem': pkg.get('ecosystem', '').lower(),
                    'installed_version': dep.get('manifest_path', ''),
                    'fix_version': str(patched),
                    'cve': cve_id,
                    'cwe': '',
                    'severity': severity,
                    'cvss': _severity_to_cvss(severity),
                    'description': adv.get('summary', ''),
                    'proof_hint': _ph,
                    'proof_type': _pt,
                    'osv_id': adv.get('ghsa_id', ''),
                    'aliases': [adv.get('ghsa_id', '')],
                    'source': 'github_dependabot',
                })
        elif resp.status_code == 403:
            logger.debug("_query_github_security: Dependabot alerts require repo admin access")
    except Exception as e:
        logger.debug("_query_github_security: dependabot query failed: %s", e)

    # ── 3. Code scanning alerts ─────────────────────────────────────────
    # NOTE: Code scanning alerts are CodeQL/static-analysis signals that need
    # investigation, NOT pre-confirmed CVEs. They are excluded from the
    # findings list to avoid injecting them as pre-confirmed with
    # llm_verdict='REAL' and confidence=1.0. The normal CodeQL/Semgrep
    # discovery pipeline in agentic_discovery.py handles these.

    logger.info("_query_github_security: %d findings from GitHub APIs", len(findings))
    return findings


def _severity_to_cvss(severity: str) -> float:
    """Map GitHub severity label to approximate CVSS score."""
    return {'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5}.get(
        str(severity).lower(), 0.0)


def _infer_defaults_from_structure(structure: Dict[str, Any], codebase_path: str = '') -> ReconReport:
    """Produce a baseline ReconReport from filesystem scan alone (no LLM).

    This serves as both a fast fallback and the starting context for the LLM.
    """
    report = ReconReport()

    # Languages
    lang_counts = structure.get('language_counts', {})
    if lang_counts:
        report.language_counts = dict(lang_counts)
        sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
        report.languages = [lang for lang, _ in sorted_langs[:5]]

        # Primary language determines runtime family
        primary_lang = sorted_langs[0][0]
        report.runtime_family = _RUNTIME_FAMILY_MAP.get(primary_lang, 'native')

    # Build system
    build_files = structure.get('build_files', [])
    if build_files:
        report.build_system = build_files[0]['build_system']
        # Infer build commands
        bs = report.build_system
        if bs == 'cmake':
            report.build_commands = ['mkdir -p build && cd build && cmake .. -DCMAKE_C_FLAGS="-fsanitize=address -g" -DCMAKE_CXX_FLAGS="-fsanitize=address -g" && make -j$(nproc)']
        elif bs == 'make':
            report.build_commands = ['make CC=clang CFLAGS="-fsanitize=address -g" -j$(nproc)']
        elif bs == 'autotools':
            report.build_commands = ['./configure CC=clang CFLAGS="-fsanitize=address -g" && make -j$(nproc)']
        elif bs == 'meson':
            report.build_commands = ['meson setup build -Db_sanitize=address && ninja -C build']
        elif bs == 'npm':
            report.build_commands = ['npm install']
        elif bs == 'pip':
            report.build_commands = ['pip install -e .']
        elif bs == 'maven':
            report.build_commands = ['mvn compile -q']
        elif bs == 'gradle':
            report.build_commands = ['./gradlew build -x test']
        elif bs == 'cargo':
            report.build_commands = ['cargo build']
        elif bs == 'go_mod':
            report.build_commands = ['go build ./...']

    # Docker image
    report.docker_image = report.resolve_docker_image()

    # Default proof strategy based on runtime family
    family = report.runtime_family
    if family == 'native':
        report.default_proof_type = 'crash_signal'
        report.default_harness_type = 'subprocess_binary'
        report.default_observable_evidence = [
            'AddressSanitizer', 'UndefinedBehaviorSanitizer',
            'heap-buffer-overflow', 'stack-buffer-overflow',
            'use-after-free', 'SEGV', 'SIGABRT',
        ]
    elif family == 'python':
        report.default_proof_type = 'exception'
        report.default_harness_type = 'direct_import'
        report.default_observable_evidence = [
            'Traceback (most recent call last)', 'Exception', 'Error',
        ]
    elif family in ('node', 'javascript'):
        report.default_proof_type = 'exception'
        report.default_harness_type = 'direct_import'
        report.default_observable_evidence = [
            'TypeError', 'ReferenceError', 'RangeError',
            'UnhandledPromiseRejection',
        ]
    elif family == 'java':
        report.default_proof_type = 'exception'
        report.default_harness_type = 'compiled_harness'
        report.default_observable_evidence = [
            'Exception in thread', 'at java.', 'Caused by:',
        ]
    else:
        report.default_proof_type = 'exception'
        report.default_harness_type = 'subprocess_binary'
        report.default_observable_evidence = ['error', 'exception', 'crash']

    # ── Deterministic docker_extra_deps from build system & manifests ──
    _extra_deps: List[str] = []
    bs = report.build_system
    if bs in ('cmake', 'make', 'autotools', 'meson'):
        # Native C/C++ projects commonly need these at build time
        _extra_deps.extend(['build-essential', 'pkg-config'])
        if bs == 'cmake':
            _extra_deps.append('cmake')
        elif bs == 'meson':
            _extra_deps.extend(['meson', 'ninja-build'])
        elif bs == 'autotools':
            _extra_deps.extend(['autoconf', 'automake', 'libtool'])
    # Detect common C library deps from configure.ac / CMakeLists.txt
    manifests = structure.get('package_manifests') or {}
    for mkey, mval in manifests.items():
        _mv = (mval or '').lower()
        if 'zlib' in _mv:
            _extra_deps.append('zlib1g-dev')
        if 'libssl' in _mv or 'openssl' in _mv:
            _extra_deps.append('libssl-dev')
        if 'libcurl' in _mv or 'curl' in _mv:
            _extra_deps.append('libcurl4-openssl-dev')
        if 'libxml' in _mv:
            _extra_deps.append('libxml2-dev')
        if 'libpng' in _mv:
            _extra_deps.append('libpng-dev')
        if 'libjpeg' in _mv or 'jpeg' in _mv:
            _extra_deps.append('libjpeg-dev')
        if 'libpcre' in _mv or 'pcre' in _mv:
            _extra_deps.append('libpcre3-dev')
        if 'libyaml' in _mv:
            _extra_deps.append('libyaml-dev')
        if 'libsqlite' in _mv or 'sqlite3' in _mv:
            _extra_deps.append('libsqlite3-dev')
        if 'libexpat' in _mv:
            _extra_deps.append('libexpat1-dev')
    # Python extras: if C extensions are built, need python3-dev
    if report.runtime_family == 'python':
        _has_ext = any(k in manifests for k in ('setup.py', 'pyproject.toml'))
        if _has_ext:
            for mkey, mval in manifests.items():
                if mkey in ('setup.py', 'pyproject.toml') and mval and 'ext_modules' in mval:
                    _extra_deps.append('python3-dev')
                    break
    if _extra_deps:
        report.docker_extra_deps = sorted(set(_extra_deps))

    # Scan dependencies for known CVEs via OSV.dev (live API + cache fallback)
    try:
        from agents.cve_lookup import query_cves_for_dependencies
        _deps = _parse_dependency_versions(structure)
        # Merge Syft SBOM discoveries (vendored deps, fat JARs) before querying
        if codebase_path:
            _syft_deps = _run_syft_sbom(codebase_path)
            if _syft_deps:
                _existing = {(d['name'], d['version'], d['ecosystem']) for d in _deps}
                _deps_before = len(_deps)
                for sd in _syft_deps:
                    key = (sd['name'], sd['version'], sd['ecosystem'])
                    if key not in _existing:
                        _deps.append(sd)
                        _existing.add(key)
                logger.info('recon_agent: %d deps after Syft merge (was %d, +%d from Syft)',
                            len(_deps), _deps_before, len(_deps) - _deps_before)
        cve_matches = query_cves_for_dependencies(_deps, timeout_s=8.0)
    except Exception as _cve_exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "recon_agent: CVE lookup failed (%s) — skipping", _cve_exc
        )
        cve_matches = []
    if cve_matches:
        report.known_cve_findings = cve_matches

    # Populate new structural fields from scan
    if structure.get('entry_point_candidates'):
        report.entry_point_candidates = structure['entry_point_candidates'][:20]
    if structure.get('sample_input_files'):
        report.sample_input_files = structure['sample_input_files'][:15]
    if structure.get('input_format_hints'):
        report.input_format_hints = list(structure['input_format_hints'])
    report.has_web_surface = bool(structure.get('has_web_surface'))
    if structure.get('web_frameworks'):
        report.web_frameworks = structure['web_frameworks']

    # Set repo_surface_class from structure hints (can be overridden later
    # by the authoritative classify_repo_surface() call in agent_graph).
    if structure.get('has_web_surface'):
        _primary = report.languages[0] if report.languages else ''
        if _primary in ('python',):
            report.repo_surface_class = 'web_service_python'
        elif _primary in ('javascript', 'typescript'):
            report.repo_surface_class = 'web_service_node'
    elif structure.get('is_library'):
        _primary = report.languages[0] if report.languages else ''
        if _primary in ('c', 'cpp'):
            report.repo_surface_class = 'library_c'
        elif _primary == 'python':
            report.repo_surface_class = 'python_module'
        elif _primary in ('javascript', 'typescript'):
            report.repo_surface_class = 'node_module'

    # ── Detect database requirements from manifests ──
    _db_detections: List[Dict[str, str]] = []
    _db_env: Dict[str, str] = {}
    # Python DB drivers
    _PY_DB_MAP = {
        'psycopg2': ('postgresql', 'sqlalchemy/psycopg2', 'sqlite'),
        'psycopg': ('postgresql', 'psycopg', 'sqlite'),
        'mysqlclient': ('mysql', 'mysqlclient', 'sqlite'),
        'pymysql': ('mysql', 'pymysql', 'sqlite'),
        'mysql-connector': ('mysql', 'mysql-connector', 'sqlite'),
        'sqlalchemy': ('generic_sql', 'sqlalchemy', 'sqlite'),
        'django': ('generic_sql', 'django_orm', 'sqlite'),
        'peewee': ('generic_sql', 'peewee', 'sqlite'),
        'tortoise-orm': ('generic_sql', 'tortoise', 'sqlite'),
        'databases': ('generic_sql', 'databases', 'sqlite'),
        'asyncpg': ('postgresql', 'asyncpg', 'sqlite'),
        'aiopg': ('postgresql', 'aiopg', 'sqlite'),
        'motor': ('mongodb', 'motor', 'mongomock'),
        'pymongo': ('mongodb', 'pymongo', 'mongomock'),
        'redis': ('redis', 'redis-py', 'fakeredis'),
    }
    # Node DB drivers
    _NODE_DB_MAP = {
        'pg': ('postgresql', 'node-pg', 'sqlite3'),
        'mysql2': ('mysql', 'mysql2', 'sqlite3'),
        'mysql': ('mysql', 'mysql', 'sqlite3'),
        'sequelize': ('generic_sql', 'sequelize', 'sqlite3'),
        'typeorm': ('generic_sql', 'typeorm', 'sqlite3'),
        'prisma': ('generic_sql', 'prisma', 'sqlite3'),
        'knex': ('generic_sql', 'knex', 'sqlite3'),
        'mongoose': ('mongodb', 'mongoose', 'mongodb-memory-server'),
        'mongodb': ('mongodb', 'mongodb', 'mongodb-memory-server'),
        'ioredis': ('redis', 'ioredis', 'ioredis-mock'),
        'redis': ('redis', 'node-redis', 'ioredis-mock'),
    }
    # Java DB drivers
    _JAVA_DB_MAP = {
        'postgresql': ('postgresql', 'jdbc-postgresql', 'h2'),
        'mysql-connector-java': ('mysql', 'jdbc-mysql', 'h2'),
        'spring-boot-starter-data-jpa': ('generic_sql', 'spring-data-jpa', 'h2'),
        'hibernate': ('generic_sql', 'hibernate', 'h2'),
        'mybatis': ('generic_sql', 'mybatis', 'h2'),
        'h2': ('h2', 'h2', 'h2'),  # already lightweight
        'jedis': ('redis', 'jedis', 'embedded-redis'),
    }
    manifests = structure.get('package_manifests') or {}
    for mkey, mval in manifests.items():
        if not mval:
            continue
        _mv_lower = mval.lower()
        # Check Python manifests
        if mkey in ('requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile') or mkey.startswith('requirements'):
            for pkg, (db_type, orm, sub) in _PY_DB_MAP.items():
                if pkg in _mv_lower:
                    _db_detections.append({'db_type': db_type, 'orm': orm, 'substitute': sub})
        # Check Node manifests
        if mkey == 'package.json':
            for pkg, (db_type, orm, sub) in _NODE_DB_MAP.items():
                if f'"' + pkg + '"' in _mv_lower or f"'" + pkg + "'" in _mv_lower:
                    _db_detections.append({'db_type': db_type, 'orm': orm, 'substitute': sub})
        # Check Java manifests
        if mkey == 'pom.xml' or mkey.endswith('/pom.xml'):
            for pkg, (db_type, orm, sub) in _JAVA_DB_MAP.items():
                if pkg in _mv_lower:
                    _db_detections.append({'db_type': db_type, 'orm': orm, 'substitute': sub})

    if _db_detections:
        # Deduplicate by db_type
        seen_db = set()
        unique_dbs = []
        for d in _db_detections:
            if d['db_type'] not in seen_db:
                seen_db.add(d['db_type'])
                unique_dbs.append(d)
        report.detected_databases = unique_dbs

        # Build substitution env vars
        for d in unique_dbs:
            sub = d['substitute']
            if sub == 'sqlite':
                _db_env['DATABASE_URL'] = 'sqlite:///tmp/autopov_test.db'
                _db_env['DB_ENGINE'] = 'django.db.backends.sqlite3'
                _db_env['DB_NAME'] = '/tmp/autopov_test.db'
            elif sub == 'sqlite3':  # node
                _db_env['DATABASE_URL'] = 'sqlite:/tmp/autopov_test.db'
                _db_env['DB_NAME'] = '/tmp/autopov_test.db'
            elif sub == 'h2':  # java
                _db_env['SPRING_DATASOURCE_URL'] = 'jdbc:h2:mem:testdb'
                _db_env['SPRING_DATASOURCE_DRIVER_CLASS_NAME'] = 'org.h2.Driver'
                _db_env['SPRING_DATASOURCE_USERNAME'] = 'sa'
                _db_env['SPRING_DATASOURCE_PASSWORD'] = ''
                _db_env['DATABASE_URL'] = 'jdbc:h2:mem:testdb'
            elif sub == 'mongomock':
                _db_env['MONGO_URL'] = 'mongomock://localhost/autopov_test'
            elif sub == 'fakeredis':
                _db_env['REDIS_URL'] = 'redis://localhost:6379/0'
        if _db_env:
            report.db_substitution_env = _db_env

    # ── Git history analysis (no LLM, no network, uses local .git) ──────────
    try:
        _git_data = _analyse_git_history(codebase_path)
        if _git_data.get('high_value_files'):
            report.high_value_files = _git_data['high_value_files']
        if _git_data.get('security_commits'):
            report.security_commits = _git_data['security_commits'][:20]
        if _git_data.get('historical_vuln_types'):
            report.historical_vuln_types = _git_data['historical_vuln_types']
        if _git_data.get('repo_activity'):
            report.repo_activity = _git_data['repo_activity']
        # Store full git data in structure for LLM prompt
        structure['git_history'] = _git_data
    except Exception as _git_exc:
        logger.debug("recon_agent: git history analysis failed: %s", _git_exc)

    # ── Security docs (SECURITY.md, CHANGELOG) ──────────────────────────
    try:
        _sec_docs = _read_security_docs(codebase_path)
        if _sec_docs.get('security_policy'):
            report.security_policy = _sec_docs['security_policy']
            structure['security_policy'] = _sec_docs['security_policy']
        if _sec_docs.get('changelog_excerpt'):
            report.changelog_excerpt = _sec_docs['changelog_excerpt']
            structure['changelog_excerpt'] = _sec_docs['changelog_excerpt']
    except Exception as _docs_exc:
        logger.debug("recon_agent: security docs read failed: %s", _docs_exc)

    return report


# ---------------------------------------------------------------------------
# LLM-powered reconnaissance
# ---------------------------------------------------------------------------

_RECON_PROMPT = """You are a security researcher analyzing a software repository to plan vulnerability exploitation.

PROJECT STRUCTURE:
- Languages: {languages}
- Build system: {build_system}
- Build files: {build_files}
- Top-level directories: {top_dirs}
- Total source files: {total_files}
- Has tests: {has_tests}
- Has main() function: {has_main}
- Detected as library: {is_library}
- Web surface detected: {has_web_surface}
- Web frameworks found: {web_frameworks}

ENTRY POINT CANDIDATES (from filesystem scan):
{entry_points}

SAMPLE INPUT FILES (from test/fixture dirs):
{sample_inputs}

INPUT FORMAT HINTS: {format_hints}

GIT HISTORY INTELLIGENCE:
- Security-related commits found: {security_commit_count}
- Historical vulnerability types: {historical_vuln_types}
- Repository activity: {repo_activity}

HIGH-VALUE FILES (from git security commits):
{high_value_files}

SECURITY DOCUMENTATION:
{security_policy_excerpt}
{changelog_excerpt}

PACKAGE MANIFESTS (first 2KB each):
{manifests}

TASK:
Analyze this project and determine:
1. What TYPE of project is this? (cli_tool, library, web_app, api_server, parser, framework, daemon, plugin, unknown)
2. What are its ATTACK SURFACES? (How does it receive input: files, stdin, HTTP requests, function calls, IPC, etc.)
3. What PROOF STRATEGIES would work for different vulnerability types in this project?
4. What additional Docker DEPENDENCIES would be needed to build and run it?
5. What are the likely BINARY names or entry points after building?
6. What FRAMEWORKS or libraries does it use that inform exploitation strategy?
7. Refine the ENTRY POINTS list: which functions/binaries are most exploitable?

Respond with ONLY this JSON:
{{
  "project_type": "cli_tool | library | web_app | api_server | parser | framework | daemon | plugin | unknown",
  "attack_surfaces": [
    {{"type": "file_input | stdin | http_request | function_call | ipc | network_socket | env_var | cli_args", "format": "what format", "entry": "entry function or route"}}
  ],
  "proof_strategies": {{
    "memory_corruption": {{"proof_type": "crash_signal", "harness_type": "subprocess_binary | compiled_harness | function_harness", "observable_evidence": ["exact strings"]}},
    "injection": {{"proof_type": "exception | behavioral_deviation | observable_output", "harness_type": "...", "observable_evidence": ["..."]}},
    "logic_bug": {{"proof_type": "behavioral_deviation | state_change", "harness_type": "...", "observable_evidence": ["..."]}}
  }},
  "docker_extra_deps": ["apt packages needed beyond base image"],
  "binary_candidates": ["expected binary names after build"],
  "entrypoints": [{{"name": "func_or_binary", "type": "function | binary | route | class", "file": "path", "how_to_invoke": "brief description"}}],
  "framework_hints": ["notable frameworks or libraries detected"],
  "default_proof_type": "crash_signal | exception | behavioral_deviation | observable_output",
  "default_harness_type": "subprocess_binary | direct_import | compiled_harness | http_request"
}}
"""


def run_recon(
    codebase_path: str,
    model_name: Optional[str] = None,
    api_key_override: Optional[str] = None,
    repo_url: Optional[str] = None,
) -> ReconReport:
    """Run reconnaissance on a codebase and return a ReconReport.
    
    This is the main entry point called by the agent graph.
    It combines deterministic filesystem scanning with LLM analysis.
    """
    # Step 1: Deterministic filesystem scan
    structure = _scan_project_structure(codebase_path)

    # Step 2: Infer defaults from structure (fast, no LLM)
    report = _infer_defaults_from_structure(structure, codebase_path)

    # Step 3: LLM-enhanced analysis (if model available)
    try:
        llm_report = _run_llm_recon(structure, report, model_name, api_key_override)
        if llm_report:
            report = _merge_llm_report(report, llm_report)
    except Exception as exc:
        logger.warning("recon_agent: LLM analysis failed (%s), using filesystem defaults", exc)

    # Step 4: GitHub / GitLab security API queries (only when repo_url provided)
    if repo_url:
        try:
            _gh_findings = _query_github_security(repo_url)
            if _gh_findings:
                _existing_cves = {f.get('cve', '') for f in report.known_cve_findings}
                for _ghf in _gh_findings:
                    if _ghf.get('cve') and _ghf['cve'] not in _existing_cves:
                        report.known_cve_findings.append(_ghf)
                        _existing_cves.add(_ghf['cve'])
                report.github_security_findings = _gh_findings
                logger.info(
                    "run_recon: added %d GitHub security findings", len(_gh_findings))
        except Exception as _gh_exc:
            logger.debug("run_recon: GitHub query failed: %s", _gh_exc)

    logger.info(
        "recon_agent: project_type=%s, runtime=%s, default_proof=%s, surfaces=%d",
        report.project_type, report.runtime_family, report.default_proof_type,
        len(report.attack_surfaces),
    )
    return report


def _run_llm_recon(
    structure: Dict[str, Any],
    baseline: ReconReport,
    model_name: Optional[str] = None,
    api_key_override: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Call the LLM to analyze the project structure."""
    from agents.investigator import get_investigator
    from langchain_core.messages import HumanMessage, SystemMessage

    investigator = get_investigator()
    llm = investigator._get_llm(model_name=model_name, api_key_override=api_key_override)

    # Format manifests for prompt
    manifests_text = ""
    for fname, content in (structure.get('package_manifests') or {}).items():
        manifests_text += f"\n--- {fname} ---\n{content[:1500]}\n"
    if not manifests_text:
        manifests_text = "(no package manifests found)"

    # Format build files
    build_files_text = json.dumps(structure.get('build_files', []), indent=2)

    # Format entry point candidates
    _ep_list = structure.get('entry_point_candidates', [])
    entry_points_text = json.dumps(_ep_list[:10], indent=2) if _ep_list else '(none detected)'

    # Format sample inputs
    _sample_list = structure.get('sample_input_files', [])
    sample_inputs_text = ', '.join(_sample_list[:10]) if _sample_list else '(none found)'

    # Format git intelligence for prompt
    _git_data = structure.get('git_history') or {}
    _hv_files = _git_data.get('high_value_files') or []
    _hv_text = '\n'.join(
        f"  {hv['file']} ({hv['security_commit_count']} security commits, "
        f"last: {hv['last_security_commit']})"
        for hv in _hv_files[:10]
    ) or '(none identified)'
    _activity = _git_data.get('repo_activity') or {}
    _activity_text = (
        f"last commit {_activity.get('last_commit_date', 'unknown')}, "
        f"active={_activity.get('is_active', 'unknown')}, "
        f"total commits={_activity.get('total_commits', 'unknown')}"
    ) if _activity else '(git history not available)'
    _sec_policy = (structure.get('security_policy') or '')[:800]
    _changelog = (structure.get('changelog_excerpt') or '')[:800]

    prompt = _RECON_PROMPT.format(
        languages=json.dumps(structure.get('language_counts', {})),
        build_system=baseline.build_system,
        build_files=build_files_text,
        top_dirs=json.dumps(structure.get('top_level_dirs', [])),
        total_files=structure.get('total_files', 0),
        has_tests=structure.get('has_tests', False),
        has_main=structure.get('has_main_function', False),
        is_library=structure.get('is_library', False),
        has_web_surface=structure.get('has_web_surface', False),
        web_frameworks=json.dumps(structure.get('web_frameworks', [])),
        entry_points=entry_points_text,
        sample_inputs=sample_inputs_text,
        format_hints=json.dumps(structure.get('input_format_hints', [])),
        security_commit_count=len(_git_data.get('security_commits') or []),
        historical_vuln_types=json.dumps(
            _git_data.get('historical_vuln_types') or []),
        repo_activity=_activity_text,
        high_value_files=_hv_text,
        security_policy_excerpt=_sec_policy or '(no SECURITY.md found)',
        changelog_excerpt=_changelog or '(no CHANGELOG found)',
        manifests=manifests_text,
    )

    messages = [
        SystemMessage(content="You are a security researcher performing reconnaissance on a target repository."),
        HumanMessage(content=prompt),
    ]

    response = llm.invoke(messages)
    content = response.content if hasattr(response, 'content') else str(response)

    # Parse JSON from response
    clean = content.strip()
    if '```json' in clean:
        clean = clean.split('```json')[-1].split('```')[0].strip()
    elif '```' in clean:
        clean = clean.split('```')[1].split('```')[0].strip()

    # Try to parse, with brace-closing recovery
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        opens = clean.count('{') - clean.count('}')
        if opens > 0:
            clean += '}' * opens
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            logger.warning("recon_agent: could not parse LLM response as JSON")
            return None


def _merge_llm_report(baseline: ReconReport, llm_data: Dict[str, Any]) -> ReconReport:
    """Merge LLM-produced data into the baseline filesystem report."""
    if not llm_data or not isinstance(llm_data, dict):
        return baseline

    # Project type
    if llm_data.get('project_type') and llm_data['project_type'] != 'unknown':
        baseline.project_type = llm_data['project_type']

    # Attack surfaces
    if llm_data.get('attack_surfaces'):
        baseline.attack_surfaces = llm_data['attack_surfaces']

    # Proof strategies
    if llm_data.get('proof_strategies'):
        baseline.proof_strategies = llm_data['proof_strategies']

    # Docker deps
    if llm_data.get('docker_extra_deps'):
        baseline.docker_extra_deps = llm_data['docker_extra_deps']

    # Binary candidates
    if llm_data.get('binary_candidates'):
        baseline.binary_candidates = llm_data['binary_candidates']

    # Entrypoints
    if llm_data.get('entrypoints'):
        baseline.entrypoints = llm_data['entrypoints']

    # Framework hints
    if llm_data.get('framework_hints'):
        baseline.framework_hints = llm_data['framework_hints']

    # Default proof type — accept the LLM's suggestion unconditionally.
    # The deterministic baseline already sets crash_signal for native projects;
    # if the LLM overrides it, it has contextual reasons (e.g., a logic-bug
    # category in the project).  The oracle crash fallback will still catch
    # ASan/UBSan evidence at runtime regardless of proof_type.
    _llm_proof_type = str(llm_data.get('default_proof_type') or '').strip().lower()
    if _llm_proof_type:
        baseline.default_proof_type = _llm_proof_type

    # Default harness type
    if llm_data.get('default_harness_type'):
        baseline.default_harness_type = llm_data['default_harness_type']

    # Proof strategies — enrich with runtime-family-aware evidence defaults.
    # When the LLM provides proof_strategies but omits observable_evidence for
    # memory_corruption on native targets, inject the standard ASan/UBSan markers.
    if baseline.proof_strategies and baseline.runtime_family == 'native':
        mem_strat = baseline.proof_strategies.get('memory_corruption')
        if mem_strat and not mem_strat.get('observable_evidence'):
            mem_strat['observable_evidence'] = [
                'AddressSanitizer', 'UndefinedBehaviorSanitizer',
                'heap-buffer-overflow', 'stack-buffer-overflow',
                'use-after-free', 'SEGV', 'SIGABRT',
            ]

    return baseline


# ---------------------------------------------------------------------------
# Module-level accessor
# ---------------------------------------------------------------------------

_recon_agent_instance = None


def get_recon_agent():
    """Singleton accessor (for consistency with other agents)."""
    global _recon_agent_instance
    if _recon_agent_instance is None:
        _recon_agent_instance = ReconAgent()
    return _recon_agent_instance


class ReconAgent:
    """Wrapper class for the recon agent (stateless)."""

    def run(
        self,
        codebase_path: str,
        model_name: Optional[str] = None,
        api_key_override: Optional[str] = None,
    ) -> ReconReport:
        return run_recon(codebase_path, model_name, api_key_override)


# ---------------------------------------------------------------------------
# Repository surface classification
# ---------------------------------------------------------------------------

def classify_repo_surface(codebase_path: str) -> str:
    """Classify the repo into a surface class for downstream routing.

    Returns one of:
      'cli_tool_c'         - C/C++ repo with a main() function (has a CLI binary)
      'library_c'          - C/C++ repo without main() at top level (pure library)
      'library_c_with_cli' - C/C++ library with main() only in wrapper/test dirs
      'cli_tool_go'        - Go module repo
      'python_module'      - Python package without web framework imports
      'web_service_python' - Python package with flask/django/aiohttp/etc.
      'node_module'        - Node.js package without HTTP framework dep
      'web_service_node'   - Node.js package with express/fastify/koa/etc.
      'unknown'            - could not determine
    """
    import re as _re
    import os as _os
    from pathlib import Path as _Path

    cb = _Path(codebase_path)
    if not cb.is_dir():
        return 'unknown'

    # -- Go --
    if (cb / 'go.mod').is_file():
        return 'cli_tool_go'

    # -- Node.js --
    pkg_json = cb / 'package.json'
    if pkg_json.is_file():
        try:
            pkg = json.loads(pkg_json.read_text(encoding='utf-8', errors='ignore'))
            all_deps = set()
            for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                all_deps.update(pkg.get(section, {}).keys())
            _HTTP_FRAMEWORKS = {
                'express', 'fastify', 'koa', '@hapi/hapi', 'hapi', 'restify',
                'nest', '@nestjs/core', 'sails', 'loopback', 'polka', 'micro',
                'connect',
            }
            if all_deps & _HTTP_FRAMEWORKS:
                return 'web_service_node'
            return 'node_module'
        except Exception:
            return 'node_module'

    # -- Python --
    _py_markers = ['setup.py', 'pyproject.toml', 'setup.cfg']
    if any((cb / m).is_file() for m in _py_markers):
        _WEB_IMPORTS = _re.compile(
            r'(import|from)\s+(flask|django|aiohttp|tornado|bottle|cherrypy|fastapi|starlette)'
        )
        for _root, _dirs, _files in _os.walk(str(cb)):
            _dirs[:] = [d for d in _dirs if d not in {'.git', '__pycache__', '.venv', 'venv', 'node_modules', 'dist', 'build'}]
            for _fname in _files:
                if not _fname.endswith('.py'):
                    continue
                try:
                    _content = (_Path(_root) / _fname).read_text(encoding='utf-8', errors='ignore')[:4096]
                    if _WEB_IMPORTS.search(_content):
                        return 'web_service_python'
                except OSError:
                    pass
        return 'python_module'

    # -- C/C++ --
    _C_BUILD_MARKERS = ['CMakeLists.txt', 'Makefile', 'makefile', 'configure.ac', 'configure.in', 'meson.build']
    _has_c_build = any((cb / m).is_file() for m in _C_BUILD_MARKERS)
    if not _has_c_build:
        _SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
        try:
            for _sub in cb.iterdir():
                if _sub.is_dir() and _sub.name not in _SKIP_DIRS:
                    if any((_sub / m).is_file() for m in _C_BUILD_MARKERS):
                        _has_c_build = True
                        break
        except OSError:
            pass

    if _has_c_build:
        _MAIN_RE = _re.compile(r'\bint\s+main\s*\(|(?:^|\s)main\s*\(\s*int', _re.MULTILINE)
        _main_files: list = []
        _IGNORE_DIRS = {'.git', 'CMakeFiles', '_codeql_build_dir', '.autopov-cmake-build',
                       '.autopov-probe-build', 'CompilerIdC', 'CompilerIdCXX'}
        for _root, _dirs, _files in _os.walk(str(cb)):
            _rel = _os.path.relpath(_root, str(cb))
            _depth = 0 if _rel == '.' else _rel.count(_os.sep) + 1
            if _depth > 3:
                _dirs[:] = []
                continue
            _dirs[:] = [d for d in _dirs if d not in _IGNORE_DIRS]
            for _fname in _files:
                if not (_fname.endswith('.c') or _fname.endswith('.cpp') or _fname.endswith('.cc') or _fname.endswith('.cxx')):
                    continue
                try:
                    _content = (_Path(_root) / _fname).read_text(encoding='utf-8', errors='ignore')[:8192]
                    if _MAIN_RE.search(_content):
                        _main_files.append(_os.path.relpath(_os.path.join(_root, _fname), str(cb)))
                except OSError:
                    pass

        if not _main_files:
            return 'library_c'

        _WRAPPER_DIR_PATTERNS = _re.compile(
            r'(^|[\\/])(test|tests|example|examples|sample|samples|tool|tools|'
            r'util|utils|wf|xmlwf|cmd|cli|app|bin|demo|bench|fuzz|contrib)([\\/$])', _re.IGNORECASE
        )
        _all_in_wrapper = all(_WRAPPER_DIR_PATTERNS.search(f) for f in _main_files)

        _has_lib_headers = False
        for _root2, _dirs2, _files2 in _os.walk(str(cb)):
            _rel2 = _os.path.relpath(_root2, str(cb))
            _depth2 = 0 if _rel2 == '.' else _rel2.count(_os.sep) + 1
            if _depth2 > 2:
                _dirs2[:] = []
                continue
            _dirs2[:] = [d for d in _dirs2 if d not in _IGNORE_DIRS]
            for _hf in _files2:
                if _hf.endswith('.h') and not _hf.startswith('internal'):
                    try:
                        _hcontent = (_Path(_root2) / _hf).read_text(encoding='utf-8', errors='ignore')[:4096]
                        if _re.search(r'\b(extern|XMLPARSEAPI|CJSON_PUBLIC|__declspec)\b|\w+\s+\w+\s*\([^)]*\)\s*;', _hcontent):
                            _has_lib_headers = True
                            break
                    except OSError:
                        pass
            if _has_lib_headers:
                break

        if _all_in_wrapper and _has_lib_headers:
            return 'library_c_with_cli'
        return 'cli_tool_c'

    return 'unknown'
