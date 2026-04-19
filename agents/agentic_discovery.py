"""
AutoPoV Agentic Discovery Module
Implements resilient language-aware vulnerability discovery.
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from app.config import settings


class DiscoveryStrategy(Enum):
    CODEQL = "codeql"
    SEMGREP = "semgrep"
    LLM_SCOUT = "llm_scout"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"


@dataclass
class LanguageProfile:
    primary: str
    all_languages: List[str]
    language_stats: Dict[str, int]
    total_files: int
    codeql_supported: bool
    semgrep_supported: bool
    codeql_languages: List[str]
    semgrep_languages: List[str]
    unsupported_languages: List[str]
    codeql_target_language: Optional[str]


@dataclass
class DiscoveryResult:
    strategy: DiscoveryStrategy
    findings: List[Dict[str, Any]]
    success: bool
    error: Optional[str]
    execution_time_s: float
    metadata: Dict[str, Any]


class AgenticDiscovery:
    """Language-aware static and heuristic discovery orchestration."""

    CODEQL_LANGUAGES = {
        'python', 'javascript', 'typescript', 'java', 'cpp', 'c', 'go', 'ruby', 'csharp'
    }

    SEMGREP_LANGUAGES = {
        'python', 'javascript', 'typescript', 'java', 'cpp', 'c', 'go', 'ruby', 'csharp',
        'php', 'swift', 'kotlin', 'scala', 'rust', 'r', 'ocaml', 'lua', 'julia', 'bash', 'docker'
    }

    HIGH_RISK_LANGUAGES = {'python', 'javascript', 'typescript', 'java', 'c', 'cpp'}

    LOCAL_SEMGREP_RULES = 'semgrep-rules/owasp-min.yml'

    def __init__(self):
        # Discover available CodeQL query paths at initialization
        self._codeql_query_paths = self._discover_codeql_queries()
        # Log discovered paths for debugging
        if self._codeql_query_paths:
            import logging
            for lang, paths in self._codeql_query_paths.items():
                logging.info(f"[AgenticDiscovery] Discovered CodeQL paths for {lang}: {paths}")
        else:
            import logging
            logging.warning("[AgenticDiscovery] No CodeQL query paths discovered - will use pack specifiers")

    def _discover_codeql_queries(self) -> Dict[str, List[str]]:
        """Discover available CodeQL query suite files in the environment.
        
        Priority order (for each language):
        1. .qls suite files inside the installed pack (e.g. codeql-suites/cpp-security-extended.qls)
        2. .qls files in codeql-suites/ directory inside the pack
        3. Security directory with recursive .ql files as fallback
        
        Returns a mapping of language -> best single path to pass to codeql database analyze.
        """
        import subprocess
        import glob
        paths: Dict[str, List[str]] = {}

        # Check both qlpacks (newer) and packs (older) locations
        base_dirs = [
            '/usr/local/codeql/qlpacks',  # Primary location
            '/usr/local/codeql/packs',    # Alternative location
            '/opt/codeql/qlpacks',
            '/opt/codeql/packs',
            os.path.expanduser('~/codeql/qlpacks'),
            os.path.expanduser('~/codeql/packs'),
            '/app/codeql/qlpacks',
            '/app/codeql/packs',
        ]

        for base in base_dirs:
            if not os.path.exists(base):
                continue

            # Look for codeql pack directory
            codeql_base = os.path.join(base, 'codeql')
            if not os.path.exists(codeql_base):
                continue

            for lang in self.CODEQL_LANGUAGES:
                if lang in paths:
                    continue

                lang_pack_pattern = os.path.join(codeql_base, f'{lang}-queries', '*')
                version_dirs = sorted(glob.glob(lang_pack_pattern), reverse=True)

                for version_dir in version_dirs:
                    if not os.path.isdir(version_dir):
                        continue

                    # Priority 1: Look for codeql-suites/*.qls files
                    suites_dir = os.path.join(version_dir, 'codeql-suites')
                    if os.path.exists(suites_dir):
                        # Prefer security-extended (more focused than security-and-quality)
                        # Note: cpp-security.qls doesn't exist, use security-extended
                        preferred = [
                            f'{lang}-security-extended.qls',
                            f'{lang}-security-experimental.qls',
                            f'{lang}-security-and-quality.qls',
                            f'{lang}-code-scanning.qls',
                            f'{lang}-lgtm.qls',
                        ]
                        found_suite = None
                        for suite_name in preferred:
                            suite_path = os.path.join(suites_dir, suite_name)
                            if os.path.isfile(suite_path):
                                found_suite = suite_path
                                break
                        # If none of the preferred, take any .qls
                        if not found_suite:
                            all_qls = glob.glob(os.path.join(suites_dir, '*.qls'))
                            if all_qls:
                                found_suite = sorted(all_qls)[0]
                        if found_suite:
                            paths[lang] = [found_suite]
                            break

                    # Priority 2: Security directory with .ql files (fallback)
                    security_dir = os.path.join(version_dir, 'Security')
                    if os.path.exists(security_dir) and os.path.isdir(security_dir):
                        try:
                            has_queries = any(
                                f.endswith('.ql')
                                for root, dirs, files in os.walk(security_dir)
                                for f in files
                            )
                            if has_queries:
                                paths.setdefault(lang, [security_dir])
                                break
                        except (OSError, PermissionError):
                            continue

        # Log what was found for debugging
        try:
            result = subprocess.run(
                ['codeql', 'resolve', 'qlpacks'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                import logging
                logging.info(f"[AgenticDiscovery] CodeQL qlpacks: {result.stdout[:500]}")
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return paths

    def _get_codeql_suite(self, codeql_language: str, state: Dict[str, Any] = None) -> Optional[str]:
        """Get the best available query path for a language.
        
        Priority:
        1. Discovered suite files from initialization
        2. Runtime discovery of suite files
        3. Direct path to known suite locations
        """
        import glob
        import subprocess
        
        def log(msg: str):
            if state:
                self._log(state, f"[AgenticDiscovery] {msg}")
            else:
                import logging
                logging.info(f"[AgenticDiscovery] {msg}")
        
        # First, try discovered paths from initialization
        if codeql_language in self._codeql_query_paths:
            path = self._codeql_query_paths[codeql_language][0]
            log(f"Using pre-discovered path for {codeql_language}: {path}")
            return path
        
        log(f"No pre-discovered paths for {codeql_language}, attempting runtime discovery...")
        
        # Second, try runtime discovery - check both qlpacks and packs locations
        base_dirs = [
            '/usr/local/codeql/qlpacks',
            '/usr/local/codeql/packs',
            '/opt/codeql/qlpacks',
            '/opt/codeql/packs',
        ]
        
        for base in base_dirs:
            codeql_base = os.path.join(base, 'codeql')
            if not os.path.exists(codeql_base):
                continue
            
            log(f"Checking base: {codeql_base}")
            lang_pack_pattern = os.path.join(codeql_base, f'{codeql_language}-queries', '*')
            version_dirs = sorted(glob.glob(lang_pack_pattern), reverse=True)
            
            for version_dir in version_dirs:
                if not os.path.isdir(version_dir):
                    continue
                log(f"Checking version dir: {version_dir}")
                
                # Look for codeql-suites directory
                suites_dir = os.path.join(version_dir, 'codeql-suites')
                if os.path.exists(suites_dir):
                    # Try security-extended first (most focused security suite)
                    preferred = [
                        f'{codeql_language}-security-extended.qls',
                        f'{codeql_language}-security-experimental.qls',
                        f'{codeql_language}-security-and-quality.qls',
                        f'{codeql_language}-code-scanning.qls',
                    ]
                    for suite_name in preferred:
                        suite_path = os.path.join(suites_dir, suite_name)
                        if os.path.isfile(suite_path):
                            log(f"Found suite: {suite_path}")
                            return suite_path
        
        # Last resort: try the Security directory
        for base in base_dirs:
            codeql_base = os.path.join(base, 'codeql')
            if not os.path.exists(codeql_base):
                continue
            
            lang_pack_pattern = os.path.join(codeql_base, f'{codeql_language}-queries', '*')
            version_dirs = sorted(glob.glob(lang_pack_pattern), reverse=True)
            
            for version_dir in version_dirs:
                security_dir = os.path.join(version_dir, 'Security')
                if os.path.exists(security_dir):
                    log(f"Using Security directory as fallback: {security_dir}")
                    return security_dir
        
        # Tier 2: Try pack specifiers directly — codeql resolves these from installed packs
        # even when the physical qlpack directory was not found by path-walking above.
        _PACK_SPECIFIERS = [
            f'codeql/{codeql_language}-queries:codeql-suites/{codeql_language}-security-extended.qls',
            f'codeql/{codeql_language}-queries:codeql-suites/{codeql_language}-security-and-quality.qls',
            f'codeql/{codeql_language}-queries:codeql-suites/{codeql_language}-code-scanning.qls',
        ]
        for spec in _PACK_SPECIFIERS:
            try:
                probe = subprocess.run(
                    ['codeql', 'resolve', 'queries', spec],
                    capture_output=True, text=True, timeout=10
                )
                if probe.returncode == 0:
                    log(f"Pack specifier resolved for {codeql_language}: {spec}")
                    return spec
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                pass

        # Tier 3: Local codeql_queries/<language>/ directory — always available, covers core CWEs.
        # Each language has its own subdirectory so queries are never run against a mismatched
        # database (e.g. C++ .ql files must not be passed to a Java CodeQL database).
        # To add coverage for a new language, create codeql_queries/<lang>/ with at least one .ql.
        local_queries_root = Path(__file__).resolve().parents[1] / 'codeql_queries'
        # Try exact language subdirectory first
        lang_subdir = local_queries_root / codeql_language
        if lang_subdir.is_dir() and any(lang_subdir.glob('*.ql')):
            log(f"Using local fallback queries for {codeql_language}: {lang_subdir}")
            return str(lang_subdir)
        # 'c' and 'cpp' both map to the cpp pack — try the cpp subdir as alias
        if codeql_language in ('c', 'cpp'):
            cpp_subdir = local_queries_root / 'cpp'
            if cpp_subdir.is_dir() and any(cpp_subdir.glob('*.ql')):
                log(f"Using local fallback queries (cpp) for {codeql_language}: {cpp_subdir}")
                return str(cpp_subdir)
        # No language-specific fallback available — skip rather than run wrong-language queries
        log(f"WARNING: No CodeQL suite or local fallback found for {codeql_language} — skipping CodeQL")
        return None

    def _get_semgrep_configs(self, languages: List[str]) -> List[str]:
        """Return the local security-focused ruleset.

        The local ruleset covers C/C++, Python, Java, and JavaScript/TypeScript
        with rules that surface real security sinks and dangerous patterns only.
        No code-quality, complexity, or style rules are included.
        """
        local_rule_path = Path(__file__).resolve().parents[1] / self.LOCAL_SEMGREP_RULES
        if local_rule_path.is_file():
            return [str(local_rule_path)]
        return []

    def _get_semgrep_command(self) -> List[str]:
        """Resolve a working Semgrep invocation for the current runtime."""
        sibling_semgrep = str(Path(sys.executable).with_name('semgrep'))
        if os.path.isfile(sibling_semgrep) and os.access(sibling_semgrep, os.X_OK):
            return [sibling_semgrep]
        semgrep_bin = shutil.which('semgrep')
        if semgrep_bin:
            return [semgrep_bin]
        return [sys.executable, '-m', 'semgrep']

    def discover(self, codebase_path: str, cwes: List[str], scan_id: str, state: Dict[str, Any]) -> List[DiscoveryResult]:
        import time
        start_time = time.time()
        results: List[DiscoveryResult] = []

        self._log(state, '[AgenticDiscovery] Step 1: Language Profiling')
        lang_profile = self._profile_languages(codebase_path)

        self._log(state, f'[AgenticDiscovery] Primary language: {lang_profile.primary}')
        self._log(state, f'[AgenticDiscovery] All languages: {", ".join(lang_profile.all_languages)}')
        for lang, count in sorted(lang_profile.language_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / lang_profile.total_files) * 100 if lang_profile.total_files else 0
            self._log(state, f'[AgenticDiscovery]   - {lang}: {count} files ({pct:.1f}%)')
        self._log(state, f'[AgenticDiscovery] CodeQL supported: {lang_profile.codeql_supported}')
        self._log(state, f'[AgenticDiscovery] Semgrep supported: {lang_profile.semgrep_supported}')
        if lang_profile.codeql_languages:
            self._log(state, f'[AgenticDiscovery] CodeQL language coverage: {", ".join(lang_profile.codeql_languages)}')
        if lang_profile.semgrep_languages:
            self._log(state, f'[AgenticDiscovery] Semgrep language coverage: {", ".join(lang_profile.semgrep_languages)}')
        if lang_profile.unsupported_languages:
            self._log(state, f'[AgenticDiscovery] Agent-only fallback languages: {", ".join(lang_profile.unsupported_languages)}')

        # Step 2: Run CodeQL for every detected language that has a pack installed.
        # Each language gets its own database + analysis pass so findings are not
        # silently dropped because the primary language consumed the only run slot.
        codeql_succeeded_langs: set = set()   # languages where CodeQL ran + found/returned results
        codeql_failed_langs: set = set()      # languages where CodeQL had no suite or crashed

        # Deduplicate: c and cpp both map to the 'cpp' extractor — only run once.
        seen_codeql_extractors: set = set()

        if lang_profile.codeql_supported and lang_profile.codeql_languages:
            self._log(state, '[AgenticDiscovery] Step 2: CodeQL Analysis (per language)')
            for lang in lang_profile.codeql_languages:
                codeql_lang = self._map_to_codeql_language(lang)
                if lang != codeql_lang:
                    self._log(state, f'[AgenticDiscovery] CodeQL extractor mapping: detected {lang} -> extractor {codeql_lang}')
                if codeql_lang in seen_codeql_extractors:
                    self._log(state, f'[AgenticDiscovery] Skipping {lang} (extractor {codeql_lang} already ran)')
                    if codeql_lang in codeql_succeeded_langs:
                        codeql_succeeded_langs.add(lang)  # credit the alias too
                    else:
                        codeql_failed_langs.add(lang)
                    continue
                seen_codeql_extractors.add(codeql_lang)

                codeql_result = self._try_codeql(codebase_path, lang, scan_id, state)
                results.append(codeql_result)
                if codeql_result.success:
                    codeql_succeeded_langs.add(lang)
                    codeql_succeeded_langs.add(codeql_lang)
                else:
                    codeql_failed_langs.add(lang)
                    codeql_failed_langs.add(codeql_lang)
                    self._log(state, f'[AgenticDiscovery] CodeQL failed for {lang}: {codeql_result.error}')

        # Step 3: Semgrep — run as fallback and/or supplemental.
        #   Fallback:     any language where CodeQL was not available or failed.
        #   Supplemental: always run for HIGH_RISK languages even when CodeQL succeeded,
        #                 because Semgrep catches pattern-level sinks that CodeQL queries
        #                 may not include in the installed pack.
        run_semgrep = False
        semgrep_reason = ''

        langs_needing_fallback = (
            set(lang_profile.semgrep_languages)
            - codeql_succeeded_langs
        )
        high_risk_covered_by_codeql = (
            set(self.HIGH_RISK_LANGUAGES)
            & codeql_succeeded_langs
            & set(lang_profile.semgrep_languages)
        )

        if langs_needing_fallback:
            run_semgrep = True
            semgrep_reason = f'fallback for {sorted(langs_needing_fallback)}'
        if high_risk_covered_by_codeql:
            run_semgrep = True
            extra = f'supplemental for high-risk {sorted(high_risk_covered_by_codeql)}'
            semgrep_reason = (semgrep_reason + '; ' + extra) if semgrep_reason else extra

        if not lang_profile.codeql_supported and lang_profile.semgrep_supported:
            run_semgrep = True
            semgrep_reason = f'no CodeQL coverage, pivoting to Semgrep ({sorted(lang_profile.semgrep_languages)})'

        if run_semgrep:
            self._log(state, f'[AgenticDiscovery] Step 3: Semgrep ({semgrep_reason})')
            semgrep_result = self._run_semgrep(codebase_path, lang_profile, state)
            results.append(semgrep_result)
        elif not results:
            self._log(state, '[AgenticDiscovery] Detected languages are not supported by CodeQL or Semgrep')

        # Run LLM Scout (triage mode) on CodeQL/Semgrep findings when enabled
        # Cost-Benefit Triage via LLM Scout - DISABLED by default (redundant with Investigator)
        # Set SCOUT_LLM_ENABLED=true to re-enable if needed for large codebases
        if settings.SCOUT_LLM_ENABLED:
            self._log(state, '[AgenticDiscovery] Step 4: Cost-Benefit Triage - Running LLM Scout on candidates')
            llm_result = self._run_llm_scout(codebase_path, cwes, results, state)
            if llm_result:
                results.append(llm_result)

        total_time = time.time() - start_time
        self._log(state, f'[AgenticDiscovery] Discovery completed in {total_time:.2f}s')
        return results

    def _profile_languages(self, codebase_path: str) -> LanguageProfile:
        extensions: Dict[str, int] = {}
        for root, _, files in os.walk(codebase_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext:
                    extensions[ext] = extensions.get(ext, 0) + 1

        lang_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript',
            '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.h': 'c', '.hpp': 'cpp',
            '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp', '.swift': 'swift', '.kt': 'kotlin',
            '.scala': 'scala', '.rs': 'rust', '.r': 'r', '.lua': 'lua', '.sh': 'bash', '.dockerfile': 'docker'
        }

        lang_counts: Dict[str, int] = {}
        for ext, count in extensions.items():
            lang = lang_map.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + count

        sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
        primary = sorted_langs[0][0] if sorted_langs else 'unknown'
        all_languages = [lang for lang, _ in sorted_langs]
        codeql_languages = [lang for lang in all_languages if lang in self.CODEQL_LANGUAGES]
        semgrep_languages = [lang for lang in all_languages if lang in self.SEMGREP_LANGUAGES]
        unsupported_languages = [lang for lang in all_languages if lang not in self.SEMGREP_LANGUAGES and lang not in self.CODEQL_LANGUAGES]
        codeql_target_language = next((lang for lang in all_languages if lang in self.CODEQL_LANGUAGES), None)

        return LanguageProfile(
            primary=primary,
            all_languages=all_languages,
            language_stats=lang_counts,
            total_files=sum(lang_counts.values()),
            codeql_supported=bool(codeql_languages),
            semgrep_supported=bool(semgrep_languages),
            codeql_languages=codeql_languages,
            semgrep_languages=semgrep_languages,
            unsupported_languages=unsupported_languages,
            codeql_target_language=codeql_target_language,
        )

    def _format_codeql_error(self, completed: Optional[subprocess.CompletedProcess[str]]) -> str:
        if completed is None:
            return 'Unknown error'
        return (completed.stderr or completed.stdout or 'Unknown error')[:600]

    def _build_codeql_create_cmd(self, db_path: str, codebase_path: str, codeql_lang: str, build_command: Optional[str] = None, build_wrapper_path: Optional[str] = None) -> List[str]:
        create_cmd = [
            settings.CODEQL_CLI_PATH,
            'database', 'create', db_path,
            f'--language={codeql_lang}',
            '--source-root', codebase_path,
            '--overwrite'
        ]
        if build_wrapper_path:
            create_cmd.append(f'--command=/bin/sh {shlex.quote(build_wrapper_path)}')
        elif build_command:
            create_cmd.append(f'--command=/bin/sh -lc {shlex.quote(build_command)}')
        return create_cmd

    def _write_codeql_manual_build_wrapper(self, codebase_path: str, build_command: str, scan_id: str, attempt_index: int) -> str:
        wrapper_dir = os.path.join(settings.TEMP_DIR, f'codeql_manual_build_{scan_id}')
        os.makedirs(wrapper_dir, exist_ok=True)
        wrapper_path = os.path.join(wrapper_dir, f'build_{attempt_index}.sh')
        script = "#!/bin/sh\nset -eu\ncd " + shlex.quote(codebase_path) + "\n" + build_command + "\n"
        Path(wrapper_path).write_text(script, encoding='utf-8')
        os.chmod(wrapper_path, 0o700)
        return wrapper_path

    def _load_benchmark_build_commands(self, codebase_path: str) -> List[str]:
        metadata_path = Path(codebase_path) / '.autopov-benchmark.json'
        if not metadata_path.is_file():
            return []
        try:
            payload = json.loads(metadata_path.read_text(encoding='utf-8'))
        except Exception:
            return []
        commands = payload.get('codeql_build_commands') or []
        if not isinstance(commands, list):
            return []
        return [str(command).strip() for command in commands if str(command).strip()]

    def _supports_manual_build_fallback(self, codeql_lang: str) -> bool:
        return codeql_lang in {'cpp', 'java'}

    def _write_codeql_extract_helper(self, codebase_path: str, codeql_lang: str, scan_id: str) -> str:
        helper_dir = os.path.join(settings.TEMP_DIR, f'codeql_extract_helper_{scan_id}')
        os.makedirs(helper_dir, exist_ok=True)
        helper_path = os.path.join(helper_dir, f'{codeql_lang}_extract.py')
        if codeql_lang == 'java':
            script = """#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
out_dir = root / '.autopov-codeql-classes'
out_dir.mkdir(exist_ok=True)
javac = shutil.which('javac')
if not javac:
    raise SystemExit('javac not found')
exclude_parts = {'build', 'target', '.git', 'node_modules', 'vendor', '.gradle', '.idea', 'out'}
preferred_prefixes = [
    root / 'src' / 'main' / 'java',
    root / 'src' / 'java',
    root / 'src',
]
def wanted(p: Path) -> bool:
    if any(part in exclude_parts for part in p.parts):
        return False
    return p.suffix == '.java'
all_sources = [p for p in root.rglob('*.java') if wanted(p)]
preferred = []
for prefix in preferred_prefixes:
    if prefix.exists():
        preferred.extend([p for p in prefix.rglob('*.java') if wanted(p)])
ordered = []
seen = set()
for p in preferred + all_sources:
    rp = str(p)
    if rp not in seen:
        seen.add(rp)
        ordered.append(p)
if not ordered:
    raise SystemExit('No Java source files found for fallback extraction')
jars = [str(p) for p in root.rglob('*.jar') if '.git' not in p.parts and 'node_modules' not in p.parts]
classpath = os.pathsep.join(jars) if jars else ''
base_cmd = [javac, '-proc:none', '-g', '-d', str(out_dir)]
if classpath:
    base_cmd.extend(['-classpath', classpath])
main_like = [p for p in ordered if '/src/test/' not in str(p).replace('\\','/') and '/test/' not in str(p).replace('\\','/')]
batches = [main_like or ordered, ordered]
for batch in batches:
    try:
        result = subprocess.run(base_cmd + [str(p) for p in batch], cwd=str(root), capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        result = None
    if result and result.returncode == 0:
        raise SystemExit(0)
successes = 0
for src in ordered:
    cmd = list(base_cmd) + [str(src)]
    try:
        result = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        continue
    if result.returncode == 0:
        successes += 1
raise SystemExit(0 if successes else 1)
"""
        else:
            script = """#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
build_dir = root / '.autopov-codeql-objs'
build_dir.mkdir(exist_ok=True)
cc = shutil.which('clang') or shutil.which('gcc') or shutil.which('cc')
cxx = shutil.which('clang++') or shutil.which('g++') or shutil.which('c++')
if not cc and not cxx:
    raise SystemExit('No C/C++ compiler found')
exclude_parts = {'build', 'target', '.git', 'node_modules', 'vendor', '.gradle', '.idea', '.autopov-codeql-build'}
def wanted(p: Path) -> bool:
    if any(part in exclude_parts for part in p.parts):
        return False
    return p.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}
sources = [p for p in root.rglob('*') if p.is_file() and wanted(p)]
if not sources:
    raise SystemExit('No C/C++ source files found for fallback extraction')
include_dirs = []
seen_dirs = set()
for src in sources:
    for candidate in [src.parent, root, root / 'include', root / 'src', root / 'lib']:
        if candidate.exists():
            key = str(candidate.resolve())
            if key not in seen_dirs:
                seen_dirs.add(key)
                include_dirs.append(candidate.resolve())
compiled = 0
for idx, src in enumerate(sources):
    suffix = src.suffix.lower()
    compiler = cxx if suffix in {'.cc', '.cpp', '.cxx'} else cc
    if not compiler:
        continue
    obj = build_dir / f'obj_{idx}.o'
    cmd = [compiler, '-c', str(src), '-o', str(obj), '-O0', '-g', '-w']
    if suffix in {'.cc', '.cpp', '.cxx'}:
        cmd.append('-std=c++11')
    for inc in include_dirs:
        cmd.extend(['-I', str(inc)])
    try:
        result = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        continue
    if result.returncode == 0:
        compiled += 1
raise SystemExit(0 if compiled else 1)
"""
        Path(helper_path).write_text(script, encoding='utf-8')
        os.chmod(helper_path, 0o700)
        return helper_path

    def _candidate_codeql_build_commands(self, codebase_path: str, codeql_lang: str, scan_id: str = 'scan') -> List[str]:
        if not self._supports_manual_build_fallback(codeql_lang):
            return []

        root = Path(codebase_path)
        jobs = max(2, min(4, os.cpu_count() or 2))
        build_dir = '.autopov-codeql-build'
        commands: List[str] = []

        benchmark_commands = self._load_benchmark_build_commands(codebase_path)
        for command in benchmark_commands:
            if command not in commands:
                commands.append(command)

        def add(command: str):
            command = command.strip()
            if command and command not in commands:
                commands.append(command)

        helper_path = self._write_codeql_extract_helper(codebase_path, codeql_lang, scan_id)
        add(f'python3 {shlex.quote(helper_path)} {shlex.quote(codebase_path)}')

        if codeql_lang == 'cpp':
            if (root / 'CMakeLists.txt').exists():
                add(
                    f'cmake -S . -B {shlex.quote(build_dir)} -DCMAKE_BUILD_TYPE=Debug '
                    f'&& cmake --build {shlex.quote(build_dir)} -j{jobs}'
                )
            if (root / 'meson.build').exists():
                add(
                    f'meson setup {shlex.quote(build_dir)} --buildtype=debug || meson setup {shlex.quote(build_dir)} --wipe --buildtype=debug; '
                    f'meson compile -C {shlex.quote(build_dir)}'
                )
            # autogen.sh generates ./configure — must run before trying ./configure
            if (root / 'autogen.sh').exists():
                add(f'chmod +x ./autogen.sh && ./autogen.sh && ./configure --disable-dependency-tracking && make -j{jobs}')
                add(f'chmod +x ./autogen.sh && ./autogen.sh && make -j{jobs}')
            # autoreconf for repos with configure.ac but no autogen.sh
            if (root / 'configure.ac').exists() or (root / 'configure.in').exists():
                add(f'autoreconf -fi && ./configure --disable-dependency-tracking && make -j{jobs}')
                add(f'autoreconf -fi && make -j{jobs}')
            if (root / 'configure').exists():
                add(f'chmod +x ./configure && ./configure --disable-dependency-tracking && make -j{jobs}')
                add(f'chmod +x ./configure && ./configure && make -j{jobs}')
            for makefile_name in ('Makefile', 'GNUmakefile', 'makefile'):
                if (root / makefile_name).exists():
                    add(f'make -j{jobs}')
                    break
        elif codeql_lang == 'java':
            if (root / 'mvnw').exists():
                add('chmod +x ./mvnw && ./mvnw -q -DskipTests compile')
            if (root / 'pom.xml').exists() and shutil.which('mvn'):
                add('mvn -q -DskipTests compile')
            if (root / 'gradlew').exists():
                add('chmod +x ./gradlew && ./gradlew --no-daemon compileJava classes -q')
                add('chmod +x ./gradlew && ./gradlew --no-daemon classes -q')
            if ((root / 'build.gradle').exists() or (root / 'build.gradle.kts').exists()) and shutil.which('gradle'):
                add('gradle --no-daemon compileJava classes -q')
                add('gradle --no-daemon classes -q')

        return commands

    def _create_codeql_database(self, codebase_path: str, codeql_lang: str, db_path: str, state: Dict[str, Any]) -> Dict[str, Any]:
        self._log(state, f'[AgenticDiscovery] Creating CodeQL database for {codeql_lang}...')
        autobuild_cmd = self._build_codeql_create_cmd(db_path, codebase_path, codeql_lang)
        autobuild = subprocess.run(autobuild_cmd, capture_output=True, text=True, timeout=settings.CODEQL_TIMEOUT_S)
        if autobuild.returncode == 0:
            return {'success': True, 'strategy': 'autobuild', 'error': None, 'command': None}

        autobuild_error = self._format_codeql_error(autobuild)
        self._log(state, f'[AgenticDiscovery] CodeQL autobuild failed for {codeql_lang}: {autobuild_error[:240]}')

        manual_commands = self._candidate_codeql_build_commands(codebase_path, codeql_lang, state.get('scan_id', 'scan'))
        if not manual_commands:
            return {'success': False, 'strategy': 'autobuild', 'error': autobuild_error, 'command': None}

        self._log(state, f'[AgenticDiscovery] Retrying CodeQL database creation with {len(manual_commands)} manual build fallback(s)...')
        last_error = autobuild_error
        for idx, build_command in enumerate(manual_commands, start=1):
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
            self._log(state, f'[AgenticDiscovery] Manual CodeQL build fallback {idx}/{len(manual_commands)}: {build_command}')
            wrapper_path = self._write_codeql_manual_build_wrapper(codebase_path, build_command, state.get('scan_id', 'scan'), idx)
            try:
                manual_cmd = self._build_codeql_create_cmd(
                    db_path,
                    codebase_path,
                    codeql_lang,
                    build_wrapper_path=wrapper_path,
                )
                manual = subprocess.run(manual_cmd, capture_output=True, text=True, timeout=settings.CODEQL_TIMEOUT_S)
            finally:
                try:
                    os.unlink(wrapper_path)
                except OSError:
                    pass
            if manual.returncode == 0:
                self._log(state, f'[AgenticDiscovery] Manual CodeQL build fallback succeeded with command: {build_command}')
                return {'success': True, 'strategy': 'manual', 'error': None, 'command': build_command}
            last_error = self._format_codeql_error(manual)
            self._log(state, f'[AgenticDiscovery] Manual CodeQL build fallback failed: {last_error[:240]}')

        return {'success': False, 'strategy': 'manual', 'error': last_error, 'command': manual_commands[-1]}

    def _try_codeql(self, codebase_path: str, language: str, scan_id: str, state: Dict[str, Any]) -> DiscoveryResult:
        import time
        start_time = time.time()
        codeql_lang = self._map_to_codeql_language(language)
        suite = self._get_codeql_suite(codeql_lang, state)
        db_path = os.path.join(settings.TEMP_DIR, f'codeql_db_{scan_id}')
        result_path = os.path.join(settings.TEMP_DIR, f'codeql_results_{scan_id}_{codeql_lang}.sarif')

        if not suite:
            self._log(state, f'[AgenticDiscovery] CodeQL suite selected: None (skipping CodeQL for {codeql_lang})')
            return DiscoveryResult(
                DiscoveryStrategy.CODEQL,
                [],
                False,
                f'No CodeQL suite available for {codeql_lang} — install the qlpacks or set CODEQL_SUITE_PATH',
                time.time() - start_time,
                {'language': codeql_lang}
            )

        try:
            create_result = self._create_codeql_database(codebase_path, codeql_lang, db_path, state)
            if not create_result['success']:
                return DiscoveryResult(
                    DiscoveryStrategy.CODEQL,
                    [],
                    False,
                    f"Database creation failed ({create_result['strategy']}): {create_result['error']}",
                    time.time() - start_time,
                    {'language': codeql_lang, 'build_strategy': create_result['strategy'], 'build_command': create_result.get('command')}
                )

            # Try primary suite first
            self._log(state, f'[AgenticDiscovery] CodeQL suite selected: {suite}')
            findings = self._run_codeql_analyze(db_path, suite, result_path, codeql_lang, state)
            
            # If primary suite failed and we have fallback paths, try them
            if not findings and codeql_lang in self._codeql_query_paths:
                for fallback_path in self._codeql_query_paths[codeql_lang][1:]:
                    self._log(state, f'[AgenticDiscovery] Retrying with fallback path: {fallback_path}')
                    findings = self._run_codeql_analyze(db_path, fallback_path, result_path, codeql_lang, state)
                    if findings:
                        break

            if findings:
                self._log(state, f'[AgenticDiscovery] CodeQL returned {len(findings)} findings')
            else:
                self._log(state, f'[AgenticDiscovery] CodeQL returned 0 findings; the codebase may not contain detectable vulnerabilities')

            return DiscoveryResult(
                strategy=DiscoveryStrategy.CODEQL,
                findings=findings,
                success=True,
                error=None,
                execution_time_s=time.time() - start_time,
                metadata={
                    'language': codeql_lang,
                    'suite': suite,
                    'findings_count': len(findings),
                    'build_strategy': create_result['strategy'],
                    'build_command': create_result.get('command'),
                }
            )
        except subprocess.TimeoutExpired:
            return DiscoveryResult(DiscoveryStrategy.CODEQL, [], False, 'CodeQL timeout', time.time() - start_time, {'language': codeql_lang, 'suite': suite})
        except Exception as e:
            return DiscoveryResult(DiscoveryStrategy.CODEQL, [], False, str(e), time.time() - start_time, {'language': codeql_lang, 'suite': suite})
        finally:
            import shutil
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)

    def _run_codeql_analyze(self, db_path: str, query_path: str, result_path: str, codeql_lang: str, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run CodeQL analyze with the given query path and return findings.
        
        Returns empty list if analysis fails or produces no results.
        """
        analyze_cmd = [
            settings.CODEQL_CLI_PATH,
            'database', 'analyze',
            db_path,
            query_path,
            '--format=sarifv2.1.0',
            f'--output={result_path}',
            '--threads=0'
        ]
        analyze = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=max(settings.CODEQL_QUERY_TIMEOUT_S, settings.CODEQL_TIMEOUT_S))
        
        if analyze.returncode != 0:
            error_msg = (analyze.stderr or analyze.stdout or 'Unknown error')[:200]
            self._log(state, f'[AgenticDiscovery] CodeQL analyze failed for {query_path}: {error_msg}')
            return []
        
        if not os.path.exists(result_path):
            self._log(state, f'[AgenticDiscovery] CodeQL analyze produced no SARIF file for {query_path}')
            return []
        
        try:
            return self._parse_codeql_sarif(result_path, codeql_lang)
        except Exception as e:
            self._log(state, f'[AgenticDiscovery] Failed to parse SARIF from {query_path}: {e}')
            return []

    def _parse_codeql_sarif(self, result_path: str, codeql_language: str) -> List[Dict[str, Any]]:
        with open(result_path) as f:
            sarif = json.load(f)
        findings: List[Dict[str, Any]] = []
        for run in sarif.get('runs', []):
            rules_by_id = {rule.get('id'): rule for rule in run.get('tool', {}).get('driver', {}).get('rules', [])}
            for res in run.get('results', []):
                locations = res.get('locations', [])
                if not locations:
                    continue
                loc = locations[0].get('physicalLocation', {})
                artifact = loc.get('artifactLocation', {})
                region = loc.get('region', {})
                rule_id = res.get('ruleId', '')
                rule_meta = rules_by_id.get(rule_id, {})
                findings.append({
                    'filepath': artifact.get('uri', ''),
                    'line_number': region.get('startLine', 0),
                    'cwe_type': 'UNCLASSIFIED',
                    'taxonomy_refs': [ref for ref in [self._extract_codeql_classification(rule_meta, rule_id), rule_id] if ref and ref != 'UNCLASSIFIED'],
                    'code_chunk': res.get('message', {}).get('text', ''),
                    'confidence': 0.82,
                    'source': 'codeql',
                    'detected_language': codeql_language,
                    'rule_id': rule_id,
                    'alert_message': res.get('message', {}).get('text', ''),
                })
        return findings

    def _run_semgrep(self, codebase_path: str, lang_profile: LanguageProfile, state: Dict[str, Any]) -> DiscoveryResult:
        import time
        start_time = time.time()
        covered = ', '.join(lang_profile.semgrep_languages) if lang_profile.semgrep_languages else lang_profile.primary
        configs = self._get_semgrep_configs(lang_profile.semgrep_languages)
        self._log(state, f'[AgenticDiscovery] Running Semgrep for {covered}...')
        self._log(state, f'[AgenticDiscovery] Semgrep configs selected: {", ".join(configs)}')

        try:
            findings, used_configs = self._run_semgrep_with_configs(codebase_path, configs, state)
            if findings:
                self._log(state, f'[AgenticDiscovery] Semgrep returned {len(findings)} findings across configs: {", ".join(used_configs)}')
            else:
                self._log(state, f'[AgenticDiscovery] Semgrep returned 0 findings across configs: {", ".join(used_configs)}')
            return DiscoveryResult(
                strategy=DiscoveryStrategy.SEMGREP,
                findings=findings,
                success=True,
                error=None,
                execution_time_s=time.time() - start_time,
                metadata={'findings_count': len(findings), 'configs': used_configs, 'covered_languages': lang_profile.semgrep_languages}
            )
        except subprocess.TimeoutExpired:
            return DiscoveryResult(DiscoveryStrategy.SEMGREP, [], False, 'Semgrep timeout', time.time() - start_time, {'configs': configs})
        except FileNotFoundError:
            return DiscoveryResult(DiscoveryStrategy.SEMGREP, [], False, 'Semgrep not installed', time.time() - start_time, {'configs': configs})
        except Exception as e:
            return DiscoveryResult(DiscoveryStrategy.SEMGREP, [], False, str(e), time.time() - start_time, {'configs': configs})

    def _run_semgrep_with_configs(self, codebase_path: str, configs: List[str], state: Dict[str, Any]) -> tuple[List[Dict[str, Any]], List[str]]:
        """Run Semgrep configs independently so one bad pack does not kill coverage."""
        findings: List[Dict[str, Any]] = []
        used_configs: List[str] = []
        seen: set[tuple[str, int, str]] = set()
        semgrep_cmd = self._get_semgrep_command()

        for config in configs:
            cmd = semgrep_cmd + ['--config', config, '--json', '--quiet', codebase_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.SEMGREP_TIMEOUT_S)
            except FileNotFoundError:
                self._log(state, '[AgenticDiscovery] Semgrep executable/module not available in the current runtime')
                break
            stderr = (result.stderr or '').strip()

            if result.returncode not in [0, 1]:
                detail = (stderr or result.stdout or f'return code {result.returncode}')[:400]
                self._log(state, f'[AgenticDiscovery] Semgrep config failed ({config}) [rc={result.returncode}]: {detail}')
                continue

            try:
                output = json.loads(result.stdout or '{}')
            except json.JSONDecodeError:
                self._log(state, f'[AgenticDiscovery] Semgrep config returned non-JSON output ({config}); skipping')
                continue

            used_configs.append(config)
            for match in output.get('results', []):
                key = (match.get('path', ''), match.get('start', {}).get('line', 0), match.get('check_id', ''))
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    'filepath': match.get('path', ''),
                    'line_number': match.get('start', {}).get('line', 0),
                    'cwe_type': 'UNCLASSIFIED',
                    'taxonomy_refs': [ref for ref in [self._map_semgrep_to_cwe(match.get('extra', {}).get('metadata', {}).get('cwe', '')), match.get('check_id', '')] if ref and ref != 'UNCLASSIFIED'],
                    'code_chunk': match.get('extra', {}).get('lines', ''),
                    'confidence': 0.72,
                    'source': 'semgrep',
                    'detected_language': self._detect_language_from_path(match.get('path', '')),
                    'rule_id': match.get('check_id', ''),
                    'alert_message': match.get('extra', {}).get('message', ''),
                })

        findings = self._filter_test_findings(findings)
        if not used_configs:
            self._log(state, '[AgenticDiscovery] All Semgrep configs failed or returned unusable output')
        return findings, (used_configs or configs)

    def _run_llm_scout(self, codebase_path: str, cwes: List[str], previous_results: List[DiscoveryResult], state: Dict[str, Any]) -> Optional[DiscoveryResult]:
        import time
        start_time = time.time()

        # Build candidate list from all prior tool findings with confidence >= 0.7
        candidates = []
        seen_keys = set()
        for result in previous_results:
            if result.success:
                for finding in result.findings:
                    if finding.get('confidence', 0) >= 0.7:
                        key = (finding.get('filepath', ''), finding.get('line_number', 0))
                        if key not in seen_keys:
                            seen_keys.add(key)
                            candidates.append(finding)

        max_candidates = settings.SCOUT_MAX_FILES  # Use full configured limit (default 25)
        if len(candidates) > max_candidates:
            # Sort by confidence desc before capping
            candidates = sorted(candidates, key=lambda f: f.get('confidence', 0), reverse=True)[:max_candidates]

        candidates = [c for c in candidates if not self._is_test_artifact_path(c.get('filepath', ''))]
        if not candidates:
            self._log(state, '[AgenticDiscovery] No high-confidence candidates for LLM scout; skipping')
            return None

        self._log(state, f'[AgenticDiscovery] Running LLM scout on {len(candidates)} candidate signals...')

        # Build enriched file snippets keyed to candidate findings
        from agents.llm_scout import get_llm_scout
        scout = get_llm_scout()

        # Gather unique files from candidates and read actual source
        file_snippets = []
        seen_files: set = set()
        max_chars = settings.SCOUT_MAX_CHARS_PER_FILE
        for candidate in candidates:
            rel_path = candidate.get('filepath', '')
            if not rel_path or rel_path in seen_files:
                continue
            seen_files.add(rel_path)
            abs_path = os.path.join(codebase_path, rel_path) if not os.path.isabs(rel_path) else rel_path
            if not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read(max_chars)
                file_snippets.append({
                    'filepath': rel_path,
                    'language': candidate.get('detected_language', 'unknown'),
                    'code': code,
                    'candidate_lines': [c.get('line_number') for c in candidates if c.get('filepath') == rel_path],
                    'candidate_cwes': [c.get('cwe_type') for c in candidates if c.get('filepath') == rel_path],
                })
            except (OSError, IOError):
                continue

        if not file_snippets:
            return None

        findings = self._filter_test_findings(scout.scan_snippets(file_snippets, cwes, model_name=state.get("model_name")))
        return DiscoveryResult(DiscoveryStrategy.LLM_SCOUT, findings, True, None, time.time() - start_time, {'candidates_analyzed': len(candidates), 'findings_count': len(findings)})

    def _is_test_artifact_path(self, filepath: str) -> bool:
        lowered = str(filepath or '').replace('\\', '/').lower()
        markers = [
            '/src/test/',
            '/tests/',
            '/test/',
            '/__tests__/',
            '/spec/',
            '/specs/',
            'test_',
            '_test.',
            '.spec.',
            '.test.',
        ]
        return any(marker in lowered for marker in markers)

    def _filter_test_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []
        for finding in findings:
            filepath = finding.get('filepath', '')
            if self._is_test_artifact_path(filepath):
                continue
            filtered.append(finding)
        return filtered

    def _map_to_codeql_language(self, language: str) -> str:
        mapping = {
            'python':     'python',
            'javascript': 'javascript',
            'typescript': 'javascript',  # CodeQL uses the javascript pack for TypeScript
            'java':       'java',
            'kotlin':     'java',        # CodeQL kotlin support uses the java database
            'c':          'cpp',
            'cpp':        'cpp',
            'c++':        'cpp',
            'go':         'go',
            'golang':     'go',
            'ruby':       'ruby',
            'csharp':     'csharp',
            'c#':         'csharp',
            'swift':      'swift',       # CodeQL 2.12+ supports Swift
        }
        return mapping.get(language.lower(), language.lower())

    def _extract_codeql_classification(self, rule_meta: Dict[str, Any], rule_id: str) -> str:
        """Extract CWE classification from CodeQL rule metadata."""
        tags = rule_meta.get('properties', {}).get('tags', []) or rule_meta.get('tags', []) or []
        for tag in tags:
            match = re.search(r'CWE-?(\d+)', str(tag), re.IGNORECASE)
            if match:
                return f'CWE-{match.group(1)}'
        match = re.search(r'CWE-?(\d+)', rule_id or '', re.IGNORECASE)
        if match:
            return f'CWE-{match.group(1)}'
        return 'UNCLASSIFIED'

    def _detect_language_from_path(self, filepath: str) -> str:
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript',
            '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.h': 'c', '.hpp': 'cpp',
            '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp'
        }
        return lang_map.get(ext, 'unknown')

    def _map_semgrep_to_cwe(self, cwe_str: str) -> str:
        if isinstance(cwe_str, list) and cwe_str:
            cwe_str = cwe_str[0]
        if isinstance(cwe_str, str):
            match = re.search(r'CWE-?(\d+)', cwe_str)
            if match:
                return f'CWE-{match.group(1)}'
        return 'UNCLASSIFIED'

    def _log(self, state: Dict[str, Any], message: str):
        if 'logs' in state:
            from datetime import datetime
            entry = f'[{datetime.utcnow().isoformat()}] {message}'
            state['logs'].append(entry)
            try:
                from app.scan_manager import get_scan_manager
                get_scan_manager().append_log(state.get('scan_id'), entry)
            except Exception:
                pass


agentic_discovery = AgenticDiscovery()


def get_agentic_discovery() -> AgenticDiscovery:
    return agentic_discovery
