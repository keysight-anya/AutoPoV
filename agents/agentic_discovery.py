"""
AutoPoV Agentic Discovery Module
Implements resilient language-aware vulnerability discovery.
"""

import os
import re
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

    HIGH_RISK_LANGUAGES = {'python', 'javascript', 'typescript', 'java'}

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
        
        log(f"WARNING: No CodeQL suite found for {codeql_language}")
        return None

    def _get_semgrep_configs(self, languages: List[str]) -> List[str]:
        """Use the stable local security ruleset for the demo path.

        The Semgrep registry packs have been failing in-container, while the
        local ruleset is language-scoped and has been producing usable security
        findings. Keep this path deterministic for the demo.
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
        if lang_profile.codeql_target_language:
            mapped = self._map_to_codeql_language(lang_profile.codeql_target_language)
            if lang_profile.codeql_target_language != mapped:
                self._log(state, f'[AgenticDiscovery] CodeQL extractor mapping: detected {lang_profile.codeql_target_language} -> extractor {mapped}')
        if lang_profile.semgrep_languages:
            self._log(state, f'[AgenticDiscovery] Semgrep language coverage: {", ".join(lang_profile.semgrep_languages)}')
        if lang_profile.unsupported_languages:
            self._log(state, f'[AgenticDiscovery] Agent-only fallback languages: {", ".join(lang_profile.unsupported_languages)}')

        if lang_profile.codeql_supported and lang_profile.codeql_target_language:
            self._log(state, '[AgenticDiscovery] Step 2: Attempting CodeQL Pre-Flight')
            codeql_result = self._try_codeql(codebase_path, lang_profile.codeql_target_language, scan_id, state)
            results.append(codeql_result)

            if any(lang in self.HIGH_RISK_LANGUAGES for lang in lang_profile.codeql_languages):
                self._log(state, '[AgenticDiscovery] Step 3: Hybrid Enforcement - Running Semgrep for additional coverage')
                semgrep_result = self._run_semgrep(codebase_path, lang_profile, state)
                results.append(semgrep_result)
            elif not codeql_result.success and lang_profile.semgrep_supported:
                self._log(state, f'[AgenticDiscovery] CodeQL failed ({codeql_result.error}), escalating to Semgrep')
                semgrep_result = self._run_semgrep(codebase_path, lang_profile, state)
                results.append(semgrep_result)
        elif lang_profile.semgrep_supported:
            self._log(state, f'[AgenticDiscovery] No CodeQL coverage for detected languages, pivoting to Semgrep ({", ".join(lang_profile.semgrep_languages)})')
            semgrep_result = self._run_semgrep(codebase_path, lang_profile, state)
            results.append(semgrep_result)
        else:
            self._log(state, '[AgenticDiscovery] Detected languages are not supported by CodeQL or Semgrep')

        # Run Exploratory Agent to find what static analyzers may have missed
        # This uses LLM reasoning instead of hardcoded patterns - ALWAYS runs for CWE-agnostic discovery
        self._log(state, '[AgenticDiscovery] Running Exploratory Agent to find additional vulnerabilities')
        try:
            exploratory_result = self._run_exploratory_agent(codebase_path, lang_profile, results, state)
        except Exception as exc:
            if settings.resolve_model_mode(state.get("model_name", "")) == "offline":
                self._log(state, f'[AgenticDiscovery] Exploratory agent failed in offline mode: {exc}')
                exploratory_result = DiscoveryResult(
                    strategy=DiscoveryStrategy.LLM_SCOUT,
                    findings=[],
                    success=False,
                    error=str(exc),
                    execution_time_s=0.0,
                    metadata={'mode': 'exploratory', 'degraded': True}
                )
            else:
                raise
        if exploratory_result:
            results.append(exploratory_result)

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

    def _try_codeql(self, codebase_path: str, language: str, scan_id: str, state: Dict[str, Any]) -> DiscoveryResult:
        import time
        start_time = time.time()
        codeql_lang = self._map_to_codeql_language(language)
        suite = self._get_codeql_suite(codeql_lang, state)
        db_path = os.path.join(settings.TEMP_DIR, f'codeql_db_{scan_id}')
        result_path = os.path.join(settings.TEMP_DIR, f'codeql_results_{scan_id}_{codeql_lang}.sarif')

        try:
            self._log(state, f'[AgenticDiscovery] Creating CodeQL database for {codeql_lang}...')
            create_cmd = [
                settings.CODEQL_CLI_PATH,
                'database', 'create', db_path,
                f'--language={codeql_lang}',
                '--source-root', codebase_path,
                '--overwrite'
            ]
            create = subprocess.run(create_cmd, capture_output=True, text=True, timeout=settings.CODEQL_TIMEOUT_S)
            if create.returncode != 0:
                error_msg = (create.stderr or create.stdout or 'Unknown error')[:300]
                return DiscoveryResult(DiscoveryStrategy.CODEQL, [], False, f'Database creation failed: {error_msg}', time.time() - start_time, {'language': codeql_lang})

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
                metadata={'language': codeql_lang, 'suite': suite, 'findings_count': len(findings)}
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

        if not used_configs:
            self._log(state, '[AgenticDiscovery] All Semgrep configs failed or returned unusable output')
        return findings, (used_configs or configs)

    def _run_exploratory_agent(self, codebase_path: str, lang_profile: LanguageProfile, previous_results: List[DiscoveryResult], state: Dict[str, Any]) -> Optional[DiscoveryResult]:
        """
        Run an exploratory agent to find vulnerabilities that static analyzers may have missed.
        
        This agent uses LLM reasoning to identify:
        - Logic bugs
        - Business logic vulnerabilities
        - Race conditions
        - Authentication/authorization flaws
        - Data validation issues
        
        No hardcoded CWE patterns - evaluates each finding on exploitability.
        """
        import time
        start_time = time.time()
        
        # Gather context from previous findings to avoid duplication
        existing_findings = []
        for result in previous_results:
            if result.success:
                existing_findings.extend(result.findings)
        
        # Get primary language files for analysis
        primary_lang = lang_profile.primary
        code_files = []
        for root, dirs, files in os.walk(codebase_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'venv', '__pycache__', 'dist', 'build')]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.rb', '.php', '.cs'}:
                    filepath = os.path.join(root, fname)
                    rel_path = os.path.relpath(filepath, codebase_path)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            code = f.read(settings.SCOUT_MAX_CHARS_PER_FILE)
                        code_files.append({
                            'filepath': rel_path,
                            'language': self._detect_language_from_path(rel_path),
                            'code': code,
                        })
                    except (OSError, IOError):
                        continue
        
        if not code_files:
            self._log(state, '[AgenticDiscovery] No code files found for exploratory analysis')
            return None
        
        # Limit files to analyze (cost control)
        scout_budget = settings.get_offline_scout_budget(state.get("model_name"), purpose="exploratory") if settings.resolve_model_mode(state.get("model_name", "")) == "offline" else {"max_files": 10}
        max_files = min(scout_budget["max_files"], len(code_files))
        code_files = code_files[:max_files]
        
        self._log(state, f'[AgenticDiscovery] Exploratory agent analyzing {len(code_files)} files for missed vulnerabilities')
        
        # Use LLM scout with exploratory prompt
        from agents.llm_scout import get_llm_scout
        scout = get_llm_scout()
        
        # Create exploratory analysis snippets
        exploratory_snippets = []
        for cf in code_files:
            exploratory_snippets.append({
                'filepath': cf['filepath'],
                'language': cf['language'],
                'code': cf['code'],
                'candidate_lines': [],  # No pre-conceived notions
                'candidate_cwes': [],   # No hardcoded CWEs
            })
        
        # Run exploratory analysis (no CWE constraints)
        findings = scout.scan_snippets(exploratory_snippets, [], model_name=state.get("model_name"))  # Empty cwes = open-ended discovery
        
        # Filter out duplicates from existing findings
        existing_keys = {(f.get('filepath'), f.get('line_number')) for f in existing_findings}
        new_findings = [f for f in findings if (f.get('filepath'), f.get('line_number')) not in existing_keys]
        
        if new_findings:
            self._log(state, f'[AgenticDiscovery] Exploratory agent found {len(new_findings)} additional findings')
        else:
            self._log(state, '[AgenticDiscovery] Exploratory agent found no additional findings')
        
        return DiscoveryResult(
            strategy=DiscoveryStrategy.LLM_SCOUT,  # Reuse LLM_SCOUT enum
            findings=new_findings,
            success=True,
            error=None,
            execution_time_s=time.time() - start_time,
            metadata={'files_analyzed': len(code_files), 'findings_count': len(new_findings), 'mode': 'exploratory'}
        )

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

        findings = scout.scan_snippets(file_snippets, cwes, model_name=state.get("model_name"))
        return DiscoveryResult(DiscoveryStrategy.LLM_SCOUT, findings, True, None, time.time() - start_time, {'candidates_analyzed': len(candidates), 'findings_count': len(findings)})

    def _map_to_codeql_language(self, language: str) -> str:
        mapping = {
            'python': 'python',
            'javascript': 'javascript',
            'typescript': 'javascript',
            'java': 'java',
            'c': 'cpp',
            'cpp': 'cpp',
            'go': 'go',
            'ruby': 'ruby',
            'csharp': 'csharp',
        }
        return mapping.get(language, language)

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
