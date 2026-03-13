"""
AutoPoV Agentic Discovery Module
Implements resilient decision-tree for vulnerability discovery
"""

import os
import subprocess
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from app.config import settings
from agents.heuristic_scout import get_heuristic_scout


class DiscoveryStrategy(Enum):
    """Discovery strategies available"""
    CODEQL = "codeql"
    SEMGREP = "semgrep"
    LLM_SCOUT = "llm_scout"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"


@dataclass
class LanguageProfile:
    """Language profile for a codebase"""
    primary: str
    all_languages: List[str]
    language_stats: Dict[str, int]
    total_files: int
    codeql_supported: bool
    semgrep_supported: bool


@dataclass
class DiscoveryResult:
    """Result of discovery attempt"""
    strategy: DiscoveryStrategy
    findings: List[Dict[str, Any]]
    success: bool
    error: Optional[str]
    execution_time_s: float
    metadata: Dict[str, Any]


class AgenticDiscovery:
    """
    Agentic discovery implementing resilient decision-tree:
    
    1. Language Profiling - Analyze codebase languages
    2. CodeQL Pre-Flight - Try CodeQL, fallback on failure
    3. Hybrid Enforcement - Run both CodeQL + Semgrep for high-risk languages
    4. Cost-Benefit Triage - Use LLM scout selectively
    """
    
    # CodeQL-supported languages
    CODEQL_LANGUAGES = {
        'python', 'javascript', 'typescript', 'java', 
        'cpp', 'c', 'go', 'ruby', 'csharp'
    }
    
    # Semgrep-supported languages (broader coverage)
    SEMGREP_LANGUAGES = {
        'python', 'javascript', 'typescript', 'java', 
        'cpp', 'c', 'go', 'ruby', 'csharp', 'php',
        'swift', 'kotlin', 'scala', 'rust', 'r',
        'ocaml', 'lua', 'julia', 'bash', 'docker'
    }
    
    # High-risk languages that benefit from hybrid analysis
    HIGH_RISK_LANGUAGES = {'python', 'javascript', 'typescript', 'java'}
    
    def __init__(self):
        self.scout = get_heuristic_scout()
    
    def discover(
        self,
        codebase_path: str,
        cwes: List[str],
        scan_id: str,
        state: Dict[str, Any]
    ) -> List[DiscoveryResult]:
        """
        Main discovery entry point implementing the decision tree.
        
        Returns list of discovery results from various strategies.
        """
        import time
        start_time = time.time()
        
        results = []
        
        # Step 1: Language Profiling
        self._log(state, "[AgenticDiscovery] Step 1: Language Profiling")
        lang_profile = self._profile_languages(codebase_path)
        
        self._log(state, f"[AgenticDiscovery] Primary language: {lang_profile.primary}")
        self._log(state, f"[AgenticDiscovery] All languages: {', '.join(lang_profile.all_languages)}")
        for lang, count in sorted(lang_profile.language_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / lang_profile.total_files) * 100 if lang_profile.total_files > 0 else 0
            self._log(state, f"[AgenticDiscovery]   - {lang}: {count} files ({pct:.1f}%)")
        self._log(state, f"[AgenticDiscovery] CodeQL supported: {lang_profile.codeql_supported}")
        self._log(state, f"[AgenticDiscovery] Semgrep supported: {lang_profile.semgrep_supported}")
        
        # Step 2 & 3: Strategy Selection
        if lang_profile.codeql_supported:
            # Try CodeQL first
            self._log(state, "[AgenticDiscovery] Step 2: Attempting CodeQL Pre-Flight")
            codeql_result = self._try_codeql(codebase_path, cwes, lang_profile.primary, scan_id, state)
            results.append(codeql_result)
            
            # Step 3: Hybrid Enforcement for high-risk languages
            if lang_profile.primary in self.HIGH_RISK_LANGUAGES and codeql_result.success:
                self._log(state, "[AgenticDiscovery] Step 3: Hybrid Enforcement - Running Semgrep for additional coverage")
                semgrep_result = self._run_semgrep(codebase_path, cwes, lang_profile, scan_id, state)
                if semgrep_result.success:
                    results.append(semgrep_result)
            
            # If CodeQL failed, fallback to Semgrep
            if not codeql_result.success and lang_profile.semgrep_supported:
                self._log(state, f"[AgenticDiscovery] CodeQL failed ({codeql_result.error}), escalating to Semgrep")
                semgrep_result = self._run_semgrep(codebase_path, cwes, lang_profile, scan_id, state)
                results.append(semgrep_result)
        
        elif lang_profile.semgrep_supported:
            # Pivot to Semgrep for unsupported languages (PHP, etc.)
            self._log(state, f"[AgenticDiscovery] {lang_profile.primary} not CodeQL-supported, pivoting to Semgrep")
            semgrep_result = self._run_semgrep(codebase_path, cwes, lang_profile, scan_id, state)
            results.append(semgrep_result)
        
        else:
            # Neither CodeQL nor Semgrep supports this language
            self._log(state, f"[AgenticDiscovery] {lang_profile.primary} not supported by CodeQL or Semgrep, using heuristics")
        
        # Always run heuristic scout as baseline
        self._log(state, "[AgenticDiscovery] Running heuristic scout for baseline coverage")
        heuristic_result = self._run_heuristic(codebase_path, cwes, state)
        results.append(heuristic_result)
        
        # Step 4: Cost-Benefit Triage - LLM Scout on findings
        if settings.SCOUT_LLM_ENABLED:
            self._log(state, "[AgenticDiscovery] Step 4: Cost-Benefit Triage - Running LLM Scout on candidates")
            llm_result = self._run_llm_scout(codebase_path, cwes, results, state)
            if llm_result:
                results.append(llm_result)
        
        total_time = time.time() - start_time
        self._log(state, f"[AgenticDiscovery] Discovery completed in {total_time:.2f}s")
        
        return results
    
    def _profile_languages(self, codebase_path: str) -> LanguageProfile:
        """Analyze codebase to determine language profile"""
        extensions = {}
        
        for root, _, files in os.walk(codebase_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext:
                    extensions[ext] = extensions.get(ext, 0) + 1
        
        # Map extensions to languages
        lang_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.tsx': 'typescript', '.jsx': 'javascript', '.java': 'java',
            '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.h': 'c',
            '.go': 'go', '.rb': 'ruby', '.php': 'php', '.cs': 'csharp',
            '.swift': 'swift', '.kt': 'kotlin', '.scala': 'scala',
            '.rs': 'rust', '.r': 'r', '.lua': 'lua', '.sh': 'bash',
            '.dockerfile': 'docker'
        }
        
        lang_counts = {}
        for ext, count in extensions.items():
            lang = lang_map.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + count
        
        sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
        primary = sorted_langs[0][0] if sorted_langs else 'unknown'
        all_languages = [lang for lang, _ in sorted_langs]
        
        return LanguageProfile(
            primary=primary,
            all_languages=all_languages,
            language_stats=lang_counts,
            total_files=sum(lang_counts.values()),
            codeql_supported=primary in self.CODEQL_LANGUAGES,
            semgrep_supported=primary in self.SEMGREP_LANGUAGES
        )
    
    def _try_codeql(
        self,
        codebase_path: str,
        cwes: List[str],
        language: str,
        scan_id: str,
        state: Dict[str, Any]
    ) -> DiscoveryResult:
        """Attempt CodeQL analysis with fallback on failure"""
        import time
        start_time = time.time()
        
        # Map to CodeQL language name
        codeql_lang = self._map_to_codeql_language(language)
        
        db_path = os.path.join(settings.TEMP_DIR, f"codeql_db_{scan_id}")
        
        try:
            # Try to create CodeQL database
            self._log(state, f"[AgenticDiscovery] Creating CodeQL database for {codeql_lang}...")
            
            cmd = [
                settings.CODEQL_CLI_PATH,
                "database", "create", db_path,
                f"--language={codeql_lang}",
                "--source-root", codebase_path,
                "--overwrite"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                error_msg = result.stderr[:200] if result.stderr else "Unknown error"
                return DiscoveryResult(
                    strategy=DiscoveryStrategy.CODEQL,
                    findings=[],
                    success=False,
                    error=f"Database creation failed: {error_msg}",
                    execution_time_s=time.time() - start_time,
                    metadata={}
                )
            
            # Run queries for each CWE
            findings = []
            for cwe in cwes:
                query_path = self._get_cwe_query(cwe, codeql_lang)
                if query_path:
                    cwe_findings = self._run_codeql_query(db_path, query_path, cwe, state)
                    findings.extend(cwe_findings)
            
            # Cleanup
            import shutil
            if os.path.exists(db_path):
                shutil.rmtree(db_path, ignore_errors=True)
            
            return DiscoveryResult(
                strategy=DiscoveryStrategy.CODEQL,
                findings=findings,
                success=True,
                error=None,
                execution_time_s=time.time() - start_time,
                metadata={"language": codeql_lang, "findings_count": len(findings)}
            )
            
        except subprocess.TimeoutExpired:
            return DiscoveryResult(
                strategy=DiscoveryStrategy.CODEQL,
                findings=[],
                success=False,
                error="Database creation timeout",
                execution_time_s=time.time() - start_time,
                metadata={}
            )
        except Exception as e:
            return DiscoveryResult(
                strategy=DiscoveryStrategy.CODEQL,
                findings=[],
                success=False,
                error=str(e),
                execution_time_s=time.time() - start_time,
                metadata={}
            )
    
    def _run_semgrep(
        self,
        codebase_path: str,
        cwes: List[str],
        lang_profile: LanguageProfile,
        scan_id: str,
        state: Dict[str, Any]
    ) -> DiscoveryResult:
        """Run Semgrep analysis"""
        import time
        start_time = time.time()
        
        try:
            self._log(state, f"[AgenticDiscovery] Running Semgrep for {lang_profile.primary}...")
            
            # Map CWEs to Semgrep rules
            rules = self._map_cwes_to_semgrep_rules(cwes)
            
            if not rules:
                return DiscoveryResult(
                    strategy=DiscoveryStrategy.SEMGREP,
                    findings=[],
                    success=True,
                    error=None,
                    execution_time_s=time.time() - start_time,
                    metadata={"message": "No Semgrep rules for specified CWEs"}
                )
            
            # Run Semgrep
            cmd = [
                "semgrep",
                "--config", "p/owasp-top-ten",
                "--json",
                "--quiet",
                codebase_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            findings = []
            if result.returncode in [0, 1]:  # 1 means findings found
                import json
                try:
                    output = json.loads(result.stdout)
                    for match in output.get("results", []):
                        findings.append({
                            "filepath": match.get("path", ""),
                            "line_number": match.get("start", {}).get("line", 0),
                            "cwe_type": self._map_semgrep_to_cwe(match.get("extra", {}).get("metadata", {}).get("cwe", "")),
                            "code_chunk": match.get("extra", {}).get("lines", ""),
                            "confidence": 0.7,
                            "source": "semgrep",
                            "detected_language": lang_profile.primary
                        })
                except json.JSONDecodeError:
                    pass
            
            return DiscoveryResult(
                strategy=DiscoveryStrategy.SEMGREP,
                findings=findings,
                success=True,
                error=None,
                execution_time_s=time.time() - start_time,
                metadata={"findings_count": len(findings)}
            )
            
        except subprocess.TimeoutExpired:
            return DiscoveryResult(
                strategy=DiscoveryStrategy.SEMGREP,
                findings=[],
                success=False,
                error="Semgrep timeout",
                execution_time_s=time.time() - start_time,
                metadata={}
            )
        except FileNotFoundError:
            return DiscoveryResult(
                strategy=DiscoveryStrategy.SEMGREP,
                findings=[],
                success=False,
                error="Semgrep not installed",
                execution_time_s=time.time() - start_time,
                metadata={}
            )
        except Exception as e:
            return DiscoveryResult(
                strategy=DiscoveryStrategy.SEMGREP,
                findings=[],
                success=False,
                error=str(e),
                execution_time_s=time.time() - start_time,
                metadata={}
            )
    
    def _run_heuristic(
        self,
        codebase_path: str,
        cwes: List[str],
        state: Dict[str, Any]
    ) -> DiscoveryResult:
        """Run heuristic scout"""
        import time
        start_time = time.time()
        
        self._log(state, "[AgenticDiscovery] Running heuristic scout...")
        
        findings = self.scout.scan_directory(codebase_path, cwes)
        
        # Add source metadata
        for finding in findings:
            finding["source"] = "heuristic"
        
        return DiscoveryResult(
            strategy=DiscoveryStrategy.HEURISTIC,
            findings=findings,
            success=True,
            error=None,
            execution_time_s=time.time() - start_time,
            metadata={"findings_count": len(findings)}
        )
    
    def _run_llm_scout(
        self,
        codebase_path: str,
        cwes: List[str],
        previous_results: List[DiscoveryResult],
        state: Dict[str, Any]
    ) -> Optional[DiscoveryResult]:
        """Run LLM scout selectively based on previous findings"""
        import time
        start_time = time.time()
        
        # Collect high-confidence findings from previous results
        candidates = []
        for result in previous_results:
            if result.success:
                for finding in result.findings:
                    if finding.get("confidence", 0) >= 0.7:
                        candidates.append(finding)
        
        # Limit to top candidates to control cost
        max_candidates = 20
        if len(candidates) > max_candidates:
            candidates = candidates[:max_candidates]
        
        if not candidates:
            return None
        
        self._log(state, f"[AgenticDiscovery] Running LLM scout on {len(candidates)} candidates...")
        
        # Import here to avoid circular dependency
        from agents.llm_scout import get_llm_scout
        
        findings = get_llm_scout().analyze_candidates(candidates, cwes)
        
        return DiscoveryResult(
            strategy=DiscoveryStrategy.LLM_SCOUT,
            findings=findings,
            success=True,
            error=None,
            execution_time_s=time.time() - start_time,
            metadata={"candidates_analyzed": len(candidates), "findings_count": len(findings)}
        )
    
    def _map_to_codeql_language(self, language: str) -> str:
        """Map detected language to CodeQL language name"""
        mapping = {
            'python': 'python',
            'javascript': 'javascript',
            'typescript': 'javascript',
            'java': 'java',
            'c': 'cpp',
            'cpp': 'cpp',
            'go': 'go',
            'ruby': 'ruby',
            'csharp': 'csharp'
        }
        return mapping.get(language, language)
    
    def _get_cwe_query(self, cwe: str, language: str) -> Optional[str]:
        """Get CodeQL query path for CWE"""
        # Use existing query mapping from agent_graph
        query_map = {
            'javascript': {
                'CWE-79': 'Security/CWE-079/Xss.ql',
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-22': 'Security/CWE-022/TaintedPath.ql',
                'CWE-78': 'Security/CWE-078/CommandInjection.ql',
            },
            'python': {
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-22': 'Security/CWE-022/PathInjection.ql',
                'CWE-78': 'Security/CWE-078/CommandInjection.ql',
            },
            'java': {
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-79': 'Security/CWE-079/Xss.ql',
            }
        }
        
        lang_queries = query_map.get(language, {})
        query_file = lang_queries.get(cwe)
        
        if query_file:
            base_path = os.path.join(settings.CODEQL_PACKS_BASE, f'codeql/{language}-queries')
            full_path = os.path.join(base_path, query_file)
            if os.path.exists(full_path):
                return full_path
        
        return None
    
    def _run_codeql_query(
        self,
        db_path: str,
        query_path: str,
        cwe: str,
        state: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run a CodeQL query and parse results"""
        import json
        import os
        
        result_path = os.path.join(settings.TEMP_DIR, f"codeql_results_{cwe}.json")
        
        cmd = [
            settings.CODEQL_CLI_PATH,
            "database", "analyze",
            db_path,
            query_path,
            "--format=sarifv2.1.0",
            f"--output={result_path}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 and os.path.exists(result_path):
                with open(result_path) as f:
                    sarif = json.load(f)
                
                findings = []
                runs = sarif.get("runs", [])
                if runs:
                    for res in runs[0].get("results", []):
                        locations = res.get("locations", [])
                        if locations:
                            loc = locations[0].get("physicalLocation", {})
                            artifact = loc.get("artifactLocation", {})
                            region = loc.get("region", {})
                            
                            findings.append({
                                "filepath": artifact.get("uri", ""),
                                "line_number": region.get("startLine", 0),
                                "cwe_type": cwe,
                                "code_chunk": res.get("message", {}).get("text", ""),
                                "confidence": 0.8,
                                "source": "codeql"
                            })
                
                return findings
                
        except Exception as e:
            self._log(state, f"[AgenticDiscovery] CodeQL query error: {e}")
        
        return []
    
    def _map_cwes_to_semgrep_rules(self, cwes: List[str]) -> List[str]:
        """Map CWEs to Semgrep rule IDs"""
        # Semgrep uses OWASP rules by default
        return ["p/owasp-top-ten"]  # Use comprehensive OWASP rules
    
    def _map_semgrep_to_cwe(self, cwe_str: str) -> str:
        """Map Semgrep CWE string to our CWE format"""
        if isinstance(cwe_str, list) and cwe_str:
            cwe_str = cwe_str[0]
        
        if isinstance(cwe_str, str):
            # Extract CWE number
            import re
            match = re.search(r'CWE-?(\d+)', cwe_str)
            if match:
                return f"CWE-{match.group(1)}"
        
        return "CWE-UNKNOWN"
    
    def _log(self, state: Dict[str, Any], message: str):
        """Log message to scan state"""
        if "logs" in state:
            from datetime import datetime
            state["logs"].append(f"[{datetime.utcnow().isoformat()}] {message}")


# Global instance
agentic_discovery = AgenticDiscovery()


def get_agentic_discovery() -> AgenticDiscovery:
    """Get the global agentic discovery instance"""
    return agentic_discovery
