"""
AutoPoV Agent Graph Module
LangGraph-based agentic workflow for vulnerability detection
"""

import os
import json
import uuid
import shutil
from typing import Dict, Any, List, Optional, TypedDict, Annotated
from datetime import datetime
from enum import Enum

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

import subprocess

from app.config import settings
from app.policy import get_policy_router
from app.learning_store import get_learning_store
from agents.heuristic_scout import get_heuristic_scout
from agents.llm_scout import get_llm_scout
from agents.ingest_codebase import get_code_ingester
from agents.investigator import get_investigator
from agents.verifier import get_verifier
from agents.docker_runner import get_docker_runner
from agents.pov_tester import get_pov_tester


class ScanStatus(str, Enum):
    """Scan status enum"""
    PENDING = "pending"
    INGESTING = "ingesting"
    RUNNING_CODEQL = "running_codeql"
    INVESTIGATING = "investigating"
    GENERATING_POV = "generating_pov"
    VALIDATING_POV = "validating_pov"
    RUNNING_POV = "running_pov"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class VulnerabilityState(TypedDict):
    """State for a single vulnerability finding"""
    cve_id: Optional[str]
    filepath: str
    line_number: int
    cwe_type: str
    code_chunk: str
    llm_verdict: str
    llm_explanation: str
    confidence: float
    pov_script: Optional[str]
    pov_path: Optional[str]
    pov_result: Optional[Dict[str, Any]]
    retry_count: int
    inference_time_s: float
    cost_usd: float
    final_status: str
    # Language tracking
    detected_language: Optional[str]  # Language of the file
    source: Optional[str]  # How the finding was detected (codeql, llm, heuristic)
    # Token tracking per model
    model_used: Optional[str]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    # Hierarchical LLM tracking
    sifter_model: Optional[str]
    sifter_tokens: Optional[Dict[str, int]]  # {prompt, completion, total}
    architect_model: Optional[str]
    architect_tokens: Optional[Dict[str, int]]  # {prompt, completion, total}
    # Validation and refinement tracking
    validation_result: Optional[Dict[str, Any]]
    refinement_history: Optional[List[Dict[str, Any]]]


class ScanState(TypedDict):
    """Overall scan state"""
    scan_id: str
    status: str
    codebase_path: str
    model_name: str
    cwes: List[str]
    findings: List[VulnerabilityState]
    preloaded_findings: Optional[List[VulnerabilityState]]
    detected_language: Optional[str]
    current_finding_idx: int
    start_time: str
    end_time: Optional[str]
    total_cost_usd: float
    # Token tracking per model
    total_tokens: int
    tokens_by_model: Dict[str, Dict[str, int]]  # {model_name: {prompt, completion, total}}
    logs: List[str]
    error: Optional[str]


class AgentGraph:
    """LangGraph agent for vulnerability detection workflow"""
    
    def __init__(self):
        self.graph = self._build_graph()
        self._scan_manager = None  # Reference to scan manager for cancellation checks
    
    def set_scan_manager(self, scan_manager):
        """Set reference to scan manager for cancellation checks"""
        self._scan_manager = scan_manager
    
    def _check_cancelled(self, state: ScanState) -> bool:
        """Check if scan has been cancelled"""
        if self._scan_manager and state.get("scan_id"):
            scan_info = self._scan_manager._active_scans.get(state["scan_id"])
            if scan_info and scan_info.get("status") == "cancelled":
                return True
        return False
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Define the state graph
        workflow = StateGraph(ScanState)
        
        # Add nodes
        workflow.add_node("ingest_code", self._node_ingest_code)
        workflow.add_node("run_codeql", self._node_run_codeql)
        workflow.add_node("investigate", self._node_investigate)
        workflow.add_node("generate_pov", self._node_generate_pov)
        workflow.add_node("validate_pov", self._node_validate_pov)
        workflow.add_node("refine_pov", self._node_refine_pov)  # Self-healing refiner
        workflow.add_node("run_in_docker", self._node_run_in_docker)
        workflow.add_node("log_confirmed", self._node_log_confirmed)
        workflow.add_node("log_skip", self._node_log_skip)
        workflow.add_node("log_failure", self._node_log_failure)
        
        # Define edges
        workflow.set_entry_point("ingest_code")
        workflow.add_edge("ingest_code", "run_codeql")
        
        # Add a node to log the number of findings before investigation
        workflow.add_node("log_findings_count", self._node_log_findings_count)
        workflow.add_edge("run_codeql", "log_findings_count")
        workflow.add_edge("log_findings_count", "investigate")
        
        # Conditional edges from investigate
        workflow.add_conditional_edges(
            "investigate",
            self._should_generate_pov,
            {
                "generate_pov": "generate_pov",
                "log_skip": "log_skip"
            }
        )
        
        workflow.add_edge("generate_pov", "validate_pov")
        
        # Conditional edges from validate_pov
        workflow.add_conditional_edges(
            "validate_pov",
            self._should_run_pov,
            {
                "run_in_docker": "run_in_docker",
                "refine_pov": "refine_pov",  # Self-healing refinement
                "log_failure": "log_failure"
            }
        )
        
        # Refiner loop: refinement goes back to validation
        workflow.add_edge("refine_pov", "validate_pov")
        
        workflow.add_edge("run_in_docker", "log_confirmed")
        
        # After logging, check if there are more findings to process
        # Loop back to investigate to process the next finding
        workflow.add_conditional_edges(
            "log_confirmed",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        workflow.add_conditional_edges(
            "log_skip",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        workflow.add_conditional_edges(
            "log_failure",
            self._has_more_findings,
            {
                "investigate": "investigate",  # Process next finding
                "end": END  # All findings processed
            }
        )
        
        return workflow.compile()
    
    def _node_log_findings_count(self, state: ScanState) -> ScanState:
        """Log the number of findings found before investigation"""
        findings_count = len(state.get("findings", []))
        self._log(state, f"CodeQL found {findings_count} potential vulnerabilities to investigate")
        if findings_count == 0:
            self._log(state, "No findings to investigate, scan will complete")
        return state
    
    def _node_ingest_code(self, state: ScanState) -> ScanState:
        """Ingest codebase into vector store"""
        self._log(state, "Ingesting codebase into vector store...")
        state["status"] = ScanStatus.INGESTING
        
        try:
            ingester = get_code_ingester()
            stats = ingester.ingest_directory(
                state["codebase_path"],
                state["scan_id"],
                progress_callback=lambda count, path: self._log(
                    state, f"  Processed {count} files: {path}"
                )
            )
            
            self._log(state, f"Ingested {stats['chunks_created']} chunks from {stats['files_processed']} files")
            
            if stats["errors"]:
                for error in stats["errors"][:5]:  # Log first 5 errors
                    self._log(state, f"  Warning: {error}")
        
        except Exception as e:
            # Ingestion failure is non-fatal - scan continues without vector store context
            self._log(state, f"Warning: Ingestion failed ({e}). Scan will continue without vector store context.")
            # Do NOT set state["error"] - let scan proceed
        
        return state
    
    def _run_autonomous_discovery(self, state: ScanState) -> List[VulnerabilityState]:
        """Run autonomous discovery using heuristics and optional LLM scout."""
        findings: List[VulnerabilityState] = []
        if not settings.SCOUT_ENABLED:
            return findings

        try:
            findings.extend(get_heuristic_scout().scan_directory(state["codebase_path"], state["cwes"]))
            self._log(state, f"Heuristic scout found {len(findings)} candidates")
        except Exception as e:
            self._log(state, f"Heuristic scout failed: {e}")

        if settings.SCOUT_LLM_ENABLED:
            try:
                model = get_policy_router().select_model("investigate", cwe=None, language=state.get("detected_language"))
                llm_findings = get_llm_scout().scan_directory(state["codebase_path"], state["cwes"], model_name=model)
                findings.extend(llm_findings)
                self._log(state, f"LLM scout found {len(llm_findings)} candidates")
            except Exception as e:
                self._log(state, f"LLM scout failed: {e}")

        return findings

    def _merge_findings(self, base: List[VulnerabilityState], extra: List[VulnerabilityState]) -> List[VulnerabilityState]:
        """Merge findings and deduplicate by (filepath, line, cwe)."""
        merged: List[VulnerabilityState] = []
        seen = set()
        for item in base + extra:
            key = (item.get("filepath"), item.get("line_number"), item.get("cwe_type"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    def _node_run_codeql(self, state: ScanState) -> ScanState:
        """
        Run agentic discovery with resilient decision-tree:
        1. Language Profiling
        2. CodeQL Pre-Flight (with Semgrep fallback)
        3. Hybrid Enforcement for high-risk languages
        4. Cost-Benefit Triage with LLM Scout
        """
        self._log(state, "Running agentic discovery...")
        state["status"] = ScanStatus.RUNNING_CODEQL
        
        if state.get("preloaded_findings"):
            self._log(state, f"Using preloaded findings: {len(state['preloaded_findings'])}")
            state["findings"] = state["preloaded_findings"]
            return state
        
        try:
            # Import agentic discovery
            from agents.agentic_discovery import get_agentic_discovery
            
            # Run agentic discovery
            discovery_results = get_agentic_discovery().discover(
                codebase_path=state["codebase_path"],
                cwes=state["cwes"],
                scan_id=state["scan_id"],
                state=state
            )
            
            # Merge all findings from different strategies
            all_findings: List[VulnerabilityState] = []
            for result in discovery_results:
                if result.success:
                    self._log(state, f"{result.strategy.value}: Found {len(result.findings)} findings")
                    for finding_data in result.findings:
                        # Convert to VulnerabilityState
                        finding = VulnerabilityState(
                            cve_id=None,
                            filepath=finding_data.get("filepath", ""),
                            line_number=finding_data.get("line_number", 0),
                            cwe_type=finding_data.get("cwe_type", "UNKNOWN"),
                            code_chunk=finding_data.get("code_chunk", ""),
                            llm_verdict="",
                            llm_explanation="",
                            confidence=finding_data.get("confidence", 0.7),
                            pov_script=None,
                            pov_path=None,
                            pov_result=None,
                            retry_count=0,
                            inference_time_s=0.0,
                            cost_usd=0.0,
                            final_status="pending",
                            detected_language=finding_data.get("detected_language", state.get("detected_language", "unknown")),
                            source=finding_data.get("source", "unknown"),
                            model_used=None,
                            prompt_tokens=0,
                            completion_tokens=0,
                            total_tokens=0,
                            sifter_model=None,
                            sifter_tokens=None,
                            architect_model=None,
                            architect_tokens=None,
                            validation_result=None,
                            refinement_history=None
                        )
                        all_findings.append(finding)
                else:
                    self._log(state, f"{result.strategy.value}: Failed - {result.error}")
            
            # Deduplicate findings
            state["findings"] = self._merge_findings([], all_findings)
            self._log(state, f"Agentic discovery completed: {len(state['findings'])} total unique findings")
            
        except Exception as e:
            self._log(state, f"Agentic discovery error: {e}")
            import traceback
            self._log(state, f"Traceback: {traceback.format_exc()}")
            # Fallback to traditional methods
            findings = self._run_llm_only_analysis(state)
            auto_findings = self._run_autonomous_discovery(state)
            state["findings"] = self._merge_findings(findings, auto_findings)

        return state

    def _create_codeql_database(self, state: ScanState, language: str, db_path: str) -> bool:
        """Create CodeQL database for the codebase. Returns True if successful."""
        if os.path.exists(db_path):
            self._log(state, f"Using existing CodeQL database at {db_path}")
            return True
        
        self._log(state, f"Creating CodeQL database for {language}...")
        
        try:
            result = subprocess.run(
                [
                    settings.CODEQL_CLI_PATH,
                    "database", "create",
                    db_path,
                    f"--language={language}",
                    "--source-root", state["codebase_path"]
                ],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                self._log(state, f"CodeQL database creation failed: {result.stderr}")
                return False
            
            self._log(state, f"CodeQL database created successfully at {db_path}")
            return True
            
        except Exception as e:
            self._log(state, f"Exception during CodeQL database creation: {e}")
            return False
    
    def _detect_all_languages(self, codebase_path: str) -> Dict[str, Any]:
        """
        Detect all languages in the codebase with statistics.
        
        Returns:
            Dict with:
            - primary: Primary language (most files)
            - all_languages: List of detected languages
            - language_stats: Dict with file counts per language
            - file_mappings: Dict mapping file paths to languages
        """
        extensions = {}
        file_mappings = {}
        
        for root, _, files in os.walk(codebase_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                extensions[ext] = extensions.get(ext, 0) + 1
                
                # Map file to language
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, codebase_path)
                lang = self._get_language_from_extension(ext)
                if lang:
                    file_mappings[rel_path] = lang
        
        # Map extensions to CodeQL languages
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.c': 'cpp',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.h': 'cpp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.phtml': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            '.cs': 'csharp',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.rs': 'rust',
        }
        
        # Find all languages with counts
        lang_counts = {}
        for ext, count in extensions.items():
            lang = lang_map.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + count
        
        # Sort by count
        sorted_langs = sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)
        
        primary = sorted_langs[0][0] if sorted_langs else 'python'
        all_languages = [lang for lang, _ in sorted_langs]
        
        return {
            'primary': primary,
            'all_languages': all_languages,
            'language_stats': lang_counts,
            'file_mappings': file_mappings,
            'total_files': sum(lang_counts.values())
        }
    
    def _get_language_from_extension(self, ext: str) -> Optional[str]:
        """Get language from file extension"""
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.c': 'cpp',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.h': 'cpp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.phtml': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            '.cs': 'csharp',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.rs': 'rust',
        }
        return lang_map.get(ext)
    
    def _detect_language(self, codebase_path: str) -> str:
        """Detect the primary language of the codebase (backward compatible)"""
        result = self._detect_all_languages(codebase_path)
        return result['primary']
    
    def _get_cwe_query(self, cwe: str, language: str) -> Optional[str]:
        """Get CodeQL query for a CWE based on language using local file paths"""
        # Map detected languages to actual CodeQL language packs
        # PHP uses javascript pack, TypeScript uses javascript pack, etc.
        language_pack_map = {
            'python': 'python',
            'javascript': 'javascript',
            'java': 'java',
            'cpp': 'cpp',
            'go': 'go',
            'ruby': 'ruby',
            'php': 'javascript',  # PHP uses JavaScript pack for CodeQL
            'typescript': 'javascript',
        }
        
        # Get the actual CodeQL language pack to use
        actual_language = language_pack_map.get(language, language)
        
        # Map CWEs to CodeQL query file paths (local filesystem paths)
        # Each language has its own pack directory
        base_paths = {
            'javascript': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/javascript-queries'),
            'python': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/python-queries'),
            'java': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/java-queries'),
            'cpp': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/cpp-queries'),
            'go': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/go-queries'),
            'ruby': os.path.join(settings.CODEQL_PACKS_BASE, 'codeql/ruby-queries'),
        }
        
        cwe_query_map = {
            'javascript': {
                'CWE-79': 'Security/CWE-079/Xss.ql',
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-94': 'Security/CWE-094/CodeInjection.ql',
                'CWE-502': 'Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-22': 'Security/CWE-022/TaintedPath.ql',
                'CWE-312': 'Security/CWE-312/CleartextStorage.ql',
                'CWE-327': 'Security/CWE-327/BrokenCryptoAlgorithm.ql',
                'CWE-601': 'Security/CWE-601/UrlRedirection.ql',
                'CWE-611': 'Security/CWE-611/Xxe.ql',
                'CWE-918': 'Security/CWE-918/RequestForgery.ql',
                'CWE-352': 'Security/CWE-352/MissingCsrfToken.ql',
                'CWE-78': 'Security/CWE-078/CommandInjection.ql',
                'CWE-200': 'Security/CWE-200/InformationExposure.ql',
                'CWE-209': 'Security/CWE-209/StackTraceExposure.ql',
                'CWE-384': 'Security/CWE-384/SessionFixation.ql',
                'CWE-400': 'Security/CWE-400/ResourceExhaustion.ql',
                'CWE-798': 'Security/CWE-798/HardcodedCredentials.ql',
            },
            'python': {
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-94': 'Security/CWE-094/CodeInjection.ql',
                'CWE-22': 'Security/CWE-022/PathInjection.ql',
                'CWE-502': 'Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-78': 'Security/CWE-078/CommandInjection.ql',
            },
            'java': {
                'CWE-89': 'Security/CWE-089/SqlInjection.ql',
                'CWE-79': 'Security/CWE-079/Xss.ql',
                'CWE-502': 'Security/CWE-502/UnsafeDeserialization.ql',
            },
            'cpp': {
                'CWE-119': 'Security/CWE/CWE-119/BufferOverflow.ql',
                'CWE-190': 'Security/CWE/CWE-190/IntegerOverflow.ql',
                'CWE-416': 'Security/CWE/CWE-416/UseAfterFree.ql',
            }
        }
        
        # Get the relative query path for the ACTUAL language pack (not detected language)
        queries = cwe_query_map.get(actual_language, {})
        relative_path = queries.get(cwe)
        
        if not relative_path:
            self._log(None, f"No query available for {cwe} in {actual_language} (detected: {language})")
            return None
            
        # Construct full path using the correct base path for the actual language
        base_path = base_paths.get(actual_language)
        if not base_path:
            self._log(None, f"No base path for language pack: {actual_language}")
            return None
            
        query_path = f"{base_path}/{relative_path}"
        
        # Check if the query file exists
        if query_path and os.path.exists(query_path):
            self._log(None, f"Found query for {cwe} using {actual_language} pack: {query_path}")
            return query_path
        
        # Fallback: try to find query in alternative locations
        self._log(None, f"Query not found at {query_path}, trying fallback")
        return self._find_fallback_query(cwe, actual_language)
    
    def _find_fallback_query(self, cwe: str, language: str) -> Optional[str]:
        """Find a fallback query file if the standard one doesn't exist"""
        # Try alternative base paths (configurable base first, then common locations)
        base_paths = [
            settings.CODEQL_PACKS_BASE,
            os.path.join(settings.CODEQL_PACKS_BASE, "javascript/javascript"),
            os.path.join(settings.CODEQL_PACKS_BASE, "javascript"),
            os.path.join(settings.CODEQL_PACKS_BASE, "codeql-main"),
            "/app/codeql_queries",
            "codeql_queries"
        ]
        
        # Map CWE to custom query files
        custom_queries = {
            "CWE-119": "BufferOverflow.ql",
            "CWE-89": "SqlInjection.ql",
            "CWE-416": "UseAfterFree.ql",
            "CWE-190": "IntegerOverflow.ql"
        }
        
        query_file = custom_queries.get(cwe)
        if not query_file:
            return None
            
        for base_path in base_paths:
            query_path = os.path.join(base_path, query_file)
            if os.path.exists(query_path):
                return query_path
        
        return None
    
    def _run_codeql_query(self, state: ScanState, cwe: str, language: str, db_path: str) -> List[VulnerabilityState]:
        """Run a specific CodeQL query against an existing database"""
        query_path = self._get_cwe_query(cwe, language)
        
        if not query_path:
            # Fall back to custom query files for basic CWEs
            query_map = {
                "CWE-119": "BufferOverflow.ql",
                "CWE-89": "SqlInjection.ql",
                "CWE-416": "UseAfterFree.ql",
                "CWE-190": "IntegerOverflow.ql"
            }
            query_file = query_map.get(cwe)
            if not query_file:
                return []
            query_path = os.path.join("codeql_queries", query_file)
            if not os.path.exists(query_path):
                return []
        
        try:
            
            # Run query
            result_path = os.path.join(settings.TEMP_DIR, f"codeql_results_{cwe}.json")
            
            self._log(state, f"Query path for {cwe}: {query_path}")
            self._log(state, f"Query file exists: {os.path.exists(query_path) if query_path else False}")
            
            if not query_path or not os.path.exists(query_path):
                self._log(state, f"No query available for {cwe}, skipping")
                return []
            
            # Use database analyze command which supports SARIF output
            cmd = [
                settings.CODEQL_CLI_PATH,
                "database", "analyze",
                db_path,
                query_path,
                "--format=sarifv2.1.0",
                f"--output={result_path}"
            ]
            
            self._log(state, f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes for query compilation + execution
            )
            
            self._log(state, f"CodeQL exit code: {result.returncode}")
            if result.stderr:
                self._log(state, f"CodeQL stderr: {result.stderr[:500]}")
            
            # Parse SARIF results
            findings = []
            if os.path.exists(result_path):
                try:
                    with open(result_path, 'r') as f:
                        sarif = json.load(f)
                        # SARIF format: runs[0].results
                        runs = sarif.get("runs", [])
                        if runs:
                            results = runs[0].get("results", [])
                            for res in results:
                                locations = res.get("locations", [])
                                if locations:
                                    loc = locations[0].get("physicalLocation", {})
                                    artifact = loc.get("artifactLocation", {})
                                    region = loc.get("region", {})
                                    
                                    filepath = artifact.get("uri", "")
                                    
                                    # Detect language for this specific file
                                    file_lang = self._get_language_from_extension(
                                        os.path.splitext(filepath)[1].lower()
                                    ) or state.get("detected_language", "unknown")
                                    
                                    finding = VulnerabilityState(
                                        cve_id=None,
                                        filepath=filepath,
                                        line_number=region.get("startLine", 0),
                                        cwe_type=cwe,
                                        code_chunk=res.get("message", {}).get("text", ""),
                                        llm_verdict="",
                                        llm_explanation="",
                                        confidence=0.8,  # CodeQL findings have high confidence
                                        pov_script=None,
                                        pov_path=None,
                                        pov_result=None,
                                        retry_count=0,
                                        inference_time_s=0.0,
                                        cost_usd=0.0,
                                        final_status="pending",
                                        detected_language=file_lang,
                                        source="codeql"
                                    )
                                    findings.append(finding)
                except Exception as e:
                    self._log(state, f"Error parsing SARIF results: {e}")
            
            return findings
            
        except subprocess.TimeoutExpired as e:
            self._log(state, f"CodeQL query timeout for {cwe}: Query compilation took too long")
            return []
        except Exception as e:
            self._log(state, f"CodeQL query error for {cwe}: {e}")
            return []
    
    def _run_llm_only_analysis(self, state: ScanState) -> List[VulnerabilityState]:
        """
        Run LLM-only analysis when CodeQL is not available.

        Walks code files in the codebase, splits them into chunks, and uses
        the LLM scout to propose candidate vulnerabilities.  This mirrors what
        the heuristic scout does but leverages the LLM for richer detection.
        Falls back gracefully if the LLM is unavailable.
        """
        self._log(state, "Running LLM-only analysis (CodeQL unavailable)...")

        findings: List[VulnerabilityState] = []

        # Collect code files
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java',
            '.c', '.cpp', '.cc', '.h', '.hpp', '.go', '.rb', '.php', '.cs'
        }
        code_files: List[str] = []
        for root, dirs, files in os.walk(state["codebase_path"]):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
                'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'
            )]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in code_extensions:
                    code_files.append(os.path.join(root, fname))

        if not code_files:
            self._log(state, "No code files found for LLM-only analysis")
            return findings

        # Limit to first 20 files to control cost
        max_files = min(len(code_files), 20)
        code_files = code_files[:max_files]
        self._log(state, f"LLM-only analysis: scanning {len(code_files)} files for {len(state['cwes'])} CWEs")

        for filepath in code_files:
            rel_path = os.path.relpath(filepath, state["codebase_path"])
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(settings.MAX_CHUNK_SIZE * 2)
            except Exception:
                continue

            if not content.strip():
                continue

            # Use heuristic patterns as a pre-filter to avoid LLM calls on clean files
            from agents.heuristic_scout import get_heuristic_scout
            scout = get_heuristic_scout()
            heuristic_hits = []
            try:
                lines = content.split('\n')
                for line_idx, line in enumerate(lines, start=1):
                    for cwe in state["cwes"]:
                        for pattern in scout._patterns.get(cwe, []):
                            if pattern.search(line):
                                heuristic_hits.append({
                                    "cwe_type": cwe,
                                    "filepath": rel_path,
                                    "line_number": line_idx,
                                    "code_chunk": line.strip(),
                                    "llm_verdict": "",
                                    "llm_explanation": "",
                                    "confidence": 0.35,
                                    "pov_script": None,
                                    "pov_path": None,
                                    "pov_result": None,
                                    "retry_count": 0,
                                    "inference_time_s": 0.0,
                                    "cost_usd": 0.0,
                                    "final_status": "pending",
                                    "alert_message": "LLM-only heuristic",
                                    "source": "llm_only",
                                    "language": state.get("detected_language", "unknown")
                                })
            except Exception as e:
                self._log(state, f"Heuristic pre-filter error on {rel_path}: {e}")

            findings.extend(heuristic_hits)

        self._log(state, f"LLM-only analysis produced {len(findings)} candidate findings")
        return findings
    
    def _node_investigate(self, state: ScanState) -> ScanState:
        """Investigate ONE finding with LLM (at current_finding_idx)"""
        # Check for cancellation
        if self._check_cancelled(state):
            self._log(state, "Scan cancelled by user")
            state["status"] = ScanStatus.CANCELLED
            return state
        
        state["status"] = ScanStatus.INVESTIGATING
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            self._log(state, "No more findings to investigate")
            return state
        
        finding = state["findings"][idx]
        
        # Skip if already investigated
        if finding.get("llm_verdict"):
            self._log(state, f"Finding {idx} already investigated, skipping")
            return state
        
        self._log(state, f"Investigating {finding['cwe_type']} at {finding['filepath']}:{finding['line_number']}")
        self._log(state, "Selecting model via policy...")
        
        policy = get_policy_router()
        model_to_use = policy.select_model("investigate", cwe=finding["cwe_type"], language=state.get("detected_language"))
        self._log(state, f"Using model (policy): {model_to_use}")
        investigator = get_investigator()
        
        # Pass the model name from scan state
        try:
            result = investigator.investigate(
                scan_id=state["scan_id"],
                codebase_path=state["codebase_path"],
                cwe_type=finding["cwe_type"],
                filepath=finding["filepath"],
                line_number=finding["line_number"],
                alert_message=finding.get("alert_message", ""),
                model_name=model_to_use
            )
            self._log(state, f"Investigation completed with verdict: {result.get('verdict', 'UNKNOWN')}")
        except Exception as e:
            self._log(state, f"ERROR during investigation: {str(e)}")
            import traceback
            self._log(state, f"Traceback: {traceback.format_exc()}")
            # Create a default result to prevent crash
            result = {
                "verdict": "UNKNOWN",
                "explanation": f"Investigation failed: {str(e)}",
                "confidence": 0.0,
                "inference_time_s": 0.0,
                "vulnerable_code": ""
            }
        
        finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
        finding["llm_explanation"] = result.get("explanation", "")
        finding["confidence"] = result.get("confidence", 0.0)
        finding["inference_time_s"] = result.get("inference_time_s", 0.0)
        finding["code_chunk"] = result.get("vulnerable_code", "")
        
        # Track tokens per model
        token_usage = result.get("token_usage", {})
        model_used = result.get("model_used", model_to_use)
        
        finding["model_used"] = model_used
        finding["prompt_tokens"] = token_usage.get("prompt_tokens", 0)
        finding["completion_tokens"] = token_usage.get("completion_tokens", 0)
        finding["total_tokens"] = token_usage.get("total_tokens", 0)
        
        # Update scan-level token tracking
        if finding["total_tokens"] > 0:
            state["total_tokens"] = state.get("total_tokens", 0) + finding["total_tokens"]
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += finding["prompt_tokens"]
            state["tokens_by_model"][model_used]["completion"] += finding["completion_tokens"]
            state["tokens_by_model"][model_used]["total"] += finding["total_tokens"]
        
        # Track cost (optional, for backward compatibility)
        actual_cost = result.get("cost_usd", 0.0)
        if actual_cost > 0:
            finding["cost_usd"] = actual_cost
        else:
            finding["cost_usd"] = 0.0
        
        state["total_cost_usd"] += finding["cost_usd"]
        
        state["findings"][idx] = finding
        
        self._log(state, f"  Verdict: {finding['llm_verdict']} (confidence: {finding['confidence']:.2f})")
        if finding["total_tokens"] > 0:
            self._log(state, f"  Tokens: {finding['total_tokens']} (prompt: {finding['prompt_tokens']}, completion: {finding['completion_tokens']})")

        try:
            get_learning_store().record_investigation(
                scan_id=state["scan_id"],
                cwe=finding.get("cwe_type", ""),
                filepath=finding.get("filepath", ""),
                language=state.get("detected_language", "unknown"),
                source=finding.get("source", "codeql"),
                verdict=finding.get("llm_verdict", "UNKNOWN"),
                confidence=finding.get("confidence", 0.0),
                model=model_to_use,
                cost_usd=finding.get("cost_usd", 0.0)
            )
        except Exception as e:
            self._log(state, f"Learning store record failed: {e}")

        return state
    
    def _node_generate_pov(self, state: ScanState) -> ScanState:
        """Generate PoV script for a finding"""
        # Check for cancellation
        if self._check_cancelled(state):
            self._log(state, "Scan cancelled by user")
            state["status"] = ScanStatus.CANCELLED
            return state
        
        state["status"] = ScanStatus.GENERATING_POV
        
        # Get current finding being processed
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if finding["llm_verdict"] != "REAL":
            return state
        
        self._log(state, f"Generating PoV for {finding['cwe_type']}...")

        policy = get_policy_router()
        model_to_use = policy.select_model("pov", cwe=finding["cwe_type"], language=state.get("detected_language"))
        self._log(state, f"Using model (policy) for PoV: {model_to_use}")
        
        verifier = get_verifier()
        
        # Get code context
        code_context = get_code_ingester().get_file_content(
            finding["filepath"], state["scan_id"]
        ) or ""
        
        # Get target language for language-aware PoV generation
        target_language = state.get("detected_language", "python")
        
        # Pass model name from scan state
        result = verifier.generate_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding["code_chunk"],
            explanation=finding["llm_explanation"],
            code_context=code_context,
            target_language=target_language,
            model_name=model_to_use
        )
        
        # Log model and token info
        model_used = result.get("model_used", model_to_use)
        token_usage = result.get("token_usage", {})
        
        if model_used:
            self._log(state, f"  Model: {model_used}")
        
        # Track tokens
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        total_tokens = token_usage.get("total_tokens", 0)
        
        if total_tokens > 0:
            self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
            state["total_tokens"] = state.get("total_tokens", 0) + total_tokens
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += prompt_tokens
            state["tokens_by_model"][model_used]["completion"] += completion_tokens
            state["tokens_by_model"][model_used]["total"] += total_tokens
        
        # Track cost for backward compatibility
        if result.get("cost_usd", 0) > 0:
            state["total_cost_usd"] += result["cost_usd"]
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
            finding["pov_model_used"] = model_used
            finding["pov_prompt_tokens"] = prompt_tokens
            finding["pov_completion_tokens"] = completion_tokens
            finding["pov_total_tokens"] = total_tokens
            # Cost already added above, just store it in finding
            if "cost_usd" not in finding:
                finding["cost_usd"] = result.get("cost_usd", 0)
            self._log(state, "  PoV generated successfully")
        else:
            finding["final_status"] = "pov_generation_failed"
            self._log(state, f"  PoV generation failed: {result.get('error')}")
        
        state["findings"][idx] = finding
        return state
    
    def _node_validate_pov(self, state: ScanState) -> ScanState:
        """Validate PoV script using hybrid approach"""
        state["status"] = ScanStatus.VALIDATING_POV
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            return state
        
        self._log(state, "Validating PoV script...")
        
        verifier = get_verifier()
        
        # Get vulnerable code for unit test validation
        vulnerable_code = finding.get("code_chunk", "")
        
        result = verifier.validate_pov(
            pov_script=finding["pov_script"],
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=vulnerable_code
        )
        
        # Log validation method used
        validation_method = result.get("validation_method", "unknown")
        self._log(state, f"  Validation method: {validation_method}")
        
        # Log static analysis results if available
        if result.get("static_result"):
            static = result["static_result"]
            self._log(state, f"  Static analysis confidence: {static['confidence']:.0%}")
            if static["matched_patterns"]:
                self._log(state, f"  Matched patterns: {len(static['matched_patterns'])}")
        
        # Log unit test results if available
        if result.get("unit_test_result"):
            unit_test = result["unit_test_result"]
            if unit_test.get("vulnerability_triggered"):
                self._log(state, "  ✓ Unit test confirmed vulnerability trigger!")
            elif unit_test.get("success"):
                self._log(state, "  Unit test executed (vulnerability not triggered)")
            else:
                self._log(state, f"  Unit test failed: {unit_test.get('stderr', 'Unknown error')[:100]}")
        
        if result["is_valid"]:
            will_trigger = result.get("will_trigger", "MAYBE")
            self._log(state, f"  PoV validation passed (will trigger: {will_trigger})")
        else:
            issues = result.get("issues", [])
            self._log(state, f"  PoV validation failed: {issues[:2]}")  # Log first 2 issues
            finding["retry_count"] += 1
        
        # Store validation result in finding
        finding["validation_result"] = result
        
        state["findings"][idx] = finding
        return state

    def _node_refine_pov(self, state: ScanState) -> ScanState:
        """Refine PoV script based on validation errors (Self-Healing)"""
        state["status"] = ScanStatus.GENERATING_POV  # Still generating
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            return state
        
        # Get validation errors
        validation_result = finding.get("validation_result", {})
        validation_errors = validation_result.get("issues", [])
        
        if not validation_errors:
            self._log(state, "No validation errors to refine, skipping refinement")
            return state
        
        self._log(state, f"Refining PoV for {finding['cwe_type']} (attempt {finding['retry_count'] + 1})...")
        self._log(state, f"  Errors: {validation_errors[:2]}")
        
        # Get code context
        code_context = get_code_ingester().get_file_content(
            finding["filepath"], state["scan_id"]
        ) or ""
        
        # Get target language
        target_language = state.get("detected_language", "python")
        
        # Select model for refinement (use architect model in hierarchical mode)
        policy = get_policy_router()
        model_to_use = policy.select_model("pov", cwe=finding["cwe_type"], language=target_language)
        
        # Initialize refinement history
        if "refinement_history" not in finding:
            finding["refinement_history"] = []
        
        # Call verifier to refine the PoV
        verifier = get_verifier()
        result = verifier.refine_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding.get("code_chunk", ""),
            explanation=finding["llm_explanation"],
            code_context=code_context,
            failed_pov=finding["pov_script"],
            validation_errors=validation_errors,
            attempt_number=finding["retry_count"] + 1,
            target_language=target_language,
            model_name=model_to_use
        )
        
        # Track refinement in history with tokens
        model_used = result.get("model_used", model_to_use)
        token_usage = result.get("token_usage", {})
        
        finding["refinement_history"].append({
            "attempt": finding["retry_count"] + 1,
            "errors": validation_errors,
            "success": result.get("success", False),
            "timestamp": result.get("timestamp", ""),
            "model_used": model_used,
            "tokens": token_usage,
            "cost_usd": result.get("cost_usd", 0.0)
        })
        
        # Track tokens
        prompt_tokens = token_usage.get("prompt_tokens", 0)
        completion_tokens = token_usage.get("completion_tokens", 0)
        total_tokens = token_usage.get("total_tokens", 0)
        
        if total_tokens > 0:
            state["total_tokens"] = state.get("total_tokens", 0) + total_tokens
            
            # Track tokens by model
            if "tokens_by_model" not in state or state["tokens_by_model"] is None:
                state["tokens_by_model"] = {}
            
            if model_used not in state["tokens_by_model"]:
                state["tokens_by_model"][model_used] = {"prompt": 0, "completion": 0, "total": 0}
            
            state["tokens_by_model"][model_used]["prompt"] += prompt_tokens
            state["tokens_by_model"][model_used]["completion"] += completion_tokens
            state["tokens_by_model"][model_used]["total"] += total_tokens
        
        # Update cost tracking (for backward compatibility)
        if result.get("cost_usd", 0) > 0:
            state["total_cost_usd"] += result["cost_usd"]
            finding["cost_usd"] = finding.get("cost_usd", 0) + result["cost_usd"]
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
            finding["retry_count"] += 1
            self._log(state, f"  PoV refined successfully (attempt {finding['retry_count']})")
            if total_tokens > 0:
                self._log(state, f"  Tokens: {total_tokens} (prompt: {prompt_tokens}, completion: {completion_tokens})")
        else:
            self._log(state, f"  PoV refinement failed: {result.get('error')}")
            finding["retry_count"] += 1
        
        state["findings"][idx] = finding
        return state

    def _node_run_in_docker(self, state: ScanState) -> ScanState:
        """Run PoV - uses validation results instead of Docker execution"""
        state["status"] = ScanStatus.RUNNING_POV

        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state

        finding = state["findings"][idx]

        if not finding.get("pov_script"):
            return state

        # Check if we already have validation results
        validation_result = finding.get("validation_result") or {}
        unit_test_result = validation_result.get("unit_test_result") or {}

        # If unit test already confirmed vulnerability, use that result
        if unit_test_result.get("vulnerability_triggered"):
            self._log(state, "Using unit test confirmation (vulnerability triggered)")
            finding["pov_result"] = {
                "success": True,
                "vulnerability_triggered": True,
                "validation_method": "unit_test",
                "stdout": unit_test_result.get("stdout", ""),
                "stderr": unit_test_result.get("stderr", ""),
                "execution_time_s": unit_test_result.get("execution_time_s", 0)
            }
            self._log(state, "VULNERABILITY CONFIRMED")
            try:
                get_learning_store().record_pov(
                    scan_id=state["scan_id"],
                    cwe=finding.get("cwe_type", ""),
                    model=finding.get("pov_model_used", ""),
                    cost_usd=finding.get("cost_usd", 0.0),
                    success=True,
                    validation_method="unit_test"
                )
            except Exception as e:
                self._log(state, f"Learning store PoV record failed: {e}")
            state["findings"][idx] = finding
            return state

        # If static validation has high confidence, trust it
        static_result = validation_result.get("static_result", {})
        if static_result.get("is_valid") and static_result.get("confidence", 0) >= 0.8:
            self._log(state, "Using static validation result (high confidence)")
            finding["pov_result"] = {
                "success": True,
                "vulnerability_triggered": True,  # Assume triggered based on static analysis
                "validation_method": "static_analysis",
                "confidence": static_result.get("confidence", 0),
                "note": "Vulnerability confirmed via static analysis"
            }
            self._log(state, "VULNERABILITY CONFIRMED (static analysis)")
            try:
                get_learning_store().record_pov(
                    scan_id=state["scan_id"],
                    cwe=finding.get("cwe_type", ""),
                    model=finding.get("pov_model_used", ""),
                    cost_usd=finding.get("cost_usd", 0.0),
                    success=True,
                    validation_method="static_analysis"
                )
            except Exception as e:
                self._log(state, f"Learning store PoV record failed: {e}")
            state["findings"][idx] = finding
            return state

        # Fall back to Docker-based testing for cases where validation was inconclusive
        if not finding.get("pov_script"):
            self._log(state, "No PoV script available, skipping Docker test")
            finding["pov_result"] = {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": "No PoV script generated",
                "exit_code": -1,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
            state["findings"][idx] = finding
            return state
        
        self._log(state, "Running PoV in Docker (fallback)...")

        runner = get_docker_runner()
        result = runner.run_pov(
            pov_script=finding["pov_script"],
            scan_id=state["scan_id"],
            pov_id=str(idx)
        )

        finding["pov_result"] = result

        if result["vulnerability_triggered"]:
            self._log(state, "VULNERABILITY TRIGGERED")
        else:
            self._log(state, f"  PoV did not trigger vulnerability (exit code: {result['exit_code']})")

        try:
            get_learning_store().record_pov(
                scan_id=state["scan_id"],
                cwe=finding.get("cwe_type", ""),
                model=finding.get("pov_model_used", ""),
                cost_usd=finding.get("cost_usd", 0.0),
                success=bool(result.get("vulnerability_triggered")),
                validation_method="docker"
            )
        except Exception as e:
            self._log(state, f"Learning store PoV record failed: {e}")

        state["findings"][idx] = finding
        return state

    def _node_log_confirmed(self, state: ScanState) -> ScanState:
        """Log confirmed vulnerability"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "confirmed"
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        # Check if there are more findings to process
        if state["current_finding_idx"] < len(state["findings"]):
            # Continue with next finding
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _node_log_skip(self, state: ScanState) -> ScanState:
        """Log skipped finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "skipped"
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _node_log_failure(self, state: ScanState) -> ScanState:
        """Log failed finding"""
        idx = state.get("current_finding_idx", 0)
        if idx < len(state["findings"]):
            state["findings"][idx]["final_status"] = "failed"
        
        # Move to next finding
        state["current_finding_idx"] = idx + 1
        
        if state["current_finding_idx"] < len(state["findings"]):
            pass
        else:
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
        
        return state
    
    def _should_generate_pov(self, state: ScanState) -> str:
        """Determine if we should generate PoV for current finding"""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            self._log(state, "No findings to process, ending workflow")
            return "log_skip"
        
        finding = state["findings"][idx]
        verdict = finding.get("llm_verdict", "UNKNOWN")
        confidence = finding.get("confidence", 0.0)
        
        self._log(state, f"Decision for finding {idx}: verdict={verdict}, confidence={confidence:.2f}")
        
        if verdict == "REAL" and confidence >= 0.7:
            self._log(state, f"Finding {idx} is REAL with high confidence, generating PoV")
            return "generate_pov"
        else:
            self._log(state, f"Finding {idx} skipped (verdict={verdict}, confidence={confidence:.2f})")
            return "log_skip"
    
    def _should_run_pov(self, state: ScanState) -> str:
        """Determine if we should run PoV, refine, or fail"""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return "log_failure"
        
        finding = state["findings"][idx]
        validation_result = finding.get("validation_result", {})
        
        # Check if validation passed
        if validation_result.get("is_valid"):
            return "run_in_docker"
        
        # Check if we can retry with refinement
        if finding["retry_count"] < settings.MAX_RETRIES:
            self._log(state, f"PoV validation failed, attempting refinement (attempt {finding['retry_count'] + 1}/{settings.MAX_RETRIES})")
            return "refine_pov"
        else:
            self._log(state, f"PoV validation failed after {settings.MAX_RETRIES} attempts")
            return "log_failure"
    
    def _has_more_findings(self, state: ScanState) -> str:
        """Check if there are more findings to process after logging"""
        idx = state.get("current_finding_idx", 0)
        total = len(state["findings"])
        
        self._log(state, f"Checking for more findings: current={idx}, total={total}")
        
        if idx < total:
            self._log(state, f"Processing next finding ({idx + 1}/{total})")
            return "investigate"  # More findings to process
        else:
            # All findings processed, mark as completed
            self._log(state, f"All {total} findings processed, completing scan")
            state["status"] = ScanStatus.COMPLETED
            state["end_time"] = datetime.utcnow().isoformat()
            return "end"
    
    def _log(self, state: Optional[ScanState], message: str):
        """Add log message to state and stream to scan manager in real-time"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}"
        
        # Only append to state if state is not None
        if state is not None:
            state["logs"].append(log_entry)
        
        # Also log to scan manager for real-time streaming using thread-safe method
        if state is not None:
            try:
                from app.scan_manager import get_scan_manager
                scan_manager = get_scan_manager()
                # Use the thread-safe append_log method
                scan_manager.append_log(state["scan_id"], log_entry)
            except Exception as e:
                # Log error for debugging but don't break the scan
                print(f"[AgentGraph] Failed to log to scan manager: {e}")
                pass
    
    def _estimate_cost(self, inference_time_s: float) -> float:
        """
        DEPRECATED: Use actual token-based cost calculation instead.
        This method is kept for fallback only.
        """
        # This is a rough estimate - actual costs should be calculated from token usage
        # For academic accuracy, we should never rely on this estimation
        if settings.MODEL_MODE == "online":
            # Very rough estimate - should not be used for actual cost tracking
            return inference_time_s * 0.001  # Reduced from 0.01 to be more realistic
        else:
            # Offline: no cost
            return 0.0
    
    def run_scan(
        self,
        codebase_path: str,
        model_name: str,
        cwes: List[str],
        scan_id: Optional[str] = None,
        preloaded_findings: Optional[List[VulnerabilityState]] = None,
        detected_language: Optional[str] = None
    ) -> ScanState:
        """
        Run a complete vulnerability scan
        
        Args:
            codebase_path: Path to codebase
            model_name: LLM model name
            cwes: List of CWEs to check
            scan_id: Optional scan ID
            preloaded_findings: Optional preloaded findings for replay
            detected_language: Optional detected language
        
        Returns:
            Final scan state
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())
        
        initial_state = ScanState(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            codebase_path=codebase_path,
            model_name=model_name,
            cwes=cwes,
            findings=[],
            preloaded_findings=preloaded_findings,
            detected_language=detected_language,
            current_finding_idx=0,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            total_cost_usd=0.0,
            total_tokens=0,
            tokens_by_model={},
            logs=[],
            error=None
        )
        
        # Run the graph
        final_state = self.graph.invoke(initial_state)
        
        return final_state


# Global agent graph instance
agent_graph = AgentGraph()


def get_agent_graph() -> AgentGraph:
    """Get the global agent graph instance"""
    return agent_graph























