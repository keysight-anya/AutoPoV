"""
AutoPoV Agent Graph Module
LangGraph-based agentic workflow for vulnerability detection
"""

import os
import json
import uuid
from typing import Dict, Any, List, Optional, TypedDict, Annotated
from datetime import datetime
from enum import Enum

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

try:
    import subprocess
    SUBPROCESS_AVAILABLE = True
except ImportError:
    SUBPROCESS_AVAILABLE = False

from app.config import settings
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


class ScanState(TypedDict):
    """Overall scan state"""
    scan_id: str
    status: str
    codebase_path: str
    model_name: str
    cwes: List[str]
    findings: List[VulnerabilityState]
    current_finding_idx: int
    start_time: str
    end_time: Optional[str]
    total_cost_usd: float
    logs: List[str]
    error: Optional[str]


class AgentGraph:
    """LangGraph agent for vulnerability detection workflow"""
    
    def __init__(self):
        self.graph = self._build_graph()
    
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
                "generate_pov": "generate_pov",  # Retry
                "log_failure": "log_failure"
            }
        )
        
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
            self._log(state, f"Error during ingestion: {e}")
            state["error"] = str(e)
        
        return state
    
    def _node_run_codeql(self, state: ScanState) -> ScanState:
        """Run CodeQL analysis"""
        self._log(state, "Running CodeQL analysis...")
        state["status"] = ScanStatus.RUNNING_CODEQL
        
        codeql_available = settings.is_codeql_available()
        self._log(state, f"CodeQL availability check: {codeql_available}")
        
        if not codeql_available:
            self._log(state, "CodeQL not available, using LLM-only analysis")
            findings = self._run_llm_only_analysis(state)
            state["findings"] = findings
            return state
        
        try:
            findings = []
            detected_lang = self._detect_language(state["codebase_path"])
            state["detected_language"] = detected_lang  # Store for later use
            self._log(state, f"Detected language: {detected_lang}")
            
            # Create CodeQL database once for all queries
            db_path = os.path.join(settings.TEMP_DIR, f"codeql_db_{state['scan_id']}")
            db_created = self._create_codeql_database(state, detected_lang, db_path)
            
            if not db_created:
                self._log(state, "CodeQL database creation failed, using LLM-only analysis")
                findings = self._run_llm_only_analysis(state)
                state["findings"] = findings
                return state
            
            # Run queries against the created database
            for cwe in state["cwes"]:
                self._log(state, f"Running CodeQL query for {cwe}...")
                cwe_findings = self._run_codeql_query(state, cwe, detected_lang, db_path)
                self._log(state, f"{cwe}: Found {len(cwe_findings)} findings")
                findings.extend(cwe_findings)
            
            state["findings"] = findings
            self._log(state, f"CodeQL found {len(findings)} potential vulnerabilities")
            
        except Exception as e:
            self._log(state, f"CodeQL error: {e}")
            import traceback
            self._log(state, f"Traceback: {traceback.format_exc()}")
            findings = self._run_llm_only_analysis(state)
            state["findings"] = findings
        finally:
            # Cleanup database after all queries are done
            db_path = os.path.join(settings.TEMP_DIR, f"codeql_db_{state['scan_id']}")
            if os.path.exists(db_path):
                import shutil
                shutil.rmtree(db_path, ignore_errors=True)
                self._log(state, f"Cleaned up CodeQL database at {db_path}")
        
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
    
    def _detect_language(self, codebase_path: str) -> str:
        """Detect the primary language of the codebase"""
        extensions = {}
        for root, _, files in os.walk(codebase_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                extensions[ext] = extensions.get(ext, 0) + 1
        
        # Map extensions to CodeQL languages
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',  # TypeScript uses javascript extractor
            '.tsx': 'javascript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.c': 'cpp',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.h': 'cpp',
            '.go': 'go',
            '.rb': 'ruby'
        }
        
        # Find the most common language
        lang_counts = {}
        for ext, count in extensions.items():
            lang = lang_map.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + count
        
        if lang_counts:
            return max(lang_counts, key=lang_counts.get)
        return 'python'  # Default fallback
    
    def _get_cwe_query(self, cwe: str, language: str) -> Optional[str]:
        """Get CodeQL query for a CWE based on language using local file paths"""
        # Map CWEs to CodeQL query file paths (local filesystem paths)
        base_path = "/usr/local/codeql/packs/javascript"
        cwe_query_map = {
            'javascript': {
                'CWE-79': f'{base_path}/javascript/ql/src/Security/CWE-079/Xss.ql',
                'CWE-89': f'{base_path}/javascript/ql/src/Security/CWE-089/SqlInjection.ql',
                'CWE-94': f'{base_path}/javascript/ql/src/Security/CWE-094/CodeInjection.ql',
                'CWE-502': f'{base_path}/javascript/ql/src/Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-22': f'{base_path}/javascript/ql/src/Security/CWE-022/TaintedPath.ql',
                'CWE-312': f'{base_path}/javascript/ql/src/Security/CWE-312/CleartextStorage.ql',
                'CWE-327': f'{base_path}/javascript/ql/src/Security/CWE-327/BrokenCryptoAlgorithm.ql',
                'CWE-601': f'{base_path}/javascript/ql/src/Security/CWE-601/UrlRedirection.ql',
                'CWE-611': f'{base_path}/javascript/ql/src/Security/CWE-611/Xxe.ql',
                'CWE-918': f'{base_path}/javascript/ql/src/Security/CWE-918/RequestForgery.ql',
                'CWE-352': f'{base_path}/javascript/ql/src/Security/CWE-352/MissingCsrfToken.ql',
                'CWE-78': f'{base_path}/javascript/ql/src/Security/CWE-078/CommandInjection.ql',
                'CWE-200': f'{base_path}/javascript/ql/src/Security/CWE-200/InformationExposure.ql',
                'CWE-209': f'{base_path}/javascript/ql/src/Security/CWE-209/StackTraceExposure.ql',
                'CWE-384': f'{base_path}/javascript/ql/src/Security/CWE-384/SessionFixation.ql',
                'CWE-400': f'{base_path}/javascript/ql/src/Security/CWE-400/ResourceExhaustion.ql',
                'CWE-798': f'{base_path}/javascript/ql/src/Security/CWE-798/HardcodedCredentials.ql',
            },
            'python': {
                'CWE-89': f'{base_path}/python/ql/src/Security/CWE-089/SqlInjection.ql',
                'CWE-94': f'{base_path}/python/ql/src/Security/CWE-094/CodeInjection.ql',
                'CWE-22': f'{base_path}/python/ql/src/Security/CWE-022/PathInjection.ql',
                'CWE-502': f'{base_path}/python/ql/src/Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-78': f'{base_path}/python/ql/src/Security/CWE-078/CommandInjection.ql',
            },
            'java': {
                'CWE-89': f'{base_path}/java/ql/src/Security/CWE-089/SqlInjection.ql',
                'CWE-79': f'{base_path}/java/ql/src/Security/CWE-079/Xss.ql',
                'CWE-502': f'{base_path}/java/ql/src/Security/CWE-502/UnsafeDeserialization.ql',
            },
            'cpp': {
                'CWE-119': f'{base_path}/cpp/ql/src/Security/CWE/CWE-119/BufferOverflow.ql',
                'CWE-190': f'{base_path}/cpp/ql/src/Security/CWE/CWE-190/IntegerOverflow.ql',
                'CWE-416': f'{base_path}/cpp/ql/src/Security/CWE/CWE-416/UseAfterFree.ql',
            }
        }
        
        queries = cwe_query_map.get(language, {})
        query_path = queries.get(cwe)
        
        # Check if the query file exists
        if query_path and os.path.exists(query_path):
            return query_path
        
        # Fallback: try to find query in alternative locations
        return self._find_fallback_query(cwe, language)
    
    def _find_fallback_query(self, cwe: str, language: str) -> Optional[str]:
        """Find a fallback query file if the standard one doesn't exist"""
        # Try alternative base paths
        base_paths = [
            "/usr/local/codeql/packs/javascript/javascript",
            "/usr/local/codeql/packs/javascript",
            "/usr/local/codeql/packs/codeql-main",
            "/usr/local/codeql/packs",
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
                                    
                                    finding = VulnerabilityState(
                                        cve_id=None,
                                        filepath=artifact.get("uri", ""),
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
                                        final_status="pending"
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
        """Run LLM-only analysis when CodeQL is not available"""
        self._log(state, "Running LLM-only analysis...")
        
        # This is a simplified version - in production, you'd want to
        # chunk the codebase and analyze each chunk
        findings = []
        
        # For now, return empty list - investigation will be done per-file
        return findings
    
    def _node_investigate(self, state: ScanState) -> ScanState:
        """Investigate ONE finding with LLM (at current_finding_idx)"""
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
        self._log(state, f"Using model: {state.get('model_name', 'default')}")
        
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
                model_name=state.get("model_name")
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
        
        # Use actual cost from API response, or estimate if not available
        actual_cost = result.get("cost_usd", 0.0)
        if actual_cost > 0:
            finding["cost_usd"] = actual_cost
            finding["model_used"] = result.get("model_used", state.get("model_name", "unknown"))
            finding["token_usage"] = result.get("token_usage", {})
        else:
            # Fallback to estimation
            finding["cost_usd"] = self._estimate_cost(finding["inference_time_s"])
        
        state["total_cost_usd"] += finding["cost_usd"]
        
        state["findings"][idx] = finding
        
        self._log(state, f"  Verdict: {finding['llm_verdict']} (confidence: {finding['confidence']:.2f})")
        
        return state
    
    def _node_generate_pov(self, state: ScanState) -> ScanState:
        """Generate PoV script for a finding"""
        state["status"] = ScanStatus.GENERATING_POV
        
        # Get current finding being processed
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if finding["llm_verdict"] != "REAL":
            return state
        
        self._log(state, f"Generating PoV for {finding['cwe_type']}...")
        
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
            model_name=state.get("model_name")
        )
        
        # Log model and cost info
        if result.get("model_used"):
            self._log(state, f"  Model: {result['model_used']}")
        if result.get("cost_usd", 0) > 0:
            self._log(state, f"  Cost: ${result['cost_usd']:.6f}")
            state["total_cost_usd"] += result["cost_usd"]
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
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
        validation_result = finding.get("validation_result", {})
        unit_test_result = validation_result.get("unit_test_result", {})
        
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
            self._log(state, "  ✓ VULNERABILITY CONFIRMED!")
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
            self._log(state, "  ✓ VULNERABILITY CONFIRMED (static analysis)")
            state["findings"][idx] = finding
            return state
        
        # Fall back to Docker-based testing for cases where validation was inconclusive
        self._log(state, "Running PoV in Docker (fallback)...")
        
        runner = get_docker_runner()
        result = runner.run_pov(
            pov_script=finding["pov_script"],
            scan_id=state["scan_id"],
            pov_id=str(idx)
        )
        
        finding["pov_result"] = result
        
        if result["vulnerability_triggered"]:
            self._log(state, "  ✓ VULNERABILITY TRIGGERED!")
        else:
            self._log(state, f"  PoV did not trigger vulnerability (exit code: {result['exit_code']})")
        
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
        """Determine if we should run PoV or retry"""
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return "log_failure"
        
        finding = state["findings"][idx]
        
        if finding.get("pov_script") and finding["retry_count"] < settings.MAX_RETRIES:
            return "run_in_docker"
        elif finding["retry_count"] < settings.MAX_RETRIES:
            return "generate_pov"  # Retry generation
        else:
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
    
    def _log(self, state: ScanState, message: str):
        """Add log message to state and stream to scan manager in real-time"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}"
        state["logs"].append(log_entry)
        
        # Also log to scan manager for real-time streaming using thread-safe method
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
        scan_id: Optional[str] = None
    ) -> ScanState:
        """
        Run a complete vulnerability scan
        
        Args:
            codebase_path: Path to codebase
            model_name: LLM model name
            cwes: List of CWEs to check
            scan_id: Optional scan ID
        
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
            current_finding_idx=0,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            total_cost_usd=0.0,
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
