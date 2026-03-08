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
        workflow.add_edge("run_codeql", "investigate")
        
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
        workflow.add_edge("log_skip", END)
        workflow.add_edge("log_failure", END)
        workflow.add_edge("log_confirmed", END)
        
        return workflow.compile()
    
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
        
        if not settings.is_codeql_available():
            self._log(state, "CodeQL not available, using LLM-only analysis")
            # Create synthetic findings from LLM analysis
            findings = self._run_llm_only_analysis(state)
            state["findings"] = findings
            return state
        
        try:
            findings = []
            
            for cwe in state["cwes"]:
                cwe_findings = self._run_codeql_query(state, cwe)
                findings.extend(cwe_findings)
            
            state["findings"] = findings
            self._log(state, f"CodeQL found {len(findings)} potential vulnerabilities")
            
        except Exception as e:
            self._log(state, f"CodeQL error: {e}")
            # Fallback to LLM-only
            findings = self._run_llm_only_analysis(state)
            state["findings"] = findings
        
        return state
    
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
        """Get CodeQL query for a CWE based on language using pack syntax"""
        # Map CWEs to CodeQL query packs (using codeql pack syntax)
        cwe_query_map = {
            'javascript': {
                'CWE-79': 'codeql/javascript-queries:Security/CWE-079/Xss.ql',
                'CWE-89': 'codeql/javascript-queries:Security/CWE-089/SqlInjection.ql',
                'CWE-94': 'codeql/javascript-queries:Security/CWE-094/CodeInjection.ql',
                'CWE-502': 'codeql/javascript-queries:Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-22': 'codeql/javascript-queries:Security/CWE-022/TaintedPath.ql',
                'CWE-312': 'codeql/javascript-queries:Security/CWE-312/CleartextStorage.ql',
                'CWE-327': 'codeql/javascript-queries:Security/CWE-327/BrokenCryptoAlgorithm.ql',
                'CWE-601': 'codeql/javascript-queries:Security/CWE-601/UrlRedirection.ql',
                'CWE-611': 'codeql/javascript-queries:Security/CWE-611/Xxe.ql',
                'CWE-918': 'codeql/javascript-queries:Security/CWE-918/RequestForgery.ql',
                'CWE-352': 'codeql/javascript-queries:Security/CWE-352/MissingCsrfToken.ql',
                'CWE-78': 'codeql/javascript-queries:Security/CWE-078/CommandInjection.ql',
                'CWE-200': 'codeql/javascript-queries:Security/CWE-200/InformationExposure.ql',
                'CWE-209': 'codeql/javascript-queries:Security/CWE-209/StackTraceExposure.ql',
                'CWE-384': 'codeql/javascript-queries:Security/CWE-384/SessionFixation.ql',
                'CWE-400': 'codeql/javascript-queries:Security/CWE-400/ResourceExhaustion.ql',
                'CWE-798': 'codeql/javascript-queries:Security/CWE-798/HardcodedCredentials.ql',
            },
            'python': {
                'CWE-89': 'codeql/python-queries:Security/CWE-089/SqlInjection.ql',
                'CWE-94': 'codeql/python-queries:Security/CWE-094/CodeInjection.ql',
                'CWE-22': 'codeql/python-queries:Security/CWE-022/PathInjection.ql',
                'CWE-502': 'codeql/python-queries:Security/CWE-502/UnsafeDeserialization.ql',
                'CWE-78': 'codeql/python-queries:Security/CWE-078/CommandInjection.ql',
            },
            'java': {
                'CWE-89': 'codeql/java-queries:Security/CWE-089/SqlInjection.ql',
                'CWE-79': 'codeql/java-queries:Security/CWE-079/Xss.ql',
                'CWE-502': 'codeql/java-queries:Security/CWE-502/UnsafeDeserialization.ql',
            },
            'cpp': {
                'CWE-119': 'codeql/cpp-queries:Security/CWE/CWE-119/BufferOverflow.ql',
                'CWE-190': 'codeql/cpp-queries:Security/CWE/CWE-190/IntegerOverflow.ql',
                'CWE-416': 'codeql/cpp-queries:Security/CWE/CWE-416/UseAfterFree.ql',
            }
        }
        
        queries = cwe_query_map.get(language, {})
        return queries.get(cwe)
    
    def _run_codeql_query(self, state: ScanState, cwe: str) -> List[VulnerabilityState]:
        """Run a specific CodeQL query"""
        language = self._detect_language(state["codebase_path"])
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
        
        # Create CodeQL database
        db_path = os.path.join(settings.TEMP_DIR, f"codeql_db_{state['scan_id']}")
        
        try:
            # Create database only once per scan
            if not os.path.exists(db_path):
                self._log(state, f"Creating CodeQL database for {language}...")
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
                    return []
            
            # Run query
            result_path = os.path.join(settings.TEMP_DIR, f"codeql_results_{cwe}.json")
            
            if query_path.startswith('codeql/'):
                # Use CodeQL pack query (pack syntax: codeql/<lang>-queries:<path>)
                cmd = [
                    settings.CODEQL_CLI_PATH,
                    "database", "analyze",
                    db_path,
                    "--format=sarifv2.1.0",
                    f"--output={result_path}",
                    query_path
                ]
            else:
                # Use custom query file
                cmd = [
                    settings.CODEQL_CLI_PATH,
                    "query", "run",
                    query_path,
                    "--database", db_path,
                    "--output", result_path,
                    "--format=sarifv2.1.0"
                ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse SARIF results
            findings = []
            if os.path.exists(result_path):
                with open(result_path, 'r') as f:
                    sarif = json.load(f)
                    # SARIF format: runs[0].results
                    runs = sarif.get("runs", [])
                    if runs:
                        results = runs[0].get("results", [])
                        for result in results:
                            locations = result.get("locations", [])
                            if locations:
                                loc = locations[0].get("physicalLocation", {})
                                artifact = loc.get("artifactLocation", {})
                                region = loc.get("region", {})
                                
                                finding = VulnerabilityState(
                                    cve_id=None,
                                    filepath=artifact.get("uri", ""),
                                    line_number=region.get("startLine", 0),
                                    cwe_type=cwe,
                                    code_chunk=result.get("message", {}).get("text", ""),
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
            
            return findings
            
        except Exception as e:
            self._log(state, f"CodeQL query error for {cwe}: {e}")
            return []
        finally:
            # Cleanup
            if os.path.exists(db_path):
                import shutil
                shutil.rmtree(db_path, ignore_errors=True)
    
    def _run_llm_only_analysis(self, state: ScanState) -> List[VulnerabilityState]:
        """Run LLM-only analysis when CodeQL is not available"""
        self._log(state, "Running LLM-only analysis...")
        
        # This is a simplified version - in production, you'd want to
        # chunk the codebase and analyze each chunk
        findings = []
        
        # For now, return empty list - investigation will be done per-file
        return findings
    
    def _node_investigate(self, state: ScanState) -> ScanState:
        """Investigate findings with LLM"""
        self._log(state, "Investigating findings with LLM...")
        state["status"] = ScanStatus.INVESTIGATING
        
        investigator = get_investigator()
        updated_findings = []
        
        for i, finding in enumerate(state["findings"]):
            self._log(state, f"  Investigating {finding['cwe_type']} at {finding['filepath']}:{finding['line_number']}")
            
            result = investigator.investigate(
                scan_id=state["scan_id"],
                codebase_path=state["codebase_path"],
                cwe_type=finding["cwe_type"],
                filepath=finding["filepath"],
                line_number=finding["line_number"],
                alert_message=finding.get("alert_message", "")
            )
            
            finding["llm_verdict"] = result.get("verdict", "UNKNOWN")
            finding["llm_explanation"] = result.get("explanation", "")
            finding["confidence"] = result.get("confidence", 0.0)
            finding["inference_time_s"] = result.get("inference_time_s", 0.0)
            finding["code_chunk"] = result.get("vulnerable_code", "")
            
            # Estimate cost (simplified)
            finding["cost_usd"] = self._estimate_cost(finding["inference_time_s"])
            state["total_cost_usd"] += finding["cost_usd"]
            
            updated_findings.append(finding)
            
            self._log(state, f"    Verdict: {finding['llm_verdict']} (confidence: {finding['confidence']:.2f})")
        
        state["findings"] = updated_findings
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
        
        result = verifier.generate_pov(
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"],
            vulnerable_code=finding["code_chunk"],
            explanation=finding["llm_explanation"],
            code_context=code_context
        )
        
        if result["success"]:
            finding["pov_script"] = result["pov_script"]
            finding["cost_usd"] += self._estimate_cost(result.get("generation_time_s", 0))
            state["total_cost_usd"] += self._estimate_cost(result.get("generation_time_s", 0))
            self._log(state, "  PoV generated successfully")
        else:
            finding["final_status"] = "pov_generation_failed"
            self._log(state, f"  PoV generation failed: {result.get('error')}")
        
        state["findings"][idx] = finding
        return state
    
    def _node_validate_pov(self, state: ScanState) -> ScanState:
        """Validate PoV script"""
        state["status"] = ScanStatus.VALIDATING_POV
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            return state
        
        self._log(state, "Validating PoV script...")
        
        verifier = get_verifier()
        result = verifier.validate_pov(
            pov_script=finding["pov_script"],
            cwe_type=finding["cwe_type"],
            filepath=finding["filepath"],
            line_number=finding["line_number"]
        )
        
        if result["is_valid"]:
            self._log(state, "  PoV validation passed")
        else:
            self._log(state, f"  PoV validation failed: {result['issues']}")
            finding["retry_count"] += 1
        
        state["findings"][idx] = finding
        return state
    
    def _node_run_in_docker(self, state: ScanState) -> ScanState:
        """Run PoV in Docker container"""
        state["status"] = ScanStatus.RUNNING_POV
        
        idx = state.get("current_finding_idx", 0)
        if idx >= len(state["findings"]):
            return state
        
        finding = state["findings"][idx]
        
        if not finding.get("pov_script"):
            return state
        
        self._log(state, "Running PoV in Docker...")
        
        runner = get_docker_runner()
        result = runner.run_pov(
            pov_script=finding["pov_script"],
            scan_id=state["scan_id"],
            pov_id=str(idx)
        )
        
        finding["pov_result"] = result
        
        if result["vulnerability_triggered"]:
            self._log(state, "  VULNERABILITY TRIGGERED!")
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
            return "log_skip"
        
        finding = state["findings"][idx]
        
        if finding["llm_verdict"] == "REAL" and finding["confidence"] >= 0.7:
            return "generate_pov"
        else:
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
    
    def _log(self, state: ScanState, message: str):
        """Add log message to state"""
        timestamp = datetime.utcnow().isoformat()
        state["logs"].append(f"[{timestamp}] {message}")
    
    def _estimate_cost(self, inference_time_s: float) -> float:
        """Estimate cost in USD based on inference time"""
        # Simplified cost estimation
        # In production, use actual token counts
        if settings.MODEL_MODE == "online":
            # Rough estimate: $0.01 per second of inference
            return inference_time_s * 0.01
        else:
            # Offline: track GPU hours instead
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
