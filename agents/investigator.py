"""
AutoPoV Investigator Agent Module
Uses RAG and LLM to investigate potential vulnerabilities
"""

import json
import subprocess
import os
from typing import Dict, Optional, Any, List
from datetime import datetime

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.tracers import LangChainTracer

try:
    from langchain_openai import ChatOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from langchain_ollama import ChatOllama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

from app.config import settings
from agents.ingest_codebase import get_code_ingester
from prompts import format_investigation_prompt, format_rag_context_prompt


class InvestigationError(Exception):
    """Exception raised during investigation"""
    pass


class VulnerabilityInvestigator:
    """Investigates potential vulnerabilities using LLM and RAG"""
    
    def __init__(self):
        self._llm = None
        self._tracer = None
        
        # Initialize LangSmith tracer if enabled
        if settings.LANGCHAIN_TRACING_V2 and settings.LANGCHAIN_API_KEY:
            self._tracer = LangChainTracer(
                project_name=settings.LANGCHAIN_PROJECT
            )
    
    def _get_llm(self):
        """Get LLM instance based on configuration"""
        if self._llm is not None:
            return self._llm
        
        llm_config = settings.get_llm_config()
        
        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise InvestigationError("OpenAI not available. Install langchain-openai")
            
            api_key = llm_config.get("api_key")
            
            if not api_key:
                raise InvestigationError("OpenRouter API key not configured. Set OPENROUTER_API_KEY environment variable.")
            
            callbacks = [self._tracer] if self._tracer else None
            
            self._llm = ChatOpenAI(
                model=llm_config["model"],
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.1,
                callbacks=callbacks
            )
        else:
            if not OLLAMA_AVAILABLE:
                raise InvestigationError("Ollama not available. Install langchain-ollama")
            
            callbacks = [self._tracer] if self._tracer else None
            
            self._llm = ChatOllama(
                model=llm_config["model"],
                base_url=llm_config["base_url"],
                temperature=0.1,
                callbacks=callbacks
            )
        
        return self._llm
    
    def _run_joern_analysis(
        self,
        codebase_path: str,
        filepath: str,
        line_number: int,
        cwe_type: str
    ) -> Optional[str]:
        """
        Run Joern analysis for use-after-free (CWE-416) vulnerabilities
        
        Args:
            codebase_path: Path to codebase
            filepath: Target file path
            line_number: Target line number
            cwe_type: CWE type
        
        Returns:
            Joern analysis results or None if skipped
        """
        # Only run Joern for CWE-416 (Use After Free)
        if cwe_type != "CWE-416":
            return None
        
        if not settings.is_joern_available():
            return "Joern not available - skipped CPG analysis"
        
        try:
            # Create CPG
            cpg_dir = os.path.join(settings.TEMP_DIR, "joern_cpg")
            os.makedirs(cpg_dir, exist_ok=True)
            
            # Run joern-parse to create CPG
            parse_result = subprocess.run(
                [
                    settings.JOERN_CLI_PATH,
                    "--script",
                    f"""
                    importCode(inputPath="{codebase_path}", projectName="autopov_scan")
                    save
                    """,
                    "--params",
                    f"output={cpg_dir}"
                ],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if parse_result.returncode != 0:
                return f"Joern parse error: {parse_result.stderr}"
            
            # Query for call graph and data flow
            query_result = subprocess.run(
                [
                    settings.JOERN_CLI_PATH,
                    "--script",
                    f"""
                    importCpg("{cpg_dir}")
                    
                    // Find calls to free and subsequent uses
                    val freeCalls = cpg.call.name("free").l
                    val results = freeCalls.map {{ freeCall =>
                        val freedVar = freeCall.argument(1)
                        val usesAfterFree = freedVar.start.isUsed.l
                        (freeCall, usesAfterFree)
                    }}
                    
                    results.foreach {{ case (free, uses) =>
                        println(s"Free at: ${{free.lineNumber.getOrElse(0)}}")
                        uses.foreach {{ use =>
                            println(s"  Use after free at: ${{use.lineNumber.getOrElse(0)}} - ${{use.code}}")
                        }}
                    }}
                    """
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse output
            output = query_result.stdout
            if query_result.stderr:
                output += f"\nErrors: {query_result.stderr}"
            
            # Cleanup
            import shutil
            if os.path.exists(cpg_dir):
                shutil.rmtree(cpg_dir)
            
            return output if output else "No use-after-free patterns found"
            
        except subprocess.TimeoutExpired:
            return "Joern analysis timed out"
        except Exception as e:
            return f"Joern analysis error: {str(e)}"
    
    def _get_code_context(
        self,
        scan_id: str,
        filepath: str,
        line_number: int,
        context_lines: int = 50
    ) -> str:
        """
        Get code context around a specific line
        
        Args:
            scan_id: Scan identifier
            filepath: File path
            line_number: Target line number
            context_lines: Number of lines of context
        
        Returns:
            Code context string
        """
        # Try to get full file content first
        full_content = get_code_ingester().get_file_content(filepath, scan_id)
        
        if full_content:
            lines = full_content.split('\n')
            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)
            
            context_lines_list = lines[start_line:end_line]
            
            # Add line numbers
            numbered_lines = []
            for i, line in enumerate(context_lines_list, start=start_line + 1):
                marker = ">>> " if i == line_number else "    "
                numbered_lines.append(f"{marker}{i:4d}: {line}")
            
            return '\n'.join(numbered_lines)
        
        # Fallback: use RAG to get related code
        query = f"Code around line {line_number} in {filepath}"
        results = get_code_ingester().retrieve_context(query, scan_id, top_k=3)
        
        if results:
            contexts = []
            for r in results:
                contexts.append(f"// File: {r['metadata']['filepath']}\n{r['content']}")
            return '\n\n'.join(contexts)
        
        return "[Code context not available]"
    
    def _get_rag_context(
        self,
        scan_id: str,
        cwe_type: str,
        filepath: str
    ) -> str:
        """Get additional context using RAG"""
        query = f"{cwe_type} vulnerability patterns in {filepath}"
        results = get_code_ingester().retrieve_context(query, scan_id, top_k=3)
        
        if not results:
            return ""
        
        contexts = []
        for r in results:
            contexts.append(f"// File: {r['metadata']['filepath']}\n{r['content']}")
        
        return '\n\n'.join(contexts)
    
    def investigate(
        self,
        scan_id: str,
        codebase_path: str,
        cwe_type: str,
        filepath: str,
        line_number: int,
        alert_message: str
    ) -> Dict[str, Any]:
        """
        Investigate a potential vulnerability
        
        Args:
            scan_id: Scan identifier
            codebase_path: Path to codebase
            cwe_type: CWE type (e.g., "CWE-119")
            filepath: File path
            line_number: Line number
            alert_message: Original alert message
        
        Returns:
            Investigation result dictionary
        """
        start_time = datetime.utcnow()
        
        try:
            # Get code context
            code_context = self._get_code_context(scan_id, filepath, line_number)
            
            # Get RAG context
            rag_context = self._get_rag_context(scan_id, cwe_type, filepath)
            
            # Run Joern for CWE-416
            joern_context = ""
            if cwe_type == "CWE-416":
                joern_result = self._run_joern_analysis(
                    codebase_path, filepath, line_number, cwe_type
                )
                if joern_result:
                    joern_context = f"\n\nJOERN CPG ANALYSIS:\n{joern_result}"
            
            # Format prompt
            prompt = format_investigation_prompt(
                code_context=code_context,
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                alert_message=alert_message,
                joern_context=joern_context
            )
            
            # Call LLM
            llm = self._get_llm()
            messages = [
                SystemMessage(content="You are a security expert analyzing code for vulnerabilities."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            response_text = response.content
            
            # Parse JSON response
            try:
                # Extract JSON from response (handle markdown code blocks)
                json_text = response_text
                if "```json" in json_text:
                    json_text = json_text.split("```json")[1].split("```")[0]
                elif "```" in json_text:
                    json_text = json_text.split("```")[1].split("```")[0]
                
                result = json.loads(json_text.strip())
            except json.JSONDecodeError:
                # Fallback: create structured result from text
                result = {
                    "verdict": "UNKNOWN",
                    "cwe_type": cwe_type,
                    "confidence": 0.5,
                    "explanation": response_text,
                    "vulnerable_code": "",
                    "root_cause": "",
                    "impact": ""
                }
            
            # Calculate inference time
            end_time = datetime.utcnow()
            inference_time = (end_time - start_time).total_seconds()
            
            # Add metadata
            result["inference_time_s"] = inference_time
            result["timestamp"] = end_time.isoformat()
            result["filepath"] = filepath
            result["line_number"] = line_number
            
            return result
            
        except Exception as e:
            end_time = datetime.utcnow()
            inference_time = (end_time - start_time).total_seconds()
            
            return {
                "verdict": "ERROR",
                "cwe_type": cwe_type,
                "confidence": 0.0,
                "explanation": f"Investigation error: {str(e)}",
                "vulnerable_code": "",
                "root_cause": "",
                "impact": "",
                "inference_time_s": inference_time,
                "timestamp": end_time.isoformat(),
                "filepath": filepath,
                "line_number": line_number
            }
    
    def batch_investigate(
        self,
        scan_id: str,
        codebase_path: str,
        alerts: List[Dict[str, Any]],
        progress_callback: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Investigate multiple alerts
        
        Args:
            scan_id: Scan identifier
            codebase_path: Path to codebase
            alerts: List of alert dictionaries
            progress_callback: Optional progress callback
        
        Returns:
            List of investigation results
        """
        results = []
        
        for i, alert in enumerate(alerts):
            result = self.investigate(
                scan_id=scan_id,
                codebase_path=codebase_path,
                cwe_type=alert.get("cwe_type", "UNKNOWN"),
                filepath=alert.get("filepath", ""),
                line_number=alert.get("line_number", 0),
                alert_message=alert.get("message", "")
            )
            
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, len(alerts), result)
        
        return results


# Global investigator instance
investigator = VulnerabilityInvestigator()


def get_investigator() -> VulnerabilityInvestigator:
    """Get the global investigator instance"""
    return investigator
