"""
AutoPoV Investigator Agent Module
Uses RAG and LLM to investigate potential vulnerabilities
"""

import json
import subprocess
import os
from typing import Dict, Optional, Any, List, Callable
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
    
    def _get_llm(self, model_name: Optional[str] = None, api_key_override: Optional[str] = None):
        """Get LLM instance based on configuration"""
        # Always create new instance if model_name or key override is specified
        if model_name is None and api_key_override is None and self._llm is not None:
            return self._llm

        llm_config = settings.get_llm_config()

        # Use provided model_name or fall back to config
        actual_model = model_name or llm_config["model"]

        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise InvestigationError("OpenAI not available. Install langchain-openai")

            # Use per-request override key if provided, else fall back to env config
            api_key = api_key_override or llm_config.get("api_key")
            
            if not api_key:
                raise InvestigationError("OpenRouter API key not configured. Set OPENROUTER_API_KEY environment variable.")
            
            callbacks = [self._tracer] if self._tracer else None
            
            llm = ChatOpenAI(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.1,
                callbacks=callbacks
            )
            
            # Store model info for cost tracking
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
        else:
            if not OLLAMA_AVAILABLE:
                raise InvestigationError("Ollama not available. Install langchain-ollama")
            
            callbacks = [self._tracer] if self._tracer else None
            
            llm = ChatOllama(
                model=actual_model,
                base_url=llm_config["base_url"],
                temperature=0.1,
                callbacks=callbacks
            )
            
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
    
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
        alert_message: str,
        model_name: Optional[str] = None,
        api_key_override: Optional[str] = None
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
            model_name: Optional model name to use (overrides default)
        
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
            
            # Call LLM with specified model and optional key override
            llm = self._get_llm(model_name, api_key_override=api_key_override)
            messages = [
                SystemMessage(content="You are a security expert analyzing code for vulnerabilities."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            response_text = response.content
            
            # Get actual token usage and cost from response
            actual_cost = 0.0
            token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            

            
            # Try multiple ways to extract token usage from LangChain/OpenRouter response
            try:
                # Method 1: Check for usage_metadata (newer LangChain versions)
                if hasattr(response, 'usage_metadata') and response.usage_metadata:
                    um = response.usage_metadata
                    token_usage = {
                        "prompt_tokens": um.get('input_tokens', 0) or um.get('prompt_tokens', 0),
                        "completion_tokens": um.get('output_tokens', 0) or um.get('completion_tokens', 0),
                        "total_tokens": um.get('total_tokens', 0)
                    }
                # Method 2: Check for response_metadata (older LangChain versions)
                elif hasattr(response, 'response_metadata') and response.response_metadata:
                    rm = response.response_metadata
                    # Try to get usage from response_metadata
                    if 'token_usage' in rm:
                        usage = rm['token_usage']
                        token_usage = {
                            "prompt_tokens": usage.get('prompt_tokens', 0),
                            "completion_tokens": usage.get('completion_tokens', 0),
                            "total_tokens": usage.get('total_tokens', 0)
                        }
                    elif 'usage' in rm:
                        usage = rm['usage']
                        token_usage = {
                            "prompt_tokens": usage.get('prompt_tokens', 0) or usage.get('input_tokens', 0),
                            "completion_tokens": usage.get('completion_tokens', 0) or usage.get('output_tokens', 0),
                            "total_tokens": usage.get('total_tokens', 0)
                        }
                
                # Calculate cost if we have token usage
                if token_usage["total_tokens"] > 0:
                    actual_cost = self._calculate_actual_cost(
                        model_name or llm._autopov_model_name,
                        token_usage["prompt_tokens"],
                        token_usage["completion_tokens"]
                    )
                    print(f"[CostTracking] Model: {model_name or llm._autopov_model_name}, Tokens: {token_usage}, Cost: ${actual_cost:.6f}")
            except Exception as e:
                print(f"[CostTracking] Error extracting token usage: {e}")
            
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
            result["model_used"] = model_name or llm._autopov_model_name
            result["cost_usd"] = actual_cost
            result["token_usage"] = token_usage
            
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
    
    def _calculate_actual_cost(self, model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        """
        Calculate actual cost based on OpenRouter pricing
        Prices per 1M tokens (as of March 2025)
        """
        # OpenRouter pricing per 1M tokens (input/output)
        pricing = {
            # OpenAI models
            "openai/gpt-4o": (2.50, 10.00),
            "openai/gpt-4o-mini": (0.15, 0.60),
            "openai/gpt-4-turbo": (10.00, 30.00),
            
            # Anthropic models
            "anthropic/claude-3.5-sonnet": (3.00, 15.00),
            "anthropic/claude-3-opus": (15.00, 75.00),
            "anthropic/claude-3-haiku": (0.25, 1.25),
            
            # Google models
            "google/gemini-2.0-flash-001": (0.10, 0.40),
            
            # Meta models
            "meta-llama/llama-3.3-70b-instruct": (0.70, 1.50),
            
            # DeepSeek
            "deepseek/deepseek-chat": (0.50, 2.00),
            
            # Qwen
            "qwen/qwen-2.5-72b-instruct": (0.50, 1.50),
        }
        
        # Get pricing for model (default to GPT-4o if unknown)
        input_price, output_price = pricing.get(model_name, (2.50, 10.00))
        
        # Calculate cost (prices are per 1M tokens)
        input_cost = (prompt_tokens / 1_000_000) * input_price
        output_cost = (completion_tokens / 1_000_000) * output_price
        
        return round(input_cost + output_cost, 6)
    
    def batch_investigate(
        self,
        scan_id: str,
        codebase_path: str,
        alerts: List[Dict[str, Any]],
        progress_callback: Optional[Callable] = None
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
                alert_message=alert.get("alert_message", "")
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
