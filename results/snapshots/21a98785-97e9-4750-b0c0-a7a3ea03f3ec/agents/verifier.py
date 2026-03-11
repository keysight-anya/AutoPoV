"""
AutoPoV Verifier Agent Module
Generates and validates Proof-of-Vulnerability (PoV) scripts
"""

import json
import re
import ast
import os
from typing import Dict, Optional, Any
from datetime import datetime

from langchain_core.messages import SystemMessage, HumanMessage

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
from prompts import (
    format_pov_generation_prompt,
    format_pov_validation_prompt,
    format_retry_analysis_prompt
)
from agents.static_validator import get_static_validator, ValidationResult
from agents.unit_test_runner import get_unit_test_runner, TestResult


class VerificationError(Exception):
    """Exception raised during verification"""
    pass


class VulnerabilityVerifier:
    """Generates and validates PoV scripts"""
    
    def __init__(self):
        self._llm = None
    
    def _get_llm(self, model_name: Optional[str] = None):
        """Get LLM instance based on configuration"""
        if model_name is None and self._llm is not None:
            return self._llm
        
        llm_config = settings.get_llm_config()
        actual_model = model_name or llm_config["model"]
        
        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise VerificationError("OpenAI not available. Install langchain-openai")
            
            api_key = llm_config.get("api_key")
            if not api_key:
                raise VerificationError("OpenRouter API key not configured")
            
            llm = ChatOpenAI(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.2
            )
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
        else:
            if not OLLAMA_AVAILABLE:
                raise VerificationError("Ollama not available. Install langchain-ollama")
            
            llm = ChatOllama(
                model=actual_model,
                base_url=llm_config["base_url"],
                temperature=0.2
            )
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
    
    def generate_pov(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        target_language: str = "python",
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a PoV script for a vulnerability
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: Vulnerable code snippet
            explanation: Vulnerability explanation
            code_context: Surrounding code context
            target_language: Language of the target codebase
            model_name: Optional model name to use
        
        Returns:
            Dictionary with PoV script and metadata
        """
        start_time = datetime.utcnow()
        
        # Determine PoV language based on target
        pov_language = "python"  # Default to Python for most cases
        if target_language in ["javascript", "typescript"]:
            pov_language = "python"
        
        try:
            # Format prompt with language info
            prompt = format_pov_generation_prompt(
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                vulnerable_code=vulnerable_code,
                explanation=explanation,
                code_context=code_context,
                target_language=target_language,
                pov_language=pov_language
            )
            
            # Call LLM with specified model
            llm = self._get_llm(model_name)
            messages = [
                SystemMessage(content=f"You are a security researcher creating {pov_language} Proof-of-Vulnerability scripts."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            pov_script = response.content.strip()
            
            # Get actual cost from response
            actual_cost = 0.0
            token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            
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
                    from agents.investigator import get_investigator
                    inv = get_investigator()
                    actual_cost = inv._calculate_actual_cost(
                        model_name or llm._autopov_model_name,
                        token_usage["prompt_tokens"],
                        token_usage["completion_tokens"]
                    )
            except Exception as e:
                print(f"[CostTracking] Error extracting token usage in verifier: {e}")
            
            # Clean up markdown code blocks if present
            if "```python" in pov_script:
                pov_script = pov_script.split("```python")[1].split("```")[0].strip()
            elif "```javascript" in pov_script:
                pov_script = pov_script.split("```javascript")[1].split("```")[0].strip()
            elif "```" in pov_script:
                pov_script = pov_script.split("```")[1].split("```")[0].strip()
            
            end_time = datetime.utcnow()
            generation_time = (end_time - start_time).total_seconds()
            
            return {
                "success": True,
                "pov_script": pov_script,
                "pov_language": pov_language,
                "target_language": target_language,
                "generation_time_s": generation_time,
                "timestamp": end_time.isoformat(),
                "model_used": model_name or llm._autopov_model_name,
                "cost_usd": actual_cost,
                "token_usage": token_usage
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            return {
                "success": False,
                "error": str(e),
                "pov_script": "",
                "pov_language": pov_language,
                "target_language": target_language,
                "generation_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat()
            }
    
    def validate_pov(
        self,
        pov_script: str,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str = ""
    ) -> Dict[str, Any]:
        """
        Validate a PoV script using hybrid approach:
        1. Static analysis (fast)
        2. Unit test execution (if code available)
        3. LLM validation (fallback)
        
        Args:
            pov_script: Python script to validate
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: The vulnerable code snippet (optional)
        
        Returns:
            Validation result dictionary
        """
        result = {
            "is_valid": True,
            "issues": [],
            "suggestions": [],
            "will_trigger": "MAYBE",
            "validation_method": "unknown",
            "static_result": None,
            "unit_test_result": None
        }
        
        # ===== STEP 1: Static Validation (Always run - fast) =====
        static_validator = get_static_validator()
        static_result = static_validator.validate(
            pov_script=pov_script,
            cwe_type=cwe_type,
            vulnerable_code=vulnerable_code,
            filepath=filepath,
            line_number=line_number
        )
        
        result["static_result"] = {
            "is_valid": static_result.is_valid,
            "confidence": static_result.confidence,
            "matched_patterns": static_result.matched_patterns,
            "issues": static_result.issues
        }
        
        result["issues"].extend(static_result.issues)
        
        # If static validation passes with high confidence, we're done
        if static_result.is_valid and static_result.confidence >= 0.8:
            result["is_valid"] = True
            result["will_trigger"] = "LIKELY"
            result["validation_method"] = "static_analysis"
            result["suggestions"].append(f"Static validation passed with {static_result.confidence:.0%} confidence")
            return result
        
        # ===== STEP 2: Unit Test Validation (If vulnerable code available) =====
        if vulnerable_code and len(vulnerable_code) > 10:
            unit_runner = get_unit_test_runner()
            
            # First check syntax
            syntax_check = unit_runner.validate_syntax(pov_script)
            if not syntax_check["valid"]:
                result["is_valid"] = False
                result["issues"].append(f"Syntax error: {syntax_check['error']}")
                return result
            
            # Run unit test
            unit_result = unit_runner.test_vulnerable_function(
                pov_script=pov_script,
                vulnerable_code=vulnerable_code,
                cwe_type=cwe_type,
                scan_id=f"validate_{cwe_type}_{line_number}"
            )
            
            result["unit_test_result"] = {
                "success": unit_result.success,
                "vulnerability_triggered": unit_result.vulnerability_triggered,
                "execution_time_s": unit_result.execution_time_s,
                "exit_code": unit_result.exit_code,
                "stdout": unit_result.stdout[:500] if unit_result.stdout else "",  # Truncate
                "stderr": unit_result.stderr[:500] if unit_result.stderr else ""  # Truncate
            }
            
            if unit_result.vulnerability_triggered:
                result["is_valid"] = True
                result["will_trigger"] = "YES"
                result["validation_method"] = "unit_test_execution"
                result["suggestions"].append("Unit test execution confirmed vulnerability trigger")
                return result
            elif unit_result.success:
                result["will_trigger"] = "MAYBE"
                result["validation_method"] = "unit_test_execution"
                result["suggestions"].append("Unit test ran but did not trigger vulnerability")
            else:
                result["issues"].append(f"Unit test failed: {unit_result.stderr[:200]}")
        
        # ===== STEP 3: Traditional Validation (Fallback) =====
        # Check 1: Syntax validation using AST
        try:
            ast.parse(pov_script)
        except SyntaxError as e:
            result["is_valid"] = False
            result["issues"].append(f"Syntax error: {str(e)}")
            return result
        
        # Check 2: Must contain "VULNERABILITY TRIGGERED"
        if "VULNERABILITY TRIGGERED" not in pov_script:
            result["is_valid"] = False
            result["issues"].append("Missing required 'VULNERABILITY TRIGGERED' print statement")
        
        # Check 3: Only standard library imports
        disallowed_imports = []
        stdlib_modules = self._get_stdlib_modules()
        try:
            tree = ast.parse(pov_script)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_module = alias.name.split('.')[0]
                        if top_module not in stdlib_modules:
                            disallowed_imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_module = node.module.split('.')[0]
                        if top_module not in stdlib_modules:
                            disallowed_imports.append(node.module)
        except Exception:
            pass
        
        if disallowed_imports:
            result["issues"].append(f"Non-stdlib imports detected: {', '.join(disallowed_imports)}")
        
        # Check 4: CWE-specific validation
        cwe_issues = self._validate_cwe_specific(pov_script, cwe_type)
        result["issues"].extend(cwe_issues)
        
        # Check 5: Use LLM for advanced validation (only if other methods inconclusive)
        if result["validation_method"] == "unknown":
            try:
                llm_result = self._llm_validate_pov(
                    pov_script, cwe_type, filepath, line_number
                )
                result["will_trigger"] = llm_result.get("will_trigger", "MAYBE")
                result["suggestions"].extend(llm_result.get("suggestions", []))
                result["issues"].extend(llm_result.get("issues", []))
                result["validation_method"] = "llm_analysis"
            except Exception as e:
                result["suggestions"].append(f"LLM validation skipped: {str(e)}")
        
        # Final validity check
        if result["issues"] and not result.get("unit_test_result", {}).get("vulnerability_triggered"):
            # If unit test didn't trigger but also didn't fail completely, still might be valid
            critical_issues = [i for i in result["issues"] if "Syntax" in i or "Missing required" in i]
            if critical_issues:
                result["is_valid"] = False
        
        return result
    
    def _get_stdlib_modules(self) -> set:
        """Get Python standard library module names"""
        return {
            'abc', 'argparse', 'array', 'ast', 'asyncio', 'base64', 'binascii',
            'binhex', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb',
            'chunk', 'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections',
            'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
            'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes',
            'curses', 'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib',
            'dis', 'distutils', 'doctest', 'email', 'encodings', 'enum', 'errno',
            'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions',
            'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext', 'glob',
            'graphlib', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http',
            'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io',
            'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
            'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math',
            'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc',
            'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev',
            'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform',
            'plistlib', 'poplib', 'posix', 'posixpath', 'pprint', 'profile',
            'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue',
            'quopri', 'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
            'runpy', 'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
            'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket',
            'socketserver', 'spwd', 'sqlite3', 'ssl', 'stat', 'statistics',
            'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
            'sys', 'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib',
            'tempfile', 'termios', 'test', 'textwrap', 'threading', 'time',
            'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
            'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing',
            'unicodedata', 'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings',
            'wave', 'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref',
            'xdrlib', 'xml', 'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
            '_thread', '__future__'
        }
    
    def _validate_cwe_specific(self, pov_script: str, cwe_type: str) -> list:
        """CWE-specific validation rules"""
        issues = []
        
        if cwe_type == "CWE-119":  # Buffer Overflow
            # Should try to write beyond buffer
            if not any(pattern in pov_script.lower() for pattern in [
                "buffer", "overflow", "size", "length", "* "
            ]):
                issues.append("CWE-119: May not effectively trigger buffer overflow")
        
        elif cwe_type == "CWE-89":  # SQL Injection
            # Should contain SQL keywords
            sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', "'", '"']
            if not any(kw in pov_script.lower() for kw in sql_keywords):
                issues.append("CWE-89: May not contain SQL injection payload")
        
        elif cwe_type == "CWE-416":  # Use After Free
            # This typically requires C code
            issues.append("CWE-416: Use-after-free may require C code execution")
        
        elif cwe_type == "CWE-190":  # Integer Overflow
            # Should use large numbers
            if not re.search(r'\d{10,}', pov_script):
                issues.append("CWE-190: May not use values large enough to overflow")
        
        return issues
    
    def _llm_validate_pov(
        self,
        pov_script: str,
        cwe_type: str,
        filepath: str,
        line_number: int
    ) -> Dict[str, Any]:
        """Use LLM to validate PoV script"""
        prompt = format_pov_validation_prompt(
            pov_script=pov_script,
            cwe_type=cwe_type,
            filepath=filepath,
            line_number=line_number
        )
        
        llm = self._get_llm()
        messages = [
            SystemMessage(content="You are validating security test scripts."),
            HumanMessage(content=prompt)
        ]
        
        response = llm.invoke(messages)
        
        try:
            json_text = response.content
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            return json.loads(json_text.strip())
        except json.JSONDecodeError:
            return {
                "is_valid": True,
                "issues": [],
                "suggestions": [],
                "will_trigger": "MAYBE"
            }
    
    def analyze_failure(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        explanation: str,
        failed_pov: str,
        execution_output: str,
        attempt_number: int,
        max_retries: int
    ) -> Dict[str, Any]:
        """
        Analyze why a PoV failed and suggest improvements
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            explanation: Vulnerability explanation
            failed_pov: The failed PoV script
            execution_output: Output from execution
            attempt_number: Current attempt number
            max_retries: Maximum retries allowed
        
        Returns:
            Analysis result with suggestions
        """
        prompt = format_retry_analysis_prompt(
            cwe_type=cwe_type,
            filepath=filepath,
            line_number=line_number,
            explanation=explanation,
            failed_pov=failed_pov,
            execution_output=execution_output,
            attempt_number=attempt_number,
            max_retries=max_retries
        )
        
        llm = self._get_llm()
        messages = [
            SystemMessage(content="You are analyzing failed security tests."),
            HumanMessage(content=prompt)
        ]
        
        response = llm.invoke(messages)
        
        try:
            json_text = response.content
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            return json.loads(json_text.strip())
        except json.JSONDecodeError:
            return {
                "failure_reason": "Could not parse analysis",
                "suggested_changes": "Review execution output manually",
                "different_approach": attempt_number >= max_retries
            }


# Global verifier instance
verifier = VulnerabilityVerifier()


def get_verifier() -> VulnerabilityVerifier:
    """Get the global verifier instance"""
    return verifier
