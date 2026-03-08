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


class VerificationError(Exception):
    """Exception raised during verification"""
    pass


class VulnerabilityVerifier:
    """Generates and validates PoV scripts"""
    
    def __init__(self):
        self._llm = None
    
    def _get_llm(self):
        """Get LLM instance based on configuration"""
        if self._llm is not None:
            return self._llm
        
        llm_config = settings.get_llm_config()
        
        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise VerificationError("OpenAI not available. Install langchain-openai")
            
            api_key = llm_config.get("api_key")
            if not api_key:
                raise VerificationError("OpenRouter API key not configured")
            
            self._llm = ChatOpenAI(
                model=llm_config["model"],
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.2
            )
        else:
            if not OLLAMA_AVAILABLE:
                raise VerificationError("Ollama not available. Install langchain-ollama")
            
            self._llm = ChatOllama(
                model=llm_config["model"],
                base_url=llm_config["base_url"],
                temperature=0.2
            )
        
        return self._llm
    
    def generate_pov(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str,
        explanation: str,
        code_context: str
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
        
        Returns:
            Dictionary with PoV script and metadata
        """
        start_time = datetime.utcnow()
        
        try:
            # Format prompt
            prompt = format_pov_generation_prompt(
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                vulnerable_code=vulnerable_code,
                explanation=explanation,
                code_context=code_context
            )
            
            # Call LLM
            llm = self._get_llm()
            messages = [
                SystemMessage(content="You are a security researcher creating Proof-of-Vulnerability scripts."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            pov_script = response.content.strip()
            
            # Clean up markdown code blocks if present
            if "```python" in pov_script:
                pov_script = pov_script.split("```python")[1].split("```")[0].strip()
            elif "```" in pov_script:
                pov_script = pov_script.split("```")[1].split("```")[0].strip()
            
            end_time = datetime.utcnow()
            generation_time = (end_time - start_time).total_seconds()
            
            return {
                "success": True,
                "pov_script": pov_script,
                "generation_time_s": generation_time,
                "timestamp": end_time.isoformat()
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            return {
                "success": False,
                "error": str(e),
                "pov_script": "",
                "generation_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat()
            }
    
    def validate_pov(
        self,
        pov_script: str,
        cwe_type: str,
        filepath: str,
        line_number: int
    ) -> Dict[str, Any]:
        """
        Validate a PoV script
        
        Args:
            pov_script: Python script to validate
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
        
        Returns:
            Validation result dictionary
        """
        result = {
            "is_valid": True,
            "issues": [],
            "suggestions": [],
            "will_trigger": "MAYBE"
        }
        
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
        try:
            tree = ast.parse(pov_script)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name not in self._get_stdlib_modules():
                            disallowed_imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module not in self._get_stdlib_modules():
                        disallowed_imports.append(node.module)
        except Exception:
            pass
        
        if disallowed_imports:
            result["issues"].append(f"Non-stdlib imports detected: {', '.join(disallowed_imports)}")
        
        # Check 4: CWE-specific validation
        cwe_issues = self._validate_cwe_specific(pov_script, cwe_type)
        result["issues"].extend(cwe_issues)
        
        # Check 5: Use LLM for advanced validation
        try:
            llm_result = self._llm_validate_pov(
                pov_script, cwe_type, filepath, line_number
            )
            result["will_trigger"] = llm_result.get("will_trigger", "MAYBE")
            result["suggestions"] = llm_result.get("suggestions", [])
            result["issues"].extend(llm_result.get("issues", []))
        except Exception as e:
            result["suggestions"].append(f"LLM validation skipped: {str(e)}")
        
        # Final validity check
        if result["issues"]:
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
