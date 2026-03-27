"""
AutoPoV Verifier Agent Module
Generates and validates Proof-of-Vulnerability (PoV) scripts
"""

import json
import re
import ast
import os
from typing import Dict, Optional, Any, List
from pathlib import Path
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
from app.openrouter_client import OpenRouterReasoningChat, extract_usage_details
from prompts import (
    format_pov_generation_prompt,
    format_pov_generation_prompt_offline,
    format_pov_validation_prompt,
    format_pov_validation_prompt_offline,
    format_retry_analysis_prompt,
    format_retry_analysis_prompt_offline,
    format_pov_refinement_prompt,
    format_pov_refinement_prompt_offline,
)
from agents.static_validator import get_static_validator, ValidationResult
from agents.unit_test_runner import get_unit_test_runner, TestResult


class VerificationError(Exception):
    """Exception raised during verification"""
    pass


class VulnerabilityVerifier:
    NATIVE_INVALID_ENTRYPOINTS = {
        "if", "for", "while", "switch", "return", "sizeof", "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strcmp", "unknown", "main-like",
    }
    """Generates and validates PoV scripts"""
    
    def __init__(self):
        self._llm = None

    def _infer_runtime_profile_from_filepath(self, filepath: str) -> str:
        ext = Path(filepath or '').suffix.lower()
        if ext in {'.c', '.h'}:
            return 'c'
        if ext in {'.cc', '.cpp', '.cxx', '.hpp'}:
            return 'cpp'
        if ext in {'.js', '.jsx'}:
            return 'javascript'
        if ext in {'.ts', '.tsx'}:
            return 'node'
        if ext == '.py':
            return 'python'
        return ''

    def _infer_pov_script_runtime(self, pov_script: str) -> str:
        script = str(pov_script or '')
        stripped = script.lstrip()
        if stripped.startswith('<?php'):
            return 'php'
        if stripped.startswith('#!/bin/bash') or stripped.startswith('#!/usr/bin/env bash'):
            return 'shell'
        if stripped.startswith('#!/usr/bin/env node') or 'console.log(' in script or 'require(' in script or 'process.env' in script:
            return 'javascript'
        return 'python'

    def _validate_pov_script_syntax(self, pov_script: str) -> Optional[str]:
        runtime = self._infer_pov_script_runtime(pov_script)
        try:
            if runtime == 'python':
                ast.parse(pov_script)
                return None
            if runtime == 'javascript':
                syntax_check = get_unit_test_runner().validate_syntax(pov_script, runtime_profile='javascript')
                if syntax_check.get('valid'):
                    return None
                return syntax_check.get('error') or 'JavaScript syntax error'
            return None
        except SyntaxError as e:
            return str(e)
        except Exception as e:
            return str(e)

    def _extract_target_entrypoint(self, vulnerable_code: str, filepath: str) -> str:
        patterns = [
            r'(?:static\s+)?(?:[\w\*\s]+)\s+(\w+)\s*\([^;]*\)\s*\{',
            r'def\s+(\w+)\s*\(',
            r'function\s+(\w+)\s*\(',
        ]
        for pattern in patterns:
            match = re.search(pattern, vulnerable_code or '')
            if match:
                candidate = match.group(1)
                if candidate.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                    return candidate
        return 'unknown'

    def _canonicalize_target_entrypoint(self, value: Any, vulnerable_code: str, explanation: str, filepath: str, runtime_profile: str = '') -> str:
        candidate = str(value or '').strip()
        if not candidate or candidate == 'unknown':
            return self._extract_target_entrypoint(vulnerable_code or explanation, filepath)
        if candidate.startswith('/') or candidate.startswith('http://') or candidate.startswith('https://'):
            return candidate
        if runtime_profile in {'c', 'cpp', 'native', 'binary'}:
            lowered = candidate.lower()
            if lowered.startswith('the ') and 'main-like entrypoint' in lowered:
                return 'main'
            if re.fullmatch(r'[A-Za-z_]\w*', candidate):
                return candidate if lowered not in self.NATIVE_INVALID_ENTRYPOINTS else 'unknown'
            if re.fullmatch(r'[A-Za-z_]\w*\s*\([^\)]*\)', candidate):
                match = re.match(r'([A-Za-z_]\w*)\s*\(', candidate)
                if match:
                    symbol = match.group(1)
                    if symbol.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                        return symbol
            backticked = re.search(r'`([A-Za-z_]\w*)\s*\(', candidate)
            if backticked and backticked.group(1).lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                return backticked.group(1)
            inferred = self._extract_target_entrypoint(vulnerable_code or explanation, filepath)
            if inferred and inferred.lower() not in self.NATIVE_INVALID_ENTRYPOINTS:
                return inferred
            return 'unknown'
        if re.fullmatch(r'[A-Za-z_]\w*', candidate):
            return candidate
        match = re.search(r'([A-Za-z_]\w*)\s*\([^\)]*\)', candidate)
        if match:
            return match.group(1)
        return candidate

    def _default_exploit_contract(self, cwe_type: str, explanation: str, vulnerable_code: str, filepath: str = '') -> Dict[str, Any]:
        runtime_profile = self._infer_runtime_profile_from_filepath(filepath)
        target_entrypoint = self._extract_target_entrypoint(vulnerable_code, filepath)
        inputs = []
        trigger_steps = ["Invoke the vulnerable code path with attacker-controlled input"]
        if cwe_type in {'CWE-120', 'CWE-121', 'CWE-122'}:
            inputs = ['oversized input string', 'undersized destination buffer']
            trigger_steps = [f'Call {target_entrypoint} with an input longer than the destination buffer', 'Observe memory corruption, crash, or sanitizer evidence']
        elif cwe_type == 'CWE-690':
            inputs = ['resource-constrained memory limit', 'oversized allocation request']
            trigger_steps = [f'Reach {target_entrypoint} with an attacker-controlled size or allocation parameter', 'Force allocation failure deterministically and observe NULL dereference or crash']
        return {
            "goal": explanation or "Demonstrate exploitability of the candidate vulnerability",
            "target_entrypoint": target_entrypoint,
            "runtime_profile": runtime_profile,
            "http_method": "GET",
            "target_url": "",
            "base_url": "",
            "preconditions": [],
            "inputs": inputs,
            "trigger_steps": trigger_steps,
            "success_indicators": ["VULNERABILITY TRIGGERED"],
            "side_effects": [],
            "expected_outcome": "The exploit should trigger observable unsafe behavior"
        }

    def _normalize_exploit_contract(self, contract: Optional[Dict[str, Any]], cwe_type: str, explanation: str, vulnerable_code: str, filepath: str = '') -> Dict[str, Any]:
        defaults = self._default_exploit_contract(cwe_type, explanation, vulnerable_code, filepath=filepath)
        merged = dict(defaults)
        if isinstance(contract, dict):
            for key, value in contract.items():
                if value not in (None, '', [], {}):
                    merged[key] = value
        if not merged.get('runtime_profile'):
            merged['runtime_profile'] = defaults.get('runtime_profile', '')
        merged['target_entrypoint'] = self._canonicalize_target_entrypoint(
            merged.get('target_entrypoint'),
            vulnerable_code,
            explanation,
            filepath,
            runtime_profile=merged.get('runtime_profile', '')
        )
        if not merged.get('success_indicators'):
            merged['success_indicators'] = defaults.get('success_indicators', ['VULNERABILITY TRIGGERED'])
        if merged.get('runtime_profile') in {'c', 'cpp', 'native', 'binary'}:
            native_indicators = [
                'VULNERABILITY TRIGGERED',
                'AddressSanitizer',
                'UndefinedBehaviorSanitizer',
                'Segmentation fault',
                'SIGSEGV',
            ]
            merged['success_indicators'] = list(dict.fromkeys([*(merged.get('success_indicators') or []), *native_indicators]))
        if not merged.get('trigger_steps'):
            merged['trigger_steps'] = defaults.get('trigger_steps', [])
        if not merged.get('inputs'):
            merged['inputs'] = defaults.get('inputs', [])
        return merged

    def _parse_pov_payload(self, raw_content: str, cwe_type: str, explanation: str, vulnerable_code: str, filepath: str = '') -> Dict[str, Any]:
        payload = raw_content.strip()
        if payload.startswith("```"):
            payload = payload.split("```", 2)[1 if "```json" not in payload else 1]
        try:
            cleaned = raw_content.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0]
            elif cleaned.startswith("```"):
                cleaned = cleaned.split("```", 1)[1].rsplit("```", 1)[0]
            data = json.loads(cleaned.strip())
            pov_script = (data.get("pov_script") or "").strip()
            contract = self._normalize_exploit_contract(data.get("exploit_contract") or {}, cwe_type, explanation, vulnerable_code, filepath=filepath)
            if pov_script:
                return {"pov_script": pov_script, "exploit_contract": contract}
            if isinstance(data, dict) and any(k in data for k in ["failure_reason", "suggested_changes", "different_approach"]):
                return {"pov_script": "", "exploit_contract": contract}
        except Exception:
            pass

        pov_script = raw_content.strip()
        if "```python" in pov_script:
            pov_script = pov_script.split("```python", 1)[1].split("```", 1)[0].strip()
        elif "```javascript" in pov_script:
            pov_script = pov_script.split("```javascript", 1)[1].split("```", 1)[0].strip()
        elif "```" in pov_script:
            pov_script = pov_script.split("```", 1)[1].split("```", 1)[0].strip()
        return {"pov_script": pov_script, "exploit_contract": self._normalize_exploit_contract({}, cwe_type, explanation, vulnerable_code, filepath=filepath)}

    
    def _is_offline_model_selected(self, model_name: Optional[str] = None) -> bool:
        selected_model = (model_name or settings.MODEL_NAME or '').strip()
        return settings.is_offline_model(selected_model)

    def _compact_text(self, value: str, max_chars: int) -> str:
        text = (value or '').strip()
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        if max_chars <= 160:
            return text[:max_chars].rstrip()
        head = max_chars // 2
        tail = max_chars - head - len('\n...\n')
        return f"{text[:head].rstrip()}\n...\n{text[-max(0, tail):].lstrip()}"

    def _trim_validation_errors(self, validation_errors: List[str], max_items: int, max_chars: int) -> List[str]:
        trimmed = []
        for item in (validation_errors or [])[:max_items]:
            trimmed.append(self._compact_text(str(item), max_chars))
        return trimmed

    def _prepare_offline_pov_inputs(
        self,
        model_name: Optional[str],
        purpose: str,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        failed_pov: str = '',
        validation_errors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        budget = settings.get_offline_pov_budget(model_name=model_name, purpose=purpose)
        return {
            'vulnerable_code': self._compact_text(vulnerable_code, budget['max_vulnerable_code_chars']),
            'explanation': self._compact_text(explanation, budget['max_explanation_chars']),
            'code_context': self._compact_text(code_context, budget['max_context_chars']),
            'failed_pov': self._compact_text(failed_pov, budget['max_failed_pov_chars']),
            'validation_errors': self._trim_validation_errors(
                validation_errors or [],
                budget['max_error_items'],
                budget['max_validation_error_chars'],
            ),
        }

    def _get_llm(self, model_name: Optional[str] = None, purpose: str = "general"):
        """Get LLM instance based on configuration"""
        llm_config = settings.get_llm_config(model_name=model_name)
        actual_model = model_name or llm_config["model"]
        
        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise VerificationError("OpenAI not available. Install langchain-openai")
            
            api_key = llm_config.get("api_key")
            if not api_key:
                raise VerificationError("OpenRouter API key not configured")
            
            llm = OpenRouterReasoningChat(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.2,
                timeout=settings.LLM_REQUEST_TIMEOUT_S,
                reasoning_enabled=llm_config.get("reasoning_enabled", True),
                default_headers={
                    "HTTP-Referer": "https://autopov.local",
                    "X-OpenRouter-Title": "AutoPoV"
                }
            )
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            return llm
        else:
            if not OLLAMA_AVAILABLE:
                raise VerificationError("Ollama not available. Install langchain-ollama")
            
            offline_options = settings.get_ollama_generation_options(actual_model, purpose=purpose)
            llm = ChatOllama(
                model=actual_model,
                base_url=llm_config["base_url"],
                temperature=0.2,
                num_ctx=offline_options["num_ctx"],
                num_predict=offline_options["num_predict"],
                client_kwargs=settings.get_ollama_client_kwargs(actual_model, purpose=purpose)
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
        model_name: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None
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
            if self._is_offline_model_selected(model_name):
                offline_inputs = self._prepare_offline_pov_inputs(
                    model_name,
                    "pov",
                    vulnerable_code,
                    explanation,
                    code_context,
                )
                prompt = format_pov_generation_prompt_offline(
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    vulnerable_code=offline_inputs["vulnerable_code"],
                    explanation=offline_inputs["explanation"],
                    code_context=offline_inputs["code_context"],
                    target_language=target_language,
                    pov_language=pov_language
                )
                llm = self._get_llm(model_name, purpose="pov")
            else:
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
                llm = self._get_llm(model_name)
            
            # Call LLM with specified model
            messages = [
                SystemMessage(content=f"You are a security researcher creating {pov_language} Proof-of-Vulnerability scripts."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            parsed = self._parse_pov_payload(response.content, cwe_type, explanation, vulnerable_code, filepath=filepath)
            pov_script = parsed["pov_script"]
            if not pov_script.strip():
                raise VerificationError("Model did not return executable PoV code")
            exploit_contract = self._normalize_exploit_contract(parsed["exploit_contract"], cwe_type, explanation, vulnerable_code, filepath=filepath)
            
            usage_details = extract_usage_details(response, agent_role="pov_generation")
            actual_cost = usage_details["cost_usd"]
            token_usage = usage_details["token_usage"]
            openrouter_usage = usage_details["openrouter_usage"]
            
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
                "exploit_contract": exploit_contract,
                "generation_time_s": generation_time,
                "timestamp": end_time.isoformat(),
                "model_used": model_name or llm._autopov_model_name,
                "cost_usd": actual_cost,
                "token_usage": token_usage,
                "openrouter_usage": openrouter_usage
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
        vulnerable_code: str = "",
        exploit_contract: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None
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

        syntax_error = self._validate_pov_script_syntax(pov_script)
        if syntax_error:
            result["is_valid"] = False
            result["issues"].append(f"Syntax error: {syntax_error}")
            return result
        
        # ===== STEP 1: Static Validation (Always run - fast) =====
        static_validator = get_static_validator()
        static_result = static_validator.validate(
            pov_script=pov_script,
            cwe_type=cwe_type,
            vulnerable_code=vulnerable_code,
            filepath=filepath,
            line_number=line_number,
            exploit_contract=exploit_contract or {}
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
        # ===== STEP 2: Unit Test Validation (If the snippet is executable in the unit harness) =====
        runtime_profile = self._infer_runtime_profile_from_filepath(filepath)
        unit_test_supported = runtime_profile in {"python", "javascript", "node"} or bool(re.search(r"(^|\n)\s*(def\s+|function\s+|async\s+function\s+)", vulnerable_code or ""))
        if vulnerable_code and len(vulnerable_code) > 10 and unit_test_supported:
            unit_runner = get_unit_test_runner()
            normalized_runtime = "javascript" if runtime_profile in {"javascript", "node"} else "python"
            
            # First check syntax
            syntax_check = unit_runner.validate_syntax(pov_script, runtime_profile=normalized_runtime)
            if not syntax_check["valid"]:
                result["is_valid"] = False
                result["issues"].append(f"Syntax error: {syntax_check['error']}")
                return result
            
            # Run unit test
            unit_result = unit_runner.test_vulnerable_function(
                pov_script=pov_script,
                vulnerable_code=vulnerable_code,
                cwe_type=cwe_type,
                scan_id=f"validate_{cwe_type}_{line_number}",
                exploit_contract=exploit_contract or {},
                runtime_profile=normalized_runtime,
                filepath=filepath,
            )
            
            # Extract oracle evidence from unit test details
            oracle_result = unit_result.details.get("oracle", {})
            
            result["unit_test_result"] = {
                "success": unit_result.success,
                "vulnerability_triggered": unit_result.vulnerability_triggered,
                "execution_time_s": unit_result.execution_time_s,
                "exit_code": unit_result.exit_code,
                "stdout": unit_result.stdout[:500] if unit_result.stdout else "",  # Truncate
                "stderr": unit_result.stderr[:500] if unit_result.stderr else "",  # Truncate
                "oracle": oracle_result  # Include detailed oracle evidence
            }
            
            if unit_result.vulnerability_triggered:
                result["is_valid"] = True
                result["will_trigger"] = "YES"
                result["validation_method"] = "unit_test_execution"
                
                # Add detailed evidence to suggestions
                evidence = oracle_result.get("evidence", [])
                confidence = oracle_result.get("confidence", "low")
                method = oracle_result.get("method", "unknown")
                
                if evidence:
                    result["suggestions"].append(f"Vulnerability confirmed with {confidence} confidence ({method}):")
                    for item in evidence[:3]:  # Show top 3 evidence items
                        result["suggestions"].append(f"  - {item}")
                else:
                    result["suggestions"].append("Unit test execution confirmed vulnerability trigger")
                
                return result
            elif unit_result.success:
                result["will_trigger"] = "MAYBE"
                result["validation_method"] = "unit_test_execution"
                result["suggestions"].append("Unit test ran but did not trigger vulnerability")
            else:
                result["issues"].append(f"Unit test failed: {unit_result.stderr[:200]}")
        elif vulnerable_code and len(vulnerable_code) > 10:
            result["suggestions"].append("Skipped unit-test harness for non-Python/non-JavaScript target code")
        
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
        if cwe_type and cwe_type != "UNCLASSIFIED":
            cwe_issues = self._validate_cwe_specific(pov_script, cwe_type)
            result["issues"].extend(cwe_issues)
        
        # Check 5: Use LLM for advanced validation (only if other methods inconclusive)
        if result["validation_method"] == "unknown":
            try:
                llm_result = self._llm_validate_pov(
                    pov_script, cwe_type, filepath, line_number, exploit_contract or {}, model_name
                )
                result["will_trigger"] = llm_result.get("will_trigger", "MAYBE")
                result["suggestions"].extend(llm_result.get("suggestions", []))
                result["issues"].extend(llm_result.get("issues", []))
                result["validation_method"] = "llm_analysis"
                result["token_usage"] = llm_result.get("token_usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
                result["cost_usd"] = llm_result.get("cost_usd", 0.0)
                result["openrouter_usage"] = llm_result.get("openrouter_usage", {})
            except Exception as e:
                result["suggestions"].append(f"LLM validation skipped: {str(e)}")
        
        # Final validity check
        unit_test_result = result.get("unit_test_result") or {}
        if result["issues"] and not unit_test_result.get("vulnerability_triggered"):
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
        line_number: int,
        exploit_contract: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Use LLM to validate PoV script"""
        if self._is_offline_model_selected(model_name):
            trimmed_script = self._compact_text(
                pov_script,
                settings.get_offline_pov_budget(model_name=model_name, purpose="validation")["max_failed_pov_chars"],
            )
            prompt = format_pov_validation_prompt_offline(
                pov_script=trimmed_script,
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                exploit_contract=exploit_contract or {}
            )
            llm = self._get_llm(model_name, purpose="validation")
        else:
            prompt = format_pov_validation_prompt(
                pov_script=pov_script,
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                exploit_contract=exploit_contract or {}
            )
            llm = self._get_llm(model_name)
        messages = [
            SystemMessage(content="You are validating security test scripts."),
            HumanMessage(content=prompt)
        ]
        
        response = llm.invoke(messages)
        usage_details = extract_usage_details(response, agent_role="llm_validation")
        
        try:
            json_text = response.content
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0]
            elif "```" in json_text:
                json_text = json_text.split("```")[1].split("```")[0]
            
            parsed = json.loads(json_text.strip())
            parsed["token_usage"] = usage_details["token_usage"]
            parsed["cost_usd"] = usage_details["cost_usd"]
            parsed["openrouter_usage"] = usage_details["openrouter_usage"]
            return parsed
        except json.JSONDecodeError:
            return {
                "is_valid": True,
                "issues": [],
                "suggestions": [],
                "will_trigger": "MAYBE",
                "token_usage": usage_details["token_usage"],
                "cost_usd": usage_details["cost_usd"],
                "openrouter_usage": usage_details["openrouter_usage"]
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
        max_retries: int,
        model_name: Optional[str] = None
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
        if self._is_offline_model_selected(model_name):
            budget = settings.get_offline_pov_budget(model_name=model_name, purpose="retry")
            prompt = format_retry_analysis_prompt_offline(
                cwe_type=cwe_type,
                filepath=filepath,
                line_number=line_number,
                explanation=self._compact_text(explanation, budget["max_explanation_chars"]),
                failed_pov=self._compact_text(failed_pov, budget["max_failed_pov_chars"]),
                execution_output=self._compact_text(execution_output, budget["max_context_chars"]),
                attempt_number=attempt_number,
                max_retries=max_retries
            )
            llm = self._get_llm(model_name, purpose="retry")
        else:
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
            llm = self._get_llm(model_name)
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
    
    def refine_pov(
        self,
        cwe_type: str,
        filepath: str,
        line_number: int,
        vulnerable_code: str,
        explanation: str,
        code_context: str,
        failed_pov: str,
        validation_errors: List[str],
        attempt_number: int,
        target_language: str = "python",
        model_name: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Refine a failed PoV script based on validation errors
        
        Args:
            cwe_type: CWE type
            filepath: File path
            line_number: Line number
            vulnerable_code: The vulnerable code snippet
            explanation: Vulnerability explanation
            code_context: Surrounding code context
            failed_pov: The failed PoV script
            validation_errors: List of validation error messages
            attempt_number: Current retry attempt number
            target_language: Language of the target codebase
            model_name: Optional model name to use
        
        Returns:
            Dictionary with refined PoV script and metadata
        """
        start_time = datetime.utcnow()
        
        try:
            normalized_contract = self._normalize_exploit_contract(exploit_contract or {}, cwe_type, explanation, vulnerable_code, filepath=filepath)
            if self._is_offline_model_selected(model_name):
                offline_inputs = self._prepare_offline_pov_inputs(
                    model_name,
                    "refinement",
                    vulnerable_code,
                    explanation,
                    code_context,
                    failed_pov=failed_pov,
                    validation_errors=validation_errors,
                )
                prompt = format_pov_refinement_prompt_offline(
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    vulnerable_code=offline_inputs["vulnerable_code"],
                    explanation=offline_inputs["explanation"],
                    code_context=offline_inputs["code_context"],
                    failed_pov=offline_inputs["failed_pov"],
                    validation_errors=offline_inputs["validation_errors"],
                    attempt_number=attempt_number,
                    target_language=target_language,
                    exploit_contract=normalized_contract
                )
                llm = self._get_llm(model_name, purpose="refinement")
            else:
                prompt = format_pov_refinement_prompt(
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    vulnerable_code=vulnerable_code,
                    explanation=explanation,
                    code_context=code_context,
                    failed_pov=failed_pov,
                    validation_errors=validation_errors,
                    attempt_number=attempt_number,
                    target_language=target_language,
                    exploit_contract=normalized_contract
                )
                llm = self._get_llm(model_name)
            
            # Call LLM with specified model
            messages = [
                SystemMessage(content="You are a security researcher fixing a failed Proof-of-Vulnerability script."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            parsed = self._parse_pov_payload(response.content, cwe_type, explanation, vulnerable_code, filepath=filepath)
            pov_script = parsed["pov_script"]
            exploit_contract = self._normalize_exploit_contract(parsed["exploit_contract"], cwe_type, explanation, vulnerable_code, filepath=filepath)
            
            usage_details = extract_usage_details(response, agent_role="pov_refinement")
            actual_cost = usage_details["cost_usd"]
            token_usage = usage_details["token_usage"]
            openrouter_usage = usage_details["openrouter_usage"]
            
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
                "refinement_time_s": generation_time,
                "timestamp": end_time.isoformat(),
                "model_used": model_name or llm._autopov_model_name,
                "cost_usd": actual_cost,
                "token_usage": token_usage,
                "attempt_number": attempt_number,
                "exploit_contract": exploit_contract,
                "openrouter_usage": openrouter_usage
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            return {
                "success": False,
                "error": str(e),
                "pov_script": failed_pov,  # Return original on failure
                "refinement_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat()
            }


# Global verifier instance
verifier = VulnerabilityVerifier()


def get_verifier() -> VulnerabilityVerifier:
    """Get the global verifier instance"""
    return verifier

