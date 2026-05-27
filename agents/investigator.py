"""
AutoPoV Investigator Agent Module
Uses RAG and LLM to investigate potential vulnerabilities
"""

import json
import re
import subprocess
import os
from typing import Dict, Optional, Any, List, Callable
from datetime import datetime, timezone

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
from app.openrouter_client import OpenRouterReasoningChat, extract_usage_details
from agents.ingest_codebase import get_code_ingester
from prompts import format_investigation_prompt, format_rag_context_prompt, PROOF_NARRATIVE_PROMPT


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

    def _compact_text(self, value: str, max_chars: int) -> str:
        text = (value or '').strip()
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        if max_chars <= 160:
            return text[:max_chars].rstrip()
        head = max_chars // 2
        tail = max_chars - head - len('\n...\n')
        return f"{text[:head].rstrip()}\n...\n{text[-max(0, tail):].lstrip()}"

    def _prepare_offline_investigation_inputs(self, model_name: Optional[str], code_context: str, alert_message: str, joern_context: str = '') -> Dict[str, str]:
        budget = settings.get_offline_investigation_budget(model_name=model_name)
        return {
            'code_context': self._compact_text(code_context, budget['max_code_context_chars']),
            'alert_message': self._compact_text(alert_message, budget['max_alert_chars']),
            'joern_context': self._compact_text(joern_context, budget['max_joern_chars']),
        }
    
    def _get_llm(self, model_name: Optional[str] = None, api_key_override: Optional[str] = None):
        """Get LLM instance based on configuration.

        FIX-8: Session-level singleton — reuses the same LLM object when
        model_name matches a previously created instance (within same api_key).
        """
        llm_config = settings.get_llm_config(model_name=model_name)

        # Use provided model_name or fall back to config
        actual_model = model_name or llm_config["model"]

        # FIX-8: Check singleton cache (keyed by model + api_key)
        _cache_key = (actual_model, api_key_override or '_default')
        if not hasattr(self, '_llm_cache'):
            self._llm_cache: dict = {}
        if _cache_key in self._llm_cache:
            return self._llm_cache[_cache_key]

        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise InvestigationError("OpenAI not available. Install langchain-openai")

            # Use per-request override key if provided, else fall back to env config
            api_key = api_key_override or llm_config.get("api_key")
            
            if not api_key:
                raise InvestigationError("OpenRouter API key not configured. Set OPENROUTER_API_KEY environment variable.")
            
            callbacks = [self._tracer] if self._tracer else None
            
            llm = OpenRouterReasoningChat(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.1,
                timeout=settings.LLM_REQUEST_TIMEOUT_S,
                reasoning_enabled=llm_config.get("reasoning_enabled", True),
                max_tokens=settings.get_online_max_tokens(),  # None = no cap
                default_headers={
                    "HTTP-Referer": "https://autopov.local",
                    "X-OpenRouter-Title": "AutoPoV"
                }
            )
            
            # Store model info for cost tracking
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            self._llm_cache[_cache_key] = llm
            return llm
        else:
            if not OLLAMA_AVAILABLE:
                raise InvestigationError("Ollama not available. Install langchain-ollama")
            
            callbacks = [self._tracer] if self._tracer else None
            
            generation_options = settings.get_ollama_generation_options(actual_model, purpose="investigation")
            llm = ChatOllama(
                model=actual_model,
                base_url=llm_config["base_url"],
                temperature=0.1,
                callbacks=callbacks,
                format="json",
                reasoning=False,
                num_ctx=generation_options["num_ctx"],
                num_predict=generation_options["num_predict"],
                client_kwargs=settings.get_ollama_client_kwargs(actual_model, purpose="investigation")
            )
            
            llm._autopov_model_name = actual_model
            
            if model_name is None:
                self._llm = llm
            self._llm_cache[_cache_key] = llm
            return llm
    
    # ---------------------------------------------------------------------------
    # Language-adaptive Joern engine (Tasks 3a–3d)
    # ---------------------------------------------------------------------------

    # All extensions Joern can analyse — gate for language detection
    _JOERN_SUPPORTED_EXTS = {
        '.c', '.cc', '.cpp', '.cxx', '.h', '.hpp',   # C / C++
        '.java',                                      # Java
        '.js', '.ts', '.mjs', '.cjs',                # JavaScript / TypeScript
        '.py',                                        # Python
    }

    def _extract_hint_fn(self, alert_message: str) -> str:
        """Heuristically extract a likely sink/source function name from the alert text."""
        import re
        m = re.search(r'\b([a-zA-Z_][\w.]*)\s*\(', alert_message or '')
        return m.group(1) if m else ''

    def _joern_query_native(self, filepath_dir: str, hint_fn: str) -> str:
        """Joern Scala query for C/C++ — sources=input calls, sinks=memory/exec ops."""
        extra_hint = f', "{hint_fn}"' if hint_fn else ''
        return f'''
importCode(inputPath="{filepath_dir}", projectName="autopov_scan")
val sourceNames = List("scanf", "gets", "fgets", "recv", "read", "getenv", "getline", "fread")
val sinkNames   = List("strcpy", "strcat", "sprintf", "snprintf", "memcpy", "memmove",
                       "system", "execl", "execle", "execlp", "execv", "execve", "execvp",
                       "popen", "free", "realloc"{extra_hint})
val sources = cpg.call.name(sourceNames: _*).l ++ cpg.method.parameter.l
val sinks   = cpg.call.name(sinkNames: _*).l
val flows   = sinks.flatMap {{ sink => sink.reachableBy(sources).path.l }}
if (flows.isEmpty) {{
    println("No taint paths found")
}} else {{
    flows.take(5).foreach {{ path =>
        val lastNode = path.last
        println(s"Taint path: ${{lastNode}}")
    }}
}}
'''

    def _joern_query_java(self, filepath_dir: str, hint_fn: str) -> str:
        """Joern Scala query for Java — sources=HTTP inputs+deserialization, sinks=SQL/exec/reflect/file."""
        extra_hint = f', "{hint_fn}"' if hint_fn else ''
        return f'''
importCode(inputPath="{filepath_dir}", projectName="autopov_scan")
val sourceNames = List("getParameter", "getHeader", "getInputStream", "getQueryString",
                       "readObject", "readUnshared")
val sinkNames   = List("executeQuery", "executeUpdate", "prepareStatement", "execute",
                       "forName", "invoke", "exec", "start", "writeFile", "write",
                       "delete", "createTempFile"{extra_hint})
val sources = cpg.call.name(sourceNames: _*).l ++ cpg.method.parameter.l
val sinks   = cpg.call.name(sinkNames: _*).l
val flows   = sinks.flatMap {{ sink => sink.reachableBy(sources).path.l }}
if (flows.isEmpty) println("No taint paths found")
else flows.take(5).foreach {{ path => println(s"Taint path: ${{path.last}}") }}
'''

    def _joern_query_js(self, filepath_dir: str, hint_fn: str) -> str:
        """Joern Scala query for JavaScript/TypeScript — sources=req/argv/env, sinks=eval/exec/fs."""
        extra_hint = f', "{hint_fn}"' if hint_fn else ''
        return f'''
importCode(inputPath="{filepath_dir}", projectName="autopov_scan")
val sourceNames = List("JSON.parse", "req.body", "req.query", "req.params",
                       "process.argv", "process.env")
val sinkNames   = List("eval", "Function", "exec", "execSync", "spawn", "spawnSync",
                       "writeFile", "writeFileSync", "innerHTML", "write"{extra_hint})
val sources = cpg.call.name(sourceNames: _*).l ++ cpg.method.parameter.l
val sinks   = cpg.call.name(sinkNames: _*).l
val flows   = sinks.flatMap {{ sink => sink.reachableBy(sources).path.l }}
if (flows.isEmpty) println("No taint paths found")
else flows.take(5).foreach {{ path => println(s"Taint path: ${{path.last}}") }}
'''

    def _joern_query_python(self, filepath_dir: str, hint_fn: str) -> str:
        """Joern Scala query for Python — sources=argv/input/env, sinks=eval/exec/subprocess/pickle."""
        extra_hint = f', "{hint_fn}"' if hint_fn else ''
        return f'''
importCode(inputPath="{filepath_dir}", projectName="autopov_scan")
val sourceNames = List("input", "sys.argv", "os.environ", "os.getenv",
                       "request.args", "request.form", "request.json")
val sinkNames   = List("eval", "exec", "system", "popen", "run", "Popen",
                       "call", "check_output", "loads", "load", "extractall", "open"{extra_hint})
val sources = cpg.call.name(sourceNames: _*).l ++ cpg.method.parameter.l
val sinks   = cpg.call.name(sinkNames: _*).l
val flows   = sinks.flatMap {{ sink => sink.reachableBy(sources).path.l }}
if (flows.isEmpty) println("No taint paths found")
else flows.take(5).foreach {{ path => println(s"Taint path: ${{path.last}}") }}
'''

    def _build_joern_query(self, language: str, filepath_dir: str, alert_message: str, recon_report: dict = None) -> str:
        """Dispatch to the appropriate language query template.
        
        Uses recon_report attack_surfaces to inject additional sink hints
        discovered during reconnaissance (e.g. specific vulnerable function names).
        """
        hint_fn = self._extract_hint_fn(alert_message)
        # Extract additional sink hints from recon report's attack surfaces
        if recon_report and not hint_fn:
            for surface in (recon_report.get('attack_surfaces') or []):
                entry = str(surface.get('entry', '')).strip()
                if entry and len(entry) > 2 and entry.isidentifier():
                    hint_fn = entry
                    break
        if language in ('c', 'cpp'):
            return self._joern_query_native(filepath_dir, hint_fn)
        elif language == 'java':
            return self._joern_query_java(filepath_dir, hint_fn)
        elif language in ('javascript', 'typescript'):
            return self._joern_query_js(filepath_dir, hint_fn)
        elif language == 'python':
            return self._joern_query_python(filepath_dir, hint_fn)
        else:
            return self._joern_query_native(filepath_dir, hint_fn)  # fallback

    def _run_joern_analysis(
        self,
        codebase_path: str,
        filepath: str,
        line_number: int,
        cwe_type: str,
        language: str = '',
        alert_message: str = '',
        codebase_loc: int = 0,
    ) -> Optional[str]:
        """
        Run Joern CPG-based taint analysis for any supported language.

        Supported: C, C++, Java, JavaScript/TypeScript, Python.
        Language detected from file extension — no CWE involvement.
        Query templates are language-specific with sources/sinks inferred
        from language semantics + optional hint from alert_message.
        Analysis is scoped to the directory containing the flagged file
        (not the full codebase) for speed and relevance.
        Timeout is adaptive: min(300, max(60, LOC//1000 * 15)) seconds.
        """
        # ── 3a: Language-aware gate ────────────────────────────────────────────
        _, ext = os.path.splitext(filepath or '')
        ext = ext.lower()
        if ext not in self._JOERN_SUPPORTED_EXTS:
            return None

        if not settings.is_joern_available():
            return 'Joern not available — skipped CPG analysis'

        # Resolve language from extension when caller doesn't supply it
        _ext_to_lang = {
            '.c': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp',
            '.h': 'c', '.hpp': 'cpp',
            '.java': 'java',
            '.js': 'javascript', '.ts': 'typescript', '.mjs': 'javascript', '.cjs': 'javascript',
            '.py': 'python',
        }
        resolved_lang = language or _ext_to_lang.get(ext, 'c')

        # ── 3c: Scope to the directory of the flagged file ─────────────────────
        if os.path.isabs(filepath):
            abs_file = filepath
        else:
            abs_file = os.path.join(codebase_path, filepath)
        filepath_dir = os.path.dirname(abs_file) or codebase_path
        # Fallback to codebase root if directory doesn't exist
        if not os.path.isdir(filepath_dir):
            filepath_dir = codebase_path

        # ── 3d: Adaptive timeout based on LOC ──────────────────────────────────
        # Joern JVM startup alone takes 30-60s; minimum must account for that.
        # Formula: 300s base + 15s per 1000 LOC, capped at 600s.
        loc = codebase_loc or 0
        timeout = min(600, 300 + (loc // 1000) * 15)

        # ── 3b: Language-adaptive query ────────────────────────────────────────
        script = self._build_joern_query(resolved_lang, filepath_dir, alert_message)

        try:
            import shutil
            import tempfile
            joern_bin = settings.JOERN_CLI_PATH or 'joern'

            # Write script to a temp file — more reliable than /dev/stdin
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sc', delete=False) as tf:
                tf.write(script)
                script_path = tf.name

            try:
                result = subprocess.run(
                    [joern_bin, '--script', script_path],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            finally:
                try:
                    os.unlink(script_path)
                except OSError:
                    pass

            output = result.stdout.strip()
            if result.stderr:
                stderr_summary = result.stderr.strip()[-400:]
                output = (output + f'\nJoern stderr: {stderr_summary}').strip()

            return output if output else 'No taint paths found'

        except subprocess.TimeoutExpired:
            return f'Joern analysis timed out after {timeout}s'
        except Exception as e:
            return f'Joern analysis error: {str(e)}'
    
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
        # Try to get full file content first from ChromaDB
        full_content = None
        try:
            full_content = get_code_ingester().get_file_content(filepath, scan_id)
        except Exception:
            pass  # ChromaDB may not be available or file not ingested
        
        # Fallback: read file directly from disk
        if not full_content:
            try:
                # Get codebase path from scan_id
                from app.scan_manager import get_scan_manager
                scan_info = get_scan_manager().get_scan(scan_id)
                if scan_info:
                    codebase_path = scan_info.get("codebase_path", "")
                    if codebase_path:
                        abs_path = os.path.join(codebase_path, filepath) if not os.path.isabs(filepath) else filepath
                        if os.path.isfile(abs_path):
                            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                                full_content = f.read()
            except Exception:
                pass
        
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
        try:
            query = f"Code around line {line_number} in {filepath}"
            results = get_code_ingester().retrieve_context(query, scan_id, top_k=3)
            
            if results:
                contexts = []
                for r in results:
                    contexts.append(f"// File: {r['metadata']['filepath']}\n{r['content']}")
                return '\n\n'.join(contexts)
        except Exception:
            pass
        
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
        api_key_override: Optional[str] = None,
        repo_web_capable: bool = False,
        recon_report: Optional[Dict[str, Any]] = None,
        is_benchmark_case: bool = False,
        benchmark_family: str = '',
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
        start_time = datetime.now(timezone.utc)
        
        try:
            # Get code context
            code_context = self._get_code_context(scan_id, filepath, line_number)
            
            # Detect language from filepath
            ext = os.path.splitext(filepath)[1].lower()
            lang_map = {
                '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                '.java': 'java', '.c': 'c', '.cpp': 'cpp', '.go': 'go',
                '.rs': 'rust', '.rb': 'ruby', '.php': 'php'
            }
            language = lang_map.get(ext, 'unknown')
            
            # Get RAG context
            rag_context = self._get_rag_context(scan_id, cwe_type, filepath)
            
            # Run Joern for all supported languages — language-adaptive CPG analysis
            joern_context = ""
            ext_check = os.path.splitext(filepath)[1].lower()
            if ext_check in self._JOERN_SUPPORTED_EXTS:
                joern_result = self._run_joern_analysis(
                    codebase_path, filepath, line_number, cwe_type,
                    language=language, alert_message=alert_message
                )
                if joern_result:
                    joern_context = f"\n\nJOERN CPG ANALYSIS:\n{joern_result}"
            
            selected_model = (model_name or settings.MODEL_NAME or '').strip()
            if settings.is_offline_model(selected_model):
                offline_inputs = self._prepare_offline_investigation_inputs(
                    selected_model,
                    code_context,
                    alert_message,
                    joern_context,
                )
                prompt = format_investigation_prompt(
                    code_context=offline_inputs['code_context'],
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    alert_message=offline_inputs['alert_message'],
                    joern_context=offline_inputs['joern_context'],
                    recon_report=recon_report,
                    is_benchmark_case=is_benchmark_case,
                    benchmark_family=benchmark_family,
                )
            else:
                prompt = format_investigation_prompt(
                    code_context=code_context,
                    cwe_type=cwe_type,
                    filepath=filepath,
                    line_number=line_number,
                    alert_message=alert_message,
                    joern_context=joern_context,
                    recon_report=recon_report,
                    is_benchmark_case=is_benchmark_case,
                    benchmark_family=benchmark_family,
                )
            
            # Call LLM with specified model and optional key override
            llm = self._get_llm(model_name, api_key_override=api_key_override)
            messages = [
                SystemMessage(content="You are a security expert analyzing code for vulnerabilities."),
                HumanMessage(content=prompt)
            ]
            
            response = llm.invoke(messages)
            response_text = response.content if isinstance(response.content, str) else json.dumps(response.content)
            
            usage_details = extract_usage_details(response, agent_role="investigator")
            actual_cost = usage_details["cost_usd"]
            token_usage = usage_details["token_usage"]
            openrouter_usage = usage_details["openrouter_usage"]
            
            # Parse JSON response
            try:
                # Extract JSON from response (handle markdown code blocks)
                json_text = response_text
                if "```json" in json_text:
                    json_text = json_text.split("```json")[1].split("```")[0]
                elif "```" in json_text:
                    json_text = json_text.split("```")[1].split("```")[0]
                else:
                    # Strip leading/trailing backticks used by some models
                    _stripped = json_text.strip().strip("`").strip()
                    if _stripped.startswith("{"):
                        json_text = _stripped

                # Attempt to recover truncated JSON by closing unclosed braces
                _attempt = json_text.strip()
                try:
                    parsed_result = json.loads(_attempt)
                except json.JSONDecodeError:
                    # Count open vs closed braces; append missing closing braces
                    _opens = _attempt.count("{") - _attempt.count("}")
                    if _opens > 0:
                        _attempt = _attempt + ("}" * _opens)
                    parsed_result = json.loads(_attempt)
                if not isinstance(parsed_result, dict):
                    raise ValueError("Investigation response was not a JSON object")

                verdict = str(parsed_result.get("verdict", "") or "").strip().upper()
                explanation = str(parsed_result.get("explanation", "") or "").strip()
                if verdict not in {"REAL", "FALSE_POSITIVE", "UNKNOWN"}:
                    raise ValueError(f"Missing or invalid verdict: {verdict!r}")
                if not explanation:
                    raise ValueError("Missing explanation in investigation response")

                try:
                    confidence = float(parsed_result.get("confidence", 0.5))
                except (TypeError, ValueError):
                    raise ValueError("Missing or invalid confidence in investigation response")

                result = dict(parsed_result)
                result["verdict"] = verdict
                result["confidence"] = max(0.0, min(1.0, confidence))
                result["explanation"] = explanation
                result["cwe_type"] = str(result.get("cwe_type") or cwe_type or "UNCLASSIFIED")

                # Extract and normalize exploit_recipe
                _raw_recipe = parsed_result.get("exploit_recipe") or {}
                if isinstance(_raw_recipe, dict):
                    result["exploit_recipe"] = {
                        "trigger_function": str(_raw_recipe.get("trigger_function") or result.get("target_entrypoint") or ""),
                        "trigger_arguments": list(_raw_recipe.get("trigger_arguments") or []),
                        "minimum_payload_size": _raw_recipe.get("minimum_payload_size"),
                        "required_preconditions": list(_raw_recipe.get("required_preconditions") or []),
                        "expected_failure_mode": str(_raw_recipe.get("expected_failure_mode") or ""),
                        "proof_of_impact": str(_raw_recipe.get("proof_of_impact") or ""),
                    }

                # ── Structural verdict filters (model-agnostic) ─────────────────────────
                # Filter A: closing-brace / empty code chunk — never exploitable.
                # If the code at the flagged line is just a closing brace or whitespace,
                # auto-downgrade to FALSE_POSITIVE regardless of LLM verdict.
                _code_stripped = str(code_context or '').strip().splitlines()
                _target_line = ''
                try:
                    _target_line = next(
                        (l.strip() for l in _code_stripped
                         if l.strip() and not l.strip().startswith('#')),
                        ''
                    )
                except Exception:
                    pass
                _TRIVIAL_TOKENS = {'}', '{', '};', '},', '{};', ''}
                if _target_line in _TRIVIAL_TOKENS or len(_target_line) < 5:
                    result["verdict"] = 'FALSE_POSITIVE'
                    result["confidence"] = 0.1
                    result["explanation"] = (
                        result["explanation"]
                        + " [Auto-downgraded: flagged code is a closing brace or empty "
                        "line — not exploitable.]"
                    )

                # Filter B: CWE type vs target language/capabilities mismatch.
                # Instead of a hardcoded list of "web-only" CWEs, we check whether
                # the detected CWE category aligns with the repo's known capabilities.
                # If the repo has NO web-serving surface detected (via recon or probe)
                # and the CWE is typically web-related, downgrade confidence — but
                # NEVER outright reject, because the LLM investigation may have found
                # a legitimate variant (e.g. SQL injection in a CLI tool using sqlite).
                _WEB_RELATED_CWES = {
                    'CWE-79', 'CWE-352', 'CWE-601', 'CWE-918',
                    'CWE-80', 'CWE-116', 'CWE-643',
                }
                _NATIVE_LANGS = {'c', 'cpp', 'c++', 'rust', 'go'}
                _detected_cwe = str(result.get('cwe_type') or '').strip().upper()
                # Only downgrade if: native lang + web-related CWE + no web capability
                # Note: CWE-89 (SQL injection) removed from this list — valid in native CLI tools
                if _detected_cwe in _WEB_RELATED_CWES and language in _NATIVE_LANGS and not repo_web_capable:
                    result["confidence"] = min(result["confidence"], 0.4)
                    result["explanation"] = (
                        result["explanation"]
                        + f" [Confidence reduced: {_detected_cwe} is typically web-related "
                        f"but no web-serving capability was detected — investigate further.]"
                    )
                # ────────────────────────────────────────────────────────────────────────
                result["cve_id"] = result.get("cve_id")
                _raw_vuln_code = str(result.get("vulnerable_code", "") or "")
                # Validate that vulnerable_code is actual source code, not a text description.
                # Code typically contains syntax characters; prose descriptions don't.
                _code_chars = sum(1 for c in _raw_vuln_code if c in '{}();=[]<>+-*/')
                _words = _raw_vuln_code.split()
                _is_prose = len(_words) > 5 and _code_chars < 3
                result["vulnerable_code"] = "" if _is_prose else _raw_vuln_code
                result["root_cause"] = str(result.get("root_cause", "") or "")
                result["impact"] = str(result.get("impact", "") or "")
            except Exception:
                # Fallback: create structured result from text or incomplete JSON
                done_reason = ""
                try:
                    done_reason = str((getattr(response, "response_metadata", {}) or {}).get("done_reason") or "")
                except Exception:
                    done_reason = ""
                response_excerpt = response_text.strip()
                if not response_excerpt:
                    response_excerpt = "[empty model response]"
                    if done_reason:
                        response_excerpt = f"{response_excerpt} done_reason={done_reason}"

                result = {
                    "verdict": "UNKNOWN",
                    "cwe_type": cwe_type,
                    "confidence": 0.5,
                    "explanation": response_excerpt,
                    "vulnerable_code": "",
                    "root_cause": "",
                    "impact": ""
                }
                # Last-resort: scan raw response_text for a "verdict" key via regex
                # This recovers verdicts from responses where the JSON was valid but
                # the outer parse loop failed for an unrelated reason (e.g. missing
                # explanation field), or where the model echoed the JSON inside prose.
                import re as _re
                _v_match = _re.search(r'"verdict"\s*:\s*"([A-Z_]+)"', response_text)
                _c_match = _re.search(r'"confidence"\s*:\s*([0-9.]+)', response_text)
                if _v_match:
                    _raw_verdict = _v_match.group(1).strip().upper()
                    if _raw_verdict in {"REAL", "FALSE_POSITIVE", "UNKNOWN"}:
                        result["verdict"] = _raw_verdict
                if _c_match:
                    try:
                        result["confidence"] = max(0.0, min(1.0, float(_c_match.group(1))))
                    except (ValueError, TypeError):
                        pass
            
            # Calculate inference time
            end_time = datetime.now(timezone.utc)
            inference_time = (end_time - start_time).total_seconds()
            
            # Add metadata
            result["inference_time_s"] = inference_time
            result["timestamp"] = end_time.isoformat()
            result["filepath"] = filepath
            result["line_number"] = line_number
            result["model_used"] = model_name or llm._autopov_model_name
            result["cost_usd"] = actual_cost
            result["token_usage"] = token_usage
            result["openrouter_usage"] = openrouter_usage
            # 2c: Forward joern taint-chain context to PoV generation
            if joern_context:
                result["joern_context"] = joern_context
            
            return result
            
        except Exception as e:
            end_time = datetime.now(timezone.utc)
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
        if not settings.COST_TRACKING_ENABLED:
            return 0.0

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
        progress_callback: Optional[Callable] = None,
        model_name: str = '',
        api_key_override: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Investigate multiple alerts
        
        Args:
            scan_id: Scan identifier
            codebase_path: Path to codebase
            alerts: List of alert dictionaries
            progress_callback: Optional progress callback
            model_name: LLM model to use for investigation
            api_key_override: Optional API key override for OpenRouter
        
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
                alert_message=alert.get("alert_message", ""),
                model_name=model_name,
                api_key_override=api_key_override,
            )
            
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, len(alerts), result)
        
        return results

    # ── Narrative text extraction helpers ──────────────────────────

    @staticmethod
    def _clean_raw_text(text: str) -> str:
        """Strip wrapping quotes, markdown fences, and JSON artifacts from raw LLM text."""
        text = text.strip().strip('"').strip("'").strip('`').strip()
        # Remove markdown code fences if present
        if text.startswith('```'):
            text = text.split('```', 2)[1] if '```' in text[3:] else text[3:]
            text = text.strip()
        return text

    @staticmethod
    def _extract_strings_from_json(text: str) -> str:
        """If *text* looks like JSON, recursively collect all string values
        and return the longest one, or join them into a composite paragraph."""
        if not text.startswith('{') and not text.startswith('['):
            return text

        # Try parsing; handle common formatting issues from LLMs
        parsed = None
        for attempt_text in [text, text.replace('\r\n', '\n'), re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)]:
            try:
                parsed = json.loads(attempt_text, strict=False)
                break
            except (json.JSONDecodeError, ValueError):
                continue

        if parsed is None:
            # JSON parsing failed (common when embedded code breaks escaping).
            # Use regex to extract meaningful text values from the JSON-like string.
            # Match quoted strings that contain spaces (prose, not code keys)
            matches = re.findall(r'"((?:[^"\\]|\\.){20,})"', text)
            if matches:
                # Prefer prose-like strings (contain spaces, not code)
                prose = [m for m in matches
                         if ' ' in m
                         and not m.lstrip().startswith('import ')
                         and not m.lstrip().startswith('def ')
                         and not m.lstrip().startswith('os.')
                         and 'subprocess' not in m[:30]]
                if prose:
                    return max(prose, key=len)
            # If regex also fails, strip JSON syntax and return remaining text
            stripped = re.sub(r'[{}\[\]"]', ' ', text)
            stripped = re.sub(r'\s+', ' ', stripped).strip()
            # Remove JSON key patterns like "key_name":
            stripped = re.sub(r'\b\w+\s*:', '', stripped)
            return stripped if len(stripped) > 50 else ''

        def _collect(obj, min_len=15):
            if isinstance(obj, str) and len(obj) >= min_len:
                return [obj]
            if isinstance(obj, dict):
                out = []
                for v in obj.values():
                    out.extend(_collect(v))
                return out
            if isinstance(obj, list):
                out = []
                for v in obj:
                    out.extend(_collect(v))
                return out
            return []

        vals = _collect(parsed)
        if not vals:
            return ''
        # Filter out PoV scripts — keep only prose/description text
        prose_vals = [v for v in vals
                      if not v.lstrip().startswith('import ')
                      and not v.lstrip().startswith('def ')
                      and not v.lstrip().startswith('os.')
                      and 'subprocess' not in v[:30]
                      and not v.lstrip().startswith('#!/')]
        candidates = prose_vals if prose_vals else vals
        # If there's a single long string (>100 chars), prefer it
        long_vals = [v for v in candidates if len(v) > 100]
        if long_vals:
            return max(long_vals, key=len)
        # Otherwise, join all extracted strings into a composite paragraph
        return ' '.join(candidates)

    def _extract_narrative_text(self, response) -> str:
        """Extract the best narrative text from an LLM response.

        Strategy:
        1. Try response.content (the normal completion text).
        2. If content is empty/too short, scan reasoning_details for
           substantial text (reasoning models sometimes put the real
           answer inside their thinking trace).
        3. Run JSON-unwrapping and cleanup on whatever we find.
        """
        # --- 1. Primary: response.content ---
        raw = response.content if isinstance(response.content, str) else str(response.content)
        narrative = self._clean_raw_text(raw)
        narrative = self._extract_strings_from_json(narrative)
        if len(narrative) > 50:
            return narrative

        # --- 2. Fallback: reasoning_details ---
        reasoning_parts = getattr(response, 'reasoning_details', None) or []
        best = ''
        for part in reasoning_parts:
            # Common shapes: {"type":"thinking","thinking":"..."}
            # or just a plain string in a list.
            chunk = ''
            if isinstance(part, dict):
                chunk = str(part.get('thinking') or part.get('content') or part.get('text') or '')
            elif isinstance(part, str):
                chunk = part
            chunk = self._clean_raw_text(chunk)
            chunk = self._extract_strings_from_json(chunk)
            if len(chunk) > len(best):
                best = chunk

        # From the reasoning trace, try to find the last coherent
        # paragraph (the model often reasons then writes the answer
        # at the end of its thinking block).
        if len(best) > 100:
            # Split by double-newline; take the longest paragraph-like block
            paragraphs = [p.strip() for p in best.split('\n\n') if len(p.strip()) > 80]
            if paragraphs:
                # Prefer the last substantial paragraph (usually the final answer)
                best = paragraphs[-1]

        return best

    def generate_proof_narrative(
        self,
        finding: Dict[str, Any],
        model_name: Optional[str] = None,
        api_key_override: Optional[str] = None,
    ) -> str:
        """Generate a dense, evidence-based proof narrative for a confirmed finding.
        
        Called after a vulnerability is confirmed via runtime proof execution.
        Returns a single paragraph describing what was identified, how it was
        exploited, the observed outcome, and the attacker impact.
        """
        try:
            pov_result = finding.get('pov_result') or {}
            oracle_result = pov_result.get('oracle_result') or {}
            exploit_contract = finding.get('exploit_contract') or {}
            pov_script = str(finding.get('pov_script') or '')
            
            # Truncate PoV script to key sections (first 800 chars + last 400)
            if len(pov_script) > 1200:
                pov_script_excerpt = pov_script[:800] + '\n...\n' + pov_script[-400:]
            else:
                pov_script_excerpt = pov_script
            
            stdout = str(pov_result.get('stdout') or '')
            stderr = str(pov_result.get('stderr') or '')
            
            prompt = PROOF_NARRATIVE_PROMPT.format(
                cwe_type=finding.get('cwe_type', 'UNCLASSIFIED'),
                filepath=finding.get('filepath', '?'),
                line_number=finding.get('line_number', 0),
                vulnerable_code=str(finding.get('code_chunk') or '')[:600],
                investigation_explanation=str(finding.get('llm_explanation') or '')[:400],
                pov_script_excerpt=pov_script_excerpt,
                exit_code=pov_result.get('exit_code', '?'),
                oracle_reason=oracle_result.get('reason', '?'),
                matched_markers=oracle_result.get('matched_evidence_markers', []),
                stdout_excerpt=stdout[-500:] if stdout else '(empty)',
                stderr_excerpt=stderr[-300:] if stderr else '(empty)',
            )
            
            llm = self._get_llm(model_name, api_key_override=api_key_override)
            messages = [
                SystemMessage(content="You are a security analyst. Write only plain text paragraphs. Never output JSON or structured data."),
                HumanMessage(content=prompt),
            ]
            response = llm.invoke(messages)
            _rd = getattr(response, 'reasoning_details', None) or []
            print(f"    [NARRATIVE] content_len={len(response.content)}, reasoning_parts={len(_rd)}")
            narrative = self._extract_narrative_text(response)
            print(f"    [NARRATIVE] extracted_len={len(narrative)}, preview={narrative[:80]!r}")
            return narrative if len(narrative) > 50 else ''
        except Exception as e:
            return ''


# Global investigator instance
investigator = VulnerabilityInvestigator()


def get_investigator() -> VulnerabilityInvestigator:
    """Get the global investigator instance"""
    return investigator


