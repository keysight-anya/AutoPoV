"""
LLM Scout
Uses a model to propose candidate vulnerabilities across files.
"""

import json
import os
from typing import List, Dict, Any, Optional

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
from prompts import format_scout_prompt, format_scout_triage_prompt


class LLMScoutError(Exception):
    pass


class LLMScout:
    """LLM-based candidate discovery."""

    def _get_llm(self, model_name: Optional[str] = None):
        llm_config = settings.get_llm_config(model_name=model_name)
        actual_model = model_name or llm_config["model"]

        if llm_config["mode"] == "online":
            if not OPENAI_AVAILABLE:
                raise LLMScoutError("OpenAI not available. Install langchain-openai")
            api_key = llm_config.get("api_key")
            if not api_key:
                raise LLMScoutError("OpenRouter API key not configured")
            return OpenRouterReasoningChat(
                model=actual_model,
                api_key=api_key,
                base_url=llm_config["base_url"],
                temperature=0.1,
                timeout=settings.LLM_REQUEST_TIMEOUT_S,
                reasoning_enabled=llm_config.get("reasoning_enabled", True),
                default_headers={
                    "HTTP-Referer": "https://autopov.local",
                    "X-OpenRouter-Title": "AutoPoV"
                }
            )
        if not OLLAMA_AVAILABLE:
            raise LLMScoutError("Ollama not available. Install langchain-ollama")
        return ChatOllama(
            model=actual_model,
            base_url=llm_config["base_url"],
            temperature=0.1,
            client_kwargs={"timeout": (settings.OLLAMA_CONNECT_TIMEOUT_S, settings.OLLAMA_READ_TIMEOUT_S)}
        )

    def _is_code_file(self, filepath: str) -> bool:
        ext = os.path.splitext(filepath)[1].lower()
        return ext in {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".cc",
            ".h", ".hpp", ".go", ".rs", ".rb", ".php", ".cs"
        }

    def _detect_language(self, filepath: str) -> str:
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp"
        }
        return lang_map.get(ext, "unknown")

    def scan_directory(self, codebase_path: str, cwes: List[str], model_name: Optional[str] = None) -> List[Dict[str, Any]]:
        max_files = settings.SCOUT_MAX_FILES
        max_chars = settings.SCOUT_MAX_CHARS_PER_FILE
        max_findings = settings.SCOUT_MAX_FINDINGS

        files: List[str] = []
        for root, dirs, filenames in os.walk(codebase_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in filenames:
                path = os.path.join(root, name)
                if self._is_code_file(path):
                    files.append(path)

        files.sort(key=lambda p: os.path.getsize(p), reverse=True)
        files = files[:max_files]

        file_snippets = []
        for path in files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    snippet = f.read(max_chars)
            except Exception:
                continue
            rel = os.path.relpath(path, codebase_path)
            file_snippets.append({"filepath": rel, "language": self._detect_language(rel), "code": snippet})

        if not file_snippets:
            return []

        prompt = format_scout_prompt(file_snippets, [])
        llm = self._get_llm(model_name)
        messages = [
            SystemMessage(content="You are a security researcher scouting for potential vulnerabilities."),
            HumanMessage(content=prompt)
        ]
        response = llm.invoke(messages)
        content = response.content.strip()

        usage_details = extract_usage_details(response, agent_role="llm_scout")
        cost_usd = usage_details["cost_usd"]
        token_usage = usage_details["token_usage"]
        openrouter_usage = usage_details["openrouter_usage"]

        if settings.SCOUT_MAX_COST_USD and settings.SCOUT_MAX_COST_USD > 0 and cost_usd > settings.SCOUT_MAX_COST_USD:
            return []

        try:
            data = json.loads(content)
        except Exception:
            return []

        findings: List[Dict[str, Any]] = []
        for item in data.get("findings", []):
            cwe = item.get("cwe") or "UNCLASSIFIED"
            findings.append({
                "cve_id": item.get("cve_id"),
                "cwe_type": "UNCLASSIFIED",
                "taxonomy_refs": [ref for ref in [cwe, item.get("cve_id")] if ref and ref != "UNCLASSIFIED"],
                "filepath": item.get("filepath", ""),
                "line_number": int(item.get("line", 0) or 0),
                "code_chunk": item.get("snippet", ""),
                "llm_verdict": "",
                "llm_explanation": item.get("reason", ""),
                "confidence": float(item.get("confidence", 0.4) or 0.4),
                "pov_script": None,
                "pov_path": None,
                "pov_result": None,
                "retry_count": 0,
                "inference_time_s": 0.0,
                "cost_usd": 0.0,
                "final_status": "",
                "alert_message": "LLM scout",
                "source": "llm_scout",
                "language": item.get("language", "unknown"),
                "scout_model_used": model_name or getattr(llm, "_autopov_model_name", ""),
                "scout_token_usage": token_usage,
                "scout_openrouter_usage": openrouter_usage
            })
            if len(findings) >= max_findings:
                break

        return findings

    def scan_snippets(self, file_snippets: List[Dict[str, Any]], cwes: List[str], model_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run LLM triage on pre-selected candidate file snippets from prior tools.
        
        Unlike scan_directory, this method takes already-enriched snippets (including
        candidate_lines and candidate_cwes) so the LLM focuses on flagged locations.
        """
        if not file_snippets:
            return []

        max_findings = settings.SCOUT_MAX_FINDINGS
        prompt = format_scout_triage_prompt(file_snippets, [])
        llm = self._get_llm(model_name)
        messages = [
            SystemMessage(content="You are a security researcher triaging pre-flagged vulnerability signals from static analysis tools."),
            HumanMessage(content=prompt)
        ]
        response = llm.invoke(messages)
        content = response.content.strip()
        usage_details = extract_usage_details(response, agent_role="llm_scout")
        token_usage = usage_details["token_usage"]
        openrouter_usage = usage_details["openrouter_usage"]

        try:
            data = json.loads(content)
        except Exception:
            # Try to extract JSON block if wrapped in markdown
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except Exception:
                    return []
            else:
                return []

        findings: List[Dict[str, Any]] = []
        for item in data.get("findings", []):
            cwe = item.get("cwe") or "UNCLASSIFIED"
            findings.append({
                "cve_id": item.get("cve_id"),
                "cwe_type": "UNCLASSIFIED",
                "taxonomy_refs": [ref for ref in [cwe, item.get("cve_id")] if ref and ref != "UNCLASSIFIED"],
                "filepath": item.get("filepath", ""),
                "line_number": int(item.get("line", 0) or 0),
                "code_chunk": item.get("snippet", ""),
                "llm_verdict": "",
                "llm_explanation": item.get("reason", ""),
                "confidence": float(item.get("confidence", 0.5) or 0.5),
                "pov_script": None,
                "pov_path": None,
                "pov_result": None,
                "retry_count": 0,
                "inference_time_s": 0.0,
                "cost_usd": 0.0,
                "final_status": "",
                "alert_message": "LLM triage",
                "source": "llm_scout",
                "language": item.get("language", "unknown"),
                "scout_model_used": model_name or getattr(llm, "_autopov_model_name", ""),
                "scout_token_usage": token_usage,
                "scout_openrouter_usage": openrouter_usage,
            })
            if len(findings) >= max_findings:
                break

        return findings


llm_scout = LLMScout()


def get_llm_scout() -> LLMScout:
    return llm_scout

