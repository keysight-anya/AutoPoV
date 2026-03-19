"""
AutoPoV Analysis Cache Module
Caches analysis results for similar code patterns to reduce LLM calls and costs.
"""

import os
import json
import hashlib
import threading
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import re


@dataclass
class CachedAnalysis:
    """Cached analysis result"""
    code_hash: str
    code_pattern: str  # Normalized code pattern (variables replaced with placeholders)
    filepath: str
    language: str
    verdict: str
    cwe_type: str
    confidence: float
    explanation: str
    vulnerable_code: str
    created_at: str
    hit_count: int = 0
    ttl_days: int = 30


class AnalysisCache:
    """Cache for code analysis results to avoid redundant LLM calls"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._cache_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'cache')
        self._prompt_cache_file = os.path.join(self._cache_dir, 'prompt_cache.json')
        self._result_cache_file = os.path.join(self._cache_dir, 'result_cache.json')
        self._prompt_cache: Dict[str, CachedAnalysis] = {}
        self._result_cache: Dict[str, Dict[str, Any]] = {}  # codebase_hash -> full result
        self._cache_lock = threading.RLock()
        
        os.makedirs(self._cache_dir, exist_ok=True)
        self._load_caches()
    
    def _load_caches(self):
        """Load caches from disk"""
        # Load prompt cache
        if os.path.exists(self._prompt_cache_file):
            try:
                with open(self._prompt_cache_file, 'r') as f:
                    data = json.load(f)
                for key, item in data.items():
                    self._prompt_cache[key] = CachedAnalysis(**item)
            except Exception as e:
                print(f"[Cache] Failed to load prompt cache: {e}")
        
        # Load result cache
        if os.path.exists(self._result_cache_file):
            try:
                with open(self._result_cache_file, 'r') as f:
                    self._result_cache = json.load(f)
            except Exception as e:
                print(f"[Cache] Failed to load result cache: {e}")
    
    def _save_prompt_cache(self):
        """Save prompt cache to disk"""
        try:
            with open(self._prompt_cache_file, 'w') as f:
                json.dump({k: asdict(v) for k, v in self._prompt_cache.items()}, f, indent=2)
        except Exception as e:
            print(f"[Cache] Failed to save prompt cache: {e}")
    
    def _save_result_cache(self):
        """Save result cache to disk"""
        try:
            with open(self._result_cache_file, 'w') as f:
                json.dump(self._result_cache, f, indent=2)
        except Exception as e:
            print(f"[Cache] Failed to save result cache: {e}")
    
    def _normalize_code(self, code: str) -> str:
        """
        Normalize code by replacing variable names, strings, and numbers with placeholders.
        This allows matching similar code patterns across different codebases.
        """
        if not code:
            return ""
        
        normalized = code
        
        # Replace string literals with placeholder
        normalized = re.sub(r'"[^"]*"', '"STRING"', normalized)
        normalized = re.sub(r"'[^']*'", "'STRING'", normalized)
        
        # Replace numbers with placeholder (but keep 0 and 1 as they're often flags)
        normalized = re.sub(r'\b[2-9]\b', 'NUM', normalized)
        normalized = re.sub(r'\b\d{2,}\b', 'NUM', normalized)
        
        # Replace common variable naming patterns
        # This is conservative - only replace very common patterns
        var_patterns = [
            (r'\b[a-z]{1,2}\b(?=\s*[=,;)])', 'VAR'),  # Single/double letter vars
            (r'\b[var_][a-zA-Z0-9]*\b', 'VAR'),  # var_prefix variables
            (r'\b[a-zA-Z]+_[a-zA-Z0-9]+\b', 'VAR'),  # snake_case variables
        ]
        # Don't replace keywords
        keywords = {'if', 'else', 'for', 'while', 'return', 'def', 'class', 'import', 
                    'from', 'try', 'except', 'with', 'as', 'in', 'is', 'not', 'and', 'or',
                    'function', 'const', 'let', 'var', 'void', 'int', 'char', 'struct'}
        
        for pattern, replacement in var_patterns:
            def replace_if_not_keyword(m):
                word = m.group(0)
                return replacement if word.lower() not in keywords else word
            normalized = re.sub(pattern, replace_if_not_keyword, normalized)
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def _compute_code_hash(self, code: str) -> str:
        """Compute hash of normalized code pattern"""
        normalized = self._normalize_code(code)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    
    def _compute_codebase_hash(self, codebase_path: str) -> str:
        """Compute hash of codebase structure and key files"""
        hasher = hashlib.sha256()
        
        # Hash file structure
        file_list = []
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.go', '.rs', '.rb', '.php'}
        
        for root, dirs, files in os.walk(codebase_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                      ('node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', '.git')]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in code_extensions:
                    fpath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(fpath)
                        mtime = os.path.getmtime(fpath)
                        file_list.append((os.path.relpath(fpath, codebase_path), size, mtime))
                    except Exception:
                        pass
        
        file_list.sort()  # Consistent ordering
        for item in file_list:
            hasher.update(str(item).encode())
        
        return hasher.hexdigest()[:16]
    
    def get_cached_analysis(self, code: str, filepath: str, language: str) -> Optional[CachedAnalysis]:
        """
        Get cached analysis for similar code pattern.
        
        Returns:
            CachedAnalysis if found and not expired, None otherwise
        """
        with self._cache_lock:
            code_hash = self._compute_code_hash(code)
            cache_key = f"{language}:{code_hash}"
            
            cached = self._prompt_cache.get(cache_key)
            if cached:
                # Check if expired
                created = datetime.fromisoformat(cached.created_at)
                if datetime.utcnow() - created > timedelta(days=cached.ttl_days):
                    del self._prompt_cache[cache_key]
                    self._save_prompt_cache()
                    return None
                
                # Increment hit count
                cached.hit_count += 1
                self._save_prompt_cache()
                return cached
            
            return None
    
    def cache_analysis(
        self,
        code: str,
        filepath: str,
        language: str,
        verdict: str,
        cwe_type: str,
        confidence: float,
        explanation: str,
        vulnerable_code: str = ""
    ):
        """Cache an analysis result"""
        with self._cache_lock:
            code_hash = self._compute_code_hash(code)
            cache_key = f"{language}:{code_hash}"
            
            cached = CachedAnalysis(
                code_hash=code_hash,
                code_pattern=self._normalize_code(code)[:200],  # Store pattern for debugging
                filepath=filepath,
                language=language,
                verdict=verdict,
                cwe_type=cwe_type,
                confidence=confidence,
                explanation=explanation[:500],  # Truncate for storage
                vulnerable_code=vulnerable_code[:500],
                created_at=datetime.utcnow().isoformat(),
                hit_count=0
            )
            
            self._prompt_cache[cache_key] = cached
            self._save_prompt_cache()
    
    def get_cached_result(self, codebase_path: str) -> Optional[Dict[str, Any]]:
        """
        Get cached full scan result for a codebase.
        
        Returns:
            Full scan result if found and codebase unchanged, None otherwise
        """
        with self._cache_lock:
            codebase_hash = self._compute_codebase_hash(codebase_path)
            cached = self._result_cache.get(codebase_hash)
            
            if cached:
                # Check if expired
                created = datetime.fromisoformat(cached.get('created_at', '2000-01-01'))
                if datetime.utcnow() - created > timedelta(days=7):  # 7 day TTL for full results
                    del self._result_cache[codebase_hash]
                    self._save_result_cache()
                    return None
                
                return cached
            
            return None
    
    def cache_result(self, codebase_path: str, result: Dict[str, Any]):
        """Cache a full scan result"""
        with self._cache_lock:
            codebase_hash = self._compute_codebase_hash(codebase_path)
            
            # Store with metadata
            cache_entry = {
                'codebase_hash': codebase_hash,
                'created_at': datetime.utcnow().isoformat(),
                'findings': result.get('findings', []),
                'total_findings': result.get('total_findings', 0),
                'confirmed_vulns': result.get('confirmed_vulns', 0),
                'status': result.get('status', 'completed'),
                'model_name': result.get('model_name', ''),
            }
            
            self._result_cache[codebase_hash] = cache_entry
            self._save_result_cache()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._cache_lock:
            total_prompt_entries = len(self._prompt_cache)
            total_hits = sum(c.hit_count for c in self._prompt_cache.values())
            total_result_entries = len(self._result_cache)
            
            # Estimate token savings (rough: ~500 tokens per cached analysis)
            estimated_tokens_saved = total_hits * 500
            estimated_cost_saved = estimated_tokens_saved * 0.00001  # Rough estimate
            
            return {
                'prompt_cache_entries': total_prompt_entries,
                'prompt_cache_hits': total_hits,
                'result_cache_entries': total_result_entries,
                'estimated_tokens_saved': estimated_tokens_saved,
                'estimated_cost_saved_usd': estimated_cost_saved,
            }
    
    def clear_all(self) -> Tuple[int, int]:
        """Clear all cache entries. Returns (prompts_cleared, results_cleared)"""
        with self._cache_lock:
            prompt_count = len(self._prompt_cache)
            result_count = len(self._result_cache)
            self._prompt_cache.clear()
            self._result_cache.clear()
            self._save_prompt_cache()
            self._save_result_cache()
            return prompt_count, result_count

    def clear_expired(self) -> Tuple[int, int]:
        """Clear expired cache entries. Returns (prompts_cleared, results_cleared)"""
        with self._cache_lock:
            now = datetime.utcnow()
            
            # Clear expired prompt cache
            expired_prompts = []
            for key, cached in self._prompt_cache.items():
                created = datetime.fromisoformat(cached.created_at)
                if now - created > timedelta(days=cached.ttl_days):
                    expired_prompts.append(key)
            
            for key in expired_prompts:
                del self._prompt_cache[key]
            
            # Clear expired result cache
            expired_results = []
            for key, cached in self._result_cache.items():
                created = datetime.fromisoformat(cached.get('created_at', '2000-01-01'))
                if now - created > timedelta(days=7):
                    expired_results.append(key)
            
            for key in expired_results:
                del self._result_cache[key]
            
            self._save_prompt_cache()
            self._save_result_cache()
            
            return len(expired_prompts), len(expired_results)


# Global cache instance
analysis_cache = AnalysisCache()


def get_analysis_cache() -> AnalysisCache:
    """Get the global analysis cache instance"""
    return analysis_cache
