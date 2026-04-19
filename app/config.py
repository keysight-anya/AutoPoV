"""
AutoPoV Configuration Module
Pydantic Settings for all environment variables and configuration
"""

import json
import os
import subprocess
import time
import urllib.request
from urllib.parse import urlparse
from typing import Optional, List, Any, Dict
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


_OLLAMA_MODEL_METADATA_CACHE: Dict[str, Dict[str, Any]] = {}
_OLLAMA_MODEL_METADATA_TTL_S = 300


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    APP_NAME: str = "AutoPoV"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # API Configuration
    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8000, env="API_PORT")
    API_PREFIX: str = "/api"
    
    # Security
    WEBHOOK_SECRET: str = Field(default="", env="WEBHOOK_SECRET")
    
    # LLM Configuration - Online (OpenRouter)
    OPENROUTER_API_KEY: str = Field(default="", env="OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_ENABLE_REASONING: bool = Field(default=True, env="OPENROUTER_ENABLE_REASONING")
    # Max completion tokens sent to OpenRouter.
    # Default 0 = NO CAP (omit max_tokens from the payload entirely, letting the model
    # use as many tokens as it needs).  This is the correct setting for accuracy.
    # Set via env var OPENROUTER_MAX_TOKENS if you want a hard ceiling (e.g. when
    # your balance is low and you want to prevent a single call exhausting it).
    OPENROUTER_MAX_TOKENS: int = Field(default=0, env="OPENROUTER_MAX_TOKENS")
    
    # UI-configured OpenRouter key (stored in learning.db, overrides env if set)
    OPENROUTER_API_KEY_UI: str = ""
    
    # LLM Configuration - Offline (Ollama)
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    OLLAMA_CONNECT_TIMEOUT_S: int = Field(default=10, env="OLLAMA_CONNECT_TIMEOUT_S")
    OLLAMA_READ_TIMEOUT_S: int = Field(default=180, env="OLLAMA_READ_TIMEOUT_S")
    LLM_REQUEST_TIMEOUT_S: int = Field(default=180, env="LLM_REQUEST_TIMEOUT_S")
    OLLAMA_NUM_CTX: int = Field(default=1536, env="OLLAMA_NUM_CTX")
    OLLAMA_NUM_PREDICT: int = Field(default=384, env="OLLAMA_NUM_PREDICT")
    
    # Model Selection - NO DEFAULTS: Must be configured in Settings
    MODEL_MODE: str = Field(default="online", env="MODEL_MODE")  # 'online' or 'offline'
    MODEL_NAME: str = Field(default="", env="MODEL_NAME")  # Must be set in Settings

    # Fixed model execution
    ROUTING_MODE: str = Field(default="fixed", env="ROUTING_MODE")
    LEARNING_DB_PATH: str = Field(default="./data/learning.db", env="LEARNING_DB_PATH")

    # Scout Settings
    SCOUT_ENABLED: bool = Field(default=True, env="SCOUT_ENABLED")
    SCOUT_LLM_ENABLED: bool = Field(default=False, env="SCOUT_LLM_ENABLED")  # Disabled - redundant with Investigator
    SCOUT_MAX_FILES: int = Field(default=100, env="SCOUT_MAX_FILES")  # Increased from 25 to process more candidates
    SCOUT_MAX_CHARS_PER_FILE: int = Field(default=4000, env="SCOUT_MAX_CHARS_PER_FILE")
    SCOUT_MAX_FINDINGS: int = Field(default=200, env="SCOUT_MAX_FINDINGS")
    SCOUT_MAX_COST_USD: float = Field(default=0.0, env="SCOUT_MAX_COST_USD")
    
    # Available Models - Only these models are supported
    ONLINE_MODELS: List[str] = [
        "openai/gpt-5.2",
        "anthropic/claude-opus-4.6"
    ]
    OFFLINE_MODELS: List[str] = [
        "llama4",
        "glm-4.7-flash",
        "qwen3"
    ]
    
    # Git Provider Tokens
    GITHUB_TOKEN: str = Field(default="", env="GITHUB_TOKEN")
    GITLAB_TOKEN: str = Field(default="", env="GITLAB_TOKEN")
    BITBUCKET_TOKEN: str = Field(default="", env="BITBUCKET_TOKEN")
    
    # GitHub/GitLab Webhook Secrets
    GITHUB_WEBHOOK_SECRET: str = Field(default="", env="GITHUB_WEBHOOK_SECRET")
    GITLAB_WEBHOOK_SECRET: str = Field(default="", env="GITLAB_WEBHOOK_SECRET")
    
    # Vector Store (ChromaDB)
    CHROMA_PERSIST_DIR: str = Field(default="./data/chroma", env="CHROMA_PERSIST_DIR")
    CHROMA_COLLECTION_NAME: str = "code_chunks"
    
    # Embeddings
    EMBEDDING_MODEL_ONLINE: str = "openai/text-embedding-3-small"  # Must be prefixed for OpenRouter
    EMBEDDING_MODEL_OFFLINE: str = "sentence-transformers/all-MiniLM-L6-v2"
    PREFER_LOCAL_EMBEDDINGS: bool = Field(default=True, env="PREFER_LOCAL_EMBEDDINGS")
    LOCAL_EMBEDDING_BACKEND: str = Field(default="sentence-transformers", env="LOCAL_EMBEDDING_BACKEND")
    HF_TOKEN: str = Field(default="", env="HF_TOKEN")
    HUGGINGFACEHUB_API_TOKEN: str = Field(default="", env="HUGGINGFACEHUB_API_TOKEN")
    
    # LangSmith Tracing
    LANGCHAIN_TRACING_V2: bool = Field(default=False, env="LANGCHAIN_TRACING_V2")
    LANGCHAIN_API_KEY: str = Field(default="", env="LANGCHAIN_API_KEY")
    LANGCHAIN_PROJECT: str = Field(default="autopov", env="LANGCHAIN_PROJECT")
    
    # Code Analysis Tools
    CODEQL_CLI_PATH: str = Field(default="codeql", env="CODEQL_CLI_PATH")
    CODEQL_PACKS_BASE: str = Field(default="/usr/local/codeql/packs", env="CODEQL_PACKS_BASE")
    JOERN_CLI_PATH: str = Field(default="joern", env="JOERN_CLI_PATH")
    KAITAI_STRUCT_COMPILER_PATH: str = Field(default="kaitai-struct-compiler", env="KAITAI_STRUCT_COMPILER_PATH")
    
    # Docker Configuration
    DOCKER_ENABLED: bool = Field(default=True, env="DOCKER_ENABLED")
    DOCKER_IMAGE: str = Field(default="autopov/proof-python:latest", env="DOCKER_IMAGE")
    DOCKER_NODE_IMAGE: str = Field(default="autopov/proof-node:latest", env="DOCKER_NODE_IMAGE")
    DOCKER_BROWSER_IMAGE: str = Field(default="autopov/proof-browser:latest", env="DOCKER_BROWSER_IMAGE")
    DOCKER_NATIVE_IMAGE: str = Field(default="autopov/proof-native:latest", env="DOCKER_NATIVE_IMAGE")
    DOCKER_PHP_IMAGE: str = Field(default="autopov/proof-php:latest", env="DOCKER_PHP_IMAGE")
    DOCKER_RUBY_IMAGE: str = Field(default="autopov/proof-ruby:latest", env="DOCKER_RUBY_IMAGE")
    DOCKER_GO_IMAGE: str = Field(default="autopov/proof-go:latest", env="DOCKER_GO_IMAGE")
    DOCKER_JAVA_IMAGE: str = Field(default="autopov/proof-java:latest", env="DOCKER_JAVA_IMAGE")
    DOCKER_SHELL_IMAGE: str = Field(default="ubuntu:24.04", env="DOCKER_SHELL_IMAGE")
    DOCKER_TIMEOUT: int = Field(default=180, env="DOCKER_TIMEOUT")
    DOCKER_IMAGE_PREP_TIMEOUT: int = Field(default=180, env="DOCKER_IMAGE_PREP_TIMEOUT")
    DOCKER_MEMORY_LIMIT: str = Field(default="2g", env="DOCKER_MEMORY_LIMIT")
    DOCKER_CPU_LIMIT: float = Field(default=2.0, env="DOCKER_CPU_LIMIT")
    
    # Cost Control
    MAX_COST_USD: float = Field(default=100.0, env="MAX_COST_USD")
    COST_TRACKING_ENABLED: bool = Field(default=False, env="COST_TRACKING_ENABLED")
    
    # Token Tracking (per model)
    TOKEN_TRACKING_ENABLED: bool = Field(default=True, env="TOKEN_TRACKING_ENABLED")
    
    # Scanning Configuration
    MAX_CHUNK_SIZE: int = 4000
    CHUNK_OVERLAP: int = 200
    MAX_RETRIES: int = 3  # Increased for self-healing refiner
    DISCOVERY_MAX_FINDINGS: int = Field(default=150, env="DISCOVERY_MAX_FINDINGS")
    PROOF_MAX_FINDINGS: int = Field(default=9999, env="PROOF_MAX_FINDINGS")  # Effectively unlimited — every REAL finding gets a proof attempt; override with env var to cap for cost control

    # Per-model capability profiles — controls max_retries, min_confidence, and code context
    # budget per model tier.  Keys map to resolved tier names from resolve_model_capability_profile().
    # Override individual values via env vars MODEL_CAPABILITY_PROFILES (JSON string) if needed.
    MODEL_CAPABILITY_PROFILES: Dict[str, Any] = Field(default={
        "offline_small":  {"max_retries": 5, "min_confidence": 0.4, "ctx_chars": 4000},
        "offline_medium": {"max_retries": 4, "min_confidence": 0.45, "ctx_chars": 8000},
        "offline_large":  {"max_retries": 4, "min_confidence": 0.45, "ctx_chars": 12000},
        "online_large":   {"max_retries": 3, "min_confidence": 0.5, "ctx_chars": 32000},
    }, env="MODEL_CAPABILITY_PROFILES")
    CODEQL_TIMEOUT_S: int = Field(default=180, env="CODEQL_TIMEOUT_S")
    CODEQL_QUERY_TIMEOUT_S: int = Field(default=90, env="CODEQL_QUERY_TIMEOUT_S")
    SEMGREP_TIMEOUT_S: int = Field(default=300, env="SEMGREP_TIMEOUT_S")
    
    # Parallel Processing Configuration
    PARALLEL_PROCESSING_ENABLED: bool = Field(default=True, env="PARALLEL_PROCESSING_ENABLED")
    PARALLEL_MAX_WORKERS: int = Field(default=5, env="PARALLEL_MAX_WORKERS")
    PARALLEL_RATE_LIMIT_RPS: int = Field(default=10, env="PARALLEL_RATE_LIMIT_RPS")  # Requests per second
    
    # Cost & Speed Optimization
    LITE_MODE: bool = Field(default=False, env="LITE_MODE")  # Quick scan without PoV execution
    EARLY_STOP_AFTER_CONFIRMED: int = Field(default=10, env="EARLY_STOP_AFTER_CONFIRMED")  # Stop after N confirmed findings
    SKIP_CHROMADB: bool = Field(default=True, env="SKIP_CHROMADB")  # Legacy flag; ignored when RAG_REQUIRED is enabled
    RAG_REQUIRED: bool = Field(default=True, env="RAG_REQUIRED")
    REQUIRE_RUNTIME_PROOF: bool = Field(default=True, env="REQUIRE_RUNTIME_PROOF")
    MIN_CONFIDENCE_FOR_POV: float = Field(default=0.50, env="MIN_CONFIDENCE_FOR_POV")  # 0.50 = attempt proof for all REAL findings with any reasonable confidence; lower = more coverage
    BATCH_SIMILAR_FINDINGS: bool = Field(default=True, env="BATCH_SIMILAR_FINDINGS")  # Group similar findings for analysis
    
    # Note: INTERNAL_SECURITY_RULESET has been removed for CWE-agnostic scanning.
    # CodeQL and Semgrep now run their full security suites without CWE filtering.
    # The exploratory agent and LLM scout perform open-ended vulnerability discovery.
    # Findings are still classified with CWE labels when appropriate, but no CWE
    # is required for detection or validation.

    # File Paths
    DATA_DIR: str = "./data"
    BENCHMARKS_DIR: str = "./data/benchmarks"
    BENCHMARK_SOURCES_DIR: str = "./data/benchmarks/sources"
    RESULTS_DIR: str = "./results"
    POVS_DIR: str = "./results/povs"
    PROOF_ARTIFACTS_DIR: str = Field(default="./results/proof_artifacts", env="PROOF_ARTIFACTS_DIR")
    RUNS_DIR: str = "./results/runs"
    ACTIVE_RUNS_DIR: str = "./results/runs/active"
    TEMP_DIR: str = "/tmp/autopov"
    MAX_UPLOAD_SIZE_MB: int = Field(default=50, env="MAX_UPLOAD_SIZE_MB")
    MAX_ARCHIVE_UNCOMPRESSED_MB: int = Field(default=250, env="MAX_ARCHIVE_UNCOMPRESSED_MB")
    MAX_ARCHIVE_FILES: int = Field(default=10000, env="MAX_ARCHIVE_FILES")
    MAX_ARCHIVE_COMPRESSION_RATIO: float = Field(default=100.0, env="MAX_ARCHIVE_COMPRESSION_RATIO")
    SNAPSHOT_DIR: str = Field(default="./results/snapshots", env="SNAPSHOT_DIR")
    
    # Snapshot Configuration
    SAVE_CODEBASE_SNAPSHOT: bool = Field(default=True, env="SAVE_CODEBASE_SNAPSHOT")
    
    # Frontend
    FRONTEND_URL: str = Field(default="http://localhost:5173", env="FRONTEND_URL")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )
    
    @field_validator("MODEL_MODE")
    def validate_model_mode(cls, v):
        if v not in ["online", "offline"]:
            raise ValueError("MODEL_MODE must be 'online' or 'offline'")
        return v
    
    def get_frontend_origin(self) -> str:
        raw = (self.FRONTEND_URL or '').rstrip('/')
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return raw

    def get_allowed_frontend_origins(self) -> List[str]:
        origin = self.get_frontend_origin()
        if not origin:
            return []

        parsed = urlparse(origin)
        hostname = parsed.hostname or ''
        port = f":{parsed.port}" if parsed.port else ''
        scheme = parsed.scheme or 'http'

        origins = {origin}
        if hostname in {'localhost', '127.0.0.1', '0.0.0.0'}:
            origins.update({
                f'{scheme}://localhost{port}',
                f'{scheme}://127.0.0.1{port}',
                f'{scheme}://0.0.0.0{port}',
            })

        return sorted(origins)

    def resolve_model_capability_profile(self, model_name: Optional[str] = None, model_mode: Optional[str] = None) -> Dict[str, Any]:
        """Return the capability profile (max_retries, min_confidence, ctx_chars) for a model.

        Tier resolution order:
          1. online model          → 'online_large'
          2. offline model whose name contains '70b' or '72b' or 'llama4'→ 'offline_large'
          3. offline model containing '13b' or '34b' or any glm/qwen named mid-tier→ 'offline_medium'
          4. everything else offline→ 'offline_small'

        Returns a dict merged from the matching profile, always containing the three keys.
        The global default (settings.MAX_RETRIES etc.) is the fallback.
        """
        profiles = dict(self.MODEL_CAPABILITY_PROFILES or {})
        default_profile = {
            'max_retries': self.MAX_RETRIES,
            'min_confidence': self.MIN_CONFIDENCE_FOR_POV,
            'ctx_chars': 8000,
        }

        name = (model_name or self.MODEL_NAME or '').strip().lower()
        mode = (model_mode or self.MODEL_MODE or '').strip().lower()

        # Determine mode if not explicitly passed
        if name and not mode:
            try:
                mode = self.resolve_model_mode(name)
            except ValueError:
                mode = 'offline'

        tier: str
        if mode == 'online':
            tier = 'online_large'
        else:
            # Offline tier classification based on known model name patterns
            if any(tag in name for tag in ('70b', '72b', '65b', 'llama4', '34b')):
                tier = 'offline_large'
            elif any(tag in name for tag in ('13b', '20b', 'glm-4', 'qwen3', 'llama3')):
                tier = 'offline_medium'
            else:
                tier = 'offline_small'

        profile = dict(profiles.get(tier) or {})
        result = dict(default_profile)
        result.update({k: v for k, v in profile.items() if v is not None})
        result['tier'] = tier
        return result


    def is_docker_available(self) -> bool:
        """Check if Docker is available and running"""
        if not self.DOCKER_ENABLED:
            return False
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def is_codeql_available(self) -> bool:
        """Check if CodeQL CLI is available"""
        try:
            result = subprocess.run(
                [self.CODEQL_CLI_PATH, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def get_openrouter_api_key(self) -> str:
        """Get the effective OpenRouter API key (env var takes precedence)"""
        # Environment variable always takes precedence
        if self.OPENROUTER_API_KEY:
            return self.OPENROUTER_API_KEY
        # Fall back to UI-configured key
        return self.OPENROUTER_API_KEY_UI
    
    def is_openrouter_key_from_env(self) -> bool:
        """Check if OpenRouter key is set via environment variable"""
        return bool(self.OPENROUTER_API_KEY)
    
    def is_joern_available(self) -> bool:
        """Runtime check: verify joern binary is executable."""
        import shutil
        cli = self.JOERN_CLI_PATH or 'joern'
        if not shutil.which(cli):
            return False
        try:
            result = subprocess.run(
                [cli, '--version'],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_effective_ollama_base_url(self) -> str:
        """Use the Docker service URL automatically when running inside Docker."""
        if self.OLLAMA_BASE_URL and 'localhost:11434' not in self.OLLAMA_BASE_URL:
            return self.OLLAMA_BASE_URL
        if os.path.exists('/.dockerenv'):
            return 'http://ollama:11434'
        return self.OLLAMA_BASE_URL

    def is_kaitai_available(self) -> bool:
        """Check if Kaitai Struct compiler is available"""
        try:
            result = subprocess.run(
                [self.KAITAI_STRUCT_COMPILER_PATH, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def get_ollama_model_metadata(self, model_name: Optional[str] = None) -> dict:
        """Fetch and cache Ollama model metadata so prompt sizing can respect each model's real limits."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        if not selected_model:
            return {}

        cache_key = f"{self.get_effective_ollama_base_url()}::{selected_model}"
        now = time.time()
        cached = _OLLAMA_MODEL_METADATA_CACHE.get(cache_key)
        if cached and now - float(cached.get("fetched_at", 0)) < _OLLAMA_MODEL_METADATA_TTL_S:
            return dict(cached)

        metadata = {
            "model": selected_model,
            "context_length": 0,
            "capabilities": [],
            "architecture": "",
            "parameter_count": 0,
            "parameters": "",
            "fetched_at": now,
        }

        try:
            url = self.get_effective_ollama_base_url().rstrip("/") + "/api/show"
            payload = json.dumps({"name": selected_model}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            timeout_s = max(10, self.OLLAMA_CONNECT_TIMEOUT_S + min(self.OLLAMA_READ_TIMEOUT_S, 20))
            with urllib.request.urlopen(req, timeout=timeout_s) as response:
                body = response.read().decode("utf-8", errors="ignore")
            parsed = json.loads(body) if body else {}
            model_info = parsed.get("model_info") if isinstance(parsed, dict) else {}
            context_candidates = []
            if isinstance(model_info, dict):
                for key, value in model_info.items():
                    lowered = str(key).lower()
                    if isinstance(value, int) and value > 0 and ("context_length" in lowered or "n_ctx" in lowered):
                        context_candidates.append(int(value))
                metadata["architecture"] = str(model_info.get("general.architecture") or "")
                try:
                    metadata["parameter_count"] = int(model_info.get("general.parameter_count") or 0)
                except (TypeError, ValueError):
                    metadata["parameter_count"] = 0
            if context_candidates:
                metadata["context_length"] = min(context_candidates)
            metadata["capabilities"] = list(parsed.get("capabilities") or []) if isinstance(parsed, dict) else []
            metadata["parameters"] = str(parsed.get("parameters") or "") if isinstance(parsed, dict) else ""
        except Exception:
            pass

        _OLLAMA_MODEL_METADATA_CACHE[cache_key] = dict(metadata)
        return metadata

    def get_offline_input_budget(self, model_name: Optional[str] = None, purpose: str = "general") -> dict:
        """Estimate a safe offline prompt budget from the configured ctx/predict settings."""
        options = self.get_ollama_generation_options(model_name=model_name, purpose=purpose)
        num_ctx = int(options.get("num_ctx") or self.OLLAMA_NUM_CTX or 2048)
        num_predict = int(options.get("num_predict") or self.OLLAMA_NUM_PREDICT or 256)
        reserved_tokens = 256 if purpose in {"pov", "refinement", "investigation"} else 192
        input_tokens = max(384, num_ctx - num_predict - reserved_tokens)
        return {
            "num_ctx": num_ctx,
            "num_predict": num_predict,
            "reserved_tokens": reserved_tokens,
            "input_tokens": input_tokens,
            "input_chars": max(1800, input_tokens * 3),
            "model_context_length": int(options.get("model_context_length") or 0),
        }

    def get_offline_investigation_budget(self, model_name: Optional[str] = None) -> dict:
        """Bound offline investigation inputs so local models do not get truncated before reasoning."""
        budget = self.get_offline_input_budget(model_name=model_name, purpose="investigation")
        chars = int(budget.get("input_chars") or 2400)
        return {
            "max_code_context_chars": max(1200, min(7200, int(chars * 0.58))),
            "max_alert_chars": max(220, min(1000, int(chars * 0.10))),
            "max_joern_chars": max(0, min(2600, int(chars * 0.22))),
        }
    
    def is_online_model(self, model_name: str) -> bool:
        return bool(model_name) and model_name in self.ONLINE_MODELS

    def is_offline_model(self, model_name: str) -> bool:
        return bool(model_name) and model_name in self.OFFLINE_MODELS

    def resolve_model_mode(self, model_name: str) -> str:
        selected_model = (model_name or "").strip()
        if not selected_model:
            raise ValueError("No model selected. Choose one in Settings or pass an explicit CLI override.")
        if self.is_online_model(selected_model):
            return "online"
        if self.is_offline_model(selected_model):
            return "offline"
        raise ValueError(
            f"Unsupported model '{selected_model}'. Choose one of the configured online or offline models."
        )

    def get_llm_config(self, model_name: Optional[str] = None, model_mode: Optional[str] = None) -> dict:
        """Get LLM configuration for an explicitly selected model."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        resolved_mode = model_mode or self.resolve_model_mode(selected_model)

        if resolved_mode == "online":
            if not self.is_online_model(selected_model):
                raise ValueError(f"Model '{selected_model}' is not configured as an online model.")
            return {
                "mode": "online",
                "model": selected_model,
                "api_key": self.get_openrouter_api_key(),
                "base_url": self.OPENROUTER_BASE_URL,
                "embedding_model": self.EMBEDDING_MODEL_ONLINE,
                "provider": "openrouter",
                "reasoning_enabled": self.OPENROUTER_ENABLE_REASONING,
            }

        if not self.is_offline_model(selected_model):
            raise ValueError(f"Model '{selected_model}' is not configured as an offline model.")
        return {
            "mode": "offline",
            "model": selected_model,
            "base_url": self.get_effective_ollama_base_url(),
            "embedding_model": self.EMBEDDING_MODEL_OFFLINE,
            "provider": "ollama",
            "reasoning_enabled": False,
        }

    def get_ollama_client_kwargs(self, model_name: Optional[str] = None, purpose: str = "general") -> dict:
        """Return offline-only Ollama request limits tuned for local execution."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        read_timeout_s = self.OLLAMA_READ_TIMEOUT_S
        timeout_floors = {
            "qwen3": {"general": 300, "scout": 300, "triage": 300, "pov": 420, "refinement": 360, "validation": 240, "retry": 240},
            "glm-4.7-flash": {"general": 480, "scout": 480, "triage": 480, "pov": 720, "refinement": 600, "validation": 360, "retry": 360},
            "llama4": {"general": 900, "scout": 900, "triage": 900, "pov": 1200, "refinement": 960, "validation": 480, "retry": 480},
        }
        model_timeouts = timeout_floors.get(selected_model, {})
        read_timeout_s = max(read_timeout_s, model_timeouts.get(purpose, model_timeouts.get("general", read_timeout_s)))
        return {"timeout": (self.OLLAMA_CONNECT_TIMEOUT_S, read_timeout_s)}

    def get_online_max_tokens(self, purpose: str = "general") -> Optional[int]:
        """Return the max_tokens value for OpenRouter requests.

        Returns None (= no cap) when OPENROUTER_MAX_TOKENS is 0 (the default).
        The model is then free to generate as many tokens as it needs, giving
        the most accurate and complete output.

        Set OPENROUTER_MAX_TOKENS > 0 via env var to impose a hard ceiling
        (e.g. OPENROUTER_MAX_TOKENS=8192 when running on a low balance).

        Empirical peaks observed across 5 real scans for reference:
          - investigation: 2,453 tokens (GPT-5.2)
          - pov:          20,507 tokens (Claude-opus-4.6)
          - refinement:   11,937 tokens (GPT-5.2)
        """
        ceiling = int(self.OPENROUTER_MAX_TOKENS)
        if ceiling <= 0:
            return None  # no cap — let the model use what it needs
        return ceiling

    def get_ollama_generation_options(self, model_name: Optional[str] = None, purpose: str = "general") -> dict:
        """Return offline generation settings without affecting online execution."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        configured_ctx = int(self.OLLAMA_NUM_CTX or 2048)
        configured_predict = int(self.OLLAMA_NUM_PREDICT or 256)

        purpose_caps = {
            "general": (4096, 320),
            "investigation": (6144, 448),
            "scout": (3072, 256),
            "triage": (3072, 256),
            "pov": (4096, 512),
            "refinement": (4096, 512),
            "validation": (3072, 320),
            "retry": (3072, 320),
        }
        model_caps = {
            "qwen3": {"general": (3072, 320), "investigation": (4096, 448), "scout": (2048, 256), "triage": (2048, 256), "pov": (4096, 2048), "refinement": (4096, 2048), "validation": (3072, 256), "retry": (3072, 512)},
            "glm-4.7-flash": {"general": (4096, 320), "investigation": (6144, 512), "scout": (3072, 256), "triage": (3072, 256), "pov": (4096, 2048), "refinement": (4096, 2048), "validation": (3072, 320), "retry": (3072, 512)},
            "llama4": {"general": (4096, 384), "investigation": (6144, 640), "scout": (3072, 256), "triage": (3072, 256), "pov": (4096, 2048), "refinement": (4096, 2048), "validation": (3072, 320), "retry": (3072, 512)},
        }
        minimum_ctx = {
            "qwen3": {"general": 3072, "investigation": 4096, "pov": 4096, "refinement": 4096, "validation": 3072, "retry": 3072},
            "glm-4.7-flash": {"general": 4096, "investigation": 6144, "pov": 4096, "refinement": 4096, "validation": 3072, "retry": 3072},
            "llama4": {"general": 4096, "investigation": 6144, "pov": 4096, "refinement": 4096, "validation": 3072, "retry": 3072},
        }

        selected_caps = model_caps.get(selected_model, purpose_caps)
        capped_ctx, capped_predict = selected_caps.get(purpose, selected_caps.get("general", (configured_ctx, configured_predict)))
        metadata = self.get_ollama_model_metadata(selected_model)
        model_context_length = int(metadata.get("context_length") or 0)
        desired_floor = minimum_ctx.get(selected_model, {}).get(purpose, minimum_ctx.get(selected_model, {}).get("general", configured_ctx))

        num_ctx = max(configured_ctx, desired_floor)
        num_ctx = min(num_ctx, capped_ctx)
        if model_context_length > 0:
            num_ctx = min(num_ctx, model_context_length)
        num_ctx = max(1024, num_ctx)

        num_predict = min(configured_predict, capped_predict)
        if purpose in {"pov", "refinement", "investigation"}:
            # Floor = the model's full cap for pov/refinement — PoV scripts need the
            # entire generation budget to fit boilerplate + exploit body without truncation.
            num_predict = max(num_predict, capped_predict)
        elif purpose in {"validation", "retry"}:
            num_predict = max(num_predict, min(512, capped_predict))

        return {
            "num_ctx": num_ctx,
            "num_predict": num_predict,
            "model_context_length": model_context_length,
            "capabilities": metadata.get("capabilities") or [],
        }

    def get_offline_pov_budget(self, model_name: Optional[str] = None, purpose: str = "pov") -> dict:
        """Cap offline PoV prompts so local models spend budget on code generation, not prompt volume."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        input_budget = self.get_offline_input_budget(model_name=model_name, purpose=purpose)
        chars = int(input_budget.get("input_chars") or 2400)
        budget = {
            "max_context_chars": max(1400, min(6400, int(chars * 0.38))),
            "max_vulnerable_code_chars": max(500, min(1800, int(chars * 0.16))),
            "max_explanation_chars": max(320, min(1200, int(chars * 0.12))),
            "max_failed_pov_chars": max(1000, min(4200, int(chars * 0.22))),
            "max_validation_error_chars": max(280, min(1000, int(chars * 0.09))),
            "max_error_items": 5,
        }

        if selected_model == "glm-4.7-flash":
            budget["max_error_items"] = 6
        elif selected_model == "llama4":
            budget["max_error_items"] = 6

        if purpose == "refinement":
            budget.update({
                "max_context_chars": max(1200, min(5600, int(chars * 0.30))),
                "max_failed_pov_chars": max(1400, min(4800, int(chars * 0.30))),
                "max_validation_error_chars": max(360, min(1200, int(chars * 0.12))),
            })
        elif purpose in {"validation", "retry"}:
            budget.update({
                "max_context_chars": max(900, min(3600, int(chars * 0.24))),
                "max_failed_pov_chars": max(900, min(2600, int(chars * 0.18))),
                "max_validation_error_chars": max(220, min(720, int(chars * 0.08))),
            })

        return budget

    def get_offline_scout_budget(self, model_name: Optional[str] = None, purpose: str = "triage") -> dict:
        """Cap offline scout workload so local inference remains responsive."""
        selected_model = (model_name or self.MODEL_NAME or "").strip()
        budget = {
            "max_files": self.SCOUT_MAX_FILES,
            "max_chars": self.SCOUT_MAX_CHARS_PER_FILE,
        }

        if selected_model == "qwen3":
            if purpose == "exploratory":
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 4), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 1800)})
            elif purpose == "directory":
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 6), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 2200)})
            else:
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 5), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 2000)})
        elif selected_model == "glm-4.7-flash":
            if purpose == "exploratory":
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 6), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 2200)})
            elif purpose == "directory":
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 8), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 2600)})
            else:
                budget.update({"max_files": min(self.SCOUT_MAX_FILES, 7), "max_chars": min(self.SCOUT_MAX_CHARS_PER_FILE, 2400)})

        return budget

    def ensure_directories(self):
        """Ensure all required directories exist"""
        dirs = [
            self.DATA_DIR,
            self.BENCHMARKS_DIR,
            self.BENCHMARK_SOURCES_DIR,
            self.RESULTS_DIR,
            self.POVS_DIR,
            self.PROOF_ARTIFACTS_DIR,
            self.RUNS_DIR,
            self.ACTIVE_RUNS_DIR,
            self.CHROMA_PERSIST_DIR,
            self.TEMP_DIR,
            self.SNAPSHOT_DIR
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)


# Global settings instance
settings = Settings()

# Ensure directories on module load
settings.ensure_directories()







