"""
AutoPoV Configuration Module
Pydantic Settings for all environment variables and configuration
"""

import os
import subprocess
from urllib.parse import urlparse
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


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
    DOCKER_IMAGE: str = "python:3.12-slim"
    DOCKER_TIMEOUT: int = 180
    DOCKER_MEMORY_LIMIT: str = "2g"
    DOCKER_CPU_LIMIT: float = 2.0
    
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
    PROOF_MAX_FINDINGS: int = Field(default=1000, env="PROOF_MAX_FINDINGS")  # Increased from 25 to allow all confirmed findings to get PoVs
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
    MIN_CONFIDENCE_FOR_POV: float = Field(default=0.65, env="MIN_CONFIDENCE_FOR_POV")  # Lower threshold for more PoV generation
    BATCH_SIMILAR_FINDINGS: bool = Field(default=True, env="BATCH_SIMILAR_FINDINGS")  # Group similar findings for analysis
    
    # Note: INTERNAL_SECURITY_RULESET has been removed for CWE-agnostic scanning.
    # CodeQL and Semgrep now run their full security suites without CWE filtering.
    # The exploratory agent and LLM scout perform open-ended vulnerability discovery.
    # Findings are still classified with CWE labels when appropriate, but no CWE
    # is required for detection or validation.

    # File Paths
    DATA_DIR: str = "./data"
    RESULTS_DIR: str = "./results"
    POVS_DIR: str = "./results/povs"
    RUNS_DIR: str = "./results/runs"
    ACTIVE_RUNS_DIR: str = "./results/runs/active"
    TEMP_DIR: str = "/tmp/autopov"
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
        """Check if Joern is available"""
        try:
            result = subprocess.run(
                [self.JOERN_CLI_PATH, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
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

    def ensure_directories(self):
        """Ensure all required directories exist"""
        dirs = [
            self.DATA_DIR,
            self.RESULTS_DIR,
            self.POVS_DIR,
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



