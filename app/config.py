"""
AutoPoV Configuration Module
Pydantic Settings for all environment variables and configuration
"""

import os
import subprocess
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
    ADMIN_API_KEY: str = Field(default="", env="ADMIN_API_KEY")
    WEBHOOK_SECRET: str = Field(default="", env="WEBHOOK_SECRET")
    
    # LLM Configuration - Online (OpenRouter)
    OPENROUTER_API_KEY: str = Field(default="", env="OPENROUTER_API_KEY")
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    
    # LLM Configuration - Offline (Ollama)
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    
    # Model Selection
    MODEL_MODE: str = Field(default="online", env="MODEL_MODE")  # 'online' or 'offline'
    MODEL_NAME: str = Field(default="openai/gpt-4o", env="MODEL_NAME")

    # Routing / Policy
    ROUTING_MODE: str = Field(default="auto", env="ROUTING_MODE")  # auto|fixed|learning
    AUTO_ROUTER_MODEL: str = Field(default="openrouter/auto", env="AUTO_ROUTER_MODEL")
    LEARNING_DB_PATH: str = Field(default="./data/learning.db", env="LEARNING_DB_PATH")

    # Scout Settings
    SCOUT_ENABLED: bool = Field(default=True, env="SCOUT_ENABLED")
    SCOUT_LLM_ENABLED: bool = Field(default=True, env="SCOUT_LLM_ENABLED")
    SCOUT_MAX_FILES: int = Field(default=25, env="SCOUT_MAX_FILES")
    SCOUT_MAX_CHARS_PER_FILE: int = Field(default=4000, env="SCOUT_MAX_CHARS_PER_FILE")
    SCOUT_MAX_FINDINGS: int = Field(default=200, env="SCOUT_MAX_FINDINGS")
    SCOUT_MAX_COST_USD: float = Field(default=0.10, env="SCOUT_MAX_COST_USD")
    
    # Available Models
    ONLINE_MODELS: List[str] = [
        "openai/gpt-4o",
        "anthropic/claude-3.5-sonnet"
    ]
    OFFLINE_MODELS: List[str] = [
        "llama3:70b",
        "mixtral:8x7b"
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
    DOCKER_TIMEOUT: int = 60
    DOCKER_MEMORY_LIMIT: str = "512m"
    DOCKER_CPU_LIMIT: float = 1.0
    
    # Cost Control
    MAX_COST_USD: float = Field(default=100.0, env="MAX_COST_USD")
    COST_TRACKING_ENABLED: bool = Field(default=True, env="COST_TRACKING_ENABLED")
    
    # Scanning Configuration
    MAX_CHUNK_SIZE: int = 4000
    CHUNK_OVERLAP: int = 200
    MAX_RETRIES: int = 2
    
    # Supported CWEs - Focused list for faster scanning (high-impact web vulnerabilities)
    # Top 20 most common web vulnerabilities (OWASP Top 10 + extras)
    SUPPORTED_CWES: List[str] = [
        # OWASP Top 10 2021
        "CWE-89",   # A01:2021 - Broken Access Control (SQL Injection)
        "CWE-79",   # A03:2021 - Injection (XSS)
        "CWE-20",   # A04:2021 - Insecure Design (Input Validation)
        "CWE-200",  # A05:2021 - Security Misconfiguration (Info Disclosure)
        "CWE-22",   # A01:2021 - Broken Access Control (Path Traversal)
        "CWE-352",  # A01:2021 - Broken Access Control (CSRF)
        "CWE-502",  # A08:2021 - Software and Data Integrity Failures (Deserialization)
        "CWE-287",  # A07:2021 - Identification and Authentication Failures
        "CWE-798",  # A07:2021 - Identification and Authentication Failures (Hardcoded Creds)
        "CWE-306",  # A07:2021 - Identification and Authentication Failures (Missing Auth)
        
        # Additional High-Impact Web Vulnerabilities
        "CWE-94",   # Code Injection
        "CWE-78",   # OS Command Injection
        "CWE-601",  # Open Redirect
        "CWE-312",  # Cleartext Storage of Sensitive Information
        "CWE-327",  # Use of Broken or Risky Cryptographic Algorithm
        "CWE-918",  # Server-Side Request Forgery (SSRF)
        "CWE-434",  # Unrestricted Upload of File with Dangerous Type
        "CWE-611",  # XML External Entity (XXE)
        "CWE-400",  # Uncontrolled Resource Consumption (DoS)
        "CWE-384",  # Session Fixation
    ]
    
    # File Paths
    DATA_DIR: str = "./data"
    RESULTS_DIR: str = "./results"
    POVS_DIR: str = "./results/povs"
    RUNS_DIR: str = "./results/runs"
    TEMP_DIR: str = "/tmp/autopov"
    SNAPSHOT_DIR: str = Field(default="./results/snapshots", env="SNAPSHOT_DIR")
    
    # Snapshot Configuration
    SAVE_CODEBASE_SNAPSHOT: bool = Field(default=False, env="SAVE_CODEBASE_SNAPSHOT")
    
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
    
    def get_llm_config(self) -> dict:
        """Get LLM configuration based on MODEL_MODE"""
        if self.MODEL_MODE == "online":
            # Use OpenRouter for all online models
            return {
                "mode": "online",
                "model": self.MODEL_NAME,
                "api_key": self.OPENROUTER_API_KEY,
                "base_url": self.OPENROUTER_BASE_URL,
                "embedding_model": self.EMBEDDING_MODEL_ONLINE,
                "provider": "openrouter"
            }
        else:
            return {
                "mode": "offline",
                "model": self.MODEL_NAME,
                "base_url": self.OLLAMA_BASE_URL,
                "embedding_model": self.EMBEDDING_MODEL_OFFLINE,
                "provider": "ollama"
            }
    
    def ensure_directories(self):
        """Ensure all required directories exist"""
        dirs = [
            self.DATA_DIR,
            self.RESULTS_DIR,
            self.POVS_DIR,
            self.RUNS_DIR,
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


