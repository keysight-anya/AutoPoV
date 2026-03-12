"""
AutoPoV Authentication Module
API key generation, hashing, and Bearer token authentication
"""

import hmac
import secrets
import hashlib
import json
import os
import threading
import time
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.config import settings


security = HTTPBearer()

# Rate limiting: max scans per key per window
_RATE_LIMIT_WINDOW_S = 60          # 1 minute window
_RATE_LIMIT_MAX_SCANS = 10         # max 10 scans per minute per key
_LAST_USED_FLUSH_INTERVAL_S = 30   # flush last_used to disk at most every 30s


class APIKey(BaseModel):
    """API Key model"""
    key_id: str
    key_hash: str
    name: str
    created_at: str
    last_used: Optional[str] = None
    is_active: bool = True


class APIKeyManager:
    """Manages API key storage and validation"""

    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or os.path.join(settings.DATA_DIR, "api_keys.json")
        self._keys: Dict[str, APIKey] = {}
        self._lock = threading.Lock()
        # In-memory cache: key_id -> pending last_used string (not yet flushed)
        self._pending_last_used: Dict[str, str] = {}
        self._last_flush_time: float = 0.0
        # Rate limiting: key_hash -> list of request timestamps
        self._rate_windows: Dict[str, List[float]] = {}
        self._load_keys()

    def _load_keys(self):
        """Load API keys from storage"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for key_id, key_data in data.items():
                        self._keys[key_id] = APIKey(**key_data)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Could not load API keys: {e}")
                self._keys = {}

    def _save_keys(self):
        """Save API keys to storage (must be called under self._lock)"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        # Apply any pending last_used updates before writing
        for key_id, last_used in self._pending_last_used.items():
            if key_id in self._keys:
                self._keys[key_id].last_used = last_used
        self._pending_last_used.clear()
        self._last_flush_time = time.monotonic()
        with open(self.storage_path, 'w') as f:
            data = {k: v.dict() for k, v in self._keys.items()}
            json.dump(data, f, indent=2)

    def _flush_last_used_if_due(self):
        """Flush pending last_used updates to disk if flush interval has elapsed"""
        if self._pending_last_used and (time.monotonic() - self._last_flush_time) >= _LAST_USED_FLUSH_INTERVAL_S:
            self._save_keys()

    def _hash_key(self, key: str) -> str:
        """Hash an API key using SHA-256"""
        return hashlib.sha256(key.encode()).hexdigest()

    def generate_key(self, name: str = "default") -> str:
        """Generate a new API key"""
        key_id = secrets.token_urlsafe(16)
        raw_key = f"apov_{secrets.token_urlsafe(32)}"
        key_hash = self._hash_key(raw_key)

        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            created_at=datetime.utcnow().isoformat()
        )

        with self._lock:
            self._keys[key_id] = api_key
            self._save_keys()

        return raw_key

    def validate_key(self, key: str) -> Optional[str]:
        """
        Validate an API key.
        Returns the key's name if valid, None if invalid.
        Uses debounced disk writes for last_used updates.
        """
        if not key:
            return None

        key_hash = self._hash_key(key)

        with self._lock:
            for api_key in self._keys.values():
                if hmac.compare_digest(api_key.key_hash, key_hash) and api_key.is_active:
                    # Track last_used in memory; flush to disk periodically
                    now = datetime.utcnow().isoformat()
                    self._pending_last_used[api_key.key_id] = now
                    self._flush_last_used_if_due()
                    return api_key.name

        return None

    def check_rate_limit(self, key: str) -> bool:
        """
        Check if an API key has exceeded the scan rate limit.
        Returns True if the request should be allowed, False if rate-limited.
        """
        key_hash = self._hash_key(key)
        now = time.monotonic()

        with self._lock:
            window = self._rate_windows.get(key_hash, [])
            # Remove timestamps outside current window
            window = [t for t in window if now - t < _RATE_LIMIT_WINDOW_S]
            if len(window) >= _RATE_LIMIT_MAX_SCANS:
                self._rate_windows[key_hash] = window
                return False
            window.append(now)
            self._rate_windows[key_hash] = window
            return True

    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].is_active = False
                self._save_keys()
                return True
        return False

    def delete_key(self, key_id: str) -> bool:
        """Delete an API key"""
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
                self._save_keys()
                return True
        return False

    def list_keys(self) -> List[Dict]:
        """List all API keys (without hashes)"""
        with self._lock:
            return [
                {
                    "key_id": k.key_id,
                    "name": k.name,
                    "created_at": k.created_at,
                    "last_used": k.last_used,
                    "is_active": k.is_active
                }
                for k in self._keys.values()
            ]

    def validate_admin_key(self, key: str) -> bool:
        """Validate admin API key using timing-safe comparison"""
        if not settings.ADMIN_API_KEY:
            return False
        # hmac.compare_digest prevents timing attacks
        return hmac.compare_digest(key, settings.ADMIN_API_KEY)


# Global API key manager
api_key_manager = APIKeyManager()


async def verify_api_key(
    request: Request
) -> Tuple[str, str]:
    """
    Dependency to verify API key from Bearer token or query parameter.
    Returns (token, key_name) tuple.
    """
    token = None

    # First try to get token from Authorization header
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")

    # If no token in header, try query parameter (for SSE/EventSource)
    if not token:
        token = request.query_params.get("api_key")

    key_name = api_key_manager.validate_key(token) if token else None
    if not key_name:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return token, key_name


async def verify_api_key_with_rate_limit(
    request: Request
) -> Tuple[str, str]:
    """
    Like verify_api_key but also enforces per-key scan rate limiting.
    Use this on scan-triggering endpoints.
    """
    token, key_name = await verify_api_key(request)

    if not api_key_manager.check_rate_limit(token):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {_RATE_LIMIT_MAX_SCANS} scans per {_RATE_LIMIT_WINDOW_S}s per key"
        )

    return token, key_name


async def verify_admin_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """Dependency to verify admin API key"""
    token = credentials.credentials

    if not api_key_manager.validate_admin_key(token):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return token


def get_api_key_manager() -> APIKeyManager:
    """Get the global API key manager instance"""
    return api_key_manager
