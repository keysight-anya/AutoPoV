"""
AutoPoV Authentication Module
API key generation, hashing, and Bearer token authentication
"""

import secrets
import hashlib
import json
import os
from datetime import datetime
from typing import Optional, Dict, List
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.config import settings


security = HTTPBearer()


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
        """Save API keys to storage"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            data = {k: v.dict() for k, v in self._keys.items()}
            json.dump(data, f, indent=2)
    
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
        
        self._keys[key_id] = api_key
        self._save_keys()
        
        return raw_key
    
    def validate_key(self, key: str) -> bool:
        """Validate an API key"""
        if not key:
            return False
        
        key_hash = self._hash_key(key)
        
        for api_key in self._keys.values():
            if api_key.key_hash == key_hash and api_key.is_active:
                # Update last used
                api_key.last_used = datetime.utcnow().isoformat()
                self._save_keys()
                return True
        
        return False
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        if key_id in self._keys:
            self._keys[key_id].is_active = False
            self._save_keys()
            return True
        return False
    
    def delete_key(self, key_id: str) -> bool:
        """Delete an API key"""
        if key_id in self._keys:
            del self._keys[key_id]
            self._save_keys()
            return True
        return False
    
    def list_keys(self) -> List[Dict]:
        """List all API keys (without hashes)"""
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
        """Validate admin API key"""
        if not settings.ADMIN_API_KEY:
            return False
        return key == settings.ADMIN_API_KEY


# Global API key manager
api_key_manager = APIKeyManager()


async def verify_api_key(
    request: Request
) -> str:
    """Dependency to verify API key from Bearer token or query parameter"""
    token = None
    
    # First try to get token from Authorization header
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
    
    # If no token in header, try query parameter (for SSE/EventSource)
    if not token:
        token = request.query_params.get("api_key")
    
    if not token or not api_key_manager.validate_key(token):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return token


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
