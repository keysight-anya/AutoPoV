"""
Tests for authentication module
"""

import pytest
import os
import tempfile
from app.auth import APIKeyManager


class TestAPIKeyManager:
    """Test API key management"""
    
    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for tests"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        yield path
        os.unlink(path)
    
    @pytest.fixture
    def key_manager(self, temp_storage):
        """Create key manager with temp storage"""
        return APIKeyManager(storage_path=temp_storage)
    
    def test_generate_key(self, key_manager):
        """Test key generation"""
        key = key_manager.generate_key("test")
        assert key.startswith("apov_")
        assert len(key) > 20
    
    def test_validate_key(self, key_manager):
        """Test key validation"""
        key = key_manager.generate_key("test")
        assert key_manager.validate_key(key) is True
        assert key_manager.validate_key("invalid_key") is False
    
    def test_revoke_key(self, key_manager):
        """Test key revocation"""
        key = key_manager.generate_key("test")
        key_id = list(key_manager._keys.keys())[0]
        
        assert key_manager.validate_key(key) is True
        key_manager.revoke_key(key_id)
        assert key_manager.validate_key(key) is False
    
    def test_list_keys(self, key_manager):
        """Test listing keys"""
        key_manager.generate_key("test1")
        key_manager.generate_key("test2")
        
        keys = key_manager.list_keys()
        assert len(keys) == 2
        assert all(k['name'].startswith('test') for k in keys)


class TestAuthDependencies:
    """Test FastAPI auth dependencies"""
    
    def test_verify_api_key_mock(self):
        """Test API key verification (mock)"""
        # This would require FastAPI test client
        # Skipping for now as it requires full app context
        pass
