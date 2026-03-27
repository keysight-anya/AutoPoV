"""
Tests for authentication module
"""

import json
import os
import tempfile

import pytest

from app.auth import APIKeyManager, SYSTEM_API_KEY_NAME


class TestAPIKeyManager:
    """Test API key management"""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for tests"""
        with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as f:
            f.write('{}')
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
        """Test key validation returns the key name"""
        key = key_manager.generate_key("test")
        assert key_manager.validate_key(key) == "test"
        assert key_manager.validate_key("invalid_key") is None

    def test_revoke_key(self, key_manager):
        """Test key revocation"""
        key = key_manager.generate_key("test")
        key_id = next(kid for kid, record in key_manager._keys.items() if record.name == "test")

        assert key_manager.validate_key(key) == "test"
        key_manager.revoke_key(key_id)
        assert key_manager.validate_key(key) is None

    def test_list_keys(self, key_manager):
        """Test listing keys excludes assumptions about the system key"""
        key_manager.generate_key("test1")
        key_manager.generate_key("test2")

        keys = key_manager.list_keys()
        user_keys = [k for k in keys if k['name'] != SYSTEM_API_KEY_NAME]
        assert len(user_keys) == 2
        assert {k['name'] for k in user_keys} == {"test1", "test2"}


class TestAuthDependencies:
    """Test FastAPI auth dependencies"""

    def test_verify_api_key_mock(self):
        """Placeholder for dependency-level tests"""
        pass
