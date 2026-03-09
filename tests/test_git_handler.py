"""
Tests for git handler module
"""

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock
from app.git_handler import GitHandler


class TestGitHandler:
    """Test Git operations"""
    
    @pytest.fixture
    def handler(self):
        """Create git handler"""
        return GitHandler()
    
    def test_detect_provider_github(self, handler):
        """Test GitHub URL detection"""
        assert handler._detect_provider("https://github.com/user/repo.git") == "github"
        assert handler._detect_provider("https://github.com/user/repo") == "github"
    
    def test_detect_provider_gitlab(self, handler):
        """Test GitLab URL detection"""
        assert handler._detect_provider("https://gitlab.com/user/repo.git") == "gitlab"
        assert handler._detect_provider("https://gitlab.example.com/user/repo") == "gitlab"
    
    def test_detect_provider_bitbucket(self, handler):
        """Test Bitbucket URL detection"""
        assert handler._detect_provider("https://bitbucket.org/user/repo.git") == "bitbucket"
    
    def test_detect_provider_unknown(self, handler):
        """Test unknown provider detection"""
        assert handler._detect_provider("https://gitea.example.com/user/repo.git") == "unknown"
    
    def test_sanitize_scan_id(self, handler):
        """Test scan ID sanitization"""
        assert handler._sanitize_scan_id("test-123") == "test-123"
        assert handler._sanitize_scan_id("test/123") == "test_123"
        assert handler._sanitize_scan_id("test.123") == "test_123"
    
    def test_get_language_from_ext(self, handler):
        """Test language detection from extension"""
        assert handler._get_language_from_ext(".py") == "Python"
        assert handler._get_language_from_ext(".js") == "JavaScript"
        assert handler._get_language_from_ext(".c") == "C"
        assert handler._get_language_from_ext(".cpp") == "C++"
        assert handler._get_language_from_ext(".unknown") is None
    
    def test_is_binary(self, handler, tmp_path):
        """Test binary file detection"""
        # Text file
        text_file = tmp_path / "test.txt"
        text_file.write_text("Hello World")
        assert handler._is_binary(str(text_file)) is False
        
        # Binary file
        binary_file = tmp_path / "test.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03")
        assert handler._is_binary(str(binary_file)) is True
