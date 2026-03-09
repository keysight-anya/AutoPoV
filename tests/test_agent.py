"""
Tests for agent components
"""

import pytest
from agents.verifier import VulnerabilityVerifier


class TestVulnerabilityVerifier:
    """Test PoV verifier"""
    
    @pytest.fixture
    def verifier(self):
        """Create verifier instance"""
        return VulnerabilityVerifier()
    
    def test_validate_pov_syntax_error(self, verifier):
        """Test validation catches syntax errors"""
        invalid_script = "def broken(:\n    pass"
        
        result = verifier.validate_pov(
            invalid_script,
            "CWE-89",
            "test.py",
            1
        )
        
        assert result["is_valid"] is False
        assert any("Syntax error" in issue for issue in result["issues"])
    
    def test_validate_pov_missing_trigger(self, verifier):
        """Test validation requires VULNERABILITY TRIGGERED"""
        script = "print('hello')"
        
        result = verifier.validate_pov(
            script,
            "CWE-89",
            "test.py",
            1
        )
        
        assert result["is_valid"] is False
        assert any("VULNERABILITY TRIGGERED" in issue for issue in result["issues"])
    
    def test_validate_pov_valid(self, verifier):
        """Test validation accepts valid script"""
        script = """
import sys
print("VULNERABILITY TRIGGERED")
sys.exit(0)
"""
        
        result = verifier.validate_pov(
            script,
            "CWE-89",
            "test.py",
            1
        )
        
        # Should be valid (no syntax errors, has trigger)
        assert result["is_valid"] is True
    
    def test_stdlib_modules(self, verifier):
        """Test stdlib module detection"""
        stdlib = verifier._get_stdlib_modules()
        
        assert "os" in stdlib
        assert "sys" in stdlib
        assert "json" in stdlib
        assert "requests" not in stdlib  # Not stdlib
