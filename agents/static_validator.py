"""
AutoPoV Static Validator Module
Validates PoV scripts using static code analysis without execution
"""

import re
import ast
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of static validation"""
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[str]
    issues: List[str]
    details: Dict[str, Any]


class StaticValidator:
    """Validates PoV scripts using static analysis"""
    
    # CWE-specific patterns that should appear in PoV scripts
    CWE_PATTERNS = {
        "CWE-89": {  # SQL Injection
            "required_imports": ["sqlite3", "mysql", "psycopg2", "sqlalchemy", "pymongo", "requests", "http.client", "urllib"],
            "attack_patterns": [
                r"['\"].*OR.*=.*['\"]",  # OR 1=1 patterns
                r"['\"].*;.*--",  # Comment injection
                r"['\"].*UNION.*SELECT",  # UNION injection
                r"['\"].*DROP.*TABLE",  # Destructive patterns
                r"admin.*['\"].*--",  # Auth bypass
            ],
            "payload_indicators": [
                "sql", "query", "injection", "payload", "exploit", "bypass"
            ]
        },
        "CWE-79": {  # XSS
            "required_imports": ["requests", "http.client", "urllib", "selenium", "playwright"],
            "attack_patterns": [
                r"<script.*>.*</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<img.*onerror=",
                r"alert\s*\(",
            ],
            "payload_indicators": [
                "xss", "script", "html", "payload", "inject", "alert"
            ]
        },
        "CWE-94": {  # Code Injection
            "required_imports": ["subprocess", "os.system", "exec", "eval", "requests"],
            "attack_patterns": [
                r"__import__\s*\(",
                r"eval\s*\(",
                r"exec\s*\(",
                r"subprocess\.call",
                r"os\.system\s*\(",
            ],
            "payload_indicators": [
                "code", "exec", "eval", "command", "shell", "inject"
            ]
        },
        "CWE-22": {  # Path Traversal
            "required_imports": ["os", "pathlib", "requests", "http.client"],
            "attack_patterns": [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e",
                r"etc/passwd",
                r"windows/system32",
            ],
            "payload_indicators": [
                "path", "traversal", "directory", "file", "../", "..\\"
            ]
        },
        "CWE-78": {  # Command Injection
            "required_imports": ["subprocess", "os.system", "os.popen", "commands"],
            "attack_patterns": [
                r";\s*\w+",
                r"\|\s*\w+",
                r"`.*`",
                r"\$\(.*\)",
                r"&&\s*\w+",
            ],
            "payload_indicators": [
                "command", "shell", "exec", "system", "pipe", "inject"
            ]
        },
        "CWE-502": {  # Deserialization
            "required_imports": ["pickle", "yaml", "json", "marshal", "requests"],
            "attack_patterns": [
                r"pickle\.loads",
                r"yaml\.load",
                r"json\.loads",
                r"__reduce__",
                r"__getstate__",
            ],
            "payload_indicators": [
                "serialize", "deserialize", "pickle", "yaml", "json", "object"
            ]
        },
        "CWE-798": {  # Hardcoded Credentials
            "required_imports": ["requests", "http.client", "urllib"],
            "attack_patterns": [
                r"password\s*[=:]\s*['\"]",
                r"secret\s*[=:]\s*['\"]",
                r"api_key\s*[=:]\s*['\"]",
                r"token\s*[=:]\s*['\"]",
                r"admin.*password",
            ],
            "payload_indicators": [
                "credential", "password", "secret", "key", "token", "auth"
            ]
        }
    }
    
    def __init__(self):
        self.validation_history = []
    
    def validate(
        self,
        pov_script: str,
        cwe_type: str,
        vulnerable_code: str,
        filepath: str,
        line_number: int,
        exploit_contract: Dict[str, Any] | None = None
    ) -> ValidationResult:
        """
        Validate a PoV script using static analysis
        
        Args:
            pov_script: The PoV script content
            cwe_type: CWE type being tested
            vulnerable_code: The vulnerable code snippet
            filepath: Path to the vulnerable file
            line_number: Line number of the vulnerability
            
        Returns:
            ValidationResult with validation details
        """
        matched_patterns = []
        issues = []
        details = {
            "cwe_type": cwe_type,
            "filepath": filepath,
            "line_number": line_number,
            "pov_length": len(pov_script),
            "has_vulnerability_check": False
        }
        exploit_contract = exploit_contract or {}
        patterns = self.CWE_PATTERNS.get(cwe_type, {})
        
        # Check for vulnerability trigger indicator
        if "VULNERABILITY TRIGGERED" in pov_script:
            matched_patterns.append("has_vulnerability_indicator")
            details["has_vulnerability_check"] = True
        else:
            issues.append("PoV script missing 'VULNERABILITY TRIGGERED' indicator")
        
        # Check generic exploit-contract alignment
        contract_signals = []
        for item in exploit_contract.get("success_indicators", []) + exploit_contract.get("inputs", []) + exploit_contract.get("side_effects", []):
            if item and str(item).lower() in pov_script.lower():
                contract_signals.append(str(item))
        if contract_signals:
            matched_patterns.append(f"contract_signals: {', '.join(contract_signals[:4])}")
        elif exploit_contract:
            issues.append("PoV does not clearly encode the exploit contract indicators")

        # Check required imports
        found_imports = []
        for imp in patterns.get("required_imports", []):
            if imp in pov_script:
                found_imports.append(imp)
        
        if found_imports:
            matched_patterns.append(f"imports: {', '.join(found_imports)}")
        
        # Check attack patterns
        for pattern in patterns.get("attack_patterns", []):
            try:
                if re.search(pattern, pov_script, re.IGNORECASE):
                    matched_patterns.append(f"pattern: {pattern[:50]}...")
            except re.error:
                continue
        
        # Check payload indicators
        found_indicators = []
        pov_lower = pov_script.lower()
        for indicator in patterns.get("payload_indicators", []):
            if indicator in pov_lower:
                found_indicators.append(indicator)
        
        if found_indicators:
            matched_patterns.append(f"indicators: {', '.join(found_indicators)}")
        
        # Check if PoV addresses the vulnerable code
        code_relevance = self._check_code_relevance(pov_script, vulnerable_code)
        details["code_relevance_score"] = code_relevance
        
        if code_relevance > 0.5:
            matched_patterns.append("addresses_vulnerable_code")
        else:
            issues.append("PoV may not directly address the vulnerable code")
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            len(matched_patterns),
            len(issues),
            details["has_vulnerability_check"],
            code_relevance
        )
        
        # Determine validity
        is_valid = (
            details["has_vulnerability_check"] and
            len(matched_patterns) >= 2 and
            confidence >= 0.55
        )
        
        result = ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            matched_patterns=matched_patterns,
            issues=issues,
            details=details
        )
        
        self.validation_history.append(result)
        return result
    
    def _check_code_relevance(self, pov_script: str, vulnerable_code: str) -> float:
        """Check how relevant the PoV is to the vulnerable code"""
        if not vulnerable_code:
            return 0.5
        
        # Extract identifiers from vulnerable code
        try:
            vulnerable_lower = vulnerable_code.lower()
            pov_lower = pov_script.lower()
            
            # Check for common keywords
            keywords = [
                "function", "def", "class", "route", "endpoint",
                "query", "execute", "select", "insert", "update", "delete",
                "render", "template", "user", "input", "request"
            ]
            
            matches = 0
            for keyword in keywords:
                if keyword in vulnerable_lower and keyword in pov_lower:
                    matches += 1
            
            return min(matches / 3, 1.0)  # Normalize to 0-1
        except Exception:
            return 0.5
    
    def _calculate_confidence(
        self,
        matched_count: int,
        issue_count: int,
        has_vuln_check: bool,
        code_relevance: float
    ) -> float:
        """Calculate overall confidence score"""
        base_score = 0.3
        
        # Add for matched patterns (up to 0.4)
        base_score += min(matched_count * 0.1, 0.4)
        
        # Add for vulnerability check (0.2)
        if has_vuln_check:
            base_score += 0.2
        
        # Add for code relevance (up to 0.2)
        base_score += code_relevance * 0.2
        
        # Subtract for issues
        base_score -= issue_count * 0.1
        
        return max(0.0, min(1.0, base_score))
    
    def quick_validate(self, pov_script: str, cwe_type: str) -> bool:
        """Quick validation check (returns True/False only)"""
        result = self.validate(
            pov_script=pov_script,
            cwe_type=cwe_type,
            vulnerable_code="",
            filepath="",
            line_number=0
        )
        return result.is_valid and result.confidence >= 0.6


# Global validator instance
static_validator = StaticValidator()


def get_static_validator() -> StaticValidator:
    """Get the global static validator instance"""
    return static_validator
