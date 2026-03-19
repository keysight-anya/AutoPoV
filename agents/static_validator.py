"""
AutoPoV Static Validator Module
Validates PoV scripts using static code analysis without execution.
"""

import re
from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float
    matched_patterns: List[str]
    issues: List[str]
    details: Dict[str, Any]


class StaticValidator:
    """Validates PoV scripts using static analysis."""

    CWE_PATTERNS = {
        'CWE-89': {
            'required_imports': ['sqlite3', 'mysql', 'psycopg2', 'sqlalchemy', 'pymongo', 'requests', 'http.client', 'urllib'],
            'attack_patterns': [r"['\"].*OR.*=.*['\"]", r"['\"].*;.*--", r"['\"].*UNION.*SELECT", r"['\"].*DROP.*TABLE"],
            'payload_indicators': ['sql', 'query', 'injection', 'payload', 'exploit', 'bypass'],
        },
        'CWE-79': {
            'required_imports': ['requests', 'http.client', 'urllib', 'selenium', 'playwright'],
            'attack_patterns': [r'<script.*>.*</script>', r'javascript:', r'on\w+\s*='],
            'payload_indicators': ['xss', 'script', 'html', 'payload', 'inject', 'alert'],
        },
        'CWE-94': {
            'required_imports': ['subprocess', 'os.system', 'exec', 'eval', 'requests'],
            'attack_patterns': [r'__import__\s*\(', r'eval\s*\(', r'exec\s*\('],
            'payload_indicators': ['code', 'exec', 'eval', 'command', 'shell', 'inject'],
        },
        'CWE-22': {
            'required_imports': ['os', 'pathlib', 'requests', 'http.client'],
            'attack_patterns': [r'\.\./', r'\.\.\\', r'%2e%2e', r'etc/passwd'],
            'payload_indicators': ['path', 'traversal', 'directory', 'file'],
        },
        'CWE-78': {
            'required_imports': ['subprocess', 'os.system', 'os.popen', 'commands'],
            'attack_patterns': [r';\s*\w+', r'\|\s*\w+', r'`.*`', r'\$\(.*\)', r'&&\s*\w+'],
            'payload_indicators': ['command', 'shell', 'exec', 'system', 'pipe', 'inject'],
        },
        'CWE-502': {
            'required_imports': ['pickle', 'yaml', 'json', 'marshal', 'requests'],
            'attack_patterns': [r'pickle\.loads', r'yaml\.load', r'json\.loads', r'__reduce__'],
            'payload_indicators': ['serialize', 'deserialize', 'pickle', 'yaml', 'json', 'object'],
        },
        'CWE-798': {
            'required_imports': ['requests', 'http.client', 'urllib'],
            'attack_patterns': [r'password\s*[=:]\s*[\'\"]', r'secret\s*[=:]\s*[\'\"]', r'api_key\s*[=:]\s*[\'\"]'],
            'payload_indicators': ['credential', 'password', 'secret', 'key', 'token', 'auth'],
        },
    }

    def __init__(self):
        self.validation_history = []

    def validate(self, pov_script: str, cwe_type: str, vulnerable_code: str, filepath: str, line_number: int, exploit_contract: Dict[str, Any] | None = None) -> ValidationResult:
        matched_patterns: List[str] = []
        issues: List[str] = []
        details = {
            'classification_label': cwe_type,
            'filepath': filepath,
            'line_number': line_number,
            'pov_length': len(pov_script),
            'has_vulnerability_check': False,
        }
        exploit_contract = exploit_contract or {}
        patterns = self.CWE_PATTERNS.get(cwe_type, {})

        if 'VULNERABILITY TRIGGERED' in pov_script:
            matched_patterns.append('has_vulnerability_indicator')
            details['has_vulnerability_check'] = True
        else:
            issues.append("PoV script missing 'VULNERABILITY TRIGGERED' indicator")

        contract_signals = self._match_contract_signals(pov_script, exploit_contract)
        if contract_signals:
            matched_patterns.append(f"contract_signals: {', '.join(contract_signals[:4])}")
        elif exploit_contract:
            issues.append('PoV does not clearly encode the exploit contract indicators')

        found_imports = [imp for imp in patterns.get('required_imports', []) if imp in pov_script]
        if found_imports:
            matched_patterns.append(f"imports: {', '.join(found_imports)}")

        for pattern in patterns.get('attack_patterns', []):
            try:
                if re.search(pattern, pov_script, re.IGNORECASE):
                    matched_patterns.append(f"pattern: {pattern[:50]}...")
            except re.error:
                continue

        found_indicators = [indicator for indicator in patterns.get('payload_indicators', []) if indicator in pov_script.lower()]
        if found_indicators:
            matched_patterns.append(f"indicators: {', '.join(found_indicators)}")

        generic_signals = self._generic_validation_signals(pov_script, vulnerable_code, exploit_contract)
        matched_patterns.extend(generic_signals['matches'])
        issues.extend(generic_signals['issues'])

        code_relevance = self._check_code_relevance(pov_script, vulnerable_code, exploit_contract)
        details['code_relevance_score'] = code_relevance
        if code_relevance > 0.45:
            matched_patterns.append('addresses_target_code_or_contract')
        else:
            issues.append('PoV may not directly address the vulnerable code or exploit contract')

        confidence = self._calculate_confidence(len(matched_patterns), len(issues), details['has_vulnerability_check'], code_relevance, bool(contract_signals), cwe_type == 'UNCLASSIFIED' or cwe_type not in self.CWE_PATTERNS)
        is_valid = details['has_vulnerability_check'] and len(matched_patterns) >= 2 and confidence >= 0.55

        result = ValidationResult(is_valid=is_valid, confidence=confidence, matched_patterns=matched_patterns, issues=issues, details=details)
        self.validation_history.append(result)
        return result

    def _match_contract_signals(self, pov_script: str, exploit_contract: Dict[str, Any]) -> List[str]:
        haystack = pov_script.lower()
        matches = []
        for item in exploit_contract.get('success_indicators', []) + exploit_contract.get('inputs', []) + exploit_contract.get('side_effects', []):
            token = str(item).strip().lower()
            if token and token in haystack:
                matches.append(str(item))
        return matches

    def _generic_validation_signals(self, pov_script: str, vulnerable_code: str, exploit_contract: Dict[str, Any]) -> Dict[str, List[str]]:
        matches: List[str] = []
        issues: List[str] = []
        pov_lower = pov_script.lower()
        vuln_lower = (vulnerable_code or '').lower()

        suspicious_terms = ['payload', 'exploit', 'trigger', 'input', 'request', 'query', 'command', 'path', 'token', 'header', 'free', 'buffer']
        shared_terms = [term for term in suspicious_terms if term in pov_lower and term in vuln_lower]
        if shared_terms:
            matches.append(f"shared_security_terms: {', '.join(shared_terms[:4])}")

        entrypoint = str(exploit_contract.get('target_entrypoint', '')).strip().lower()
        if entrypoint:
            if entrypoint in pov_lower:
                matches.append('references_target_entrypoint')
            else:
                issues.append('PoV does not reference the target entrypoint from the exploit contract')

        if any(word in pov_lower for word in ['assert', 'sys.exit', 'raise', 'print(']):
            matches.append('contains_observable_outcome_logic')
        else:
            issues.append('PoV lacks a clear observable outcome check')

        return {'matches': matches, 'issues': issues}

    def _check_code_relevance(self, pov_script: str, vulnerable_code: str, exploit_contract: Dict[str, Any]) -> float:
        if not vulnerable_code and not exploit_contract:
            return 0.5
        vulnerable_lower = (vulnerable_code or '').lower()
        pov_lower = pov_script.lower()
        keywords = ['function', 'def', 'class', 'route', 'endpoint', 'query', 'execute', 'render', 'template', 'user', 'input', 'request', 'free', 'malloc', 'buffer', 'path']
        matches = sum(1 for keyword in keywords if keyword in vulnerable_lower and keyword in pov_lower)
        for item in exploit_contract.get('inputs', []) + exploit_contract.get('trigger_steps', []) + [exploit_contract.get('target_entrypoint', '')]:
            token = str(item).strip().lower()
            if token and token in pov_lower:
                matches += 1
        return min(matches / 4, 1.0)

    def _calculate_confidence(self, matched_count: int, issue_count: int, has_vuln_check: bool, code_relevance: float, has_contract_signal: bool, generic_mode: bool) -> float:
        base_score = 0.25
        base_score += min(matched_count * 0.08, 0.36)
        if has_vuln_check:
            base_score += 0.2
        if has_contract_signal:
            base_score += 0.12
        if generic_mode:
            base_score += 0.05
        base_score += code_relevance * 0.18
        base_score -= issue_count * 0.08
        return max(0.0, min(1.0, base_score))

    def quick_validate(self, pov_script: str, cwe_type: str) -> bool:
        result = self.validate(pov_script=pov_script, cwe_type=cwe_type, vulnerable_code='', filepath='', line_number=0)
        return result.is_valid and result.confidence >= 0.6


static_validator = StaticValidator()


def get_static_validator() -> StaticValidator:
    return static_validator