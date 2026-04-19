"""
AutoPoV Static Validator Module
Validates PoV scripts using static code analysis without execution.
"""

import re
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float
    matched_patterns: List[str]
    issues: List[str]
    details: Dict[str, Any]
    warnings: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.warnings is None:
            self.warnings = []


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

        warnings: List[str] = []
        if 'VULNERABILITY TRIGGERED' in pov_script:
            matched_patterns.append('has_vulnerability_indicator')
            details['has_vulnerability_check'] = True
        else:
            # Downgraded from blocking issue to warning — the runtime oracle can confirm
            # via crash_signal or sanitizer_output even without the print statement.
            # The scaffold already emits print('VULNERABILITY TRIGGERED'); if the model
            # stripped it we still want to attempt execution rather than hard-blocking.
            warnings.append(
                "PoV does not print 'VULNERABILITY TRIGGERED' — oracle will rely on "
                "crash signal / sanitizer output. Add print('VULNERABILITY TRIGGERED') "
                "after the trigger call if the binary does not crash."
            )

        contract_signals = self._match_contract_signals(pov_script, exploit_contract)
        thin_contract = self._is_thin_contract(exploit_contract)
        if contract_signals:
            matched_patterns.append(f"contract_signals: {', '.join(contract_signals[:4])}")
        elif exploit_contract and not thin_contract:
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

        generic_signals = self._generic_validation_signals(pov_script, vulnerable_code, exploit_contract, filepath=filepath)
        _raw_matches = generic_signals['matches']
        # Extract internal sentinel flag before extending matched_patterns
        if '__self_compile_detected__' in _raw_matches:
            _raw_matches = [m for m in _raw_matches if m != '__self_compile_detected__']
            details['self_compile_detected'] = True
        matched_patterns.extend(_raw_matches)
        issues.extend(generic_signals['issues'])

        code_relevance = self._check_code_relevance(pov_script, vulnerable_code, exploit_contract)
        details['code_relevance_score'] = code_relevance
        if code_relevance > 0.45:
            matched_patterns.append('addresses_target_code_or_contract')
        else:
            issues.append('PoV may not directly address the vulnerable code or exploit contract')

        is_native_target = Path(filepath or '').suffix.lower() in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'} or any(term in (vulnerable_code or '').lower() for term in ['malloc', 'free', 'memcpy', 'strcpy', 'sizeof'])
        critical_issues = {
            'PoV does not reference the target entrypoint from the exploit contract',
            'Native PoV does not appear to execute or target a compiled binary',
        }
        has_critical_issue = any(issue in critical_issues for issue in issues)

        confidence = self._calculate_confidence(len(matched_patterns), len(issues), details['has_vulnerability_check'], code_relevance, bool(contract_signals), cwe_type == 'UNCLASSIFIED' or cwe_type not in self.CWE_PATTERNS)
        if has_critical_issue:
            confidence = min(confidence, 0.49)
        if is_native_target and exploit_contract and not contract_signals and not thin_contract:
            confidence = min(confidence, 0.45)
        # Self-compile detected: hard block — confidence floor 0.2, forces is_valid=False
        if details.get('self_compile_detected'):
            confidence = min(confidence, 0.2)
        # 'has_vulnerability_check' no longer gates is_valid — oracle decides at runtime.
        # We only block on truly structural issues (no binary reference, critical contract gaps).
        is_valid = (
            len(matched_patterns) >= 2
            and confidence >= 0.55
            and not has_critical_issue
            and not details.get('self_compile_detected')
            and not (is_native_target and exploit_contract and not contract_signals and not thin_contract)
        )

        result = ValidationResult(is_valid=is_valid, confidence=confidence, matched_patterns=matched_patterns, issues=issues, details=details, warnings=warnings)
        self.validation_history.append(result)
        return result

    def _is_thin_contract(self, exploit_contract: Dict[str, Any]) -> bool:
        if not exploit_contract:
            return True
        meaningful_lists = [
            exploit_contract.get('success_indicators') or [],
            exploit_contract.get('inputs') or [],
            exploit_contract.get('side_effects') or [],
            exploit_contract.get('trigger_steps') or [],
            exploit_contract.get('preconditions') or [],
        ]
        if any(any(str(item).strip() for item in values) for values in meaningful_lists):
            return False
        entrypoint = str(exploit_contract.get('target_entrypoint') or '').strip().lower()
        if entrypoint not in {'', 'unknown', 'none', 'n/a'}:
            return False
        goal = str(exploit_contract.get('goal') or '').strip()
        expected_outcome = str(exploit_contract.get('expected_outcome') or '').strip()
        if goal or expected_outcome:
            return False
        return True

    def _contract_list(self, exploit_contract: Dict[str, Any], key: str) -> List[Any]:
        value = exploit_contract.get(key, [])
        if value in (None, ''):
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, dict):
            normalized: List[Any] = []
            for item_key, item_value in value.items():
                if item_key not in (None, ''):
                    normalized.append(item_key)
                if item_value not in (None, '', [], {}, ()):
                    normalized.append(item_value)
            return normalized
        return [value]

    def _match_contract_signals(self, pov_script: str, exploit_contract: Dict[str, Any]) -> List[str]:
        haystack = pov_script.lower()
        matches = []
        contract_items = (
            self._contract_list(exploit_contract, 'success_indicators')
            + self._contract_list(exploit_contract, 'inputs')
            + self._contract_list(exploit_contract, 'side_effects')
        )
        for item in contract_items:
            token = str(item).strip().lower()
            if token and token in haystack:
                matches.append(str(item))
        return matches

    def _generic_validation_signals(self, pov_script: str, vulnerable_code: str, exploit_contract: Dict[str, Any], filepath: str = '') -> Dict[str, List[str]]:
        matches: List[str] = []
        issues: List[str] = []
        pov_lower = pov_script.lower()
        vuln_lower = (vulnerable_code or '').lower()
        ext = Path(filepath or '').suffix.lower()
        is_native = ext in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'} or any(term in vuln_lower for term in ['malloc', 'free', 'memcpy', 'strcpy', 'sizeof'])

        suspicious_terms = ['payload', 'exploit', 'trigger', 'input', 'request', 'query', 'command', 'path', 'token', 'header', 'free', 'buffer']
        shared_terms = [term for term in suspicious_terms if term in pov_lower and term in vuln_lower]
        if shared_terms:
            matches.append(f"shared_security_terms: {', '.join(shared_terms[:4])}")

        entrypoint = str(exploit_contract.get('target_entrypoint', '')).strip().lower()
        unresolved_entrypoints = {'', 'unknown', 'none', 'n/a'}
        if entrypoint not in unresolved_entrypoints:
            if entrypoint in pov_lower:
                matches.append('references_target_entrypoint')
            else:
                issues.append('PoV does not reference the target entrypoint from the exploit contract')

        observable_tokens = ['assert', 'sys.exit', 'raise', 'print(']
        if is_native:
            observable_tokens.extend(['subprocess.run', 'target_binary', 'target_bin', 'mqjs_bin', 'addresssanitizer', 'undefinedbehaviorsanitizer'])
        if any(word in pov_lower for word in observable_tokens):
            matches.append('contains_observable_outcome_logic')
        else:
            issues.append('PoV lacks a clear observable outcome check')

        if is_native:
            native_markers = ['target_binary', 'target_bin', 'mqjs_bin', 'subprocess.run', 'stdin', 'argv', 'input_file', 'addresssanitizer', 'undefinedbehaviorsanitizer']
            found_native = [marker for marker in native_markers if marker in pov_lower]
            if found_native:
                matches.append(f"native_execution_signals: {', '.join(found_native[:4])}")
            else:
                issues.append('Native PoV does not appear to execute or target a compiled binary')
            # Detect self-compile pattern: model trying to rebuild the binary with clang/gcc
            # inside the PoV script, OR writing a C source file and compiling it.
            # The binary is pre-built by the harness; recompilation
            # never works inside the proof container and wastes all retry attempts.
            _COMPILE_SIGNALS = [
                'subprocess.run.*clang', 'subprocess.run.*gcc', 'subprocess.call.*clang',
                'subprocess.call.*gcc', 'subprocess.check_call.*clang', 'subprocess.check_call.*gcc',
                'subprocess.run.*cmake', 'subprocess.call.*cmake', 'subprocess.check_call.*cmake',
                'subprocess.run.*["\']make', 'subprocess.call.*["\']make', 'subprocess.check_call.*["\']make',
                'cc -', 'gcc -', 'clang -', 'compile_cmd', 'link_cmd', 'compile_command',
                'fsanitize=address', '-fsanitize=address',
            ]
            # C file-dropper variant: model writes a .c file and compiles it via a harness path.
            # Signals: writing to *.c files, open(.*\.c.*w), pov_payload.c, exploit.c, etc.
            _C_DROPPER_SIGNALS_RE = [
                r"open\([^)]*\.c[\"'\s]",
                r'with open\([^)]*\.c',
                r'pov_payload\.c',
                r'/tmp/exploit\.c',
                r'exploit\.c',
                r'payload\.c',
                r'subprocess\.run.*\.c\b',
            ]
            import re as _re_sv
            _self_compile = (
                any(_re_sv.search(sig, pov_lower) for sig in _COMPILE_SIGNALS if '.' in sig)
                or any(sig in pov_lower for sig in _COMPILE_SIGNALS if '.' not in sig)
                or any(_re_sv.search(sig, pov_script) for sig in _C_DROPPER_SIGNALS_RE)
            )
            if _self_compile:
                issues.append(
                    'PoV attempts to self-compile the target binary — the binary is already '
                    'built with ASan by the harness and exposed via TARGET_BINARY. '
                    'Remove all compilation steps and use TARGET_BINARY directly.'
                )
                # Signal back to validate() via a sentinel in matches list so that
                # details['self_compile_detected'] can be set there (details is not in scope here).
                matches.append('__self_compile_detected__')

        # Detect: model initializes `binary = ''` or `binary = None` without first reading
        # TARGET_BINARY. This causes binary-not-found failures when TARGET_BINARY is set.
        # Correct pattern: `binary = TARGET_BINARY` (module-level var) as the first assignment.
        import re as _re_bv
        _binary_empty = _re_bv.search(r"\bbinary\s*=\s*(?:''|\"\")", pov_script)
        _binary_uses_target = 'binary = TARGET_BINARY' in pov_script or 'binary = os.environ' in pov_script
        if _binary_empty and not _binary_uses_target and 'TARGET_BINARY' in pov_script:
            issues.append(
                'PoV initializes `binary = ""` or `binary = None` without first assigning '
                '`binary = TARGET_BINARY`. The harness sets TARGET_BINARY in the environment. '
                'The first line of main() MUST be `binary = TARGET_BINARY`.'
            )

        return {'matches': matches, 'issues': issues}

    def _check_code_relevance(self, pov_script: str, vulnerable_code: str, exploit_contract: Dict[str, Any]) -> float:
        if not vulnerable_code and not exploit_contract:
            return 0.5
        vulnerable_lower = (vulnerable_code or '').lower()
        pov_lower = pov_script.lower()
        keywords = ['function', 'def', 'class', 'route', 'endpoint', 'query', 'execute', 'render', 'template', 'user', 'input', 'request', 'free', 'malloc', 'buffer', 'path', 'argc', 'argv', 'stdin', 'fopen', 'read', 'write']
        matches = sum(1 for keyword in keywords if keyword in vulnerable_lower and keyword in pov_lower)
        relevance_items = (
            self._contract_list(exploit_contract, 'inputs')
            + self._contract_list(exploit_contract, 'trigger_steps')
            + self._contract_list({'target_entrypoint': exploit_contract.get('target_entrypoint', '')}, 'target_entrypoint')
        )
        for item in relevance_items:
            token = str(item).strip().lower()
            if token and token not in {'unknown', 'none', 'n/a'} and token in pov_lower:
                matches += 1

        proof_plan = exploit_contract.get('proof_plan') or {}
        runtime_family = str(proof_plan.get('runtime_family') or exploit_contract.get('runtime_profile') or '').lower()
        if runtime_family in {'native', 'c', 'cpp', 'binary'}:
            native_tokens = ['target_binary', 'target_bin', 'mqjs_bin', 'subprocess.run', 'argv', 'stdin']
            native_matches = sum(1 for token in native_tokens if token in pov_lower)
            matches += native_matches
            target_entrypoint = str(exploit_contract.get('target_entrypoint', '')).strip().lower()
            if target_entrypoint in {'', 'unknown', 'none', 'n/a'} and native_matches:
                matches = max(matches, 3)

        return min(matches / 5, 1.0)

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