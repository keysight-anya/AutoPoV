"""
AutoPoV Prompts Module
Centralized LLM prompts for vulnerability discovery, investigation, and proof generation.
"""

import json

INVESTIGATION_PROMPT = """You are a security expert analyzing a candidate vulnerability in code.

CODE CONTEXT:
{code_context}

CANDIDATE SIGNAL:
- Initial signal label: {cwe_type}
- File: {filepath}
- Line: {line_number}
- Detection note: {alert_message}

{joern_context}

TASK:
Determine whether this issue is a REAL exploitable vulnerability or a FALSE_POSITIVE.
If it is real, classify it as precisely as possible:
- map it to a known CWE if the match is strong
- include a known CVE only if there is a strong and specific match
- if it is real but does not cleanly map to a known taxonomy entry, return UNCLASSIFIED

Respond in this exact JSON format:
{{
    "verdict": "REAL" or "FALSE_POSITIVE",
    "cwe_type": "CWE-XXX" or "UNCLASSIFIED",
    "cve_id": "CVE-YYYY-NNNN" or null,
    "confidence": 0.0 to 1.0,
    "explanation": "Detailed explanation of your analysis",
    "vulnerable_code": "The specific vulnerable code snippet",
    "root_cause": "Root cause of the vulnerability",
    "impact": "Potential impact if exploited"
}}

Guidelines:
- Be evidence-driven
- Do not invent taxonomy labels when the mapping is weak
- A real vulnerability can still be UNCLASSIFIED
- Prefer exploitability and concrete impact over naming purity
"""

POV_GENERATION_PROMPT = """You are a security researcher creating a Proof-of-Vulnerability (PoV) script.

VULNERABILITY DETAILS:
- Current classification label: {cwe_type}
- File: {filepath}
- Line: {line_number}
- Vulnerable Code: {vulnerable_code}
- Explanation: {explanation}
- Target Language: {target_language}

TARGET CODE:
```
{code_context}
```

TASK:
Create a {pov_language} PoV and an exploit contract that explains how the proof should work.
The PoV must be runnable in the AutoPoV harness against the real repository or built target.
For native C/C++ targets, prefer executing the real built binary or directly invoking the vulnerable helper with deterministic inputs.
Use environment variables like TARGET_BINARY, TARGET_BIN, MQJS_BIN, and CODEBASE_PATH when the exploit needs the built artifact or repository path.

REQUIREMENTS:
1. Use only {pov_language} standard library
2. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed
3. Include error handling
4. Make the PoV as deterministic as possible
5. Prefer directly exercising the vulnerable function, route, binary, or code path
6. For native targets, prefer subprocess crash detection, sanitizer evidence, or direct helper invocation over abstract mock logic
7. The exploit_contract.target_entrypoint must be a concise function name, route, or binary path hint, not a prose sentence
8. If the issue is not cleanly mapped to a known taxonomy entry, still produce the best exploit strategy you can

Respond in JSON only with this exact shape:
{{
  "pov_script": "full {pov_language} script",
  "exploit_contract": {{
    "goal": "one sentence description of what the exploit proves",
    "target_entrypoint": "function, method, route, or code path to exercise",
    "preconditions": ["required setup or assumptions"],
    "inputs": ["important attacker-controlled inputs or payloads"],
    "trigger_steps": ["ordered exploit steps"],
    "success_indicators": ["observable outputs or strings that prove success"],
    "side_effects": ["files, state changes, or other concrete effects expected on success"],
    "expected_outcome": "what should happen if the vulnerability is real"
  }}
}}
"""

POV_GENERATION_PROMPT_OFFLINE = """You are creating a compact Proof-of-Vulnerability (PoV) script for a local offline model.

VULNERABILITY:
- Label: {cwe_type}
- Location: {filepath}:{line_number}
- Target Language: {target_language}
- Explanation: {explanation}

VULNERABLE SNIPPET:
```
{vulnerable_code}
```

TARGET EXCERPT:
```
{code_context}
```

TASK:
Return JSON only. Generate the smallest runnable {pov_language} script that can test the real vulnerable path. Prefer direct local execution, deterministic payloads, and concrete success checks. Do not include prose outside JSON.

JSON SHAPE:
{{
  "pov_script": "full runnable {pov_language} script",
  "exploit_contract": {{
    "goal": "one sentence exploit goal",
    "target_entrypoint": "function, route, helper, or binary hint",
    "runtime_profile": "web|python|javascript|node|c|cpp|native|binary",
    "preconditions": ["required setup or assumptions"],
    "inputs": ["attacker-controlled inputs or payloads"],
    "trigger_steps": ["ordered exploit steps"],
    "success_indicators": ["observable proof strings or effects"],
    "side_effects": ["files, state changes, or other effects"],
    "expected_outcome": "what should happen if the vulnerability is real"
  }}
}}
"""

POV_VALIDATION_PROMPT = """You are validating a Proof-of-Vulnerability (PoV) Python script.

POV SCRIPT:
```python
{pov_script}
```

VULNERABILITY CONTEXT:
- Current classification label: {cwe_type}
- Target: {filepath}:{line_number}
- Exploit Goal: {exploit_goal}
- Success Indicators: {success_indicators}

TASK:
Validate this PoV script and respond in JSON format:
{{
    "is_valid": true or false,
    "issues": ["List any issues found"],
    "suggestions": ["Suggestions for improvement"],
    "will_trigger": "YES", "MAYBE", or "NO"
}}

Validation Criteria:
1. Uses only standard library
2. Contains "VULNERABILITY TRIGGERED" print statement
3. Logic is aligned with the exploit goal, success indicators, and expected side effects
4. Has proper error handling
5. Is deterministic
"""

CODE_ANALYSIS_PROMPT = """You are analyzing a codebase for security vulnerabilities.

CODE:
```
{code}
```

LANGUAGE: {language}
FILE: {filepath}

TASK:
Identify potential security vulnerabilities in this code without assuming a predefined taxonomy.
If a finding strongly aligns with a known CWE, you may include it. Otherwise use UNCLASSIFIED.

For each vulnerability found, provide:
- classification label (known CWE if justified, otherwise UNCLASSIFIED)
- line number(s)
- description
- severity (Critical/High/Medium/Low)
- suggested fix

Respond in JSON format:
{{
    "vulnerabilities": [
        {{
            "cwe": "CWE-XXX or UNCLASSIFIED",
            "line": line_number,
            "description": "Description",
            "severity": "Critical|High|Medium|Low",
            "fix": "Suggested fix"
        }}
    ],
    "summary": "Brief summary of findings"
}}

If no vulnerabilities found, return an empty vulnerabilities array.
"""

RAG_CONTEXT_PROMPT = """You are enhancing context for a vulnerability investigation.

PRIMARY CODE:
```
{primary_code}
```

RELATED CODE CHUNKS:
{related_chunks}

TASK:
Synthesize this information to provide a concise understanding of:
1. How the relevant code functions
2. What inputs it receives
3. How data flows through it
4. Any security controls present
5. What makes the candidate vulnerability plausible or implausible
"""

RETRY_ANALYSIS_PROMPT = """A Proof-of-Vulnerability script failed to trigger the vulnerability.

ORIGINAL VULNERABILITY:
- Classification label: {cwe_type}
- Location: {filepath}:{line_number}
- Explanation: {explanation}

FAILED POV SCRIPT:
```python
{failed_pov}
```

EXECUTION OUTPUT:
```
{execution_output}
```

ATTEMPT: {attempt_number} of {max_retries}

TASK:
Analyze why the PoV failed and suggest improvements. Consider:
1. Was the vulnerability path incorrect?
2. Are there input validation checks or preconditions we missed?
3. Is there a specific state required to trigger it?
4. Do we need different input data or a different exploit path?

Respond in JSON format:
{{
    "failure_reason": "Explanation of why it failed",
    "suggested_changes": "Specific changes to make",
    "different_approach": true or false
}}
"""

POV_REFINEMENT_PROMPT = """You are fixing a failed Proof-of-Vulnerability (PoV) script.

VULNERABILITY DETAILS:
- Current classification label: {cwe_type}
- File: {filepath}
- Line: {line_number}
- Vulnerable Code: {vulnerable_code}
- Explanation: {explanation}
- Target Language: {target_language}

TARGET CODE:
```
{code_context}
```

FAILED POV SCRIPT:
```python
{failed_pov}
```

VALIDATION / EXECUTION ERRORS:
{validation_errors}

CURRENT EXPLOIT CONTRACT:
{exploit_contract}

TASK:
Return a corrected, executable PoV script and an updated exploit contract.
Do not return failure analysis, prose, or planning notes.
Return only runnable code in the `pov_script` field.

REQUIREMENTS:
1. The response must be JSON only.
2. `pov_script` must contain executable code, not analysis text.
3. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed.
4. The script must explicitly use the exploit contract target entrypoint if one is provided.
5. Prefer deterministic local proof techniques for native targets: controlled inputs, subprocess crash detection, sanitizer evidence, or direct invocation of the vulnerable helper when possible.
6. Include concrete success indicators and side effects in the exploit contract.

Respond in JSON only with this exact shape:
{{
  "pov_script": "full runnable PoV script",
  "exploit_contract": {{
    "goal": "one sentence description of what the exploit proves",
    "target_entrypoint": "function, method, route, binary, or code path to exercise",
    "runtime_profile": "web|python|javascript|node|c|cpp|native|binary",
    "preconditions": ["required setup or assumptions"],
    "inputs": ["important attacker-controlled inputs or payloads"],
    "trigger_steps": ["ordered exploit steps"],
    "success_indicators": ["observable outputs or strings that prove success"],
    "side_effects": ["files, state changes, or other concrete effects expected on success"],
    "expected_outcome": "what should happen if the vulnerability is real"
  }}
}}
"""

POV_REFINEMENT_PROMPT_OFFLINE = """You are repairing a failed Proof-of-Vulnerability (PoV) for a local offline model.

VULNERABILITY:
- Label: {cwe_type}
- Location: {filepath}:{line_number}
- Target Language: {target_language}
- Explanation: {explanation}

VULNERABLE SNIPPET:
```
{vulnerable_code}
```

TARGET EXCERPT:
```
{code_context}
```

FAILED POV SCRIPT:
```python
{failed_pov}
```

VALIDATION ERRORS:
{validation_errors}

CURRENT EXPLOIT CONTRACT:
{exploit_contract}

TASK:
Return JSON only with a corrected runnable `pov_script` and an updated `exploit_contract`. Keep the script compact, deterministic, and focused on the declared target entrypoint.
"""

POV_VALIDATION_PROMPT_OFFLINE = """You are validating a compact offline PoV script.

POV SCRIPT:
```python
{pov_script}
```

VULNERABILITY CONTEXT:
- Label: {cwe_type}
- Target: {filepath}:{line_number}
- Goal: {exploit_goal}
- Success Indicators: {success_indicators}

TASK:
Return JSON only with:
{{
  "is_valid": true or false,
  "issues": ["issue"],
  "suggestions": ["suggestion"],
  "will_trigger": "YES", "MAYBE", or "NO"
}}
"""

RETRY_ANALYSIS_PROMPT_OFFLINE = """A compact offline PoV failed.

VULNERABILITY:
- Label: {cwe_type}
- Location: {filepath}:{line_number}
- Explanation: {explanation}

FAILED POV:
```python
{failed_pov}
```

EXECUTION OUTPUT:
```
{execution_output}
```

ATTEMPT: {attempt_number} of {max_retries}

TASK:
Return JSON only with:
{{
  "failure_reason": "why it failed",
  "suggested_changes": "specific next change",
  "different_approach": true or false
}}
"""

SUMMARY_REPORT_PROMPT = """You are generating a summary of a vulnerability scan.

SCAN METRICS:
- Total Files Scanned: {total_files}
- Total Lines Scanned: {total_lines}
- Discovery Scope: {cwes_checked}
- Model Used: {model_name}
- Duration: {duration_seconds}s

FINDINGS SUMMARY:
- Total Alerts: {total_alerts}
- Confirmed Vulnerabilities: {confirmed_vulns}
- False Positives: {false_positives}
- PoV Success Rate: {pov_success_rate}%
- Detection Rate: {detection_rate}%
- False Positive Rate: {false_positive_rate}%

CONFIRMED VULNERABILITIES:
{vulnerabilities_list}

TASK:
Generate an executive summary of this security scan. Include:
1. Overall security posture assessment
2. Key findings and their severity
3. Patterns observed
4. Recommendations for remediation
5. Notable proven vulnerabilities vs inconclusive candidates

Format as a professional security report summary.
"""


def format_investigation_prompt(code_context: str, cwe_type: str, filepath: str, line_number: int, alert_message: str, joern_context: str = "") -> str:
    return INVESTIGATION_PROMPT.format(
        code_context=code_context,
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        alert_message=alert_message or 'Candidate security signal',
        joern_context=joern_context or ''
    )


def format_pov_generation_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, target_language: str, pov_language: str) -> str:
    return POV_GENERATION_PROMPT.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code or '',
        explanation=explanation or '',
        code_context=code_context or '',
        target_language=target_language or 'unknown',
        pov_language=pov_language or 'python'
    )


def format_pov_generation_prompt_offline(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, target_language: str, pov_language: str) -> str:
    return POV_GENERATION_PROMPT_OFFLINE.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code or '',
        explanation=explanation or '',
        code_context=code_context or '',
        target_language=target_language or 'unknown',
        pov_language=pov_language or 'python'
    )


def format_pov_validation_prompt(pov_script: str, cwe_type: str, filepath: str, line_number: int, exploit_goal: str = '', success_indicators: str = '', exploit_contract=None) -> str:
    contract = exploit_contract or {}
    derived_goal = exploit_goal or contract.get('goal') or 'Establish whether the identified vulnerability is real.'
    indicators = success_indicators
    if not indicators:
        parts = []
        if contract.get('success_indicators'):
            parts.append(', '.join(str(x) for x in contract.get('success_indicators', []) if str(x).strip()))
        if contract.get('side_effects'):
            parts.append('Side effects: ' + ', '.join(str(x) for x in contract.get('side_effects', []) if str(x).strip()))
        indicators = ' | '.join([p for p in parts if p]) or 'Observable exploit success indicators not specified.'
    return POV_VALIDATION_PROMPT.format(
        pov_script=pov_script or '',
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        exploit_goal=derived_goal,
        success_indicators=indicators
    )


def format_pov_validation_prompt_offline(pov_script: str, cwe_type: str, filepath: str, line_number: int, exploit_goal: str = '', success_indicators: str = '', exploit_contract=None) -> str:
    contract = exploit_contract or {}
    derived_goal = exploit_goal or contract.get('goal') or 'Establish whether the identified vulnerability is real.'
    indicators = success_indicators
    if not indicators:
        parts = []
        if contract.get('success_indicators'):
            parts.append(', '.join(str(x) for x in contract.get('success_indicators', []) if str(x).strip()))
        if contract.get('side_effects'):
            parts.append('Side effects: ' + ', '.join(str(x) for x in contract.get('side_effects', []) if str(x).strip()))
        indicators = ' | '.join([p for p in parts if p]) or 'Observable exploit success indicators not specified.'
    return POV_VALIDATION_PROMPT_OFFLINE.format(
        pov_script=pov_script or '',
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        exploit_goal=derived_goal,
        success_indicators=indicators
    )


def format_rag_context_prompt(primary_code: str, related_chunks: str) -> str:
    return RAG_CONTEXT_PROMPT.format(
        primary_code=primary_code or '',
        related_chunks=related_chunks or '[No related chunks available]'
    )


def format_retry_analysis_prompt(cwe_type: str, filepath: str, line_number: int, explanation: str, failed_pov: str, execution_output: str, attempt_number: int, max_retries: int) -> str:
    return RETRY_ANALYSIS_PROMPT.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        explanation=explanation or '',
        failed_pov=failed_pov or '',
        execution_output=execution_output or '',
        attempt_number=attempt_number,
        max_retries=max_retries
    )


def format_retry_analysis_prompt_offline(cwe_type: str, filepath: str, line_number: int, explanation: str, failed_pov: str, execution_output: str, attempt_number: int, max_retries: int) -> str:
    return RETRY_ANALYSIS_PROMPT_OFFLINE.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        explanation=explanation or '',
        failed_pov=failed_pov or '',
        execution_output=execution_output or '',
        attempt_number=attempt_number,
        max_retries=max_retries
    )


def format_pov_refinement_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, failed_pov: str, validation_errors, attempt_number: int, target_language: str = 'python', exploit_contract=None) -> str:
    rendered_errors = ''
    if validation_errors:
        if isinstance(validation_errors, (list, tuple)):
            rendered_errors = '\n'.join(f'- {x}' for x in validation_errors)
        else:
            rendered_errors = str(validation_errors)
    return POV_REFINEMENT_PROMPT.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code or '',
        explanation=explanation or '',
        code_context=code_context or '',
        failed_pov=failed_pov or '',
        validation_errors=rendered_errors or '[No validation errors supplied]',
        attempt_number=attempt_number,
        target_language=target_language or 'python',
        exploit_contract=json.dumps(exploit_contract or {}, indent=2)
    )


def format_pov_refinement_prompt_offline(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, failed_pov: str, validation_errors, attempt_number: int, target_language: str = 'python', exploit_contract=None) -> str:
    rendered_errors = ''
    if validation_errors:
        if isinstance(validation_errors, (list, tuple)):
            rendered_errors = '\n'.join(f'- {x}' for x in validation_errors)
        else:
            rendered_errors = str(validation_errors)
    return POV_REFINEMENT_PROMPT_OFFLINE.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code or '',
        explanation=explanation or '',
        code_context=code_context or '',
        failed_pov=failed_pov or '',
        validation_errors=rendered_errors or '[No validation errors supplied]',
        attempt_number=attempt_number,
        target_language=target_language or 'python',
        exploit_contract=json.dumps(exploit_contract or {}, indent=2)
    )


def format_scout_prompt(file_snippets, cwes) -> str:
    taxonomy_hint = 'No predefined taxonomy focus. Discover any credible vulnerability class and use UNCLASSIFIED when no precise known mapping is justified.'
    if cwes:
        taxonomy_hint = 'Optional taxonomy focus labels: ' + ', '.join(cwes)
    rendered = []
    for item in file_snippets:
        rendered.append(
            f"FILE: {item.get('filepath','unknown')}\nLANGUAGE: {item.get('language','unknown')}\n```\n{item.get('code','')}\n```"
        )
    return (
        'You are scouting a codebase for security vulnerabilities.\n\n'
        f'{taxonomy_hint}\n\n'
        'Return JSON with this shape: {"findings": [{"filepath": str, "language": str, "line": int, "cwe": "CWE-XXX or UNCLASSIFIED", "cve_id": null or str, "snippet": str, "reason": str, "confidence": float}]}\n\n'
        'Prioritize exploitable issues, dangerous sinks, memory/lifecycle mistakes, unsafe trust boundaries, and missing controls.\n\n'
        + '\n\n'.join(rendered)
    )


def format_scout_triage_prompt(file_snippets, cwes) -> str:
    """Prompt for LLM triage of pre-selected candidate signals from static tools.
    
    Each file_snippet includes candidate_lines and candidate_cwes from prior tools,
    so the LLM focuses its analysis on flagged locations rather than full-file scanning.
    """
    taxonomy_hint = 'No predefined taxonomy focus. Validate and refine each candidate — use UNCLASSIFIED when no precise known mapping exists.'
    if cwes:
        taxonomy_hint = 'Optional taxonomy context from prior tools: ' + ', '.join(cwes)
    rendered = []
    for item in file_snippets:
        candidate_info = ''
        lines = item.get('candidate_lines', [])
        cwes_hint = item.get('candidate_cwes', [])
        if lines or cwes_hint:
            candidate_info = f'\nCANDIDATE SIGNALS: lines {lines}, prior labels {cwes_hint}'
        rendered.append(
            f"FILE: {item.get('filepath','unknown')}\nLANGUAGE: {item.get('language','unknown')}{candidate_info}\n```\n{item.get('code','')}\n```"
        )
    return (
        'You are triaging pre-flagged vulnerability candidates from static analysis tools.\n\n'
        f'{taxonomy_hint}\n\n'
        'For each file, review the CANDIDATE SIGNALS (flagged lines/labels) and the full code context. '
        'Determine: is each signal a real exploitable vulnerability, a false positive, or something different?\n\n'
        'Return JSON with this shape: {"findings": [{"filepath": str, "language": str, "line": int, "cwe": "CWE-XXX or UNCLASSIFIED", "cve_id": null or str, "snippet": str, "reason": str, "confidence": float}]}\n\n'
        'Rules:\n'
        '- confidence >= 0.8 means you are certain it is exploitable\n'
        '- confidence < 0.5 means likely false positive (still include it)\n'
        '- Use UNCLASSIFIED for real issues that do not map to a known CWE\n'
        '- Do not invent taxonomy labels; accuracy over completeness\n\n'
        + '\n\n'.join(rendered)
    )


def format_summary_report_prompt(**kwargs) -> str:
    return SUMMARY_REPORT_PROMPT.format(**kwargs)


def format_code_analysis_prompt(code: str, language: str, filepath: str) -> str:
    return CODE_ANALYSIS_PROMPT.format(code=code or '', language=language or 'unknown', filepath=filepath or 'unknown')


__all__ = [
    'INVESTIGATION_PROMPT',
    'POV_GENERATION_PROMPT',
    'POV_VALIDATION_PROMPT',
    'CODE_ANALYSIS_PROMPT',
    'RAG_CONTEXT_PROMPT',
    'RETRY_ANALYSIS_PROMPT',
    'SUMMARY_REPORT_PROMPT',
    'format_investigation_prompt',
    'format_pov_generation_prompt',
    'format_pov_generation_prompt_offline',
    'format_pov_validation_prompt',
    'format_pov_validation_prompt_offline',
    'format_rag_context_prompt',
    'format_retry_analysis_prompt',
    'format_retry_analysis_prompt_offline',
    'format_pov_refinement_prompt',
    'format_pov_refinement_prompt_offline',
    'format_scout_prompt',
    'format_scout_triage_prompt',
    'format_summary_report_prompt',
    'format_code_analysis_prompt',
]
