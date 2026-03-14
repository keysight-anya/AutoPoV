"""
AutoPoV Prompts Module
Centralized LLM prompts for vulnerability detection and PoV generation
"""


# Investigation Prompt - Used by the investigator agent
INVESTIGATION_PROMPT = """You are a security expert analyzing a candidate vulnerability in code.

CODE CONTEXT:
{code_context}

CANDIDATE SIGNAL:
- Initial classification: {cwe_type}
- File: {filepath}
- Line: {line_number}
- Detection note: {alert_message}

{joern_context}

TASK:
Determine whether this issue is a REAL exploitable vulnerability or a FALSE_POSITIVE.
If it is real, classify it as precisely as possible:
- map it to a known CWE if you can
- include a known CVE only if there is a strong and specific match
- if it is real but does not cleanly map to a known CWE, return UNCLASSIFIED

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
- Do not invent a CWE or CVE if the mapping is weak
- A real vulnerability can still be UNCLASSIFIED
- Prefer exploitability and concrete impact over taxonomy purity
"""


# PoV Generation Prompt - Used to generate Proof-of-Vulnerability scripts
POV_GENERATION_PROMPT = """You are a security researcher creating a Proof-of-Vulnerability (PoV) script.

VULNERABILITY DETAILS:
- Classification: {cwe_type}
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
The PoV will run in an isolated test harness where the target code has already been loaded and its functions
are available in globals.

REQUIREMENTS:
1. Use only {pov_language} standard library (no external packages)
2. The script must print "VULNERABILITY TRIGGERED" when successful
3. Include error handling
4. Make the PoV as deterministic as possible
5. Do NOT make network calls and do NOT reference target_url
6. Prefer calling the vulnerable function(s) defined in the target code context
7. If the issue is not cleanly mapped to a known CWE, still produce the best exploit strategy you can

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


# PoV Validation Prompt - Used to validate generated PoV scripts
POV_VALIDATION_PROMPT = """You are validating a Proof-of-Vulnerability (PoV) Python script.

POV SCRIPT:
```python
{pov_script}
```

VULNERABILITY CONTEXT:
- Classification: {cwe_type}
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
3. Logic appears aligned with the exploit goal and success indicators
4. Has proper error handling
5. Is deterministic
"""


# Code Analysis Prompt - Used for initial code analysis
CODE_ANALYSIS_PROMPT = """You are analyzing a codebase for security vulnerabilities.

CODE:
```
{code}
```

LANGUAGE: {language}
FILE: {filepath}

TASK:
Identify potential security vulnerabilities in this code. Focus on:
1. Buffer overflows (CWE-119)
2. SQL injections (CWE-89)
3. Use after free (CWE-416)
4. Integer overflows (CWE-190)

For each vulnerability found, provide:
- CWE type
- Line number(s)
- Description
- Severity (Critical/High/Medium/Low)
- Suggested fix

Respond in JSON format:
{{
    "vulnerabilities": [
        {{
            "cwe": "CWE-XXX",
            "line": line_number,
            "description": "Description",
            "severity": "Critical|High|Medium|Low",
            "fix": "Suggested fix"
        }}
    ],
    "summary": "Brief summary of findings"
}}

If no vulnerabilities found, return empty vulnerabilities array.
"""


# RAG Context Enhancement Prompt
RAG_CONTEXT_PROMPT = """You are enhancing context for a vulnerability investigation.

PRIMARY CODE:
```
{primary_code}
```

RELATED CODE CHUNKS:
{related_chunks}

TASK:
Synthesize this information to provide a comprehensive understanding of:
1. How the vulnerable code functions
2. What inputs it receives
3. How data flows through it
4. Any security controls present

Provide a concise summary that will help in vulnerability analysis.
"""


# Retry Analysis Prompt - Used when PoV fails
RETRY_ANALYSIS_PROMPT = """A Proof-of-Vulnerability script failed to trigger the vulnerability.

ORIGINAL VULNERABILITY:
- CWE: {cwe_type}
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
2. Are there input validation checks we missed?
3. Is there a specific condition required to trigger it?
4. Do we need different input data?

Respond in JSON format:
{{
    "failure_reason": "Explanation of why it failed",
    "suggested_changes": "Specific changes to make",
    "different_approach": true or false - whether to try a completely different approach
}}
"""


# Summary Report Prompt - Used for generating analysis summaries
SUMMARY_REPORT_PROMPT = """You are generating a summary of a vulnerability scan.

SCAN METRICS:
- Total Files Scanned: {total_files}
- Total Lines Scanned: {total_lines}
- CWEs Checked: {cwes_checked}
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
5. Notable true positives vs false positives

Format as a professional security report summary.
"""


def format_investigation_prompt(
    code_context: str,
    cwe_type: str,
    filepath: str,
    line_number: int,
    alert_message: str,
    joern_context: str = ""
) -> str:
    """Format the investigation prompt with context"""
    return INVESTIGATION_PROMPT.format(
        code_context=code_context,
        cwe_type=cwe_type,
        filepath=filepath,
        line_number=line_number,
        alert_message=alert_message,
        joern_context=joern_context if joern_context else ""
    )


def format_pov_generation_prompt(
    cwe_type: str,
    filepath: str,
    line_number: int,
    vulnerable_code: str,
    explanation: str,
    code_context: str,
    target_language: str = "python",
    pov_language: str = "python"
) -> str:
    """Format the PoV generation prompt"""
    return POV_GENERATION_PROMPT.format(
        cwe_type=cwe_type,
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        explanation=explanation,
        code_context=code_context,
        target_language=target_language,
        pov_language=pov_language
    )


def format_pov_validation_prompt(
    pov_script: str,
    cwe_type: str,
    filepath: str,
    line_number: int,
    exploit_contract: dict | None = None
) -> str:
    """Format the PoV validation prompt"""
    exploit_contract = exploit_contract or {}
    return POV_VALIDATION_PROMPT.format(
        pov_script=pov_script,
        cwe_type=cwe_type,
        filepath=filepath,
        line_number=line_number,
        exploit_goal=exploit_contract.get("goal", "Demonstrate the vulnerability with a deterministic exploit"),
        success_indicators=", ".join(exploit_contract.get("success_indicators", [])) or "VULNERABILITY TRIGGERED"
    )


def format_code_analysis_prompt(
    code: str,
    language: str,
    filepath: str
) -> str:
    """Format the code analysis prompt"""
    return CODE_ANALYSIS_PROMPT.format(
        code=code,
        language=language,
        filepath=filepath
    )


def format_rag_context_prompt(
    primary_code: str,
    related_chunks: str
) -> str:
    """Format the RAG context enhancement prompt"""
    return RAG_CONTEXT_PROMPT.format(
        primary_code=primary_code,
        related_chunks=related_chunks
    )


def format_retry_analysis_prompt(
    cwe_type: str,
    filepath: str,
    line_number: int,
    explanation: str,
    failed_pov: str,
    execution_output: str,
    attempt_number: int,
    max_retries: int
) -> str:
    """Format the retry analysis prompt"""
    return RETRY_ANALYSIS_PROMPT.format(
        cwe_type=cwe_type,
        filepath=filepath,
        line_number=line_number,
        explanation=explanation,
        failed_pov=failed_pov,
        execution_output=execution_output,
        attempt_number=attempt_number,
        max_retries=max_retries
    )


def format_summary_report_prompt(
    total_files: int,
    total_lines: int,
    cwes_checked: str,
    model_name: str,
    duration_seconds: float,
    total_alerts: int,
    confirmed_vulns: int,
    false_positives: int,
    pov_success_rate: float,
    detection_rate: float,
    false_positive_rate: float,
    vulnerabilities_list: str
) -> str:
    """Format the summary report prompt"""
    return SUMMARY_REPORT_PROMPT.format(
        total_files=total_files,
        total_lines=total_lines,
        cwes_checked=cwes_checked,
        model_name=model_name,
        duration_seconds=duration_seconds,
        total_alerts=total_alerts,
        confirmed_vulns=confirmed_vulns,
        false_positives=false_positives,
        pov_success_rate=pov_success_rate,
        detection_rate=detection_rate,
        false_positive_rate=false_positive_rate,
        vulnerabilities_list=vulnerabilities_list
    )

# Scout Prompt - Used for autonomous candidate discovery
SCOUT_PROMPT = """You are a security scout analyzing multiple files for potential vulnerabilities.

FILES:
{files}

FOCUS:
{cwe_guidance}

TASK:
Return a JSON object with an array named "findings". Each finding must include:
- cwe: a best-effort CWE-XXX value, or UNCLASSIFIED if no precise mapping fits
- cve_id: CVE-YYYY-NNNN if there is a strong specific match, otherwise null
- filepath: path of the file
- line: line number (best estimate)
- snippet: short code snippet
- reason: short reasoning
- confidence: 0.0 to 1.0

Prioritize real exploit paths, unsafe trust boundaries, auth flaws, injection, memory safety, insecure deserialization, unsafe execution, crypto misuse, privilege issues, and any other security-relevant weakness.
Respond in JSON only.
"""


def format_scout_prompt(file_snippets, cwes):
    formatted_files = []
    for item in file_snippets:
        formatted_files.append(
            f"FILE: {item.get('filepath')}\nLANGUAGE: {item.get('language')}\nCODE:\n{item.get('code')}\n"
        )

    return SCOUT_PROMPT.format(
        files="\n---\n".join(formatted_files),
        cwes=", ".join(cwes)
    )


# PoV Refinement Prompt - Used to fix failed PoV scripts
POV_REFINEMENT_PROMPT = """You are fixing a failed Proof-of-Vulnerability (PoV) script.

VULNERABILITY DETAILS:
- Classification: {cwe_type}
- File: {filepath}
- Line: {line_number}
- Vulnerable Code: {vulnerable_code}
- Explanation: {explanation}
- Target Language: {target_language}
- Existing Exploit Goal: {exploit_goal}
- Existing Success Indicators: {success_indicators}

TARGET CODE:
```
{code_context}
```

FAILED POV SCRIPT:
```python
{failed_pov}
```

VALIDATION ERRORS:
{validation_errors}

ATTEMPT: {attempt_number}

TASK:
Fix the PoV script and refresh the exploit contract so the proof is more likely to succeed.
The script must:
1. Use only Python standard library
2. Print "VULNERABILITY TRIGGERED" when successful
3. Include error handling
4. Be deterministic
5. Avoid network calls

Respond in JSON only with this exact shape:
{{
  "pov_script": "corrected python script",
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


def format_pov_refinement_prompt(
    cwe_type: str,
    filepath: str,
    line_number: int,
    vulnerable_code: str,
    explanation: str,
    code_context: str,
    failed_pov: str,
    validation_errors: list,
    attempt_number: int,
    target_language: str = "python",
    exploit_contract: dict | None = None
) -> str:
    """Format the PoV refinement prompt"""
    return POV_REFINEMENT_PROMPT.format(
        cwe_type=cwe_type,
        filepath=filepath,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        explanation=explanation,
        code_context=code_context,
        failed_pov=failed_pov,
        validation_errors="\n".join(f"- {e}" for e in validation_errors),
        attempt_number=attempt_number,
        target_language=target_language
    )
