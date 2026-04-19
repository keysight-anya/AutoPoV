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

Also resolve the concrete entry point for exploitation:
- For Python/Node/Java: identify the specific function name, method, class, or importable module that must be called to trigger the vulnerability. Look at the file path and code context — the function name is almost always visible in the surrounding code.
- For C/C++: identify the function name or binary entry point.
- For web/HTTP: identify the route path (e.g. /api/login).
- NEVER output "unknown" — always extract the most specific callable or entry point visible in the code context.

Respond in this exact JSON format:
{{
    "verdict": "REAL" or "FALSE_POSITIVE",
    "cwe_type": "CWE-XXX" or "UNCLASSIFIED",
    "cve_id": "CVE-YYYY-NNNN" or null,
    "confidence": 0.0 to 1.0,
    "explanation": "Detailed explanation of your analysis",
    "vulnerable_code": "The specific vulnerable code snippet",
    "root_cause": "Root cause of the vulnerability",
    "impact": "Potential impact if exploited",
    "target_entrypoint": "The specific function name, method, route, or module entrypoint to exploit"
}}

Guidelines:
- Be evidence-driven
- Do not invent taxonomy labels when the mapping is weak
- A real vulnerability can still be UNCLASSIFIED
- Prefer exploitability and concrete impact over naming purity
- target_entrypoint must be a concrete identifier from the code — never a sentence, never \"unknown\"
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
Create a {pov_language} PoV, an exploit contract, and a structured proof plan that explains how the proof should work based on observed code and runtime evidence.
The PoV must be runnable in the AutoPoV harness against the real repository or built target. Base the plan on observed sinks, inputs, entrypoints, and runtime surfaces, not on generic guesses.
For native C/C++ targets, prefer executing the real built binary or directly invoking the vulnerable helper with deterministic inputs.
Use environment variables like TARGET_BINARY, TARGET_BIN, MQJS_BIN, and CODEBASE_PATH when the exploit needs the built artifact or repository path.

REQUIREMENTS:
1. Use only {pov_language} standard library
2. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed — never as a standalone self-report without runtime corroboration
3. Include error handling
4. Make the PoV as deterministic as possible
5. Prefer directly exercising the vulnerable function, route, binary, or code path
6. For native C/C++ targets: the proof MUST produce an observable crash signal — AddressSanitizer output, SIGSEGV/SIGABRT (exit codes 134 or 139), or structured crash JSON. Printing "VULNERABILITY TRIGGERED" alone is NOT accepted as proof for native targets.
7. When embedding C source code inside a Python string, ALL C newlines MUST be written as \\n (double-escaped), never as \n (single-escaped). Single-escaped \n inside a Python string literal causes unterminated string literal syntax errors.
8. The exploit_contract.target_entrypoint must be a concise function name, route, or binary path hint, not a prose sentence
9. If the issue is not cleanly mapped to a known taxonomy entry, still produce the best exploit strategy you can
10. Do not use a nonexistent or missing-file path as the final exploit trigger unless the observed vulnerability specifically depends on that condition
11. If the proof plan uses file input, keep the final exploit on file input and do not silently switch to inline eval mode
12. Any inline eval payload must be syntactically valid for the target runtime
13. For multi-file C/C++ projects: when building a standalone harness that calls functions defined in project source files, you MUST compile ALL relevant sibling .c/.cpp files together — not just the file that declares the vulnerable function. Use a glob pattern (e.g. `glob.glob('src/*.c')`) to include all source files automatically. Compiling only one .c file will always produce 'undefined reference' linker errors for any helper function defined in a sibling file.

Respond in JSON only with this exact shape:
{{
  "pov_script": "full {pov_language} script",
  "proof_plan": {{
    "runtime_family": "native|python|node|web|browser|php|ruby|go|unknown",
    "execution_surface": "binary_cli|repo_script|function_call|http_request|browser_dom|docker_runtime",
    "input_mode": "argv|stdin|file|function|request",
    "input_format": "text|json|javascript|python|http|binary",
    "oracle": ["observable proof types such as crash_signal, sanitizer_output, response_marker, dom_execution"],
    "preflight_checks": ["checks that must pass before the exploit is attempted"],
    "binary_candidates": ["candidate executable names when relevant"],
    "fallback_strategies": ["allowed deterministic fallback strategies"]
  }},
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

# Note: POV_GENERATION_PROMPT_OFFLINE and POV_REFINEMENT_PROMPT_OFFLINE raw template strings
# have been removed. Both format_pov_generation_prompt_offline() and
# format_pov_refinement_prompt_offline() are identity aliases that route through
# format_pov_generation_prompt() / format_pov_refinement_prompt() which use the
# structured POV_GENERATION_PROMPT_STRUCTURED / POV_REFINEMENT_PROMPT_STRUCTURED templates.
# Offline vs online differences are handled purely by context compaction in verifier.py.

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

CURRENT RUNTIME / VALIDATION FEEDBACK:
{runtime_feedback}

TASK:
Return a corrected, executable PoV script, an updated exploit contract, and an updated structured proof_plan.
Use the CURRENT RUNTIME / VALIDATION FEEDBACK as binding evidence. Do not repeat a trigger shape, argument structure, route shape, or payload mode that already failed unless the feedback explicitly says it was a harness problem rather than a semantic mismatch.
Do not return failure analysis, prose, or planning notes.
Return only runnable code in the `pov_script` field.

REQUIREMENTS:
1. The response must be JSON only.
2. `pov_script` must contain executable code, not analysis text.
3. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed — never as a standalone self-report without runtime corroboration.
4. The script must explicitly use the exploit contract target entrypoint if one is provided.
5. Prefer deterministic local proof techniques for native targets: controlled inputs, subprocess crash detection, sanitizer evidence, or direct invocation of the vulnerable helper when possible.
6. For native C/C++ targets: the proof MUST produce an observable crash signal — ASan output, SIGSEGV/SIGABRT exit codes (134 or 139), or structured crash JSON. Self-report prints alone will be rejected.
7. When embedding C source code inside a Python string, ALL C newlines MUST be written as \\n (double-escaped). Single-escaped \n inside a Python string literal causes a syntax error.
8. Include concrete success indicators and side effects in the exploit contract.
9. Do not use a nonexistent or missing-file path as the final exploit trigger unless the vulnerability specifically depends on missing-file handling.
10. If the proof plan requires file input, keep the final exploit on file input and do not switch to eval mode.
11. Any inline eval payload must be syntactically valid for the target runtime.
12. If preflight observed supported options, routes, or target surfaces, preserve that observed structure exactly in the next attempt.
13. If the previous failure category was `path_exercised_no_oracle`, keep the same runtime surface but change the payload or trigger logic, not the target shape.
14. If the previous failure category was `guardrail_rejected`, fix the proof-plan contradiction directly instead of inventing a new execution style.
15. For multi-file C/C++ projects: when building a standalone harness that calls functions defined in project source files, you MUST compile ALL relevant sibling .c/.cpp files together. Use a glob pattern (e.g. `glob.glob('src/*.c')`) to collect all source files automatically. If the previous attempt failed with 'undefined reference' errors, adding the missing source files to the compile command is the correct fix — not rewriting the harness logic.

Respond in JSON only with this exact shape:
{{
  "pov_script": "full runnable PoV script",
  "proof_plan": {{
    "runtime_family": "native|python|node|web|browser|php|ruby|go|unknown",
    "execution_surface": "binary_cli|repo_script|function_call|http_request|browser_dom|docker_runtime",
    "input_mode": "argv|stdin|file|function|request",
    "input_format": "text|json|javascript|python|http|binary",
    "oracle": ["observable proof types"],
    "preflight_checks": ["required preflight checks"],
    "binary_candidates": ["candidate executable names when relevant"],
    "fallback_strategies": ["deterministic fallback strategies"]
  }},
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

# Note: POV_REFINEMENT_PROMPT_OFFLINE raw template removed (see POV_GENERATION_PROMPT_OFFLINE note above).

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


POV_GENERATION_PROMPT_STRUCTURED = """You are a security researcher creating a Proof-of-Vulnerability (PoV) script.

INPUT PAYLOAD JSON:
```json
{input_payload}
```

TASK:
Create a {pov_language} PoV, an exploit contract, and a structured proof plan that explains how the proof should work based on observed code and runtime evidence.
The PoV must be runnable in the AutoPoV harness against the real repository or built target. Base the plan on observed sinks, inputs, entrypoints, runtime surfaces, exploit contract details, and runtime feedback from the payload above.
For native C/C++ targets, prefer executing the real built binary or directly invoking the vulnerable helper with deterministic inputs.
Use environment variables like TARGET_BINARY, TARGET_BIN, MQJS_BIN, and CODEBASE_PATH when the exploit needs the built artifact or repository path.

REQUIREMENTS:
0. CRITICAL — DO NOT COMPILE FROM SOURCE FOR NATIVE TARGETS: When `TARGET_BINARY`,
   `probe_binary_name`, or `AUTOPOV_PROBE_BINARY` is present in the payload, the
   prebuilt binary is ALREADY compiled and available at that path. You MUST invoke
   it directly with crafted input. NEVER write gcc / clang / cmake / make / ninja
   compile commands in the PoV script. Compiling from source in the PoV will be
   rejected by the static validator (confidence forced to 0.2).
1. Use only {pov_language} standard library.
2. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed.
3. Include error handling and concrete observable outcome checks.
4. Make the PoV as deterministic as possible.
5. Prefer directly exercising the vulnerable function, route, binary, or code path declared in the payload.
6. For native C/C++ targets: the proof MUST produce an observable crash signal — AddressSanitizer output, SIGSEGV/SIGABRT (exit codes 134 or 139), or structured crash JSON. Printing "VULNERABILITY TRIGGERED" alone is NOT accepted as proof for native targets.
7. When embedding C source code inside a Python string, use a raw triple-quoted string (r\"\"\") or ensure ALL C newlines are written as \\n (double-escaped). A bare newline inside a Python string literal will produce an unterminated C string literal syntax error.
8. The exploit_contract.target_entrypoint must be a concise function name, route, or binary path hint, not prose.
9. If the proof plan uses file input, keep the final exploit on file input and do not silently switch to inline eval mode.
10. Any inline eval payload must be syntactically valid for the target runtime.
11. For multi-file C/C++ projects: when building a standalone harness that calls functions defined in project source files, compile ALL relevant sibling .c/.cpp files together using a glob pattern (e.g. glob.glob('src/*.c')). Compiling only a single .c file produces 'undefined reference' linker errors for any helper in a sibling file.
12. Python scoping: if you assign TARGET_BINARY at module level (e.g. TARGET_BINARY = os.environ.get(...)), you MUST NOT reassign it inside a function without declaring `global TARGET_BINARY` at the top of that function. Failure to do so raises UnboundLocalError at runtime.
13. Return JSON only with the exact response shape described below.

RESPONSE JSON SHAPE:
{{
  "pov_script": "full runnable {pov_language} script",
  "proof_plan": {{
    "runtime_family": "native|python|node|web|browser|php|ruby|go|unknown",
    "execution_surface": "binary_cli|repo_script|function_call|http_request|browser_dom|docker_runtime",
    "input_mode": "argv|stdin|file|function|request",
    "input_format": "text|json|javascript|python|http|binary",
    "oracle": ["observable proof types"],
    "preflight_checks": ["checks that must pass before the exploit is attempted"],
    "binary_candidates": ["candidate executable names when relevant"],
    "fallback_strategies": ["allowed deterministic fallback strategies"]
  }},
  "exploit_contract": {{
    "goal": "one sentence description of what the exploit proves",
    "target_entrypoint": "function, method, route, or code path to exercise",
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

POV_VALIDATION_PROMPT_STRUCTURED = """You are validating a Proof-of-Vulnerability (PoV) script.

INPUT PAYLOAD JSON:
```json
{input_payload}
```

TASK:
Validate the PoV script against the exploit contract and success criteria in the payload.
Return JSON only with this exact shape:
{{
  "is_valid": true or false,
  "issues": ["issue"],
  "suggestions": ["suggestion"],
  "will_trigger": "YES", "MAYBE", or "NO"
}}
"""

RETRY_ANALYSIS_PROMPT_STRUCTURED = """A Proof-of-Vulnerability (PoV) attempt failed.

INPUT PAYLOAD JSON:
```json
{input_payload}
```

TASK:
Analyze why the PoV failed and suggest the next best deterministic change.
Return JSON only with this exact shape:
{{
  "failure_reason": "why it failed",
  "suggested_changes": "specific next change",
  "different_approach": true or false
}}
"""

POV_REFINEMENT_PROMPT_STRUCTURED = """You are fixing a failed Proof-of-Vulnerability (PoV) script.

INPUT PAYLOAD JSON:
```json
{input_payload}
```

TASK:
Return JSON only with a corrected runnable `pov_script`, an updated `proof_plan`, and an updated `exploit_contract`.
Treat the payload as binding evidence. Do not repeat a trigger shape, argument structure, route shape, or payload mode that already failed unless the payload clearly says the failure was caused by harnessing rather than exploit semantics.

REQUIREMENTS:
0. CRITICAL — DO NOT COMPILE FROM SOURCE FOR NATIVE TARGETS: When `TARGET_BINARY`,
   `probe_binary_name`, or `AUTOPOV_PROBE_BINARY` is present in the payload, the
   prebuilt binary is ALREADY compiled and available at that path. You MUST invoke
   it directly with crafted input. NEVER write gcc / clang / cmake / make / ninja
   compile commands in the PoV script. Compiling from source in the PoV will be
   rejected by the static validator (confidence forced to 0.2).
1. `pov_script` must contain executable code, not analysis text.
2. The script must print "VULNERABILITY TRIGGERED" only when the exploit condition is actually observed — never as a standalone self-report.
3. Explicitly use the exploit contract target entrypoint when one is available.
4. Prefer deterministic local proof techniques for native targets.
5. For native C/C++ targets: the proof MUST produce an observable crash signal — ASan output, SIGSEGV/SIGABRT exit codes (134 or 139), or structured crash JSON. Self-report prints alone will be rejected.
6. When embedding C source code inside a Python string, use a raw triple-quoted string (r\"\"\") or ensure ALL C newlines are double-escaped (\\n). A bare newline inside a Python string literal produces an unterminated C string literal syntax error that will prevent the harness from compiling.
7. For multi-file C/C++ projects: compile ALL relevant sibling .c/.cpp files together using a glob (e.g. glob.glob('src/*.c')). Compiling only one .c file produces 'undefined reference' linker errors for any function defined in a sibling file. If the previous attempt failed with 'undefined reference' errors, adding missing source files is the correct fix.
8. Keep the proof aligned with the exploit contract, proof plan, and runtime feedback in the payload.
9. Python scoping: if you assign TARGET_BINARY at module level (e.g. TARGET_BINARY = os.environ.get(...)), you MUST NOT reassign it inside a function (e.g. main()) without declaring `global TARGET_BINARY` at the top of that function. Failure to do so raises UnboundLocalError at runtime.
10. Return JSON only.
"""


def _render_structured_payload(payload: dict) -> str:
    return json.dumps(payload or {}, indent=2, sort_keys=True)


def _build_binary_surface_block(subcommands=None, help_text: str = '', observed_surface: dict = None, setup_requirements: list = None, probe_binary_name: str = '') -> str:
    """Build a BINARY SURFACE section from runtime-discovered data.

    This is injected into every PoV generation and refinement prompt so models
    use real subcommands/flags from the binary rather than guessing or probing
    with --help.  All three sources are combined and de-duplicated:
      1. explicit subcommands list (from contract's known_subcommands)
      2. observed_surface dict (from preflight probe)
      3. help_text string (from preflight --help invocation)
      4. setup_requirements list (bootstrap steps like keygen)
    """
    if observed_surface is None:
        observed_surface = {}

    # Collect subcommands from all available sources
    combined_subcmds: list = list(subcommands or [])
    surface_subcmds = (
        list(observed_surface.get('subcommands') or [])
        + list(observed_surface.get('commands') or [])
    )
    for s in surface_subcmds:
        if s not in combined_subcmds:
            combined_subcmds.append(s)

    # Collect help_text from all sources
    combined_help = (
        str(help_text or '')
        or str(observed_surface.get('help_text') or '')
    ).strip()

    _input_surface = str(observed_surface.get('input_surface') or '').strip()
    # Task 5: if input_surface is unknown/empty but we have help_text, classify it now
    # so the INPUT SURFACE directive is always emitted when help text is available.
    if (not _input_surface or _input_surface == 'unknown') and combined_help:
        try:
            from agents.probe_runner import _classify_input_surface as _cls
            _bin_hint = (
                str(probe_binary_name or '')
                or str(observed_surface.get('probe_binary_name') or '')
                or str(observed_surface.get('binary_name') or '')
            ).strip()
            _derived = _cls(combined_help, _bin_hint)
            if _derived != 'unknown':
                _input_surface = _derived
        except Exception:
            pass

    if not combined_subcmds and not combined_help and not _input_surface:
        # Nothing discovered — fall back to the legacy subcmd-only block if subcommands given
        return ''

    block = "\n\nBINARY SURFACE (discovered at runtime — use this):\n"
    # Inject probe-discovered binary name as explicit TARGET_SYMBOL directive.
    # This is the single most important hint: the model must NOT set TARGET_SYMBOL to a
    # C function name (e.g. 'enchive_decrypt') — it must use the actual executable name.
    _bin_name = (
        str(probe_binary_name or '')
        or str(observed_surface.get('probe_binary_name') or '')
        or str(observed_surface.get('binary_name') or '')
    ).strip()
    # Strip directory prefix if present (e.g. /workspace/codebase/enchive -> enchive)
    if _bin_name and '/' in _bin_name:
        _bin_name = _bin_name.split('/')[-1]
    if _bin_name:
        block += (
            f"BINARY NAME: '{_bin_name}' — this is the name of the compiled executable.\n"
            f"MANDATORY: Set TARGET_SYMBOL = {_bin_name!r} in your PoV script. "
            f"Do NOT set TARGET_SYMBOL to a C function name (e.g. 'enchive_decrypt', "
            f"'agent_addr', 'command_extract'). Use the BINARY name '{_bin_name}'.\n"
        )
    if combined_subcmds:
        block += f"Known subcommands: {', '.join(str(s) for s in combined_subcmds)}\n"
        block += (
            "The first positional argument after the binary MUST be one of these subcommands. "
            "Do NOT pass raw payload bytes, flags, or --help as the first argument.\n"
        )
    if combined_help:
        # Truncate to avoid prompt blowup; 1500 chars covers any normal help output
        block += f"Help output:\n```\n{combined_help[:1500]}\n```\n"
    block += (
        "CRITICAL: Use ONLY these subcommands with REAL INPUT DATA that exercises the "
        "vulnerable code path. Do NOT call the binary with --help, -h, --version, or bare "
        "invocation. Those never trigger crashes."
    )
    # Inject input surface constraint when discovered from probe
    if _input_surface == 'file_argument':
        block += (
            "\n\nINPUT SURFACE: file_argument — this binary reads input from a FILE PATH passed as "
            "a CLI argument (NOT from stdin). "
            "You MUST: (1) write your crafted payload to a temporary file (e.g. /tmp/autopov_payload.bin), "
            "(2) pass the file path as a positional argument: argv = [binary, '/tmp/autopov_payload.bin']. "
            "Do NOT use subprocess.run(argv, input=payload) or pipe bytes to stdin."
        )
    elif _input_surface == 'stdin':
        block += (
            "\n\nINPUT SURFACE: stdin — this binary reads input from stdin. "
            "Pass your crafted payload via subprocess.run(argv, input=payload, capture_output=True). "
            "If payload is bytes, do NOT use text=True."
        )
    elif _input_surface == 'network':
        block += (
            "\n\nINPUT SURFACE: network — this binary is a server. "
            "Start it as a subprocess, then connect to it with a socket and send your crafted payload."
        )
    # Inject repo-derived input format hints if discovered during ingestion
    repo_files = observed_surface.get('repo_sample_files') or []
    repo_exts  = observed_surface.get('repo_input_extensions') or []
    if repo_files or repo_exts:
        block += "\n\nREPO-DERIVED INPUT HINTS (from this repository's own test data):\n"
        if repo_exts:
            block += f"Expected input file extensions: {', '.join(repo_exts)}\n"
        if repo_files:
            block += "Sample test files available in the codebase:\n"
            for rf in repo_files[:8]:  # cap to 8 paths
                block += f"  {rf}\n"
        block += "Use these as a guide for crafting your input payload."
    # Inject structured-format hint when the binary/filepath signals a specific input format.
    # This prevents the model from sending JPEG/PNG binary blobs to XML or JSON parsers.
    _binary_name = str((exploit_contract or {}).get('probe_binary_name') or '').lower()
    _fp_lower = str(filepath or '').lower()
    _XML_SIGNALS = ('xml', 'expat', 'libxml', 'htmlparser', 'xmlwf', 'xmllint', 'tidy', 'pugixml', 'rapidxml', 'minixml', 'mxml')
    _JSON_SIGNALS = ('json', 'cjson', 'jansson', 'parson', 'jsmn', 'ujson', 'jq', 'yajl')
    _HTML_SIGNALS = ('html', 'htmlparser', 'gumbo', 'modest', 'lexbor')
    _CSV_SIGNALS  = ('csv', 'tsv')
    if any(s in _binary_name or s in _fp_lower for s in _XML_SIGNALS):
        block += (
            "\n\nINPUT FORMAT: XML — this parser reads XML. Your payload MUST be syntactically"
            " valid XML that is structurally over-long or contains crafted attribute/element values\n"
            " that exercise the vulnerable code path. Do NOT send JPEG, PNG, or random binary data.\n"
            " Example malicious payloads:\n"
            "  - Deeply nested elements: <a><b><c>...repeat 10000x...</c></b></a>\n"
            "  - Oversized attribute value: <root attr=\"AAA...65536 As...\"/>\n"
            "  - Billion-laughs-style entity expansion (if DTD processing is enabled).\n"
            "  - A valid XML document with a very long text node (b'<r>' + b'A'*131072 + b'</r>').\n"
        )
    elif any(s in _binary_name or s in _fp_lower for s in _JSON_SIGNALS):
        block += (
            "\n\nINPUT FORMAT: JSON — this parser reads JSON. Your payload MUST be JSON text\n"
            " (bytes encoded as UTF-8) that exercises the vulnerable code path.\n"
            " Example: deeply nested arrays, very long string values, or malformed JSON.\n"
            " Do NOT send JPEG, PNG, or random binary data.\n"
        )
    elif any(s in _binary_name or s in _fp_lower for s in _HTML_SIGNALS):
        block += (
            "\n\nINPUT FORMAT: HTML — this parser reads HTML. Your payload must be HTML text.\n"
            " Use oversized attribute values, deeply nested tags, or malformed HTML.\n"
        )
    # Detect key-material bootstrap requirement and inject step-by-step keygen instructions.
    # Triggered when setup_requirements or observed_surface contains a keygen bootstrap signal.
    _all_setup_reqs = list(setup_requirements or []) + list(observed_surface.get('setup_requirements') or [])
    _BOOTSTRAP_SUBCOMMAND_HINTS = {'keygen', 'init', 'setup', 'configure', 'genkey', 'gen-key', 'generate-key', 'generate_key'}
    _needs_bootstrap = (
        any('key material' in str(r).lower() or 'bootstrap key material' in str(r).lower() for r in _all_setup_reqs)
        or bool(combined_subcmds and _BOOTSTRAP_SUBCOMMAND_HINTS & {str(s).lower() for s in combined_subcmds})
    )
    if _needs_bootstrap:
        # Find the bootstrap subcommand name from known subcommands
        _boot_sub = next(
            (str(s) for s in combined_subcmds if str(s).lower() in _BOOTSTRAP_SUBCOMMAND_HINTS),
            'keygen'
        )
        block += (
            f"\n\nKEY MATERIAL BOOTSTRAP REQUIRED: This binary needs a keypair generated BEFORE "
            f"calling archive/extract/decrypt. The harness has already set AUTOPOV_BOOTSTRAP_HOME "
            f"to a writable temp directory. You MUST follow these steps in main():\n"
            f"  Step 1 — set HOME = os.environ.get('AUTOPOV_BOOTSTRAP_HOME') or os.environ.get('HOME')\n"
            f"  Step 2 — run keygen non-interactively:\n"
            f"    import subprocess, os\n"
            f"    keygen_env = dict(os.environ); keygen_env['HOME'] = HOME\n"
            f"    subprocess.run([binary, '{_boot_sub}'], input='autopov\\nautopov\\n', "
            f"capture_output=True, text=True, env=keygen_env)\n"
            f"  Step 3 — run trigger subcommand with the SAME HOME env so it finds the keys:\n"
            f"    trigger_env = dict(os.environ); trigger_env['HOME'] = HOME\n"
            f"    result = subprocess.run([binary, '<trigger_subcommand>', <payload>], "
            f"env=trigger_env, capture_output=True, text=True)\n"
            f"DO NOT skip the keygen step — the trigger will fail with 'failed to open key file' without it."
        )
    # Detect PTY/passphrase requirement and inject a non-interactive invocation hint
    if observed_surface.get('requires_interactive_input') and not _needs_bootstrap:
        block += (
            "\n\nIMPORTANT \u2014 INTERACTIVE INPUT DETECTED: This binary reads a passphrase or PIN "
            "from the terminal (TTY) interactively. A bare subprocess.run() call will hang. "
            "You MUST handle this non-interactively. Options (pick one):\n"
            "  a) subprocess.Popen with stdin=subprocess.PIPE and proc.stdin.write(b'passphrase\\npassphrase\\n')\n"
            "  b) Use the pexpect library: child = pexpect.spawn(...); child.expect('assphrase'); child.sendline('passphrase')\n"
            "  c) Pass --no-agent or equivalent flag if the binary supports it to skip passphrase prompts."
        )
    # Inject entrypoint candidates discovered from code + probe reconnaissance.
    # Shown when the surface block fires so the model can pick the right TARGET_SYMBOL.
    _ep_candidates = observed_surface.get('entrypoint_candidates') or []
    _active_ep = str(observed_surface.get('active_entrypoint') or '').strip()
    if _ep_candidates:
        block += (
            f"\n\nENTRYPOINT CANDIDATES (ranked by confidence, derived from source + probe):\n"
            f"  {', '.join(str(c) for c in _ep_candidates)}\n"
        )
        if _active_ep:
            block += (
                f"ACTIVE TARGET_SYMBOL for this attempt: '{_active_ep}'.\n"
                f"Set TARGET_SYMBOL = {_active_ep!r} in your script.\n"
                "If this entrypoint produces no oracle match, the next candidate will be tried on the following retry."
            )
        else:
            block += (
                f"Set TARGET_SYMBOL to the first candidate that appears in the crash stack trace.\n"
                f"Prefer the first candidate in the list unless a prior attempt proved it wrong."
            )
    return block


def format_pov_generation_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, target_language: str, pov_language: str, exploit_contract=None, runtime_feedback: str = '', subcommands=None, probe_context: str = '', observed_surface: dict = None, joern_context: str = '') -> str:
    payload = {
        'cwe_type': cwe_type or 'UNCLASSIFIED',
        'filepath': filepath,
        'line_number': line_number,
        'target_language': target_language or 'unknown',
        'pov_language': pov_language or 'python',
        'vulnerable_code': vulnerable_code or '',
        'explanation': explanation or '',
        'code_context': code_context or '',
        'exploit_contract': exploit_contract or {},
        'runtime_feedback': runtime_feedback or '',
    }
    if probe_context:
        payload['probe_context'] = probe_context
    if joern_context:
        payload['joern_context'] = joern_context
    # Task 4: if Joern ran but found no taint path, add an advisory note
    if isinstance(exploit_contract, dict) and exploit_contract.get('joern_unreachable'):
        payload['joern_unreachable_note'] = (
            'NOTE: Static taint analysis (Joern CPG) found no data-flow path from '
            'attacker-controlled input to this sink. This may be a false positive. '
            'If generating a PoV, prioritise demonstrating a concrete data-flow path '
            'rather than triggering a crash directly.'
        )
    # Task 5: surface-adaptive notes for every runtime family
    _probe_surface = str((exploit_contract or {}).get('probe_input_surface') or '').strip().lower()
    _probe_surface_type = str((exploit_contract or {}).get('probe_surface_type') or '').strip().lower()
    _probe_entry_cmd = str((exploit_contract or {}).get('probe_entry_command') or '').strip()
    _probe_base_url = str((exploit_contract or {}).get('probe_base_url') or '').strip()
    # JS library
    if _probe_surface == 'function_call' and (target_language or '').lower() in ('javascript', 'typescript', 'node'):
        payload['js_library_note'] = (
            'This is a Node.js LIBRARY target (no HTTP server). The PoV MUST: '
            '1) Use require(process.env.LIB_REQUIRE_PATH || "/workspace/codebase") to load the library. '
            '2) Call the vulnerable function directly with a crafted payload. '
            '3) Detect the vulnerability via uncaught exception, thrown TypeError/RangeError, or non-zero exit. '
            'Do NOT attempt to start a server or make HTTP requests.'
        )
    elif _probe_surface == 'network' and (target_language or '').lower() in ('javascript', 'typescript', 'node'):
        payload['js_server_note'] = (
            'This is a Node.js HTTP SERVER target. The server is auto-started by the harness and '
            'exposed at process.env.APP_URL (default: http://localhost:3000). '
            'The PoV MUST make HTTP requests to APP_URL to trigger the vulnerability.'
        )
    # Task 4A: C library harness hint — when repo_surface_class is library_c or
    # probe_surface_type indicates a pure C library (no CLI entry point), instruct
    # the model to write an inline C harness rather than a file-fuzzer.
    _repo_surface_cls = str((exploit_contract or {}).get('repo_surface_class') or '').strip().lower()
    _lib_api_ctx = str((exploit_contract or {}).get('library_api_context') or '').strip()
    _probe_sfc = str((exploit_contract or {}).get('probe_surface_type') or '').strip().lower()
    if _repo_surface_cls == 'library_c' or _probe_sfc == 'c_library':
        _api_hint = f'\nKnown public API functions:\n{_lib_api_ctx}' if _lib_api_ctx else ''
        payload['c_library_harness_note'] = (
            'This target is a C LIBRARY — it has no CLI entry point. '
            'The PoV MUST write an inline C harness program that:\n'
            '  1) #includes the library header (search /workspace/codebase for .h files).\n'
            '  2) Calls one or more public API functions with a crafted/malformed payload.\n'
            '  3) Compiles the harness with ASan: '
            'clang -fsanitize=address,undefined -O0 -g harness.c -I/workspace/codebase '
            '-L/workspace/codebase -Wl,-rpath,/workspace/codebase -l<libname> -o /tmp/harness.\n'
            '  4) Runs /tmp/harness and checks for ASan output or non-zero exit.\n'
            'Set execution_surface="c_library_harness" in the exploit_contract.\n'
            'Do NOT invoke a binary with a file argument — there is no binary.'
            + _api_hint
        )

    # Python module / web service surface hints
    if _probe_surface_type == 'python_module':
        _entry_hint = f'Use `{_probe_entry_cmd}` or' if _probe_entry_cmd else 'Use'
        payload['python_module_note'] = (
            f'This is a Python PACKAGE target. {_entry_hint} '
            'os.environ.get("AUTOPOV_ENTRY") for the entry command. '
            'Import the package directly and call the vulnerable function; '
            'detect the vulnerability via uncaught exception or non-zero exit. '
            'Set execution_surface="repo_script" in the exploit_contract.'
        )
    elif _probe_surface_type == 'web_service':
        _url_hint = _probe_base_url or 'http://localhost:8000'
        payload['web_service_note'] = (
            f'This is a Python WEB SERVICE target. The harness auto-starts it at {_url_hint} '
            '(also available as os.environ.get("AUTOPOV_BASE_URL")). '
            'The PoV MUST make HTTP requests to that base URL to trigger the vulnerability. '
            'Set execution_surface="http_request" in the exploit_contract.'
        )
    base = POV_GENERATION_PROMPT_STRUCTURED.format(pov_language=pov_language or 'python', input_payload=_render_structured_payload(payload))
    _probe_bin_name = str((exploit_contract or {}).get('probe_binary_name') or '').strip()
    surface_block = _build_binary_surface_block(
        subcommands=subcommands,
        observed_surface=observed_surface or {},
        probe_binary_name=_probe_bin_name,
    )
    if surface_block:
        base = base.rstrip() + surface_block
    return base


def format_pov_generation_prompt_offline(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, target_language: str, pov_language: str, exploit_contract=None, runtime_feedback: str = '', probe_context: str = '') -> str:
    return format_pov_generation_prompt(cwe_type, filepath, line_number, vulnerable_code, explanation, code_context, target_language, pov_language, exploit_contract=exploit_contract, runtime_feedback=runtime_feedback, probe_context=probe_context)


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
    payload = {
        'pov_script': pov_script or '',
        'cwe_type': cwe_type or 'UNCLASSIFIED',
        'filepath': filepath,
        'line_number': line_number,
        'exploit_goal': derived_goal,
        'success_indicators': indicators,
        'exploit_contract': contract,
    }
    return POV_VALIDATION_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))


def format_pov_validation_prompt_offline(pov_script: str, cwe_type: str, filepath: str, line_number: int, exploit_goal: str = '', success_indicators: str = '', exploit_contract=None) -> str:
    return format_pov_validation_prompt(pov_script, cwe_type, filepath, line_number, exploit_goal=exploit_goal, success_indicators=success_indicators, exploit_contract=exploit_contract)


def format_retry_analysis_prompt(cwe_type: str, filepath: str, line_number: int, explanation: str, failed_pov: str, execution_output: str, attempt_number: int, max_retries: int) -> str:
    payload = {
        'cwe_type': cwe_type or 'UNCLASSIFIED',
        'filepath': filepath,
        'line_number': line_number,
        'explanation': explanation or '',
        'failed_pov': failed_pov or '',
        'execution_output': execution_output or '',
        'attempt_number': attempt_number,
        'max_retries': max_retries,
    }
    return RETRY_ANALYSIS_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))


def format_retry_analysis_prompt_offline(cwe_type: str, filepath: str, line_number: int, explanation: str, failed_pov: str, execution_output: str, attempt_number: int, max_retries: int) -> str:
    return format_retry_analysis_prompt(cwe_type, filepath, line_number, explanation, failed_pov, execution_output, attempt_number, max_retries)


def format_pov_refinement_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, failed_pov: str, validation_errors, attempt_number: int, target_language: str = 'python', exploit_contract=None, runtime_feedback: str = '', subcommands=None, probe_context: str = '', observed_surface: dict = None) -> str:
    payload = {
        'cwe_type': cwe_type or 'UNCLASSIFIED',
        'filepath': filepath,
        'line_number': line_number,
        'target_language': target_language or 'python',
        'vulnerable_code': vulnerable_code or '',
        'explanation': explanation or '',
        'code_context': code_context or '',
        'failed_pov': failed_pov or '',
        'validation_errors': list(validation_errors or []),
        'attempt_number': attempt_number,
        'exploit_contract': exploit_contract or {},
        'runtime_feedback': runtime_feedback or '',
    }
    if probe_context:
        payload['probe_context'] = probe_context
    base = POV_REFINEMENT_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))
    # Task 5: surface-adaptive hints for refinement (same logic as generation)
    _probe_surface_type = str((exploit_contract or {}).get('probe_surface_type') or '').strip().lower()
    _probe_entry_cmd = str((exploit_contract or {}).get('probe_entry_command') or '').strip()
    _probe_base_url = str((exploit_contract or {}).get('probe_base_url') or '').strip()
    # Task 4A (refinement): C library harness hint
    _repo_surface_cls_r = str((exploit_contract or {}).get('repo_surface_class') or '').strip().lower()
    _lib_api_ctx_r = str((exploit_contract or {}).get('library_api_context') or '').strip()
    _probe_sfc_r = str((exploit_contract or {}).get('probe_surface_type') or '').strip().lower()
    if _repo_surface_cls_r == 'library_c' or _probe_sfc_r == 'c_library':
        _api_hint_r = f'\nKnown public API functions:\n{_lib_api_ctx_r}' if _lib_api_ctx_r else ''
        payload['c_library_harness_note'] = (
            'This target is a C LIBRARY — it has no CLI entry point. '
            'The PoV MUST write an inline C harness program that calls the vulnerable API '
            'with ASan enabled (clang -fsanitize=address,undefined).\n'
            'Set execution_surface="c_library_harness" in the exploit_contract.'
            + _api_hint_r
        )
        base = POV_REFINEMENT_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))
    if _probe_surface_type == 'python_module':
        _entry_hint = f'Use `{_probe_entry_cmd}` or' if _probe_entry_cmd else 'Use'
        payload['python_module_note'] = (
            f'This is a Python PACKAGE target. {_entry_hint} '
            'os.environ.get("AUTOPOV_ENTRY") for the entry command. '
            'Import the package directly and call the vulnerable function; '
            'detect the vulnerability via uncaught exception or non-zero exit. '
            'Set execution_surface="repo_script" in the exploit_contract.'
        )
        # Rebuild base with surface note now in payload
        base = POV_REFINEMENT_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))
    elif _probe_surface_type == 'web_service':
        _url_hint = _probe_base_url or 'http://localhost:8000'
        payload['web_service_note'] = (
            f'This is a Python WEB SERVICE target. The harness auto-starts it at {_url_hint} '
            '(also available as os.environ.get("AUTOPOV_BASE_URL")). '
            'The PoV MUST make HTTP requests to that base URL to trigger the vulnerability. '
            'Set execution_surface="http_request" in the exploit_contract.'
        )
        base = POV_REFINEMENT_PROMPT_STRUCTURED.format(input_payload=_render_structured_payload(payload))
    _probe_bin_name = str((exploit_contract or {}).get('probe_binary_name') or '').strip()
    surface_block = _build_binary_surface_block(
        subcommands=subcommands,
        observed_surface=observed_surface or {},
        probe_binary_name=_probe_bin_name,
    )
    if surface_block:
        base = base.rstrip() + surface_block
    return base


def format_pov_refinement_prompt_offline(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, failed_pov: str, validation_errors, attempt_number: int, target_language: str = 'python', exploit_contract=None, runtime_feedback: str = '', probe_context: str = '') -> str:
    return format_pov_refinement_prompt(cwe_type, filepath, line_number, vulnerable_code, explanation, code_context, failed_pov, validation_errors, attempt_number, target_language=target_language, exploit_contract=exploit_contract, runtime_feedback=runtime_feedback, probe_context=probe_context)


def format_rag_context_prompt(primary_code: str, related_chunks: str) -> str:
    return RAG_CONTEXT_PROMPT.format(
        primary_code=primary_code or '',
        related_chunks=related_chunks or '[No related chunks available]'
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


# ---------------------------------------------------------------------------
# Scaffold PoV generation prompt (JSON-first, used for offline and online)
# ---------------------------------------------------------------------------

_POV_SCAFFOLD_BODY = '''\
You are a security researcher writing a proof-of-vulnerability (PoV) script.

VULNERABILITY CONTEXT:
  File:           {filepath}
  Line:           {line_number}
  Target runtime: {target_language}
  Entrypoint:     {target_entrypoint}
  Explanation:    {explanation}

OBSERVED SUBCOMMANDS (use one as first positional arg after binary):
{subcommands_line}

OBSERVED FLAGS / OPTIONS:
{surface_options}

EXPLOIT CONTRACT SUMMARY:
{exploit_contract_summary}

STEP 1 — Output a JSON proof plan inside ```json ... ``` fences.  All fields required.
{{
  "target_binary":        "<exact binary filename — no paths, no placeholders>",
  "target_entrypoint":    "{target_entrypoint}",
  "subcommand":           "<CLI subcommand or null>",
  "argv":                 ["<arg1>", "<arg2>"],
  "stdin_payload":        "<content or null>",
  "files_to_create":      [{{"name": "<filename>", "content": "<content>"}}],
  "environment":          {{}},
  "expected_oracle":      "<exact string you expect in stderr — from sanitizer or crash>",
  "why_this_hits_target": "<one sentence: how argv/payload reaches {target_entrypoint}>"
}}

STEP 2 — Write the Python PoV script that implements the plan exactly.

CONSTRAINTS:
- target_entrypoint MUST be: {target_entrypoint}
- When OBSERVED SUBCOMMANDS are listed, the first positional argument MUST be one of them.
- Only use flags/subcommands listed in OBSERVED SUBCOMMANDS and OBSERVED FLAGS / OPTIONS above.
- Do not invent flags.  Do not use placeholder paths.
- expected_oracle must be a real crash/sanitizer string, not "VULNERABILITY TRIGGERED".
- Python scoping: if TARGET_BINARY is assigned at module level, do NOT reassign it inside main() without `global TARGET_BINARY`.
- Output only the JSON block and the script.  No prose explanation.
- main() MUST perform the actual exploit steps: build the argument vector, create any required files, and run the binary with the correct subcommand and arguments.
- A main() that only calls subprocess.run([binary]) with no subcommand or arguments is WRONG — it will just print the help page and fail.
- If a subcommand is listed in OBSERVED SUBCOMMANDS, it MUST appear as the first positional argument in the subprocess.run() call.
- Do NOT emit the comment "# no subcommand known".
- When a SETUP step (keygen, archive creation, compile, etc.) crashes with a sanitizer
  signal, write the captured stderr to sys.stderr BEFORE printing "VULNERABILITY TRIGGERED".
  Example pattern: sys.stderr.write(decode(se)); print("VULNERABILITY TRIGGERED"); return
- Do NOT silently swallow sanitizer output from setup steps. The harness oracle needs the
  raw sanitizer text (AddressSanitizer / UndefinedBehaviorSanitizer / runtime error:) to
  corroborate the self-report string and avoid classifying the result as non_evidence.
'''

_POV_SCAFFOLD_OFFLINE_ADDENDUM = '''
ADDITIONAL OFFLINE CONSTRAINTS:
- Output ONLY the ```json proof-plan block followed by the Python script block.
- Do NOT output any reasoning, explanation, preamble, or <think> tags.
- Do not rewrite the approach.  Fill the plan fields, then render the script.
- If you are unsure of a field, use null -- do not guess.
- Script must be between 40 and 100 lines. A script shorter than 40 lines cannot contain the required build step, binary invocation, and crash detection — do not produce a stub.
- Do NOT leave main() as a stub. Write out the complete exploit invocation with the correct subcommand and arguments.
- A main() function with only subprocess.run([binary]) or subprocess.run([binary, 'archive', '--help']) is a stub and will fail. main() MUST: (1) invoke the binary with the correct subcommand and a crafted exploit payload, (2) check the exit code and stderr for crash signals, (3) print "VULNERABILITY TRIGGERED" ONLY when a crash or sanitizer output is observed.
- If a setup step (keygen, compile, archive) crashes with a sanitizer signal, write its
  stderr to sys.stderr before printing VULNERABILITY TRIGGERED and returning.
- EXPLOIT PAYLOAD PRECISION: The stdin_payload and argv fields in the JSON plan MUST contain
  concrete malicious bytes/strings — NOT a description of what to put there. For example:
    WRONG:  "stdin_payload": "a string longer than the buffer"
    CORRECT: "stdin_payload": "A" * 512  (or the literal oversized string)
  The PoV script must construct the exact overflowing/malformed payload at runtime,
  not rely on the binary happening to crash with an empty input.
- For CWE-120 / CWE-787 / CWE-125 (buffer overflow/OOB): the payload MUST be larger than
  the vulnerable buffer. Use at least 512 bytes for unknown buffer sizes.
- For CWE-476 (null deref): trigger the code path that dereferences null — usually by
  passing a specially crafted input that reaches the vulnerable line.
- For CWE-401 (memory leak): trigger repeated allocation without free — run the binary in
  a loop or pass input that exercises the leaky code path multiple times.
- Do NOT print "VULNERABILITY TRIGGERED" unless stderr or stdout contains one of:
  AddressSanitizer, UndefinedBehaviorSanitizer, runtime error:, SIGSEGV, Segmentation fault,
  double free, heap-buffer-overflow, stack-buffer-overflow, use-after-free, abort
'''

_POV_SCAFFOLD_C_HARNESS_ADDENDUM = '''
C/C++ HARNESS REQUIREMENT:
This vulnerability is in a compiled C/C++ binary. Your PoV script MUST:
1. Compile a small C exploit harness (or use gcc/clang directly) with -fsanitize=address,undefined.
   Alternatively, invoke the pre-built binary with a crafted payload if the binary is already present.
2. The harness MUST pass a payload that overflows the specific vulnerable buffer identified above.
3. Check for AddressSanitizer / UBSan output in stderr — that is your crash oracle.
4. Do NOT rely on the Python script alone to crash a C program — C programs need oversized
   inputs, not generic test data.
5. If writing a C harness, write it as a string to a .c file, compile it, then run it.
   Example pattern:
     c_src = r\'\'\'\nint main(){char buf[32]; memset(buf,'A',512); ...}\n\'\'\'
     with open(\'harness.c\', \'w\') as f: f.write(c_src)
     subprocess.run([\'gcc\',\'-fsanitize=address\',\'-o\'\'/tmp/harness\',\'harness.c\'])
     result = subprocess.run([\'./harness\'], capture_output=True)
'''



def format_pov_scaffold_prompt(
    filepath: str,
    line_number: int,
    explanation: str,
    target_language: str,
    target_entrypoint: str,
    exploit_contract=None,
    surface_options=None,
    subcommands=None,
    offline: bool = False,
    observed_surface: dict = None,
) -> str:
    """Scaffold PoV generation prompt: JSON proof plan first, then script.

    Used for both online and offline models.  When offline=True the tighter
    constraint addendum is appended to reduce improvisation.
    """
    import json as _json
    contract = exploit_contract or {}
    contract_summary_lines = []
    for key in ('runtime_profile', 'execution_surface', 'target_entrypoint', 'target_binary',
                'success_indicators', 'expected_outcome'):
        val = contract.get(key)
        if val:
            contract_summary_lines.append(f'  {key}: {_json.dumps(val)}')
    contract_summary = '\n'.join(contract_summary_lines) or '  (no contract fields available)'

    options_text = '  (no surface options observed)'
    if surface_options:
        options_text = '\n'.join(f'  {o}' for o in surface_options)

    if subcommands:
        subcommands_text = '  ' + ', '.join(str(s) for s in subcommands)
    else:
        subcommands_text = '  (none observed -- subcommand may not be required)'

    body = _POV_SCAFFOLD_BODY.format(
        filepath=filepath or 'unknown',
        line_number=line_number or 0,
        target_language=target_language or 'c',
        target_entrypoint=target_entrypoint or 'unknown',
        explanation=(explanation or '').strip(),
        surface_options=options_text,
        subcommands_line=subcommands_text,
        exploit_contract_summary=contract_summary,
    )
    if offline:
        body = body + _POV_SCAFFOLD_OFFLINE_ADDENDUM
    # For C/C++ targets add the harness compilation guidance regardless of online/offline
    if (target_language or '').lower() in ('c', 'cpp', 'c++'):
        body = body + _POV_SCAFFOLD_C_HARNESS_ADDENDUM
    # Append binary surface block (help_text + subcommands) so model uses real invocations
    surface_block = _build_binary_surface_block(
        subcommands=subcommands,
        observed_surface=observed_surface or {},
    )
    if surface_block:
        body = body.rstrip() + surface_block
    return body


# ---------------------------------------------------------------------------
# Constrained retry prompt (patch-style, shrinking latitude on attempt >= 2)
# ---------------------------------------------------------------------------

_RETRY_CONSTRAINED_BODY = '''\
A previous PoV attempt failed.  Fix ONLY the listed issues.  Do not rewrite anything else.

PREVIOUS SCRIPT:
```python
{failed_pov}
```

FAILURE REASON(S):
{required_changes}

EXACT ERROR OUTPUT:
{exact_error}

Rules:
- Change ONLY the lines that caused the listed failures.
- Keep the overall approach, binary, and subcommand identical.
- Output only the corrected Python script.  No explanation.
'''


def format_retry_constrained_prompt(
    failed_pov: str,
    exact_error: str,
    required_changes,
) -> str:
    """Constrained patch-style retry prompt used on attempt >= 2.

    required_changes can be a list of strings or a single string.
    """
    if isinstance(required_changes, (list, tuple)):
        changes_text = '\n'.join(f'- {c}' for c in required_changes if str(c).strip())
    else:
        changes_text = str(required_changes or '')
    return _RETRY_CONSTRAINED_BODY.format(
        failed_pov=failed_pov or '',
        required_changes=changes_text or '(see exact error output)',
        exact_error=exact_error or '(no error output captured)',
    )


__all__ = [
    'format_pov_scaffold_prompt',
    'format_retry_constrained_prompt',
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


