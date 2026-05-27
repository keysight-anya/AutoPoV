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

{recon_context}

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
    "explanation": "A concrete description of: (1) what the vulnerability is and where it occurs, (2) how an attacker could exploit it with a specific attack scenario, and (3) what the observable outcome or impact would be. Reference actual variable names, function names, and code paths from the CODE CONTEXT.",
    "vulnerable_code": "Copy-paste the EXACT source code lines from the CODE CONTEXT above that contain the vulnerability. This MUST be actual source code, NOT a description or summary. Extract the relevant lines verbatim.",
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

PROOF_NARRATIVE_PROMPT = """You are a security analyst writing a post-mortem exploit narrative for a confirmed vulnerability.

VULNERABILITY:
- Classification: {cwe_type}
- File: {filepath}:{line_number}
- Vulnerable code:
```
{vulnerable_code}
```

INVESTIGATION FINDING:
{investigation_explanation}

PROOF-OF-VULNERABILITY SCRIPT (excerpt):
```python
{pov_script_excerpt}
```

RUNTIME EXECUTION RESULTS:
- Exit code: {exit_code}
- Oracle verdict: {oracle_reason}
- Evidence markers: {matched_markers}
- Stdout (last 500 chars):
{stdout_excerpt}
- Stderr (last 300 chars):
{stderr_excerpt}

TASK:
Write a single paragraph of dense, technical prose (150-250 words). The paragraph must follow this logical structure as a continuous narrative — no bullet points, no lists, no headers:

1. Start with what was identified: the specific vulnerability in the specific function/code location, referencing actual variable names and code constructs.
2. Describe what the automated proof system did: how the PoV script exercised the vulnerable path, what input was crafted, and what operations were performed.
3. State the observed outcome: what the runtime execution actually produced as evidence — reference concrete output from stdout/stderr, exit codes, or filesystem state changes.
4. Conclude with what this means for an attacker: since the system demonstrated the exploit end-to-end, state the real-world attack surface this opens.

IMPORTANT:
- Describe what DID happen, not what COULD happen. You have the actual runtime evidence above.
- Reference specific function names, variable names, file paths, and output strings from the provided data.
- Do NOT use phrases like "could potentially", "may allow", "might lead to". Use past tense: "was exploited", "produced", "demonstrated", "resulted in".
- Keep it as one dense paragraph.
- Do NOT wrap in JSON, do NOT use keys like "vulnerability" or "proof". Just output the raw paragraph text.
- Do NOT use markdown formatting, headers, or bullet points.

Respond with ONLY the paragraph text — a single block of prose, nothing else.
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

TARGET TYPE GUIDANCE:
- For WEB APPLICATION targets (execution_surface is http_request, web, rest_api, or browser_dom): Do NOT use TARGET_BINARY or subprocess. Instead, use Python 'requests' library to send HTTP requests. The target URL is available via os.environ.get('AUTOPOV_TARGET_URL') or os.environ.get('TARGET_URL', 'http://localhost:3000'). The server is auto-started before your script runs.
- For NATIVE BINARY targets (execution_surface is binary_cli): Use os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') to get the binary path. Do NOT use requests or HTTP calls.
- For LIBRARY/FUNCTION targets (execution_surface is function_call or repo_script): Use require()/import to load the library directly and call the vulnerable function.

REQUIREMENTS:
1. Use only {pov_language} standard library
2. Print the SPECIFIC behavioral marker for the vulnerability type (listed in observable_evidence) when the exploit condition is observed. Do NOT print generic "VULNERABILITY TRIGGERED" — the oracle treats it as self-report. Examples: XSS_CONFIRMED, PROTOTYPE_POLLUTED, RESOURCE_EXHAUSTION, UNAUTHORIZED_ACCESS_GRANTED, EXCEPTION_TRIGGERED
3. Include error handling
4. Make the PoV as deterministic as possible
5. Prefer directly exercising the vulnerable function, route, binary, or code path
6. For native C/C++ targets:
   - If the exploit contract's proof_category is "crash" (memory corruption): the proof MUST produce an observable crash signal — AddressSanitizer output, SIGSEGV/SIGABRT (exit codes 134 or 139), or structured crash JSON. Printing "VULNERABILITY TRIGGERED" alone is NOT accepted.
   - If proof_category is "behavioral" (logic/design bug): the proof must include POST-EXECUTION VERIFICATION — after invoking the binary, check filesystem state, file permissions, or output content. Print structured evidence markers (e.g. "FILE_CREATED_OUTSIDE_ALLOWED_DIR:/path", "INSECURE_PERMISSION:0o666", "SENSITIVE_DATA_LEAKED") that the oracle can detect. Do NOT expect or rely on crash signals.
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
2. Prints a specific behavioral marker (e.g. XSS_CONFIRMED, PROTOTYPE_POLLUTED, RESOURCE_EXHAUSTION) or produces crash/sanitizer evidence when the vulnerability is triggered. Do NOT use generic "VULNERABILITY TRIGGERED".
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
3. Print the SPECIFIC behavioral marker for the vulnerability type (listed in observable_evidence) when the exploit condition is observed. Do NOT print generic "VULNERABILITY TRIGGERED" — the oracle treats it as self-report. For crash proof types, the sanitizer/crash output IS the evidence.
4. The script must explicitly use the exploit contract target entrypoint if one is provided.
5. Prefer deterministic local proof techniques for native targets: controlled inputs, subprocess crash detection, sanitizer evidence, or direct invocation of the vulnerable helper when possible.
6. For native C/C++ targets:
   - If the exploit contract's proof_category is "crash": the proof MUST produce an observable crash signal — ASan output, SIGSEGV/SIGABRT exit codes (134 or 139). Self-report prints alone will be rejected.
   - If proof_category is "behavioral": include POST-EXECUTION VERIFICATION — check filesystem state, permissions, or output content after invoking the binary. Print structured evidence markers. Do NOT expect crash signals.
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


def format_investigation_prompt(code_context: str, cwe_type: str, filepath: str, line_number: int, alert_message: str, joern_context: str = "", recon_report: dict = None, is_benchmark_case: bool = False, benchmark_family: str = '') -> str:
    # Build recon context block so the investigation LLM knows what kind of
    # project this is, what attack surfaces exist, and what input formats to expect.
    recon_context = ''
    if recon_report:
        _rc_lines = ['REPOSITORY INTELLIGENCE (from reconnaissance):']
        if recon_report.get('project_type'):
            _rc_lines.append(f'- Project type: {recon_report["project_type"]}')
        if recon_report.get('runtime_family'):
            _rc_lines.append(f'- Runtime family: {recon_report["runtime_family"]}')
        if recon_report.get('repo_surface_class') and recon_report['repo_surface_class'] != 'unknown':
            _rc_lines.append(f'- Repo surface class: {recon_report["repo_surface_class"]}')
        if recon_report.get('attack_surfaces'):
            _atk = recon_report['attack_surfaces'][:5]
            _rc_lines.append(f'- Attack surfaces: {json.dumps(_atk)}')
        if recon_report.get('framework_hints'):
            _rc_lines.append(f'- Frameworks: {", ".join(recon_report["framework_hints"][:5])}')
        if recon_report.get('input_format_hints'):
            _rc_lines.append(f'- Input format hints: {", ".join(str(h) for h in recon_report["input_format_hints"][:5])}')
        if recon_report.get('entrypoints'):
            _eps = recon_report['entrypoints'][:5]
            _ep_names = [str(ep.get('name', '')) for ep in _eps if ep.get('name')]
            if _ep_names:
                _rc_lines.append(f'- Known entry points: {", ".join(_ep_names)}')
        if recon_report.get('build_system'):
            _rc_lines.append(f'- Build system: {recon_report["build_system"]}')
        if len(_rc_lines) > 1:
            recon_context = '\n'.join(_rc_lines)
    return INVESTIGATION_PROMPT.format(
        code_context=code_context,
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath,
        line_number=line_number,
        alert_message=alert_message or 'Candidate security signal',
        joern_context=joern_context or '',
        recon_context=recon_context,
    )


POV_GENERATION_PROMPT_STRUCTURED = """You are a security researcher creating a Proof-of-Vulnerability (PoV) script.

{priority_sections}

TASK:
Create a {pov_language} PoV, an exploit contract, and a structured proof plan that explains how the proof should work based on observed code and runtime evidence.
The PoV must be runnable in the AutoPoV harness against the real repository or built target. Base the plan on observed sinks, inputs, entrypoints, and runtime surfaces above.
For native C/C++ targets, prefer executing the real built binary or directly invoking the vulnerable helper with deterministic inputs.
Use environment variables like TARGET_BINARY, TARGET_BIN, MQJS_BIN, and CODEBASE_PATH when the exploit needs the built artifact or repository path.

HARNESS TYPE GUIDANCE:
If the payload contains a `proof_strategy` block, use it to guide your proof approach:
- `proof_type` tells you what kind of evidence to produce (crash, exception, timing, state change, etc.)
- `harness_type` tells you the execution approach (subprocess, direct import, HTTP, threaded, etc.)
- `observable_evidence` lists the exact strings/patterns that must appear in output to confirm the vulnerability
- `verification_method` describes how to ensure the evidence is genuine
Your PoV MUST produce the evidence described in `observable_evidence`. Do NOT fall back to generic
"VULNERABILITY TRIGGERED" prints unless the proof_type is crash_signal.

HARNESS TEMPLATES BY TYPE:
When `harness_type` is one of the following, model your PoV on the corresponding template:

  threaded_race (for race conditions / TOCTOU / concurrent access):
    import threading, time
    RACE_DETECTED = False
    def racer(target_func, args):
        global RACE_DETECTED
        try:
            result = target_func(*args)
            # check for corruption / unexpected state
        except Exception:
            RACE_DETECTED = True
    threads = [threading.Thread(target=racer, args=(vuln_func, payload)) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    if RACE_DETECTED:
        print("TIMING_ANOMALY")

  resource_exhaustion (for DoS / ReDoS / memory bomb / CPU bomb):
    import time, resource
    start = time.monotonic()
    try:
        result = target_func(malicious_input)  # e.g. catastrophic regex, zip bomb, recursive parse
    except (MemoryError, RecursionError):
        print("RESOURCE_EXHAUSTION")
    elapsed = time.monotonic() - start
    if elapsed > THRESHOLD_SECONDS:
        print(f"RESOURCE_EXHAUSTION: {{elapsed:.2f}}s")

  timing_difference (for timing side-channels / timing oracle):
    import time, statistics
    def measure(input_val, iterations=50):
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            target_func(input_val)
            times.append(time.perf_counter() - start)
        return statistics.median(times)
    t_correct = measure(correct_prefix_input)
    t_wrong = measure(wrong_prefix_input)
    ratio = t_correct / max(t_wrong, 1e-9)
    if ratio > 1.5:  # measurable timing difference
        print(f"TIMING_ANOMALY: ratio={{ratio:.2f}}")

  compiled_harness (for C/C++ library targets — compile a small driver):
    # Build a minimal C harness that calls the vulnerable function:
    harness_src = r\"\"\"
    #include "vulnerable_header.h"
    int main(int argc, char **argv) {{
        unsigned char buf[4096];
        FILE *f = fopen(argv[1], "rb");
        size_t n = fread(buf, 1, sizeof(buf), f);
        vulnerable_function(buf, n);  // should trigger ASan
        return 0;
    }}
    \"\"\"
    # Compile with: gcc -fsanitize=address -g harness.c -I$CODEBASE_PATH -L$LIB_DIR -lvuln -o harness

LANGUAGE-SPECIFIC HARNESS NOTES:
- Python: use `import` + direct function call. The codebase is pip-installed into the container.
  Access via `from package.module import vulnerable_function` or `import package`.
  Environment: CODEBASE_PATH=/workspace/codebase, packages installed from requirements.txt.
- Node.js: use `require()` or dynamic `import()`. The codebase is npm-installed.
  Access via `const pkg = require('/workspace/codebase')` or `require('/workspace/codebase/lib/vulnerable')`.
  Environment: NODE_PATH=/workspace/codebase/node_modules, LIB_REQUIRE_PATH=/workspace/codebase.
- Java: compile a .java harness that imports the vulnerable class.
  The target jar is at $TARGET_BINARY, classpath at $CLASSPATH.
  Use: `javac -cp $CLASSPATH Harness.java && java -cp .:$CLASSPATH Harness`
- Native C/C++: prefer invoking the pre-built binary via subprocess.
  Binary at $TARGET_BINARY or $AUTOPOV_PROBE_BINARY. Do NOT recompile unless harness_type=compiled_harness.
  MANDATORY scaffold for native targets:
    import os, subprocess, sys, tempfile
    TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN', '')
    CODEBASE_PATH = os.environ.get('CODEBASE_PATH', '/workspace/codebase')
    def main():
        binary = TARGET_BINARY  # local alias — do NOT reassign TARGET_BINARY here
        if not binary or not os.path.isfile(binary):
            print(f'binary not found: {{binary!r}}', file=sys.stderr); sys.exit(1)
        # ... build payload, write to temp file ...
        result = subprocess.run([binary, payload_path], capture_output=True, timeout=30)
        stderr_text = result.stderr.decode('utf-8', errors='replace')
        if result.returncode in (134, 139) or 'AddressSanitizer' in stderr_text:
            print(stderr_text)
            # For native crash targets, the ASan/crash output IS the proof.
            # Optionally print a specific marker: EXCEPTION_TRIGGERED for unhandled crashes
    if __name__ == '__main__':
        main()
  WRONG (causes UnboundLocalError — NEVER do this):
    def main():
        TARGET_BINARY = os.environ.get('TARGET_BINARY')  # WRONG! Shadows module-level var
- JavaScript/TypeScript (Python PoV): do NOT use TARGET_BINARY or subprocess with a binary.
  Instead, write a .js exploit file and run it with node:
    import os, subprocess, sys
    CODEBASE_PATH = os.environ.get('CODEBASE_PATH', '/workspace/codebase')
    def main():
        exploit_code = '''const vuln = require(process.env.CODEBASE_PATH || '/workspace/codebase');
    // ... trigger vulnerability ...
    '''
        result = subprocess.run(['node', '-e', exploit_code],
            capture_output=True, timeout=30,
            env={{**os.environ, 'NODE_PATH': os.path.join(CODEBASE_PATH, 'node_modules')}})
    if __name__ == '__main__':
        main()
- Web applications (HTTP targets): use Python `requests` library to send HTTP requests.
  Target URL at os.environ.get('AUTOPOV_TARGET_URL') or os.environ.get('TARGET_URL', 'http://localhost:3000').
  The server is auto-started before your script runs. Do NOT use subprocess or TARGET_BINARY.

  http_request (for web application SQL injection, XSS, auth bypass, SSRF, etc.):
    import requests, os
    TARGET = os.environ.get('AUTOPOV_TARGET_URL') or os.environ.get('TARGET_URL', 'http://localhost:3000')
    session = requests.Session()
    # Example: SQL injection
    payload = {{"username": "admin' OR '1'='1", "password": "anything"}}
    r = session.post(f"{{TARGET}}/api/login", json=payload)
    if r.status_code == 200 and ('token' in r.text.lower() or 'admin' in r.text.lower()):
        print("UNAUTHORIZED_ACCESS_GRANTED")
    # Example: XSS reflection
    xss = '<script>alert(1)</script>'
    r = session.get(f"{{TARGET}}/search?q={{xss}}")
    if xss in r.text:
        print("XSS_CONFIRMED")

REQUIREMENTS:
0. CRITICAL — DO NOT COMPILE FROM SOURCE FOR NATIVE TARGETS: When `TARGET_BINARY`,
   `probe_binary_name`, or `AUTOPOV_PROBE_BINARY` is present in the payload, the
   prebuilt binary is ALREADY compiled with ASan and available at that path. You MUST invoke
   it directly with crafted input. NEVER write gcc / clang / cmake / make / ninja / meson / bazel
   compile commands in the PoV script. NEVER use subprocess.run/call/Popen with gcc/clang/cmake/make.
   NEVER use os.system("gcc ...") or os.popen("gcc ..."). NEVER use shutil.which("gcc").
   NEVER write .c/.cpp files and compile them. Compiling from source in the PoV will be
   STRIPPED by the pre-execution rewriter and REJECTED by the static validator (confidence forced to 0.2).
1. Use only {pov_language} standard library.
2. Print the SPECIFIC behavioral marker for the vulnerability type (listed in observable_evidence) when the exploit condition is observed. Do NOT print generic "VULNERABILITY TRIGGERED" — the oracle treats it as self-report.
3. Include error handling and concrete observable outcome checks.
4. Make the PoV as deterministic as possible.
5. Prefer directly exercising the vulnerable function, route, binary, or code path declared in the payload.
6. For native C/C++ targets:
   - If the exploit contract's proof_category is "crash": the proof MUST produce an observable crash signal — AddressSanitizer output, SIGSEGV/SIGABRT (exit codes 134 or 139). Printing "VULNERABILITY TRIGGERED" alone is NOT accepted.
   - If proof_category is "behavioral": include POST-EXECUTION VERIFICATION — check filesystem state, permissions, or output content after invoking the binary. Print structured evidence markers. Do NOT expect crash signals.
7. When embedding C source code inside a Python string, use a raw triple-quoted string (r\"\"\") or ensure ALL C newlines are written as \\n (double-escaped). A bare newline inside a Python string literal will produce an unterminated C string literal syntax error.
8. The exploit_contract.target_entrypoint must be a concise function name, route, or binary path hint, not prose.
9. If the proof plan uses file input, keep the final exploit on file input and do not silently switch to inline eval mode.
10. Any inline eval payload must be syntactically valid for the target runtime.
11. For multi-file C/C++ projects: when building a standalone harness that calls functions defined in project source files, compile ALL relevant sibling .c/.cpp files together using a glob pattern (e.g. glob.glob('src/*.c')). Compiling only a single .c file produces 'undefined reference' linker errors for any helper in a sibling file.
12. Python scoping: TARGET_BINARY MUST be assigned at MODULE LEVEL ONLY:
   TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN', '')
   Inside functions (e.g. main()), reference it directly: `binary = TARGET_BINARY`.
   NEVER write `TARGET_BINARY = ...` inside any function — this shadows the module-level
   variable and causes UnboundLocalError. If you must reassign, add `global TARGET_BINARY`
   at the top of the function, but the preferred pattern is a local alias.
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

HARNESS TYPE GUIDANCE:
If the payload contains a `proof_strategy` block, use it to guide your refinement:
- `proof_type` tells you what kind of evidence is expected (NOT necessarily a crash)
- `observable_evidence` lists exact strings/patterns that MUST appear in output
- `harness_type` determines the execution approach
- If the previous attempt failed, check whether it produced the WRONG kind of evidence
  (e.g., looking for crash signals when the proof_type is timing_difference)

NON-NATIVE HARNESS PATTERNS (use when harness_type matches):
- threaded_race: spawn N threads calling the vulnerable function concurrently.
  Detect corruption, duplicates, or exceptions from concurrent access.
- resource_exhaustion: time the call with a malicious input (ReDoS payload, zip bomb, deep recursion).
  If elapsed > threshold, report resource_exhaustion.
- timing_difference: measure median execution time of correct vs. incorrect inputs over 50+ iterations.
  If ratio > 1.5, report timing_difference.
- direct_import (Python): `from package.module import vuln_func; vuln_func(payload)`
- direct_import (Node): `const m = require('/workspace/codebase'); m.vulnFunc(payload)`
- compiled_harness (Java): write a .java file, compile with $CLASSPATH, run with java -cp.

REQUIREMENTS:
0. CRITICAL — DO NOT COMPILE FROM SOURCE FOR NATIVE TARGETS: When `TARGET_BINARY`,
   `probe_binary_name`, or `AUTOPOV_PROBE_BINARY` is present in the payload, the
   prebuilt binary is ALREADY compiled with ASan and available at that path. You MUST invoke
   it directly with crafted input. NEVER write gcc / clang / cmake / make / ninja / meson / bazel
   compile commands in the PoV script. NEVER use subprocess.run/call/Popen with gcc/clang/cmake/make.
   NEVER use os.system("gcc ...") or os.popen("gcc ..."). NEVER use shutil.which("gcc").
   NEVER write .c/.cpp files and compile them. Compiling from source in the PoV will be
   STRIPPED by the pre-execution rewriter and REJECTED by the static validator (confidence forced to 0.2).
1. `pov_script` must contain executable code, not analysis text.
2. Print the SPECIFIC behavioral marker for the vulnerability type when the exploit condition is observed. Do NOT print generic "VULNERABILITY TRIGGERED" — the oracle treats it as self-report. For crash targets, sanitizer/crash output IS the evidence.
3. Explicitly use the exploit contract target entrypoint when one is available.
4. Prefer deterministic local proof techniques for native targets.
5. For native C/C++ targets:
   - If the exploit contract's proof_category is "crash": the proof MUST produce an observable crash signal — ASan output, SIGSEGV/SIGABRT exit codes (134 or 139). Self-report prints alone will be rejected.
   - If proof_category is "behavioral": include POST-EXECUTION VERIFICATION — check filesystem state, permissions, or output content after invoking the binary. Print structured evidence markers. Do NOT expect crash signals.
6. When embedding C source code inside a Python string, use a raw triple-quoted string (r\"\"\") or ensure ALL C newlines are double-escaped (\\n). A bare newline inside a Python string literal produces an unterminated C string literal syntax error that will prevent the harness from compiling.
7. For multi-file C/C++ projects: compile ALL relevant sibling .c/.cpp files together using a glob (e.g. glob.glob('src/*.c')). Compiling only one .c file produces 'undefined reference' linker errors for any function defined in a sibling file. If the previous attempt failed with 'undefined reference' errors, adding missing source files is the correct fix.
8. Keep the proof aligned with the exploit contract, proof plan, and runtime feedback in the payload.
9. Python scoping: TARGET_BINARY MUST be assigned at MODULE LEVEL ONLY:
   TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN', '')
   Inside functions, use `binary = TARGET_BINARY` (a local alias). NEVER write
   `TARGET_BINARY = ...` inside any function. If you must, add `global TARGET_BINARY` first.
10. Return JSON only.
"""


PROOF_STRATEGY_PROMPT = """You are a security expert determining the optimal proof strategy for a vulnerability.

VULNERABILITY CONTEXT:
- CWE: {cwe_type}
- File: {filepath}
- Language: {target_language}
- Explanation: {explanation}
- Vulnerable code:
```
{vulnerable_code}
```

EXPLOIT CONTRACT:
```json
{exploit_contract_json}
```

RECON CONTEXT (from automated reconnaissance of this repository):
{recon_context}

TASK:
Determine the runtime proof strategy — what observable evidence proves this vulnerability is real,
and what harness/execution approach is needed to produce that evidence.

DERIVATION RULES (apply in order):
0. DYNAMIC PROOF CATEGORY (CWE-agnostic, highest priority):
   The finding's dynamically-inferred proof_category is "{proof_category}".
   This was derived from the vulnerability description, code patterns, and impact
   analysis — NOT from a hardcoded CWE list.
   - If proof_category == "crash": use crash_signal with ASan/UBSan/SIGSEGV detection.
   - If proof_category == "behavioral": use behavioral_deviation or state_change.
     Do NOT expect a crash. After running the binary, perform POST-EXECUTION VERIFICATION.
     observable_evidence MUST describe verifiable post-conditions (file existence, permissions,
     leaked data patterns, unauthorized state changes, output content).
     Example evidence markers the PoV script should print:
       FILE_CREATED_OUTSIDE_ALLOWED_DIR:/path/...
       INSECURE_PERMISSION:0o666
       SENSITIVE_DATA_LEAKED
       UNAUTHORIZED_ACCESS_GRANTED
       PATH_TRAVERSAL_CONFIRMED:/tmp/escaped/file
       COMMAND_INJECTION_CONFIRMED
       XSS_CONFIRMED
       RESOURCE_EXHAUSTION:<measurement>

0a. EXPLOITATION APPROACH HINT (CWE-agnostic):
   {exploitation_approach}
   This concrete hint was dynamically derived from the vulnerability description.
   Use it as actionable guidance for HOW to construct the proof-of-concept.
   The PoV script should follow this approach to demonstrate the vulnerability.

1. If the target is a NATIVE binary (C/C++/Rust/Go) AND proof_category is "crash":
   - proof_type SHOULD be "crash_signal" — the binary is compiled with AddressSanitizer/UBSan
     which emits structured crash reports on any memory safety violation.
   - observable_evidence SHOULD include ASan/UBSan markers: "AddressSanitizer",
     "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
     "UndefinedBehaviorSanitizer", "SEGV", "SIGABRT".
   - harness_type SHOULD be "subprocess_binary".
   - Only deviate from crash_signal if you have a SPECIFIC reason (e.g., the vulnerability
     is an information leak with no memory corruption, or requires multi-step state).

2. If the target is a Python/Node/Java/Ruby application:
   - Think about whether the vulnerability produces an exception, observable output,
     state change, or behavioral deviation.
   - Do NOT default to crash_signal — these runtimes rarely crash on memory issues.

3. For logic bugs, race conditions, auth bypass, info disclosure, timing attacks:
   - These produce NO crash. Use behavioral_deviation, observable_output, state_change,
     timing_difference, or information_disclosure as appropriate.
   - For race conditions: use harness_type="threaded_race", execution_strategy="concurrent_threads".
     Evidence: corrupted state, duplicate operations, or exception from concurrent access.
   - For timing attacks: use harness_type="repeated_execution", execution_strategy="timed_measurement".
     Evidence: measurable timing ratio > 1.5x between correct and incorrect inputs.
   - For ReDoS / resource exhaustion: use execution_strategy="timed_measurement".
     Evidence: elapsed time > threshold (e.g. 5s for a regex, 10s for parsing).
   - For info disclosure: use harness_type appropriate to the surface.
     Evidence: leaked data pattern (e.g. secret key, stack trace, memory contents).

4. The recon_context above shows the project's recommended default_proof_type. This is a
   STRONG hint derived from the project's runtime family. Follow it unless the specific
   vulnerability clearly requires a different approach.

IMPORTANT: The "observable_evidence" field must contain EXACT strings that will literally appear
in stdout or stderr when the vulnerability triggers. These are used by the oracle to confirm.
Examples: "AddressSanitizer: heap-buffer-overflow", "Traceback (most recent call last)",
"RCE_MARKER_12345", "UnhandledPromiseRejectionWarning".

Respond with ONLY this JSON:
{{{{
  "proof_type": "crash_signal | exception | observable_output | state_change | timing_difference | resource_exhaustion | information_disclosure | behavioral_deviation | multi_step_chain",
  "observable_evidence": ["exact strings, patterns, or conditions that prove the vulnerability"],
  "setup_requirements": ["state or files that must exist before the exploit runs"],
  "execution_strategy": "single_call | repeated_calls | concurrent_threads | timed_measurement | stateful_sequence | comparative_runs",
  "harness_type": "subprocess_binary | direct_import | http_request | threaded_race | repeated_execution | stateful_session | in_process_mutation | compiled_harness | multi_process",
  "verification_method": "how to confirm the evidence is genuine and not a false positive",
  "negative_control": "what a non-vulnerable version would produce instead",
  "estimated_difficulty": "low | medium | high",
  "why_this_works": "1-2 sentence explanation of why this proof strategy is appropriate"
}}}}
"""


EXPLOIT_PLAN_PROMPT = """You are planning a multi-step exploit for a vulnerability.

## VULNERABILITY
CWE: {cwe_type}
File: {filepath}:{line_number}
Root Cause: {root_cause}
Explanation: {explanation}

## BINARY PROTOCOL
{protocol_section}

## REPO PROFILE
Project Type: {project_type}
Runtime: {runtime_family}
Input Format: {input_format}
Input Surface: {input_surface}
Accepted Extensions: {accepted_extensions}

TASK:
Produce an ordered list of exploit steps. Each step must be concrete and executable.
Consider: setup/bootstrap requirements, input preparation, trigger execution, evidence collection.

Respond with ONLY this JSON:
{{{{
  "exploit_steps": [
    {{{{
      "step_number": 1,
      "action": "what to do",
      "command_template": "shell command or code snippet",
      "expected_result": "what success looks like",
      "failure_fallback": "what to try if this step fails"
    }}}}
  ],
  "total_steps": <int>,
  "critical_step": <step_number of the actual trigger>,
  "evidence_step": <step_number where observable evidence appears>
}}}}
"""


def generate_ranked_strategies(
    finding: dict,
    exploit_contract: dict = None,
    repo_profile: dict = None,
) -> list:
    """Generate a ranked list of exploit strategies for strategy rotation.

    Returns a list of dicts, each with 'strategy_name', 'description',
    'input_approach', 'priority' (1=highest). On each retry, the next
    strategy in the list should be tried.
    """
    _ec = exploit_contract or {}
    _rp = repo_profile or {}
    strategies = []

    _fmt = _ec.get('probe_format_hint') or _rp.get('input_format', '')
    _surface = _ec.get('execution_surface', '') or _rp.get('input_surface', '')
    _protocol = _ec.get('multi_step_protocol') or _rp.get('multi_step_protocol', [])
    _cwe = str(finding.get('cwe_type', '')).upper()
    _bootstrap = _ec.get('bootstrap_subcommand') or _rp.get('bootstrap_subcommand', '')

    # Strategy 1: Direct format-aware payload via binary CLI
    if _surface in ('file_argument', 'stdin', 'binary_cli'):
        strategies.append({
            'strategy_name': 'format_aware_file_input',
            'description': f'Feed a crafted {_fmt or "binary"} file that triggers the vulnerable code path',
            'input_approach': f'Write format-valid {_fmt or "binary"} payload to temp file, pass as argument',
            'priority': 1,
        })

    # Strategy 2: Multi-step protocol (if applicable)
    if _protocol and len(_protocol) > 1:
        strategies.append({
            'strategy_name': 'multi_step_protocol',
            'description': f'Execute full protocol sequence: {" \u2192 ".join(_protocol)}',
            'input_approach': 'Run each protocol step in order with appropriate inputs',
            'priority': 2 if _bootstrap else 1,
        })

    # Strategy 3: Stdin pipe
    strategies.append({
        'strategy_name': 'stdin_pipe',
        'description': 'Pipe crafted payload directly to binary stdin',
        'input_approach': 'Use subprocess with stdin=PIPE to feed payload bytes',
        'priority': 3,
    })

    # Strategy 4: Oversized input (for buffer overflows)
    if 'CWE-12' in _cwe or 'overflow' in _cwe.lower() or 'CWE-787' in _cwe or 'CWE-122' in _cwe:
        strategies.append({
            'strategy_name': 'oversized_payload',
            'description': 'Feed input exceeding expected buffer size',
            'input_approach': f'Generate {_fmt or "binary"} payload with oversized fields (64KB-1MB)',
            'priority': 2,
        })

    # Strategy 5: Malformed format (for parser bugs)
    if _fmt:
        strategies.append({
            'strategy_name': 'malformed_format',
            'description': f'Feed structurally invalid {_fmt} that passes initial magic check but triggers parser bug',
            'input_approach': f'Valid {_fmt} header + corrupted/truncated body',
            'priority': 4,
        })

    # Strategy 6: Function harness (for libraries)
    if _surface in ('function_call', 'c_library_harness'):
        strategies.append({
            'strategy_name': 'direct_function_call',
            'description': 'Compile inline harness calling vulnerable function directly',
            'input_approach': 'Write C harness, compile with ASan, call function with crafted args',
            'priority': 1,
        })

    # Strategy 7: HTTP request (for web targets)
    if _surface in ('http_request', 'network', 'web'):
        strategies.append({
            'strategy_name': 'http_exploit',
            'description': 'Send crafted HTTP request to vulnerable endpoint',
            'input_approach': 'Use requests library to POST/GET with malicious payload',
            'priority': 1,
        })

    # Sort by priority
    strategies.sort(key=lambda s: s['priority'])
    return strategies


def format_exploit_plan_prompt(
    finding: dict,
    exploit_contract: dict = None,
    repo_profile: dict = None,
) -> str:
    """Build the exploit planning prompt from finding + repo profile data."""
    _ec = exploit_contract or {}
    _rp = repo_profile or {}

    _protocol = _ec.get('multi_step_protocol') or _rp.get('multi_step_protocol') or []
    _protocol_section = ''
    if _protocol:
        _protocol_section = f'Multi-step sequence: {" \u2192 ".join(_protocol)}\n'
        _protocol_section += 'Your exploit MUST follow this exact step ordering.'
    else:
        _protocol_section = 'No multi-step protocol detected. Single-step exploit likely sufficient.'

    if _ec.get('needs_key_bootstrap') or _rp.get('needs_key_bootstrap'):
        _protocol_section += '\nKEY BOOTSTRAP REQUIRED: Generate keys before exploit step.'
    if _ec.get('needs_passphrase') or _rp.get('needs_passphrase'):
        _protocol_section += '\nPASSPHRASE REQUIRED: Supply passphrase non-interactively.'

    return EXPLOIT_PLAN_PROMPT.format(
        cwe_type=finding.get('cwe_type', 'UNCLASSIFIED'),
        filepath=finding.get('filepath', ''),
        line_number=finding.get('line_number', 0),
        root_cause=_ec.get('root_cause', finding.get('root_cause', 'unknown')),
        explanation=finding.get('explanation', ''),
        protocol_section=_protocol_section,
        project_type=_rp.get('project_type', 'unknown'),
        runtime_family=_rp.get('runtime_family', 'native'),
        input_format=_rp.get('input_format', 'unknown'),
        input_surface=_rp.get('input_surface', 'unknown'),
        accepted_extensions=', '.join(_rp.get('accepted_extensions', [])) or 'unknown',
    )


def format_proof_strategy_prompt(cwe_type: str, filepath: str, target_language: str,
                                  explanation: str, vulnerable_code: str,
                                  exploit_contract: dict = None,
                                  recon_report: dict = None,
                                  probe_result: dict = None,
                                  proof_category: str = 'crash',
                                  exploitation_approach: str = '') -> str:
    """Format the proof strategy prompt for LLM consumption."""
    # Build recon context block — use full lists (no truncation)
    recon_lines = []
    if recon_report:
        if recon_report.get('project_type'):
            recon_lines.append(f"- Project type: {recon_report['project_type']}")
        if recon_report.get('runtime_family'):
            recon_lines.append(f"- Runtime family: {recon_report['runtime_family']}")
        if recon_report.get('build_system'):
            recon_lines.append(f"- Build system: {recon_report['build_system']}")
        if recon_report.get('attack_surfaces'):
            recon_lines.append(f"- Attack surfaces: {json.dumps(recon_report['attack_surfaces'])}")
        if recon_report.get('framework_hints'):
            recon_lines.append(f"- Frameworks: {', '.join(recon_report['framework_hints'])}")
        if recon_report.get('binary_candidates'):
            recon_lines.append(f"- Binary candidates: {', '.join(recon_report['binary_candidates'])}")
        # Inject recon proof_strategies as explicit directives (not just defaults)
        _recon_strategies = recon_report.get('proof_strategies') or {}
        if _recon_strategies:
            recon_lines.append(f"- RECOMMENDED proof strategies from reconnaissance (prefer these): {json.dumps(_recon_strategies)}")
        if recon_report.get('default_proof_type'):
            recon_lines.append(f"- RECOMMENDED default proof_type for this project: {recon_report['default_proof_type']}")
        if recon_report.get('default_harness_type'):
            recon_lines.append(f"- RECOMMENDED default harness_type: {recon_report['default_harness_type']}")
        if recon_report.get('entrypoints'):
            recon_lines.append(f"- Entry points with invocation: {json.dumps(recon_report['entrypoints'])}")
    # ── Probe intelligence (runtime-observed, highest confidence) ──
    _pr = probe_result or {}
    if _pr:
        if _pr.get('probe_crash_observed'):
            recon_lines.append('- PROBE OBSERVED CRASH: the binary crashed during probing — strong exploitation signal')
        if _pr.get('probe_input_surface'):
            recon_lines.append(f"- Probe-observed input surface: {_pr['probe_input_surface']}")
        if _pr.get('probe_format_hint'):
            recon_lines.append(f"- Probe-observed format: {_pr['probe_format_hint']}")
        if _pr.get('probe_baseline_exit_code') is not None:
            recon_lines.append(f"- Probe baseline exit code: {_pr['probe_baseline_exit_code']}")
        if _pr.get('probe_discovered_subcommands'):
            recon_lines.append(f"- Probe discovered subcommands: {', '.join(_pr['probe_discovered_subcommands'][:10])}")
    recon_context = '\n'.join(recon_lines) if recon_lines else '(no recon data available)'

    return PROOF_STRATEGY_PROMPT.format(
        cwe_type=cwe_type or 'UNCLASSIFIED',
        filepath=filepath or '',
        target_language=target_language or 'unknown',
        explanation=explanation or '',
        vulnerable_code=vulnerable_code or '',
        exploit_contract_json=json.dumps(exploit_contract or {}, indent=2, default=str),
        recon_context=recon_context,
        proof_category=proof_category or 'crash',
        exploitation_approach=exploitation_approach or 'No specific exploitation approach hint available.',
    )


def _render_structured_payload(payload: dict) -> str:
    return json.dumps(payload or {}, indent=2, sort_keys=True)


def compact_prompt_for_model(prompt: str, max_chars: int = 0, model_name: str = '', ctx=None) -> str:
    """Compact a narrative prompt to fit within a model's context budget.

    Structure-aware: EXPLOIT BRIEF and EXECUTION RECIPE are never trimmed.
    VULNERABLE CODE, REFERENCE DATA, and CONSTRAINTS are trimmed progressively.
    The `ctx` parameter (FindingContext) is accepted but optional for backward compat.
    """
    if not max_chars:
        _model = (model_name or '').lower()
        if any(k in _model for k in ('qwen', 'llama', 'mistral', 'phi', 'gemma')):
            max_chars = 12000  # ~3k tokens for smaller models
        elif any(k in _model for k in ('gpt-4', 'claude', 'gpt-5')):
            max_chars = 40000  # ~10k tokens for large models
        else:
            max_chars = 24000  # default ~6k tokens

    if len(prompt) <= max_chars:
        return prompt

    # Progressive trimming: remove sections from lowest to highest value.
    # EXPLOIT BRIEF and EXECUTION RECIPE are NEVER trimmed — they contain
    # the synthesized high-confidence intel the LLM needs most.
    _TRIM_ORDER = [
        # Lowest value first
        '## REFERENCE DATA',
        '## ADDITIONAL EXPLOIT CONTRACT',
        '## PROBE DATA',
        '## RECON INTELLIGENCE',
        '## CODE CONTEXT',
        '## VULNERABLE CODE',
        '## RUNTIME FEEDBACK',
        '## FAILURE ANALYSIS',
    ]
    result = prompt
    for section_header in _TRIM_ORDER:
        if len(result) <= max_chars:
            break
        idx = result.find(section_header)
        if idx == -1:
            continue
        # Find next section boundary
        next_section = len(result)
        for _h in ['## EXPLOIT BRIEF', '## EXECUTION RECIPE', '## VULNERABLE CODE',
                    '## CONSTRAINTS', '## REFERENCE DATA', '## ADDITIONAL',
                    '## RUNTIME FEEDBACK', '## FAILURE ANALYSIS', '## WHAT WENT WRONG',
                    '## WHAT TO CHANGE', '## FAILED SCRIPT',
                    '\nTASK:', '\nRESPONSE JSON']:
            _ni = result.find(_h, idx + len(section_header))
            if _ni != -1 and _ni < next_section:
                next_section = _ni
        result = result[:idx] + result[next_section:]

    # Final fallback: truncate VULNERABLE CODE to 30 lines if still over
    if len(result) > max_chars:
        _vc_start = result.find('## VULNERABLE CODE')
        if _vc_start != -1:
            _code_start = result.find('```', _vc_start)
            _code_end = result.find('```', _code_start + 3) if _code_start != -1 else -1
            if _code_start != -1 and _code_end != -1:
                _code_block = result[_code_start:_code_end + 3]
                _lines = _code_block.split('\n')
                if len(_lines) > 35:
                    _trimmed = '\n'.join(_lines[:32]) + '\n... (truncated)\n```'
                    result = result[:_code_start] + _trimmed + result[_code_end + 3:]

    return result


def _build_binary_surface_block(subcommands=None, help_text: str = '', observed_surface: dict = None, setup_requirements: list = None, probe_binary_name: str = '', recon_subcommands: list = None) -> str:
    """Build a BINARY SURFACE section from runtime-discovered data.

    This is injected into every PoV generation and refinement prompt so models
    use real subcommands/flags from the binary rather than guessing or probing
    with --help.  All sources are combined and de-duplicated:
      1. explicit subcommands list (from contract's known_subcommands)
      2. observed_surface dict (from preflight probe)
      3. help_text string (from preflight --help invocation)
      4. setup_requirements list (bootstrap steps like keygen)
      5. recon_subcommands list (from recon entrypoints)
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
    # Merge recon-discovered subcommands (from entrypoints analysis)
    for s in (recon_subcommands or []):
        if s and s not in combined_subcmds:
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
            from agents.probe_runner import classify_input_surface as _cls
            _bin_hint = (
                str(probe_binary_name or '')
                or str(observed_surface.get('probe_binary_name') or '')
                or str(observed_surface.get('binary_name') or '')
            ).strip()
            _derived = _cls(combined_help, _bin_hint)
            if _derived != 'unknown':
                _input_surface = _derived
        except Exception as _cls_err:
            import logging as _logging
            _logging.getLogger(__name__).warning('Failed to classify input surface: %s', _cls_err)

    if not combined_subcmds and not combined_help and not _input_surface:
        # Nothing discovered — fall back to the legacy subcmd-only block if subcommands given
        return ''

    block = "\n\nBINARY SURFACE (discovered at runtime — use this):\n"
    # Inject probe-discovered binary name as explicit TARGET_BINARY directive.
    # This is the single most important hint: the model must NOT set TARGET_BINARY to a
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
            f"MANDATORY: Read TARGET_BINARY from environment at MODULE LEVEL: "
            f"TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN', ''). "
            f"The harness sets TARGET_BINARY={_bin_name!r} before your script runs. "
            f"Do NOT set TARGET_BINARY to a C function name (e.g. 'enchive_decrypt', "
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
            "Do NOT use subprocess.run(argv, input=payload) or pipe bytes to stdin.\n"
            "CRITICAL: Every positional argument after the binary is treated as a FILENAME by the target. "
            "Do NOT pass raw strings like 'A'*256 or fake subcommand names like 'main' as arguments — "
            "the binary will try to open them as files and exit with 'No such file'. "
            "Always create a real file on disk first, then pass the file path."
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
    # This prevents the model from sending JPEG/PNG binary blobs to XML or JSON parsers
    # and vice-versa. Covers the most common parser failure categories seen in batch results.
    _binary_name = str(probe_binary_name or observed_surface.get('probe_binary_name') or '').lower()
    _fp_lower = str(observed_surface.get('filepath') or '').lower()
    # Also check probe_format_hint if the probe explicitly classified the format
    _probe_fmt = str(observed_surface.get('probe_format_hint') or '').lower()
    _XML_SIGNALS = ('xml', 'expat', 'libxml', 'htmlparser', 'xmlwf', 'xmllint', 'tidy', 'pugixml', 'rapidxml', 'minixml', 'mxml', 'xerces', 'nanoxml')
    _JSON_SIGNALS = ('json', 'cjson', 'jansson', 'parson', 'jsmn', 'ujson', 'jq', 'yajl', 'jsonc', 'simdjson', 'nlohmann')
    _HTML_SIGNALS = ('html', 'htmlparser', 'gumbo', 'modest', 'lexbor', 'libhtmlparser')
    _CSV_SIGNALS  = ('csv', 'tsv', 'libcsv')
    _IMAGE_SIGNALS = ('jpeg', 'jpg', 'jhead', 'jpegtran', 'jpegoptim', 'png', 'libpng', 'gif', 'tiff', 'bmp', 'webp',
                      'imagemagick', 'convert', 'exif', 'exiftool', 'imgfile', 'libjpeg')
    _PDF_SIGNALS = ('pdf', 'mupdf', 'poppler', 'pdfium', 'ghostscript', 'gs')
    _ARCHIVE_SIGNALS = ('zip', 'tar', 'gzip', 'bzip2', 'xz', 'lzma', 'zlib', 'unzip', 'bsdtar', 'bsdcat',
                        'libarchive', 'zstd', 'lz4', 'snappy', 'squashfs')
    _AUDIO_SIGNALS = ('mp3', 'ogg', 'flac', 'wav', 'aac', 'opus', 'vorbis', 'libsndfile', 'sox', 'ffmpeg', 'avcodec')
    _FONT_SIGNALS = ('ttf', 'otf', 'woff', 'freetype', 'harfbuzz', 'fonttools')
    _fmt_hit = _probe_fmt  # prefer explicit probe hint
    if not _fmt_hit:
        if any(s in _binary_name or s in _fp_lower for s in _XML_SIGNALS):
            _fmt_hit = 'xml'
        elif any(s in _binary_name or s in _fp_lower for s in _JSON_SIGNALS):
            _fmt_hit = 'json'
        elif any(s in _binary_name or s in _fp_lower for s in _HTML_SIGNALS):
            _fmt_hit = 'html'
        elif any(s in _binary_name or s in _fp_lower for s in _IMAGE_SIGNALS):
            _fmt_hit = 'image'
        elif any(s in _binary_name or s in _fp_lower for s in _PDF_SIGNALS):
            _fmt_hit = 'pdf'
        elif any(s in _binary_name or s in _fp_lower for s in _ARCHIVE_SIGNALS):
            _fmt_hit = 'archive'
        elif any(s in _binary_name or s in _fp_lower for s in _AUDIO_SIGNALS):
            _fmt_hit = 'audio'
        elif any(s in _binary_name or s in _fp_lower for s in _FONT_SIGNALS):
            _fmt_hit = 'font'
    if _fmt_hit == 'xml':
        block += (
            "\n\nINPUT FORMAT: XML \u2014 this parser reads XML. Your payload MUST be syntactically"
            " valid XML that is structurally over-long or contains crafted attribute/element values\n"
            " that exercise the vulnerable code path. Do NOT send JPEG, PNG, or random binary data.\n"
            " Example malicious payloads:\n"
            "  - Deeply nested elements: <a><b><c>...repeat 10000x...</c></b></a>\n"
            "  - Oversized attribute value: <root attr=\"AAA...65536 As...\"/>\n"
            "  - Billion-laughs-style entity expansion (if DTD processing is enabled).\n"
            "  - A valid XML document with a very long text node (b'<r>' + b'A'*131072 + b'</r>').\n"
        )
    elif _fmt_hit == 'json':
        block += (
            "\n\nINPUT FORMAT: JSON \u2014 this parser reads JSON. Your payload MUST be JSON text\n"
            " (bytes encoded as UTF-8) that exercises the vulnerable code path.\n"
            " Example: deeply nested arrays, very long string values, or malformed JSON.\n"
            " Do NOT send JPEG, PNG, or random binary data.\n"
        )
    elif _fmt_hit == 'html':
        block += (
            "\n\nINPUT FORMAT: HTML \u2014 this parser reads HTML. Your payload must be HTML text.\n"
            " Use oversized attribute values, deeply nested tags, or malformed HTML.\n"
        )
    elif _fmt_hit == 'image':
        block += (
            "\n\nINPUT FORMAT: IMAGE \u2014 this tool processes image files (JPEG/PNG/BMP/WebP/GIF/TIFF).\n"
            " Your payload MUST be a valid or near-valid image file. Random bytes will be rejected\n"
            " before reaching the vulnerable code path. Use one of these approaches:\n"
            "  a) Craft a minimal JFIF/JPEG header followed by oversized EXIF/IPTC data:\n"
            "     payload = b'\\xff\\xd8\\xff\\xe0' + b'\\x00\\x10JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00'\n"
            "     payload += b'\\xff\\xe1' + len(exif_data).to_bytes(2,'big') + exif_data  # oversized Exif\n"
            "  b) PNG: valid 8-byte PNG magic + IHDR chunk + crafted oversized IDAT\n"
            "     PNG_MAGIC = b'\\x89PNG\\r\\n\\x1a\\n'\n"
            "  c) Use a real test image file if one is listed in REPO-DERIVED INPUT HINTS.\n\n"
            "STARTER CODE for JPEG-like tools (copy and adapt):\n"
            "```python\n"
            "import tempfile, os\n"
            "\n"
            "# Create a minimal valid image file with malformed data\n"
            "with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as f:\n"
            "    # JPEG SOI + APP0 marker + JFIF header\n"
            "    header = b'\\xff\\xd8\\xff\\xe0\\x00\\x10JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x01\\x00\\x00'\n"
            "    # Oversized EXIF segment to trigger buffer overflow\n"
            "    exif = b'\\xff\\xe1' + (65535).to_bytes(2, 'big') + b'A' * 65535\n"
            "    f.write(header + exif)\n"
            "    payload_path = f.name\n"
            "\n"
            "# Pass the FILE PATH as argument — NOT the raw bytes\n"
            "result = subprocess.run([binary, payload_path], capture_output=True, text=True, timeout=30)\n"
            "```\n"
            "Do NOT pass raw strings or bytes as argv — the tool expects a FILE PATH.\n"
        )
    elif _fmt_hit == 'pdf':
        block += (
            "\n\nINPUT FORMAT: PDF \u2014 this tool processes PDF files.\n"
            " Your payload must start with the PDF magic bytes: b'%PDF-1.4\\n'.\n"
            " Construct a minimal valid PDF and embed oversized or malformed cross-reference tables,\n"
            " object streams, or name dictionaries to trigger the vulnerable code path.\n"
        )
    elif _fmt_hit == 'archive':
        block += (
            "\n\nINPUT FORMAT: ARCHIVE \u2014 this tool processes compressed archives (ZIP/tar/gzip/bzip2/xz).\n"
            " Your payload must be a syntactically valid archive container. Random bytes will\n"
            " be rejected at header parsing before reaching the vulnerable code. Use:\n"
            "  a) Python zipfile / tarfile modules to create a valid archive with oversized\n"
            "     filenames, long path components, or deeply nested entries.\n"
            "  b) For gzip: b'\\x1f\\x8b\\x08' + valid gzip header + crafted FNAME/comment.\n"
            "  c) For bzip2: b'BZh9' + valid block header before the overflow content.\n"
        )
    elif _fmt_hit == 'audio':
        block += (
            "\n\nINPUT FORMAT: AUDIO \u2014 this tool processes audio files.\n"
            " Your payload must start with the correct magic bytes for the format:\n"
            "  - MP3: b'\\xff\\xfb' (sync word) or b'ID3' (ID3 tag header)\n"
            "  - OGG: b'OggS' capture pattern\n"
            "  - FLAC: b'fLaC' stream marker\n"
            "  - WAV: b'RIFF' + size bytes + b'WAVE' + fmt chunk\n"
            " Do NOT send random binary data without valid container headers.\n"
        )
    elif _fmt_hit == 'font':
        block += (
            "\n\nINPUT FORMAT: FONT \u2014 this tool processes font files (TTF/OTF/WOFF).\n"
            " Your payload must begin with valid font magic bytes:\n"
            "  - TTF/OTF: b'\\x00\\x01\\x00\\x00' (TrueType) or b'OTTO' (CFF/OTF)\n"
            "  - WOFF: b'wOFF' + size\n"
            " Craft oversized table entries or malformed glyph data after the valid header.\n"
        )
    # Detect key-material bootstrap requirement and inject step-by-step keygen instructions.
    # Triggered when setup_requirements or observed_surface contains a keygen bootstrap signal.
    _all_setup_reqs = list(setup_requirements or []) + list(observed_surface.get('setup_requirements') or [])
    _BOOTSTRAP_SUBCOMMAND_HINTS = {'keygen', 'init', 'setup', 'configure', 'genkey', 'gen-key', 'generate-key', 'generate_key'}
    # Use probe-discovered bootstrap subcommand if available
    _probe_bootstrap_sub = str(observed_surface.get('probe_bootstrap_subcommand') or '').strip()
    _probe_subcmds_list = observed_surface.get('probe_discovered_subcommands') or []
    _needs_bootstrap = (
        any('key material' in str(r).lower() or 'bootstrap key material' in str(r).lower() for r in _all_setup_reqs)
        or bool(_probe_bootstrap_sub)  # Probe found bootstrap subcommand
        or bool(combined_subcmds and _BOOTSTRAP_SUBCOMMAND_HINTS & {str(s).lower() for s in combined_subcmds})
        or bool(_probe_subcmds_list and _BOOTSTRAP_SUBCOMMAND_HINTS & {str(s).lower() for s in _probe_subcmds_list})
    )
    if _needs_bootstrap:
        # Find the bootstrap subcommand name: prefer probe-discovered, then known subcommands
        _boot_sub = (
            _probe_bootstrap_sub
            or next((str(s) for s in combined_subcmds if str(s).lower() in _BOOTSTRAP_SUBCOMMAND_HINTS), '')
            or next((str(s) for s in _probe_subcmds_list if str(s).lower() in _BOOTSTRAP_SUBCOMMAND_HINTS), '')
            or 'keygen'
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
    # Shown when the surface block fires so the model can pick the right TARGET_BINARY.
    _ep_candidates = observed_surface.get('entrypoint_candidates') or []
    _active_ep = str(observed_surface.get('active_entrypoint') or '').strip()
    if _ep_candidates:
        block += (
            f"\n\nENTRYPOINT CANDIDATES (ranked by confidence, derived from source + probe):\n"
            f"  {', '.join(str(c) for c in _ep_candidates)}\n"
        )
        if _active_ep:
            block += (
                f"ACTIVE binary entrypoint for this attempt: '{_active_ep}'.\n"
                f"The harness sets TARGET_BINARY to the path of '{_active_ep}'.\n"
                "If this entrypoint produces no oracle match, the next candidate will be tried on the following retry."
            )
        else:
            block += (
                f"Use the first candidate that appears in the crash stack trace.\n"
                f"Prefer the first candidate in the list unless a prior attempt proved it wrong."
            )
    return block


# ---------------------------------------------------------------------------
# Narrative prompt builder (FindingContext-based)
# ---------------------------------------------------------------------------

def _build_exploit_brief(ctx) -> str:
    """Build the EXPLOIT BRIEF section — a filled-in narrative, not a data dump."""
    lines = ['## EXPLOIT BRIEF']

    # Binary / target identification
    if ctx.binary_name:
        _path_hint = f' at `{ctx.binary_path}`' if ctx.binary_path else ''
        _fmt_hint = f' {ctx.input_format.upper()}' if ctx.input_format else ''
        _method_hint = ''
        if ctx.input_method == 'file_argument':
            _method_hint = f' via file argument'
        elif ctx.input_method == 'stdin':
            _method_hint = ' via stdin'
        elif ctx.input_method == 'network':
            _method_hint = ' via network connection'
        elif ctx.input_method == 'function_call':
            _method_hint = ' via direct function call'
        _ext_hint = ''
        if ctx.input_extensions:
            _ext_hint = f' with `{ctx.input_extensions[0]}` extension'
        lines.append(
            f'The binary `{ctx.binary_name}`{_path_hint} accepts{_fmt_hint} input'
            f'{_method_hint}{_ext_hint}.'
        )
    elif ctx.surface_type == 'python_module':
        lines.append(f'Target is a Python module. Entry: `{ctx.entry_command or ctx.entry_function or "import package"}`.')
    elif ctx.surface_type == 'node_module':
        lines.append(f'Target is a Node.js module. Entry: `{ctx.entry_command or "require(package)"}`.')
    elif ctx.surface_type == 'web_service':
        _url = ctx.base_url or 'http://localhost:8000'
        lines.append(f'Target is a web service at `{_url}`. Use HTTP requests to trigger the vulnerability.')

    # Vulnerability identification
    _vuln_line = f'The vulnerability is {ctx.cwe}'
    if ctx.filepath:
        _vuln_line += f' at `{ctx.filepath}:{ctx.line_number}`'
    if ctx.entry_function:
        _vuln_line += f' in function `{ctx.entry_function}()`'
    _vuln_line += '.'
    lines.append(_vuln_line)

    if ctx.cwe_source:
        lines.append(f'CWE Source: {ctx.cwe_source} (tool=CodeQL/Semgrep identified, llm_inferred=LLM classified)')

    # Root cause
    if ctx.root_cause:
        lines.append(f'Root Cause: {ctx.root_cause}')
    if ctx.impact:
        lines.append(f'Impact: {ctx.impact}')

    # Data flow path (Joern-derived)
    if ctx.data_flow_path:
        lines.append(f'Data Flow: `{ctx.data_flow_path}`')

    # Input rejection
    if ctx.rejection_patterns:
        lines.append(f'The binary rejects invalid input with: {", ".join(ctx.rejection_patterns[:3])}')

    # Required proof output
    if ctx.observable_evidence:
        lines.append(f'Required output: {", ".join(str(e) for e in ctx.observable_evidence)}')
    elif ctx.proof_type == 'crash_signal':
        lines.append('Required output: AddressSanitizer output, SIGSEGV/SIGABRT (exit code 134/139).')

    # CVE proof hint (Task 6: inject here, not at bottom)
    if ctx.cve_proof_hint:
        _cve_label = f' ({ctx.cve_id})' if ctx.cve_id else ''
        lines.append(f'CVE advisory hint{_cve_label}: {ctx.cve_proof_hint}')
    elif ctx.cve_id and ctx.cve_summary:
        lines.append(f'CVE: {ctx.cve_id} — {ctx.cve_summary[:200]}')

    return '\n'.join(lines)


def _build_execution_recipe(ctx) -> str:
    """Build the EXECUTION RECIPE — step-by-step instructions, not strategy options."""
    lines = ['## EXECUTION RECIPE']
    lines.append(f'Proof Type: {ctx.proof_type}')
    lines.append(f'Harness Type: {ctx.harness_type}')

    # Multi-step protocol
    if ctx.multi_step_protocol:
        lines.append(f'Protocol sequence: {" \u2192 ".join(ctx.multi_step_protocol)}')
        lines.append('Your exploit MUST follow this exact step ordering.')

    # Bootstrap requirement
    if ctx.needs_key_bootstrap:
        _boot = ctx.bootstrap_subcommand or 'keygen'
        lines.append(
            f'KEY BOOTSTRAP REQUIRED: Run `{_boot}` BEFORE the exploit step.\n'
            f'  Step 1: HOME = os.environ.get("AUTOPOV_BOOTSTRAP_HOME") or os.environ.get("HOME")\n'
            f'  Step 2: subprocess.run([binary, "{_boot}"], input="autopov\\nautopov\\n", '
            f'capture_output=True, text=True, env={{**os.environ, "HOME": HOME}})\n'
            f'  Step 3: Run trigger subcommand with the SAME HOME env.'
        )
    if ctx.needs_passphrase:
        lines.append('PASSPHRASE REQUIRED: Feed passphrase non-interactively via stdin pipe.')

    # Concrete trigger steps
    if ctx.trigger_steps:
        lines.append('Trigger Steps:')
        for i, step in enumerate(ctx.trigger_steps, 1):
            lines.append(f'  {i}. {step}')
    elif ctx.exploit_plan_steps:
        lines.append('Exploit Plan:')
        for _step in ctx.exploit_plan_steps:
            _sn = _step.get('step_number', '?')
            _act = _step.get('action', '')
            _cmd = _step.get('command_template', '')
            lines.append(f'  Step {_sn}: {_act}')
            if _cmd:
                lines.append(f'    Command: {_cmd}')
        _crit = None
        if ctx.exploit_plan_steps:
            # Find critical step from parent exploit_plan if available
            pass

    # Binary surface directives
    if ctx.binary_name:
        lines.append(
            f'BINARY: The target binary is {ctx.binary_name!r}. '
            f'It is pre-built and available via the TARGET_BINARY environment variable. '
            f'Read it at MODULE LEVEL like this:\n'
            f'  TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", "")\n'
            f'Then reference TARGET_BINARY directly in your main() function — do NOT reassign it inside main().'
        )
    if ctx.subcommands:
        lines.append(f'Subcommands: {", ".join(ctx.subcommands)}')
        lines.append('The first positional argument MUST be one of these subcommands.')

    # Input method directives
    if ctx.input_method == 'file_argument':
        lines.append(
            'INPUT: Write crafted payload to temp file, pass path as CLI argument. '
            'Do NOT pipe to stdin.'
        )
    elif ctx.input_method == 'stdin':
        lines.append(
            'INPUT: Pipe payload to binary via subprocess.run(argv, input=payload). '
            'If payload is bytes, do NOT use text=True.'
        )
    elif ctx.input_method == 'network':
        lines.append('INPUT: Start binary as subprocess, connect via socket/HTTP.')

    # Format-specific payload guidance
    _fmt = ctx.input_format
    if _fmt == 'xml':
        lines.append(
            'FORMAT: XML — payload MUST be valid XML. Use deeply nested elements, '
            'oversized attribute values, or entity expansion. Do NOT send binary data.'
        )
    elif _fmt == 'json':
        lines.append(
            'FORMAT: JSON — payload MUST be UTF-8 JSON. Use deeply nested arrays, '
            'very long strings. Do NOT send binary data.'
        )
    elif _fmt == 'image':
        lines.append(
            'FORMAT: IMAGE — payload MUST start with valid image magic bytes '
            '(JFIF/PNG/BMP header) followed by oversized metadata. Random bytes will be rejected.'
        )
    elif _fmt == 'pdf':
        lines.append('FORMAT: PDF — payload MUST start with b\'%PDF-1.4\\n\' + malformed structure.')
    elif _fmt == 'archive':
        lines.append(
            'FORMAT: ARCHIVE — use Python zipfile/tarfile to create valid archive '
            'with oversized filenames or deeply nested entries.'
        )
    elif _fmt == 'html':
        lines.append('FORMAT: HTML — payload MUST be HTML. Use oversized attributes or deeply nested tags.')
    elif _fmt == 'audio':
        lines.append('FORMAT: AUDIO — payload MUST start with correct magic bytes (MP3/OGG/FLAC/WAV).')
    elif _fmt == 'font':
        lines.append('FORMAT: FONT — payload MUST start with valid font magic (TTF/OTF/WOFF header).')

    # Exported names (Python/Node modules)
    if ctx.exported_names:
        lines.append(f'Exported symbols: {ctx.exported_names}')

    # Sample files hint
    if ctx.sample_files:
        lines.append(f'Sample input files in repo: {", ".join(ctx.sample_files[:5])}')

    # Attacker inputs from contract
    _inputs = list(ctx.exploit_contract_extra.get('inputs') or [])
    if _inputs:
        lines.append(f'Attacker Inputs: {", ".join(str(i) for i in _inputs)}')

    # Seed PoC from CVE references
    if ctx.seed_poc:
        _poc_snippet = ctx.seed_poc[:3000]
        lines.append(
            f'\n## SEED PoC / REFERENCE IMPLEMENTATION\n'
            f'An existing exploit or patch was found for this CVE. '
            f'Adapt and reuse this proven code instead of writing from scratch. '
            f'Modify it only as needed to fit the current codebase, TARGET_BINARY / '
            f'library harness, and observed_surface.\n'
            f'```\n{_poc_snippet}\n```'
        )

    return '\n'.join(lines)


def _build_surface_constraints(ctx, pov_language: str) -> str:
    """Build CONSTRAINTS section — only rules relevant to this surface type."""
    lines = ['## CONSTRAINTS']

    # Universal constraints
    lines.append(f'0. Use only {pov_language} standard library.')
    lines.append('1. Print the SPECIFIC behavioral marker for the vulnerability type (from observable_evidence) when the exploit condition is observed. Do NOT print generic "VULNERABILITY TRIGGERED" — the oracle treats it as self-report.')
    lines.append('2. Include error handling and concrete observable outcome checks.')
    lines.append('3. Make the PoV as deterministic as possible.')

    # Surface-specific constraints
    _stype = ctx.surface_type or ''
    _harness = ctx.harness_type or ''
    _repo_cls = ctx.repo_surface_class or ''
    # Resolve runtime early so all branches can use it; fall back to detected_language
    # when runtime_family is not set (ensures JS/TS repos get the right scaffold).
    _runtime = (ctx.runtime_family or getattr(ctx, 'detected_language', '') or '').lower()

    if _stype in ('native_elf', '') and _harness != 'compiled_harness' and 'library' not in _repo_cls \
            and _runtime not in ('javascript', 'node', 'typescript', 'python', 'ruby', 'php', 'java'):
        # Native CLI binary
        lines.append(
            '4. CRITICAL — DO NOT COMPILE FROM SOURCE: The binary is ALREADY built with ASan. '
            'Use TARGET_BINARY env var. NEVER write gcc/clang/cmake compile commands.'
        )
        lines.append(
            '5. Native proof MUST produce ASan output, SIGSEGV/SIGABRT (exit 134/139). '
            'Printing "VULNERABILITY TRIGGERED" alone is NOT accepted for native targets.'
        )
        # Canonical PoV scaffold for native targets
        lines.append(
            '6. MANDATORY SCAFFOLD for native CLI targets — your script MUST follow this structure:\n'
            '```python\n'
            'import os, subprocess, sys, tempfile\n'
            '\n'
            '# Module-level: read binary path from environment (set by harness)\n'
            'TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", "")\n'
            'CODEBASE_PATH = os.environ.get("CODEBASE_PATH", "/workspace/codebase")\n'
            '\n'
            'def main():\n'
            '    binary = TARGET_BINARY  # reference module-level var, do NOT reassign TARGET_BINARY\n'
            '    if not binary or not os.path.isfile(binary):\n'
            '        print(f"binary not found: {binary!r}", file=sys.stderr)\n'
            '        sys.exit(1)\n'
            '    # ... build payload, write to temp file ...\n'
            '    result = subprocess.run([binary, payload_path], capture_output=True, timeout=30)\n'
            '    stderr_text = result.stderr.decode("utf-8", errors="replace")\n'
            '    if result.returncode in (134, 139) or "AddressSanitizer" in stderr_text:\n'
            '        print(stderr_text)\n'
            '        # ASan/crash output IS the proof — no generic marker needed\n'
            '\n'
            'if __name__ == "__main__":\n'
            '    main()\n'
            '```\n'
            'CRITICAL: TARGET_BINARY is set at module level. Inside main(), use `binary = TARGET_BINARY` '
            '(a local alias) — NEVER write `TARGET_BINARY = ...` inside any function.'
        )
    elif _harness == 'compiled_harness' or 'library_c' in _repo_cls:
        lines.append(
            '4. C LIBRARY TARGET — write inline C harness calling vulnerable function directly. '
            'Compile with: gcc -fsanitize=address,undefined -g harness.c -I$CODEBASE_PATH -lLIBNAME'
        )
    elif _stype == 'python_module':
        lines.append(
            '4. Python module: use `from package.module import vulnerable_function`. '
            'The codebase is pip-installed. CODEBASE_PATH=/workspace/codebase.'
        )
    elif _stype == 'node_module':
        lines.append(
            '4. Node.js module: use require(process.env.LIB_REQUIRE_PATH || "/workspace/codebase"). '
            'NODE_PATH is set.'
        )
    elif _stype == 'web_service':
        _url = ctx.base_url or 'http://localhost:8000'
        lines.append(
            f'4. Web service target at {_url}. Use Python requests library. '
            'Do NOT use subprocess or TARGET_BINARY. Server is auto-started.'
        )

    # JS/TS target with Python PoV: provide the correct scaffold that uses
    # node subprocess instead of TARGET_BINARY (there is no compiled binary).
    # _runtime is already resolved above with detected_language fallback.
    if _runtime in ('javascript', 'node', 'typescript') and pov_language == 'python' and _stype not in ('web_service',):
        lines.append(
            '5. MANDATORY SCAFFOLD for JavaScript/TypeScript targets (Python PoV):\n'
            'Do NOT use TARGET_BINARY — there is no compiled binary for JS/TS targets.\n'
            'Instead, write a .js exploit file and run it with node:\n'
            '```python\n'
            'import os, subprocess, sys\n'
            '\n'
            'CODEBASE_PATH = os.environ.get("CODEBASE_PATH", "/workspace/codebase")\n'
            '\n'
            'def main():\n'
            '    exploit_js = """\n'
            'const mod = require(process.env.CODEBASE_PATH || \'/workspace/codebase\');\n'
            '// ... trigger the vulnerability ...\n'
            '// Print the SPECIFIC behavioral marker for this CWE type:\n'
            '//   Prototype pollution → console.log("PROTOTYPE_POLLUTED")\n'
            '//   XSS                → console.log("XSS_CONFIRMED")\n'
            '//   Path traversal     → console.log("PATH_TRAVERSAL_CONFIRMED")\n'
            '//   Auth bypass        → console.log("UNAUTHORIZED_ACCESS_GRANTED")\n'
            '//   Info disclosure    → console.log("SENSITIVE_DATA_LEAKED")\n'
            '// Do NOT print "VULNERABILITY TRIGGERED" — the oracle ignores it.\n'
            'console.log("PROTOTYPE_POLLUTED");  // replace with correct marker for this CWE\n'
            '"""\n'
            '    env = {**os.environ, "NODE_PATH": os.path.join(CODEBASE_PATH, "node_modules"),\n'
            '           "CODEBASE_PATH": CODEBASE_PATH}\n'
            '    result = subprocess.run(["node", "-e", exploit_js],\n'
            '        capture_output=True, timeout=30, env=env)\n'
            '    sys.stdout.write(result.stdout.decode("utf-8", errors="replace"))\n'
            '    sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))\n'
            '    sys.exit(result.returncode)\n'
            '\n'
            'if __name__ == "__main__":\n'
            '    main()\n'
            '```\n'
            'CRITICAL: For JS/TS targets, use `node -e` or write a .js temp file and run with node. '
            'Do NOT reference TARGET_BINARY at all. Print ONLY the specific behavioral marker for the CWE type.'
        )

    # C string embedding rule (relevant for compiled harness and native)
    if _stype in ('native_elf', '') or _harness == 'compiled_harness':
        lines.append(
            '6. When embedding C source in Python string, use raw triple-quoted string (r\"\"\") '
            'or double-escape all newlines (\\\\n).'
        )
        lines.append(
            '7. For multi-file C projects: compile ALL relevant sibling .c files together '
            'using glob.glob("src/*.c"). Single file compile causes undefined reference errors.'
        )

    # Python scoping rule
    lines.append(
        '8. Python scoping: TARGET_BINARY is defined at MODULE LEVEL. Inside functions, '
        'reference it directly (e.g. `binary = TARGET_BINARY`). NEVER write '
        '`TARGET_BINARY = os.environ.get(...)` inside a function — that causes UnboundLocalError.'
    )
    lines.append('9. Return JSON only with the exact response shape described below.')

    return '\n'.join(lines)


# ── Repo-adaptive rules constant & builder ──────────────────────────
_C_LIBRARY_HARNESS_TEMPLATE = (
    'CRITICAL: This is a C/C++ library target (no standalone binary or function harness required).\n'
    'Use this EXACT pattern:\n'
    '\n'
    '```python\n'
    'import subprocess, os, glob, tempfile\n'
    '\n'
    '# Auto-discovered by the harness\n'
    'LIB_NAMES = os.environ.get("AUTOPOV_LIB_NAMES", "").split()\n'
    'LIB_DIRS = [d for d in os.environ.get("AUTOPOV_LIB_LINK_DIRS", "").split(":") if d]\n'
    'INC_DIRS = [d for d in os.environ.get("AUTOPOV_LIB_INCLUDE_DIRS", "/workspace/codebase").split(":") if d]\n'
    '\n'
    'harness_code = r"""#include <stdio.h>\n'
    '#include <string.h>\n'
    '#include "HEADER_FROM_REPO.h"   // replace with actual header\n'
    '\n'
    'int main(void) {\n'
    '    // Craft payload that reaches the vulnerable line\n'
    '    VULNERABLE_FUNCTION(...);   // exact function from contract.target_entrypoint\n'
    '    return 0;\n'
    '}\n'
    '"""\n'
    '\n'
    'with open("/tmp/harness.c", "w") as f:\n'
    '    f.write(harness_code)\n'
    '\n'
    'cmd = ["clang", "-fsanitize=address,undefined", "-g", "-O0", "/tmp/harness.c"]\n'
    'for d in INC_DIRS:\n'
    '    cmd.extend(["-I", d])\n'
    'for d in LIB_DIRS:\n'
    '    cmd.extend(["-L", d, f"-Wl,-rpath,{d}"])\n'
    'for lib in LIB_NAMES:\n'
    '    cmd.append(f"-l{lib}")\n'
    'cmd.extend(["-o", "/tmp/harness"])\n'
    '\n'
    'subprocess.run(cmd, check=True, capture_output=True)\n'
    'result = subprocess.run(["/tmp/harness"], capture_output=True, text=True, timeout=15)\n'
    'print(result.stdout)\n'
    'print(result.stderr)\n'
    'if "AddressSanitizer" in result.stderr or "UndefinedBehaviorSanitizer" in result.stderr or result.returncode in (134, 139):\n'
    '    print("EXCEPTION_TRIGGERED")  # sanitizer/crash evidence is the real proof\n'
    '```\n'
)


def _build_repo_adaptive_rules(ctx) -> str:
    """Build REPO-ADAPTIVE RULES section — conditional on surface intelligence."""
    _repo_cls = (ctx.repo_surface_class or '').lower()
    _harness = ctx.harness_type or ''
    _probe_surface = ''
    _exec_surf = ''
    if ctx.exploit_contract_extra:
        _probe_surface = (str(ctx.exploit_contract_extra.get('probe_surface_type') or '')).lower()
        _exec_surf = (str(ctx.exploit_contract_extra.get('execution_surface') or '')).lower()

    # Only inject when surface intelligence is available
    _has_real_harness = _harness and _harness not in ('subprocess_binary', 'unknown', '')
    if not (_repo_cls or _has_real_harness or ctx.binary_name or _probe_surface):
        return ''

    lines = ['## REPO-ADAPTIVE RULES (follow exactly what recon/probe discovered)']
    lines.append(
        '- If observed_surface or probe_result shows a real binary and entrypoint_candidates, '
        'use subprocess_binary with the exact binary name and observed subcommands/flags.'
    )
    lines.append(
        '- If the repo is a library (no standalone binary, or repo_surface_class contains "library" '
        'or target_entrypoint is a function name), output a C harness that compiles and directly '
        'calls the vulnerable function using AUTOPOV_LIB_* env vars.'
    )
    lines.append('- Always compile C harnesses with `-fsanitize=address,undefined -g -O0`.')

    # Inject full C library harness template when target is a C library
    if ('library' in _repo_cls and 'c' in _repo_cls) \
            or _probe_surface == 'c_library' \
            or _exec_surf == 'c_library_harness' \
            or _harness == 'compiled_harness':
        lines.append('')
        lines.append(_C_LIBRARY_HARNESS_TEMPLATE)
        # Include library API context when available
        _lib_api = (ctx.library_api_context or '').strip()
        if _lib_api:
            lines.append(f'Known public API functions:\n{_lib_api[:2000]}')

    return '\n'.join(lines)


def _build_narrative_generation_prompt(ctx, pov_language: str) -> str:
    """Build a complete narrative PoV generation prompt from FindingContext."""
    sections = []

    # Section 1: EXPLOIT BRIEF (highest value — never trimmed)
    sections.append(_build_exploit_brief(ctx))

    # Section 2: EXECUTION RECIPE (highest value — never trimmed)
    sections.append(_build_execution_recipe(ctx))

    # Section 2.25: REPO-ADAPTIVE RULES (conditional on surface intel)
    _adaptive = _build_repo_adaptive_rules(ctx)
    if _adaptive:
        sections.append(_adaptive)

    # Section 2.5: WINNING STRATEGIES (high value — never trimmed)
    if ctx.previous_winning_strategies:
        ws_lines = ['## PROVEN STRATEGIES FROM PREVIOUS SCANS']
        ws_lines.append('These strategies previously SUCCEEDED for this exact repo. Prefer them:')
        for _ws in ctx.previous_winning_strategies[:5]:
            ws_lines.append(f'  - CWE={_ws.get("cwe", "?")} proof={_ws.get("proof_type", "?")} '
                           f'harness={_ws.get("harness_type", "?")} format={_ws.get("input_format", "?")} '
                           f'strategy={_ws.get("strategy_summary", "")}')
        sections.append('\n'.join(ws_lines))

    # Section 3: VULNERABLE CODE (trimmable)
    if ctx.vulnerable_code:
        vc_section = '## VULNERABLE CODE'
        vc_section += f'\n```\n{ctx.vulnerable_code}\n```'
        if ctx.data_flow_path:
            vc_section += f'\nData flow: {ctx.data_flow_path}'
        if ctx.joern_context and not ctx.data_flow_path:
            # Include compact Joern context
            _joern_compact = ctx.joern_context[:500].strip()
            vc_section += f'\nStatic analysis:\n{_joern_compact}'
        sections.append(vc_section)

    if ctx.joern_unreachable:
        sections.append(
            '## WARNING: No static taint path found\n'
            'Joern CPG found no data-flow path from attacker-controlled input to this sink. '
            'Prioritise demonstrating a concrete data-flow path.'
        )

    # Section 4: CONSTRAINTS (surface-type-specific)
    sections.append(_build_surface_constraints(ctx, pov_language))

    # Section 5: RUNTIME FEEDBACK (from previous attempts)
    if ctx.runtime_feedback:
        sections.append(f'## RUNTIME FEEDBACK (from previous attempt)\n{ctx.runtime_feedback}')

    # Section 6: REFERENCE DATA (lowest priority — trimmed first)
    ref_lines = []
    if ctx.help_text:
        ref_lines.append(f'Help output:\n```\n{ctx.help_text[:1200]}\n```')
    if ctx.recon_entrypoints:
        ref_lines.append('Entry points:')
        for ep in ctx.recon_entrypoints[:5]:
            ref_lines.append(f'  - {ep.get("name", "")} ({ep.get("file", "")}): {ep.get("how_to_invoke", "")}')
    if ctx.attack_surfaces:
        ref_lines.append('Attack surfaces:')
        for surf in ctx.attack_surfaces[:5]:
            ref_lines.append(f'  - type={surf.get("type", "")}, format={surf.get("format", "")}, entry={surf.get("entry", "")}')
    if ctx.framework_hints:
        ref_lines.append(f'Frameworks: {", ".join(ctx.framework_hints)}')
    if ctx.interesting_strings:
        ref_lines.append(f'Binary strings of interest: {"; ".join(ctx.interesting_strings[:10])}')
    if ctx.code_context:
        ref_lines.append(f'Surrounding code:\n```\n{ctx.code_context[:1500]}\n```')
    if ref_lines:
        sections.append('## REFERENCE DATA\n' + '\n'.join(ref_lines))

    # Remaining contract fields as JSON
    if ctx.exploit_contract_extra:
        _filtered = {k: v for k, v in ctx.exploit_contract_extra.items()
                     if k not in ('runtime_feedback', 'inputs') and v}
        if _filtered:
            sections.append(f'## ADDITIONAL EXPLOIT CONTRACT\n```json\n{json.dumps(_filtered, indent=2, default=str)}\n```')

    priority_sections = '\n\n'.join(sections)
    return POV_GENERATION_PROMPT_STRUCTURED.format(
        pov_language=pov_language or 'python',
        priority_sections=priority_sections,
    )


def format_pov_generation_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, target_language: str, pov_language: str, exploit_contract=None, runtime_feedback: str = '', subcommands=None, probe_context: str = '', observed_surface: dict = None, joern_context: str = '', recon_report: dict = None) -> str:
    """Build PoV generation prompt. Backward-compatible signature.

    Internally synthesizes a FindingContext from all available arguments,
    then delegates to the narrative prompt builder.
    """
    from agents.finding_context import synthesize_finding_context

    _ec = exploit_contract or {}
    _obs = dict(observed_surface or {})
    _rr = dict(recon_report or {})

    # Build probe_dict from observed_surface + exploit_contract probe fields
    _probe_dict = {}
    for _pk in ('probe_binary_path', 'probe_input_surface', 'probe_format_hint',
                'probe_surface_type', 'probe_entry_command', 'probe_base_url',
                'probe_help_text', 'probe_discovered_subcommands',
                'probe_inferred_extensions', 'probe_rejection_patterns',
                'probe_bootstrap_subcommand', 'probe_cli_flags',
                'probe_crash_observed', 'probe_crash_signal', 'probe_crash_output',
                'probe_exports', 'probe_baseline_exit_code', 'probe_baseline_stderr',
                'probe_binary_is_test', 'probe_install_ok'):
        _val = _ec.get(_pk) or _obs.get(_pk)
        if _val:
            _probe_dict[_pk] = _val

    # Build finding dict from arguments
    _finding = {
        'cwe_type': cwe_type,
        'filepath': filepath,
        'line_number': line_number,
        'explanation': explanation,
        'language': target_language,
        'exploit_contract': _ec,
    }

    ctx = synthesize_finding_context(
        finding=_finding,
        exploit_contract=_ec,
        recon_report=_rr,
        probe_dict=_probe_dict,
        vulnerable_code=vulnerable_code,
        code_context=code_context,
        joern_context=joern_context,
        runtime_feedback=runtime_feedback,
        observed_surface=_obs,
    )

    return _build_narrative_generation_prompt(ctx, pov_language or 'python')


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


def _build_narrative_refinement_prompt(ctx, pov_language: str) -> str:
    """Build a complete narrative refinement prompt from FindingContext."""
    sections = []

    # Section 1: WHAT WENT WRONG (most important for refinement)
    s1_lines = [f'## WHAT WENT WRONG (Attempt #{ctx.attempt_number})']
    if ctx.validation_errors:
        s1_lines.append('Validation Errors:')
        for err in ctx.validation_errors:
            s1_lines.append(f'  - {err}')
    # Extract exact failing line from stderr traceback if available
    _stderr_full = ''
    if ctx.runtime_feedback_dict:
        _sd = ctx.runtime_feedback_dict.get('signal_detail')
        if _sd and isinstance(_sd, dict):
            _stderr_full = _sd.get('stderr_snippet', '')
        if not _stderr_full:
            _stderr_full = str(ctx.runtime_feedback_dict.get('stderr', ''))
    if not _stderr_full and ctx.runtime_feedback:
        _rf = ctx.runtime_feedback
        if isinstance(_rf, dict):
            _stderr_full = str(_rf.get('stderr_excerpt', '') or _rf.get('stderr', ''))
    if _stderr_full:
        _tb_match = re.search(r'File "[^"]+", line (\d+), in .+\n\s+(.+)\n(\w+Error: .+)', _stderr_full)
        if _tb_match:
            _line_no = _tb_match.group(1)
            _code_line = _tb_match.group(2).strip()
            _err_msg = _tb_match.group(3).strip()
            s1_lines.append(
                f"EXACT FAILURE LOCATION:\n"
                f"  Line {_line_no}: {_code_line}\n"
                f"  Error: {_err_msg}\n"
                f"  FIX: Change line {_line_no} so that '{_err_msg}' does not occur."
            )
    if ctx.runtime_feedback:
        s1_lines.append(f'Runtime Feedback:\n{str(ctx.runtime_feedback)[:800]}')
    elif ctx.runtime_feedback_dict:
        _sd = ctx.runtime_feedback_dict.get('signal_detail')
        if _sd and isinstance(_sd, dict):
            s1_lines.append(f'Signal Class: {_sd.get("signal_class", "unknown")}')
            s1_lines.append(f'Exit Code: {_sd.get("exit_code", "N/A")}')
            _stderr = _sd.get('stderr_snippet', '')
            if _stderr:
                s1_lines.append(f'Stderr:\n{_stderr[:500]}')
        else:
            s1_lines.append(f'Runtime Feedback: {json.dumps(ctx.runtime_feedback_dict, default=str)[:800]}')
    sections.append('\n'.join(s1_lines))

    # Section 2: WHAT TO CHANGE
    s2_lines = ['## WHAT TO CHANGE']
    s2_lines.append('Based on the failure above, you must fix the PoV. Key reminders:')
    if ctx.binary_name:
        s2_lines.append(
            f'- Binary name is {ctx.binary_name!r}. Read it from env at MODULE LEVEL: '
            f'TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", ""). '
            f'Inside main(), use `binary = TARGET_BINARY` — do NOT reassign TARGET_BINARY in functions.'
        )
    if ctx.input_method == 'file_argument':
        s2_lines.append('- Input via FILE ARGUMENT — write payload to temp file, pass path as CLI arg')
    elif ctx.input_method == 'stdin':
        s2_lines.append('- Input via STDIN — pipe payload via subprocess input=')
    if ctx.subcommands:
        s2_lines.append(f'- First positional arg MUST be a subcommand: {", ".join(ctx.subcommands)}')
    if ctx.input_format:
        s2_lines.append(f'- Payload format: {ctx.input_format.upper()} — must be valid {ctx.input_format}')
    if ctx.needs_key_bootstrap:
        _boot = ctx.bootstrap_subcommand or 'keygen'
        s2_lines.append(f'- KEY BOOTSTRAP: Run `{_boot}` before the exploit step')
    if ctx.cve_proof_hint:
        s2_lines.append(f'- CVE hint: {ctx.cve_proof_hint}')

    # If any validation error mentions TARGET_BINARY shadowing or NameError,
    # inject the canonical corrected scaffold so the LLM sees exactly what to produce.
    _has_target_binary_issue = any(
        'TARGET_BINARY' in str(e) and ('shadow' in str(e).lower() or 'nameerror' in str(e).lower() or 'unboundlocal' in str(e).lower())
        for e in (ctx.validation_errors or [])
    )
    _stype = ctx.surface_type or ''
    _harness = ctx.harness_type or ''
    if _has_target_binary_issue:
        # Put the critical fix instruction at the VERY TOP of the WHAT TO CHANGE section
        # so the LLM sees it first, before any other instructions.
        s2_lines.insert(0,
            '- **CRITICAL FIX REQUIRED**: Your previous script put `TARGET_BINARY = os.environ.get(...)` '
            'INSIDE a function. This causes Python UnboundLocalError. You MUST move it to MODULE LEVEL '
            '(BEFORE any `def`). Inside main(), use `binary = TARGET_BINARY` (a read-only alias). '
            'Do NOT write `TARGET_BINARY = ...` inside any function.'
        )
    if _has_target_binary_issue or (_stype in ('native_elf', '') and _harness != 'compiled_harness'):
        # Choose scaffold based on proof_category: behavioral vs crash
        _proof_cat = getattr(ctx, 'proof_category', '') or ''
        _proof_t = ctx.proof_type or ''
        _is_behavioral = (_proof_cat == 'behavioral' or _proof_t in (
            'behavioral_deviation', 'state_change', 'information_disclosure',
            'observable_output',
        ))
        if _is_behavioral:
            s2_lines.append(
                '- MANDATORY corrected structure for your PoV script (BEHAVIORAL VERIFICATION):\n'
                '```python\n'
                'import os, subprocess, sys, tempfile, stat\n'
                '\n'
                '# Module-level: read binary path from environment (set by harness)\n'
                'TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", "")\n'
                'CODEBASE_PATH = os.environ.get("CODEBASE_PATH", "/workspace/codebase")\n'
                '\n'
                'def main():\n'
                '    binary = TARGET_BINARY  # local alias, do NOT reassign TARGET_BINARY\n'
                '    if not binary or not os.path.isfile(binary):\n'
                '        print(f"binary not found: {binary!r}", file=sys.stderr)\n'
                '        sys.exit(1)\n'
                '    # ... build crafted input, invoke binary ...\n'
                '    result = subprocess.run([binary, ...], capture_output=True, timeout=30)\n'
                '    # POST-EXECUTION VERIFICATION (check state, not crash):\n'
                '    # Print SPECIFIC evidence markers — the oracle matches these exact strings.\n'
                '    # Do NOT print generic "VULNERABILITY TRIGGERED" — it will be rejected.\n'
                '    # Example: check if file was created at a traversed path\n'
                '    if os.path.exists(suspect_path):\n'
                '        print(f"FILE_CREATED_OUTSIDE_ALLOWED_DIR: {suspect_path}")\n'
                '        sys.exit(1)\n'
                '    # Example: check file permissions\n'
                '    if os.path.exists(output_file):\n'
                '        mode = os.stat(output_file).st_mode & 0o777\n'
                '        if mode & 0o002:  # world-writable\n'
                '            print(f"INSECURE_PERMISSION: {oct(mode)}")\n'
                '            sys.exit(1)\n'
                '    # Example: check output for sensitive data\n'
                '    stdout_text = result.stdout.decode("utf-8", errors="replace")\n'
                '    if "secret" in stdout_text or "/etc/" in stdout_text:\n'
                '        print(f"SENSITIVE_DATA_LEAKED")\n'
                '        sys.exit(1)\n'
                '\n'
                'if __name__ == "__main__":\n'
                '    main()\n'
                '```'
            )
        else:
            s2_lines.append(
                '- MANDATORY corrected structure for your PoV script:\n'
                '```python\n'
                'import os, subprocess, sys, tempfile\n'
                '\n'
                '# Module-level: read binary path from environment (set by harness)\n'
                'TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", "")\n'
                'CODEBASE_PATH = os.environ.get("CODEBASE_PATH", "/workspace/codebase")\n'
                '\n'
                'def main():\n'
                '    binary = TARGET_BINARY  # local alias, do NOT reassign TARGET_BINARY\n'
                '    if not binary or not os.path.isfile(binary):\n'
                '        print(f"binary not found: {binary!r}", file=sys.stderr)\n'
                '        sys.exit(1)\n'
                '    # ... build payload, write to temp file ...\n'
                '    result = subprocess.run([binary, payload_path], capture_output=True, timeout=30)\n'
                '    # Propagate ALL output so the crash oracle can detect ASan/SEGV evidence\n'
                '    if result.stderr:\n'
                '        sys.stderr.write(result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else result.stderr)\n'
                '    if result.stdout:\n'
                '        sys.stdout.write(result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else result.stdout or "")\n'
                '    # Propagate the binary exit code so the harness captures crash signals\n'
                '    sys.exit(result.returncode)\n'
                '\n'
                'if __name__ == "__main__":\n'
                '    main()\n'
                '```'
            )

    sections.append('\n'.join(s2_lines))

    # Section 3: EXPLOIT BRIEF (reminder)
    sections.append(_build_exploit_brief(ctx))

    # Section 3.25: REPO-ADAPTIVE RULES (conditional on surface intel)
    _adaptive = _build_repo_adaptive_rules(ctx)
    if _adaptive:
        sections.append(_adaptive)

    # Section 3.5: WINNING STRATEGIES (high value — never trimmed)
    if ctx.previous_winning_strategies:
        ws_lines = ['## PROVEN STRATEGIES FROM PREVIOUS SCANS']
        ws_lines.append('These strategies previously SUCCEEDED for this exact repo. Prefer them:')
        for _ws in ctx.previous_winning_strategies[:5]:
            ws_lines.append(f'  - CWE={_ws.get("cwe", "?")} proof={_ws.get("proof_type", "?")} '
                           f'harness={_ws.get("harness_type", "?")} format={_ws.get("input_format", "?")} '
                           f'strategy={_ws.get("strategy_summary", "")}')
        sections.append('\n'.join(ws_lines))

    # Section 4: FAILED SCRIPT
    if ctx.failed_pov:
        sections.append(f'## FAILED SCRIPT\n```python\n{ctx.failed_pov}\n```')

    # Section 5: VULNERABLE CODE (trimmable)
    if ctx.vulnerable_code:
        vc = f'## VULNERABLE CODE\n```\n{ctx.vulnerable_code}\n```'
        if ctx.data_flow_path:
            vc += f'\nData flow: {ctx.data_flow_path}'
        sections.append(vc)

    # Section 6: REFERENCE DATA (lowest priority)
    if ctx.code_context:
        sections.append(f'## CODE CONTEXT\n```\n{ctx.code_context[:1000]}\n```')

    # Contract extras
    if ctx.exploit_contract_extra:
        _filtered = {k: v for k, v in ctx.exploit_contract_extra.items()
                     if k not in ('runtime_feedback',) and v}
        if _filtered:
            sections.append(f'## ADDITIONAL EXPLOIT CONTRACT\n```json\n{json.dumps(_filtered, indent=2, default=str)}\n```')

    return POV_REFINEMENT_PROMPT_STRUCTURED.format(
        input_payload='\n\n'.join(sections)
    )


def format_pov_refinement_prompt(cwe_type: str, filepath: str, line_number: int, vulnerable_code: str, explanation: str, code_context: str, failed_pov: str, validation_errors, attempt_number: int, target_language: str = 'python', exploit_contract=None, runtime_feedback: str = '', subcommands=None, probe_context: str = '', observed_surface: dict = None, recon_report: dict = None) -> str:
    """Build PoV refinement prompt. Backward-compatible signature.

    Internally synthesizes FindingContext and delegates to narrative builder.
    """
    from agents.finding_context import synthesize_finding_context

    _ec = exploit_contract or {}
    _obs = dict(observed_surface or {})

    _probe_dict = {}
    for _pk in ('probe_binary_path', 'probe_input_surface', 'probe_format_hint',
                'probe_surface_type', 'probe_entry_command', 'probe_base_url',
                'probe_help_text', 'probe_discovered_subcommands',
                'probe_inferred_extensions', 'probe_rejection_patterns',
                'probe_bootstrap_subcommand'):
        _val = _ec.get(_pk) or _obs.get(_pk)
        if _val:
            _probe_dict[_pk] = _val

    _finding = {
        'cwe_type': cwe_type,
        'filepath': filepath,
        'line_number': line_number,
        'explanation': explanation,
        'language': target_language,
        'exploit_contract': _ec,
    }

    ctx = synthesize_finding_context(
        finding=_finding,
        exploit_contract=_ec,
        recon_report=dict(recon_report or {}),
        probe_dict=_probe_dict,
        vulnerable_code=vulnerable_code,
        code_context=code_context,
        runtime_feedback=runtime_feedback,
        observed_surface=_obs,
    )
    # Populate refinement-specific fields
    ctx.attempt_number = attempt_number
    ctx.failed_pov = failed_pov or ''
    ctx.validation_errors = list(validation_errors or [])

    return _build_narrative_refinement_prompt(ctx, target_language or 'python')


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
  signal, write the captured stderr to sys.stderr BEFORE printing a specific marker.
  Example pattern: sys.stderr.write(decode(se)); print("EXCEPTION_TRIGGERED"); return
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
    recon_report: dict = None,
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

    # ── Env var guidance so offline models know about TARGET_BINARY discovery ──
    env_guidance = (
        '\nEnvironment Variables Available at Runtime:\n'
        '  TARGET_BINARY / TARGET_BIN: path to the pre-built target binary (read via os.environ.get)\n'
        '  AUTOPOV_BOOTSTRAP_HOME: writable home dir for keygen operations\n'
        '  AUTOPOV_MODE: set to "c_library_harness" when no CLI binary exists\n'
        '  AUTOPOV_LIB_NAMES / AUTOPOV_LIB_LINK_DIRS / AUTOPOV_LIB_INCLUDE_DIRS: library discovery env vars\n'
        '\nYour script MUST read TARGET_BINARY from environment:\n'
        '  TARGET_BINARY = os.environ.get("TARGET_BINARY") or os.environ.get("TARGET_BIN", "")\n'
    )
    contract_summary = contract_summary + env_guidance

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

    # ---------- c_library_harness enrichment for offline models ----------
    # The structured prompt path (format_pov_generation_prompt) injects a rich
    # c_library_harness_note with example harness, API context, and vulnerable
    # function source.  The scaffold path must replicate this so offline models
    # (e.g. qwen3) receive the same guidance.
    _repo_surface_cls_sc = str(contract.get('repo_surface_class') or '').strip().lower()
    _probe_sfc_sc = str(contract.get('probe_surface_type') or '').strip().lower()
    _exec_surf_sc = str(contract.get('execution_surface') or '').strip().lower()
    if (_repo_surface_cls_sc in ('library_c', 'library_c_with_cli')
            or _probe_sfc_sc == 'c_library'
            or _exec_surf_sc == 'c_library_harness'):
        _lib_api_ctx_sc = str(contract.get('library_api_context') or '').strip()
        _api_hint_sc = f'\nKnown public API functions:\n{_lib_api_ctx_sc}' if _lib_api_ctx_sc else ''
        _lib_harness_block = (
            '\n\n=== C LIBRARY HARNESS INSTRUCTIONS ===\n'
            'CRITICAL: This target is a C LIBRARY with NO standalone CLI binary. '
            'You MUST write an inline C harness that directly calls the vulnerable library function.\n\n'
            'The build environment automatically builds the library and exports these env vars:\n'
            '  - AUTOPOV_LIB_NAMES: space-separated library names (e.g. "z expat cjson")\n'
            '  - AUTOPOV_LIB_LINK_DIRS: colon-separated directories containing .a/.so files\n'
            '  - AUTOPOV_LIB_INCLUDE_DIRS: colon-separated include directories\n\n'
            'Your PoV script MUST follow this exact pattern:\n'
            '```\n'
            'import subprocess, os, tempfile, glob\n'
            '\n'
            'HARNESS_CODE = r"""\n'
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n'
            '#include <string.h>\n'
            '#include "LIBRARY_HEADER.h"  // Replace with actual header from /workspace/codebase\n'
            '\n'
            'int main(void) {\n'
            '    // Craft malformed input that triggers the vulnerability\n'
            '    unsigned char payload[] = { /* malicious bytes */ };\n'
            '    size_t payload_len = sizeof(payload);\n'
            '\n'
            '    // Call the vulnerable API function directly\n'
            '    VULNERABLE_FUNCTION(payload, payload_len);\n'
            '\n'
            '    printf("PoV completed\\n");\n'
            '    return 0;\n'
            '}\n'
            '"""\n'
            '\n'
            'with open("/tmp/harness.c", "w") as f:\n'
            '    f.write(HARNESS_CODE)\n'
            '\n'
            '# Auto-discover library paths from the build environment\n'
            'lib_link_dirs = [d for d in os.environ.get("AUTOPOV_LIB_LINK_DIRS", "").split(":") if d]\n'
            'lib_names = os.environ.get("AUTOPOV_LIB_NAMES", "").split()\n'
            'inc_dirs = [d for d in os.environ.get("AUTOPOV_LIB_INCLUDE_DIRS", "/workspace/codebase").split(":") if d and os.path.isdir(d)]\n'
            '\n'
            '# Build compile command dynamically\n'
            'compile_cmd = ["clang", "-fsanitize=address,undefined", "-O0", "-g", "/tmp/harness.c"]\n'
            'for d in inc_dirs:\n'
            '    compile_cmd.extend(["-I", d])\n'
            'for d in lib_link_dirs:\n'
            '    compile_cmd.extend([f"-L{d}", f"-Wl,-rpath,{d}"])\n'
            'for name in lib_names:\n'
            '    compile_cmd.append(f"-l{name}")\n'
            'if not lib_names:\n'
            '    for d in lib_link_dirs:\n'
            '        for a in sorted(glob.glob(os.path.join(d, "lib*.a"))):\n'
            '            compile_cmd.append(a)\n'
            'compile_cmd.extend(["-lm", "-lpthread", "-o", "/tmp/harness"])\n'
            '\n'
            'result = subprocess.run(compile_cmd, capture_output=True, text=True)\n'
            'if result.returncode != 0:\n'
            '    print(f"Compile failed: {result.stderr}")\n'
            '    exit(1)\n'
            '\n'
            '# Run the harness\n'
            'result = subprocess.run(["/tmp/harness"], capture_output=True, text=True, timeout=10)\n'
            'print(result.stdout)\n'
            'print(result.stderr)\n'
            '```\n\n'
            'IMPORTANT RULES:\n'
            '  - Replace LIBRARY_HEADER.h with the actual header (find .h files in /workspace/codebase or /workspace/codebase/include)\n'
            '  - Replace VULNERABLE_FUNCTION with the actual function from the API below\n'
            '  - The environment auto-discovers library names and paths — use the env vars as shown above\n'
            '  - The harness must DIRECTLY call library functions — do NOT shell out to a binary\n'
            '  - Success = AddressSanitizer output in stderr (heap-buffer-overflow, use-after-free, etc.)\n'
            '  - Do NOT just print VULNERABILITY TRIGGERED — you MUST trigger a real ASan crash\n'
            + _api_hint_sc
        )
        # Inject vulnerable function source if available
        _vuln_func_src_sc = str(contract.get('vulnerable_function_source') or '').strip()
        if _vuln_func_src_sc:
            _lib_harness_block += (
                '\n\nVULNERABLE FUNCTION SOURCE CODE (from the actual repo):\n'
                '```c\n' + _vuln_func_src_sc[:4000] + '\n```\n'
                'Study this function carefully. Your harness MUST call this exact function '
                'with arguments that trigger the vulnerability path shown above. '
                'Pay attention to argument types, required initialization calls, and cleanup.'
            )
        body = body.rstrip() + _lib_harness_block

    # Append binary surface block (help_text + subcommands) so model uses real invocations
    surface_block = _build_binary_surface_block(
        subcommands=subcommands,
        observed_surface=observed_surface or {},
        recon_subcommands=(exploit_contract or {}).get('recon_subcommands') if exploit_contract else None,
    )
    if surface_block:
        body = body.rstrip() + surface_block
    # ── Append recon intelligence for offline scaffold (mirrors online path) ──
    if recon_report:
        _sc_rc = []
        if recon_report.get('project_type'):
            _sc_rc.append(f'- Project type: {recon_report["project_type"]}')
        if recon_report.get('runtime_family'):
            _sc_rc.append(f'- Runtime: {recon_report["runtime_family"]}')
        if recon_report.get('input_format_hints'):
            _sc_rc.append(f'- Input formats: {", ".join(str(h) for h in recon_report["input_format_hints"][:5])}')
        if recon_report.get('attack_surfaces'):
            _sc_rc.append(f'- Attack surfaces: {json.dumps(recon_report["attack_surfaces"][:3])}')
        if recon_report.get('build_system'):
            _sc_rc.append(f'- Build system: {recon_report["build_system"]}')
        if _sc_rc:
            body = body.rstrip() + '\n\nREPOSITORY INTELLIGENCE:\n' + '\n'.join(_sc_rc)
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
    'PROOF_STRATEGY_PROMPT',
    'format_proof_strategy_prompt',
]


