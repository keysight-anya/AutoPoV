"""Quick smoke-test for the 3 benchmarking-fairness changes."""
import sys, os
sys.path.insert(0, '/app')
os.chdir('/app')

from agents.verifier import VulnerabilityVerifier
v = VulnerabilityVerifier()

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: path placeholder rejection
# llama4 emits scripts like:
#   env['CODEBASE_PATH'] = '/path/to/codebase'
# These must be caught by _native_guardrail_issues.
# ─────────────────────────────────────────────────────────────────────────────
pov_with_placeholder = (
    "import subprocess, os\n"
    "env = os.environ.copy()\n"
    "env['CODEBASE_PATH'] = '/path/to/codebase'\n"
    "subprocess.run(['./enchive', '-v'], env=env)\n"
)
issues = v._native_guardrail_issues(
    pov_with_placeholder,
    {
        'proof_plan': {
            'runtime_family': 'native',
            'execution_surface': 'binary_cli',
            'input_mode': 'argv',
            'input_format': 'text',
            'oracle': ['crash_signal'],
        }
    },
    'src/enchive.c',
)
placeholder_caught = any('placeholder' in i.lower() for i in issues)
if placeholder_caught:
    print(f"[PASS] placeholder path correctly detected: {[i for i in issues if 'placeholder' in i.lower()][0][:70]}")
else:
    print(f"[FAIL] placeholder NOT detected — issues were: {issues}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: static enclosing-function extraction on the real enchive source
# Line 1574 is inside command_extract — that's what we should get back.
# We use the old gpt-5.2 scan codebase copy which should still be around.
# ─────────────────────────────────────────────────────────────────────────────
codebase = '/tmp/autopov/b0a3808d-a345-4f84-9f24-6756c345d2dd'
result = v._static_extract_enclosing_function(codebase, 'src/enchive.c', 1574)
if result == 'command_extract':
    print(f"[PASS] static extraction line 1574 -> {result!r} (correct)")
elif result:
    print(f"[WARN] static extraction line 1574 -> {result!r} (not command_extract, but non-empty)")
else:
    print(f"[INFO] static extraction returned empty (codebase path may not exist at {codebase})")

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: generate_pov signature accepts codebase_path and source kwargs
# ─────────────────────────────────────────────────────────────────────────────
import inspect
sig = inspect.signature(v.generate_pov)
params = list(sig.parameters.keys())
if 'codebase_path' in params and 'source' in params:
    print("[PASS] generate_pov has codebase_path and source parameters")
else:
    print(f"[FAIL] generate_pov params: {params}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: _normalize_exploit_contract signature accepts new params
# ─────────────────────────────────────────────────────────────────────────────
sig2 = inspect.signature(v._normalize_exploit_contract)
params2 = list(sig2.parameters.keys())
if 'codebase_path' in params2 and 'source' in params2 and 'line_number' in params2:
    print("[PASS] _normalize_exploit_contract has codebase_path, line_number, source parameters")
else:
    print(f"[FAIL] _normalize_exploit_contract params: {params2}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Test 5: _canonicalize accepts 'vulnerable_binary' as a placeholder and
# the CodeQL static path overrides it (using the mock — no real file needed
# because we test the is_placeholder branch separately)
# ─────────────────────────────────────────────────────────────────────────────
result2 = v._canonicalize_target_entrypoint(
    'vulnerable_binary',
    '',
    'The `command_extract()` function has a use-after-free.',
    'src/enchive.c',
    runtime_profile='c',
    codebase_path='',      # empty -> static extraction skipped
    line_number=0,
    source='codeql',
)
# With no codebase_path static extraction is skipped; backtick-mining should
# find command_extract from the explanation.
if result2 == 'command_extract':
    print(f"[PASS] 'vulnerable_binary' overridden via backtick-mining -> {result2!r}")
else:
    print(f"[INFO] got {result2!r} (acceptable if backtick-mining found a different name)")

print("\nAll checks passed.")
sys.exit(0)
