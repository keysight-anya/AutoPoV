"""Verify the verifier false-positive fix and the entrypoint canonicalisation fix."""
import sys, os
sys.path.insert(0, '/app')
os.chdir('/app')

from agents.verifier import VulnerabilityVerifier
v = VulnerabilityVerifier()

# ──────────────────────────────────────────────────────────────────────────────
# Test 1: the joinstr PoV must NOT trigger the bare-newline guard.
# The fprintf inside the r-string uses \\n (double-escaped) which is correct C.
# The multiline r-string body has REAL newlines but the regex must not cross them.
# ──────────────────────────────────────────────────────────────────────────────
joinstr_pov = r'''#!/usr/bin/env python3
import os, tempfile, subprocess

harness_c = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_strlen_calls = 0;

size_t strlen(const char *s) {
    g_strlen_calls++;
    if (g_strlen_calls == 1) return (size_t)-6;
    if (g_strlen_calls == 2) return 10;
    size_t n = 0;
    while (s[n] != '\0') n++;
    return n;
}

int main(void) {
    char *a = (char*)malloc(101);
    memset(a, 'A', 100);
    a[100] = '\0';
    fprintf(stdout, "out=%p calls=%d\n", (void*)a, g_strlen_calls);
    free(a);
    return 0;
}
"""

with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "pov_joinstr.c")
    with open(p, "w") as f:
        f.write(harness_c)
'''

issues = v._generated_c_harness_escaping_issues(joinstr_pov)
if issues:
    print(f"[FAIL] joinstr PoV still raises false positive: {issues}")
    sys.exit(1)
else:
    print("[PASS] joinstr PoV: no false positive (fix 1 works)")

# ──────────────────────────────────────────────────────────────────────────────
# Test 2: a GENUINELY broken harness (real bare newline inside fprintf arg) MUST
# still be caught.  The C source has a real newline mid-string, not \n.
# ──────────────────────────────────────────────────────────────────────────────
# Build a script where fprintf has a REAL newline between the quotes.
# We deliberately construct it in Python so the \n is a real newline char.
frprintf_with_real_nl = 'import os\nwith open("h.c","w") as f:\n    f.write(harness_c)\nharness_c = "int main(){fprintf(stdout, \\"hello\nworld\\"  );return 0;}"\n'
# Double-check: the \n above in the f-string is a *real* newline (ASCII 10)
assert '\n' in frprintf_with_real_nl, "test construction error"
broken_pov = frprintf_with_real_nl
issues2 = v._generated_c_harness_escaping_issues(broken_pov)
if not issues2:
    print("[FAIL] broken harness NOT detected (fix 1 is too permissive)")
    sys.exit(1)
else:
    print(f"[PASS] broken harness correctly detected: {issues2[0][:60]}...")

# ──────────────────────────────────────────────────────────────────────────────
# Test 3: backtick-function mining for CWE-787 / unknown entrypoint.
# ──────────────────────────────────────────────────────────────────────────────
explanation = (
    "The `key_derive()` function computes `memlen = 1UL << iexp` and then "
    "derives `memptr = memory + memlen - SHA256_BLOCK_SIZE`. If iexp < 5, "
    "memlen underflows. This is a real CWE-787 write out-of-bounds."
)
result = v._canonicalize_target_entrypoint(
    "unknown",
    "unsigned long memlen = 1UL << iexp;\nunsigned long mask = memlen - 1;",
    explanation,
    "/src/enchive.c",
    runtime_profile="c",
)
if result == "key_derive":
    print("[PASS] CWE-787 entrypoint extracted from explanation backticks: key_derive")
else:
    print(f"[FAIL] expected 'key_derive', got '{result}'")
    sys.exit(1)

print("\nAll 3 checks passed.")
sys.exit(0)
