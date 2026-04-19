#!/usr/bin/env python3
"""Quick smoke-test for the fixed _generated_c_harness_escaping_issues logic."""
import sys
sys.path.insert(0, '/app')

from agents.verifier import VulnerabilityVerifier

v = VulnerabilityVerifier.__new__(VulnerabilityVerifier)

# ── GOOD cases ────────────────────────────────────────────────────────────────
# 1. Double-quoted concatenated string with \\n (correct Python → C escape)
good_concat = (
    'harness_src = (\n'
    '    "#include <stdio.h>\\\\n"\n'
    '    "    fprintf(stderr, \\"fatal\\\\n\\");\\\\n"\n'
    ')\n'
    'harness_c.write_text(harness_src)\n'
)

# 2. Raw string with \n (also fine — the raw r-prefix makes \n literal backslash-n in the string)
good_raw = (
    "harness_c.write_text(r'''\n"
    "#include <stdio.h>\n"
    "int main(void) { fprintf(stderr, \"hello\\n\"); return 0; }\n"
    "''')\n"
)

# 3. The actual PoV from the fe5dec1f scan (the one that was wrongly rejected)
good_actual = (
    'harness_src = (\n'
    '    "#include <stdio.h>\\n"\n'   # \\n in JSON = \n in the string; but the C file gets \n
    '    "    fprintf(stderr, \\"fatal\\\\n\\");\\n"\n'
    ')\n'
    'harness_c.write_text(harness_src)\n'
)

# ── BAD cases ─────────────────────────────────────────────────────────────────
# 4. Actual bare newline inside a C string being written
bad_real_newline = (
    'code = \'fprintf(stderr, "hello\n'
    'world");\'\n'
    'open("test.c", "w").write(code)\n'
)

results = []
for name, script, expect_issues in [
    ("good_concat",        good_concat,     False),
    ("good_raw",           good_raw,        False),
    ("good_actual",        good_actual,     False),
    ("bad_real_newline",   bad_real_newline, True),
]:
    issues = v._generated_c_harness_escaping_issues(script)
    got_issues = bool(issues)
    status = "PASS" if (got_issues == expect_issues) else "FAIL"
    print(f"  [{status}] {name}: issues={issues}")

print("\nDone.")
