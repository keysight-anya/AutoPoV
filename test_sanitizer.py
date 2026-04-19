#!/usr/bin/env python3
"""
Comprehensive test for agents/pov_sanitizer.py

Tests all C source embedding patterns an LLM might produce,
AND confirms the sanitizer is a strict no-op for every non-C language:
  Python, JavaScript/Node, Go, Ruby, PHP, Java, Web/HTTP harnesses.

C-language tests:
  1. Triple-quoted strings (most common with bare newlines)
  2. Concatenated double-quoted strings (correctly escaped — should be no-op)
  3. The actual enchive pattern (joinstr extractor)
  4. LD_PRELOAD library pattern (evil.c)
  5. Scripts that don’t write C — must be untouched
  6. Already-sanitized scripts — must not double-process
  7. Script with word 'harness' but no C file — no-op (regression guard)

Non-C language no-op tests:
  8.  Python PoV (eval sink)
  9.  JavaScript / Node PoV (command injection)
  10. Go PoV (race condition)
  11. Ruby PoV (command injection)
  12. PHP PoV (RCE via system())
  13. Java PoV (SQL injection via subprocess)
  14. Web / HTTP PoV (SSRF / request-based)
  15. Offline compact PoV (no C, short)
"""
import sys
sys.path.insert(0, '/app')

from agents.pov_sanitizer import sanitize_pov_script, SANITIZER_MARKER, _repair_c_source


def check_compiles(c_src: str, label: str) -> bool:
    """Try to compile a C source string with gcc and report the result."""
    import subprocess, tempfile, os
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(c_src)
        fname = f.name
    try:
        r = subprocess.run(
            ['gcc', '-x', 'c', '-fsyntax-only', '-w', fname],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            print(f"    [gcc OK] {label}")
            return True
        else:
            print(f"    [gcc FAIL] {label}: {r.stderr[:200]}")
            return False
    except FileNotFoundError:
        print(f"    [gcc N/A] {label}: gcc not found, skipping compile check")
        return True
    finally:
        os.unlink(fname)


TESTS = []

# ─────────────────────────────────────────────────────────────────────────────
# C LANGUAGE TESTS
# ─────────────────────────────────────────────────────────────────────────────

# TEST 1: Triple-quoted string with bare newlines in C string args (MUST REPAIR)
TESTS.append(("triple_quoted_bare_newline", True, r'''
#!/usr/bin/env python3
import tempfile
from pathlib import Path

harness_src = """
#include <stdio.h>
int main(void) {
    fprintf(stderr, "hello
world");
    return 0;
}
"""
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "h.c"
    p.write_text(harness_src)
'''))

# TEST 2: Concatenated double-quoted strings with CORRECT \n (NO-OP — already valid)
TESTS.append(("concat_correct_escape_noop", False, r'''
#!/usr/bin/env python3
import tempfile
from pathlib import Path

harness_src = (
    "#include <stdio.h>\n"
    "int main(void) {\n"
    "    fprintf(stderr, \"hello\\nworld\");\n"
    "    return 0;\n"
    "}\n"
)
Path("/tmp/h.c").write_text(harness_src)
'''))

# TEST 3: The actual enchive pattern — extract_joinstr + LD_PRELOAD
TESTS.append(("enchive_joinstr_pattern", True, '''
#!/usr/bin/env python3
import tempfile
from pathlib import Path

harness_src = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static void fatal(const char *msg) {
    fprintf(stderr, "fatal: %s\n", msg);
    abort();
}

static char *joinstr(int n, ...) {
    int i;
    size_t len = 1;
    return NULL;
}

int main(void) {
    char *r = joinstr(1, "x");
    fprintf(stderr, "done\n");
    return 0;
}
"""
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "harness.c"
    p.write_text(harness_src)
'''))

# TEST 4: Script that does NOT write any C file — must be completely unchanged
TESTS.append(("no_c_write_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys

def main():
    r = subprocess.run(["node", "--version"], capture_output=True, text=True)
    if "VULNERABILITY TRIGGERED" in r.stdout:
        print("VULNERABILITY TRIGGERED")
        return 0
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
'''))

# TEST 5: Bare newline in LD_PRELOAD evil_strlen.so source (evil.c)
TESTS.append(("ld_preload_pattern", True, '''
#!/usr/bin/env python3
import tempfile
from pathlib import Path

evil_src = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

size_t strlen(const char *s) {
    static size_t (*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "strlen");
    const char *e = getenv("POV");
    if (e && e[0] == '1' && s && strncmp(s, "POV_A:", 6) == 0) {
        fprintf(stderr, "intercepted\n");
        return (size_t)-1 - 64;
    }
    return real(s);
}
"""
with tempfile.TemporaryDirectory() as td:
    Path(td, "evil.c").write_text(evil_src)
'''))

# TEST 6: Already sanitized — must NOT be processed again (idempotent)
already_sanitized = '''#!/usr/bin/env python3
harness_src = r"""
#include <stdio.h>
int main(void) {
    fprintf(stderr, "hello\\nworld");
    return 0;
}
"""
from pathlib import Path
Path("/tmp/h.c").write_text(harness_src)
''' + SANITIZER_MARKER + '\n'

TESTS.append(("already_sanitized_idempotent", False, already_sanitized))

# TEST 7: Script with word 'harness' in variable name but no C file write — NO-OP
# Regression guard for the old broad heuristic that matched 'harness' anywhere
TESTS.append(("harness_word_no_c_file_noop", False, r'''
#!/usr/bin/env python3
import subprocess

# This is a JavaScript harness test — no C file involved
harness_runner = "node"
harness_script = "exploit.js"

r = subprocess.run([harness_runner, harness_script], capture_output=True, text=True)
if "ReferenceError" in r.stderr:
    print("VULNERABILITY TRIGGERED")
'''))

# ─────────────────────────────────────────────────────────────────────────────
# NON-C LANGUAGE NO-OP TESTS
# All of these must be returned UNCHANGED by the sanitizer.
# ─────────────────────────────────────────────────────────────────────────────

# TEST 8: Python PoV — eval/exec injection
TESTS.append(("python_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile, os
from pathlib import Path

def main():
    """Prove eval() accepts attacker-controlled input."""
    payload = "__import__('os').system('echo PWNED')"
    target_script = Path(tempfile.mktemp(suffix='.py'))
    target_script.write_text(
        "import sys\n"
        f"eval(sys.argv[1])\n"
    )
    r = subprocess.run(
        [sys.executable, str(target_script), payload],
        capture_output=True, text=True, timeout=10
    )
    if 'PWNED' in r.stdout or r.returncode == 0:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 9: JavaScript / Node PoV — command injection via child_process
TESTS.append(("javascript_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile, json
from pathlib import Path

def main():
    payload = {"cmd": "; echo PWNED"}
    js_src = """
const { execSync } = require('child_process');
const args = JSON.parse(process.argv[2]);
try {
    const out = execSync('ls ' + args.cmd, {encoding:'utf8'});
    if (out.includes('PWNED')) process.stdout.write('VULNERABILITY TRIGGERED\\n');
} catch(e) {}
"""
    td = Path(tempfile.mkdtemp())
    js_file = td / "exploit.js"
    js_file.write_text(js_src)
    r = subprocess.run(
        ['node', str(js_file), json.dumps(payload)],
        capture_output=True, text=True, timeout=15
    )
    if 'VULNERABILITY TRIGGERED' in r.stdout:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 10: Go PoV — race condition / data race
TESTS.append(("go_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile
from pathlib import Path

def main():
    go_src = """
package main

import (
    "fmt"
    "sync"
)

var counter int

func increment(wg *sync.WaitGroup) {
    defer wg.Done()
    counter++
}

func main() {
    var wg sync.WaitGroup
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go increment(&wg)
    }
    wg.Wait()
    if counter != 1000 {
        fmt.Println("VULNERABILITY TRIGGERED")
    }
}
"""
    td = Path(tempfile.mkdtemp())
    go_file = td / "main.go"
    go_file.write_text(go_src)
    r = subprocess.run(
        ['go', 'run', str(go_file)],
        capture_output=True, text=True, timeout=30
    )
    if 'VULNERABILITY TRIGGERED' in r.stdout:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 11: Ruby PoV — command injection via system()
TESTS.append(("ruby_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile
from pathlib import Path

def main():
    payload = "ls; echo PWNED"
    ruby_src = """
user_input = ARGV[0]
result = `#{user_input}`
if result.include?('PWNED')
  puts 'VULNERABILITY TRIGGERED'
end
"""
    td = Path(tempfile.mkdtemp())
    rb_file = td / "exploit.rb"
    rb_file.write_text(ruby_src)
    r = subprocess.run(
        ['ruby', str(rb_file), payload],
        capture_output=True, text=True, timeout=15
    )
    if 'VULNERABILITY TRIGGERED' in r.stdout:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 12: PHP PoV — RCE via shell_exec
TESTS.append(("php_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile
from pathlib import Path

def main():
    php_src = """
<?php
$input = $_GET['cmd'] ?? $argv[1] ?? '';
$out = shell_exec($input);
if (strpos($out, 'PWNED') !== false) {
    echo 'VULNERABILITY TRIGGERED';
}
?>
"""
    td = Path(tempfile.mkdtemp())
    php_file = td / "exploit.php"
    php_file.write_text(php_src)
    r = subprocess.run(
        ['php', str(php_file), 'echo PWNED'],
        capture_output=True, text=True, timeout=15
    )
    if 'VULNERABILITY TRIGGERED' in r.stdout:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 13: Java PoV — SQL injection via subprocess invocation
TESTS.append(("java_pov_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys, tempfile
from pathlib import Path

def main():
    java_src = """
public class Exploit {
    public static void main(String[] args) throws Exception {
        String userInput = args.length > 0 ? args[0] : "";
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        // Demonstrate unsanitized SQL
        if (query.contains("' OR '1'='1")) {
            System.out.println("VULNERABILITY TRIGGERED");
        }
    }
}
"""
    td = Path(tempfile.mkdtemp())
    (td / "Exploit.java").write_text(java_src)
    subprocess.run(['javac', str(td / 'Exploit.java')], capture_output=True)
    r = subprocess.run(
        ['java', '-cp', str(td), 'Exploit', "' OR '1'='1"],
        capture_output=True, text=True, timeout=15
    )
    if 'VULNERABILITY TRIGGERED' in r.stdout:
        print('VULNERABILITY TRIGGERED')
        return 0
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 14: Web / HTTP PoV — SSRF via requests
TESTS.append(("web_http_pov_noop", False, r'''
#!/usr/bin/env python3
import requests, sys

def main():
    try:
        r = requests.get(
            'http://localhost:8080/redirect',
            params={'url': 'http://169.254.169.254/latest/meta-data/'},
            timeout=5,
            allow_redirects=True
        )
        if r.status_code == 200 and 'ami-id' in r.text:
            print('VULNERABILITY TRIGGERED')
            return 0
    except Exception:
        pass
    return 1

if __name__ == '__main__':
    raise SystemExit(main())
'''))

# TEST 15: Offline compact PoV — short script, no C
TESTS.append(("offline_compact_noop", False, r'''
#!/usr/bin/env python3
import subprocess, sys
r = subprocess.run(['python3', '-c', 'import pickle; pickle.loads(b"\x80\x04N.")'],
    capture_output=True, text=True, timeout=10)
if r.returncode == 0:
    print('VULNERABILITY TRIGGERED')
'''))

# TEST 16: LLM refinement stripped the sanitizer marker and introduced a new bare newline
# Simulates: second-pass (retry) where the LLM rewrote the script without preserving the comment
# Expected: re-sanitized + marker re-added
refinement_stripped_marker = '''
#!/usr/bin/env python3
import os, subprocess, tempfile
from pathlib import Path

harness_c = """
#include <stdio.h>
int main(void) {
    fprintf(stderr, "refined\nhello");
    return 0;
}
"""

with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "harness.c"
    p.write_text(harness_c)
    subprocess.run(["gcc", str(p), "-o", str(Path(td) / "h")], check=True)
'''
TESTS.append(("refinement_strips_marker_re_sanitized", True, refinement_stripped_marker))

# ─────────────────────────────────────────────────────────────────────────────
# _repair_c_source unit tests
# ─────────────────────────────────────────────────────────────────────────────
REPAIR_TESTS = [
    (
        "bare_nl_in_fprintf",
        'fprintf(stderr, "hello\nworld");\n',
        'fprintf(stderr, "hello\\nworld");\n',
    ),
    (
        "backslash_n_unchanged",
        'fprintf(stderr, "hello\\nworld");\n',
        'fprintf(stderr, "hello\\nworld");\n',
    ),
    (
        "nl_between_statements_preserved",
        '#include <stdio.h>\nint main(void) {\n    return 0;\n}\n',
        '#include <stdio.h>\nint main(void) {\n    return 0;\n}\n',
    ),
    (
        "line_comment_preserved",
        '// this is a comment\nfprintf(stderr, "ok\\n");\n',
        '// this is a comment\nfprintf(stderr, "ok\\n");\n',
    ),
    (
        "block_comment_preserved",
        '/* multi\nline\ncomment */\nfprintf(stderr, "ok\\n");\n',
        '/* multi\nline\ncomment */\nfprintf(stderr, "ok\\n");\n',
    ),
    (
        "multiple_bare_nls_in_printf",
        'printf("line1\nline2\nline3");\n',
        'printf("line1\\nline2\\nline3");\n',
    ),
    (
        "char_literal_unchanged",
        "char c = '\n';\n",
        "char c = '\\n';\n",  # bare \n in char literal should also be repaired
    ),
]


def run_tests():
    pass_count = 0
    fail_count = 0

    print("\n=== _repair_c_source unit tests ===")
    for label, inp, expected in REPAIR_TESTS:
        got = _repair_c_source(inp)
        if got == expected:
            print(f"  [PASS] {label}")
            pass_count += 1
        else:
            print(f"  [FAIL] {label}")
            print(f"    input:    {repr(inp)}")
            print(f"    expected: {repr(expected)}")
            print(f"    got:      {repr(got)}")
            fail_count += 1

    print("\n=== sanitize_pov_script integration tests ===")
    for label, expect_change, script in TESTS:
        result = sanitize_pov_script(script)

        changed = (result != script)
        marker_present = SANITIZER_MARKER in result

        if expect_change:
            if changed and marker_present:
                print(f"  [PASS] {label}: repaired + marker added")
                pass_count += 1
                # Compile-check the repaired C source
                import ast as _ast
                try:
                    tree = _ast.parse(result)
                    for node in _ast.walk(tree):
                        if isinstance(node, _ast.Assign):
                            try:
                                val = _ast.literal_eval(node.value)
                                if isinstance(val, str) and '#include' in val:
                                    check_compiles(val, f"{label}:c_source")
                            except Exception:
                                pass
                except Exception:
                    pass
            else:
                print(f"  [FAIL] {label}: expected repair but changed={changed}, marker={marker_present}")
                print(f"    original[:200]: {repr(script[:200])}")
                print(f"    result[:200]:   {repr(result[:200])}")
                fail_count += 1
        else:
            if label == "already_sanitized_idempotent":
                if result == script:
                    print(f"  [PASS] {label}: correctly returned unchanged")
                    pass_count += 1
                else:
                    print(f"  [FAIL] {label}: should not have been modified")
                    fail_count += 1
            else:
                if not changed:
                    print(f"  [PASS] {label}: correctly unchanged (no-op)")
                    pass_count += 1
                else:
                    print(f"  [FAIL] {label}: should not have been modified (non-C language or already correct)")
                    print(f"    diff first 300 chars: {repr(result[:300])}")
                    fail_count += 1

    print(f"\n{'='*60}")
    print(f"Results: {pass_count} passed, {fail_count} failed")

    # ── Multi-retry stability test ──────────────────────────────────────────
    # Simulates MAX_RETRIES=3 passes through the sanitizer (as agent_graph.py
    # calls sanitize_pov_script after every refinement). The result must be
    # stable (identical) from the 2nd pass onwards.
    print("\n=== Multi-retry stability tests ===")
    multi_retry_scripts = [
        ("multi_retry_c_bare_newline", refinement_stripped_marker),
        ("multi_retry_already_correct", TESTS[1][2]),  # concat_correct_escape_noop
        ("multi_retry_idempotent", already_sanitized),
    ]
    for label, script in multi_retry_scripts:
        r1 = sanitize_pov_script(script)
        r2 = sanitize_pov_script(r1)
        r3 = sanitize_pov_script(r2)
        if r1 == r2 == r3:
            print(f"  [PASS] {label}: stable across 3 passes")
            pass_count += 1
        else:
            print(f"  [FAIL] {label}: output changed between passes")
            print(f"    pass1==pass2: {r1==r2}, pass2==pass3: {r2==r3}")
            fail_count += 1

    print(f"\n{'='*60}")
    print(f"Results (final): {pass_count} passed, {fail_count} failed")
    return fail_count == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
