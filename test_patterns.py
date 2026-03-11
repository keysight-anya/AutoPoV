#!/usr/bin/env python3
"""Test regex patterns from heuristic_scout.py"""

import re

patterns = [
    ("CWE-89-1", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*\+", re.IGNORECASE)),
    ("CWE-89-2", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*%s", re.IGNORECASE)),
    ("CWE-89-3", re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*format\(", re.IGNORECASE)),
    ("CWE-89-4", re.compile(r'f["\x27].*(SELECT|INSERT|UPDATE|DELETE).*\{.*\}', re.IGNORECASE)),
    ("CWE-89-5", re.compile(r'execute\s*\(\s*f["\x27]', re.IGNORECASE)),
    ("CWE-89-6", re.compile(r'cursor\.execute\s*\(\s*[^"\x27]*\+', re.IGNORECASE)),
    ("CWE-89-7", re.compile(r'\.execute\s*\(\s*f["\x27].*SELECT', re.IGNORECASE)),
]

# Test code
test_code = '''cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")'''

print("Testing patterns against:")
print(f"  {test_code}")
print()

for name, pattern in patterns:
    try:
        match = pattern.search(test_code)
        print(f"{name}: {'MATCH' if match else 'NO MATCH'}")
        if match:
            print(f"  -> {match.group()}")
    except Exception as e:
        print(f"{name}: ERROR - {e}")

print("\nAll patterns compiled successfully!")
