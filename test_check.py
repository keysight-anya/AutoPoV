#!/usr/bin/env python3
"""Quick check of heuristic scout patterns"""

import sys
sys.path.insert(0, '/home/user/AutoPoV')

from agents.heuristic_scout import HeuristicScout

h = HeuristicScout()
print("Patterns loaded OK")
print("CWE-89 patterns:", len(h._patterns["CWE-89"]))

# Test against SQL injection code
test_code = '''cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")'''

for i, pattern in enumerate(h._patterns["CWE-89"], 1):
    match = pattern.search(test_code)
    if match:
        print(f"Pattern {i}: MATCH - {match.group()[:30]}...")
