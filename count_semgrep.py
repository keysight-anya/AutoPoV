#!/usr/bin/env python3
"""Count Semgrep findings by rule ID to see noise level."""
import subprocess, json, sys

result = subprocess.run(
    ["semgrep", "--config", "/app/semgrep-rules/owasp-min.yml",
     "/tmp/autopov/", "--json", "--quiet"],
    capture_output=True, text=True
)

try:
    data = json.loads(result.stdout)
except Exception as e:
    print(f"JSON parse error: {e}")
    print(result.stderr[:500])
    sys.exit(1)

findings = data.get("results", [])
rules = {}
for f in findings:
    rid = f["check_id"].split(".")[-1]  # short name
    rules[rid] = rules.get(rid, 0) + 1

print(f"\nFindings by rule ({len(findings)} total):")
for k, v in sorted(rules.items(), key=lambda x: -x[1]):
    print(f"  {v:4d}  {k}")

errors = data.get("errors", [])
if errors:
    print(f"\n{len(errors)} error(s):")
    for e in errors[:5]:
        print(f"  {e}")
