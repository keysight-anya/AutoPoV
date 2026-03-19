#!/usr/bin/env python3
import json
import sys

scan_id = sys.argv[1] if len(sys.argv) > 1 else "40745440-b559-4c57-ae86-f882ceba022e"

with open(f"/home/user/AutoPoV/results/runs/{scan_id}.json", "r") as f:
    d = json.load(f)

print(f"Status: {d['status']}")
print(f"Findings: {len(d['findings'])}")
print(f"Confirmed: {sum(1 for f in d['findings'] if f.get('final_status')=='confirmed')}")
print(f"End time: {d.get('end_time', 'None')}")

# Check for duplicate keys
keys = []
for f in d['findings']:
    key = f"{f.get('filepath')}:{f.get('line_number')}:{f.get('cwe_type')}"
    keys.append(key)

duplicates = [k for k in set(keys) if keys.count(k) > 1]
if duplicates:
    print(f"\nDuplicate keys found: {duplicates}")
else:
    print("\nNo duplicate keys")
