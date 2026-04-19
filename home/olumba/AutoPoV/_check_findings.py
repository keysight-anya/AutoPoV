#!/usr/bin/env python3
import json
import sys

scan_file = sys.argv[1] if len(sys.argv) > 1 else "/home/olumba/AutoPoV/results/runs/0d88a5a6-08e1-4963-b928-150087223077.json"

with open(scan_file) as f:
    data = json.load(f)

findings = data.get("findings", [])
print(f"Total findings: {len(findings)}")
print()

for i, f in enumerate(findings):
    print(f"{i+1}. {f.get('cwe_type')} @ {f.get('filepath')}:{f.get('line_number')}")
    print(f"   Status: {f.get('final_status')}")
    print(f"   PoV: {'Yes' if f.get('pov_script') else 'No'}")
    print(f"   Retries: {f.get('retry_count', 0)}")
    
    # Show refinement history if available
    history = f.get("refinement_history") or []
    if history:
        print(f"   Refinement attempts: {len(history)}")
        for j, h in enumerate(history[:2]):
            print(f"     Attempt {h.get('attempt', j+1)}: success={h.get('success')}")
    print()
