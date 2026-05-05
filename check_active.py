#!/usr/bin/env python3
import json, os, glob

active_dir = '/app/results/runs/active'
files = glob.glob(os.path.join(active_dir, '*.json'))

if not files:
    print("No active scans.")
    exit(0)

for fp in files:
    with open(fp) as f:
        d = json.load(f)
    print(f"=== {d.get('scan_id')} ===")
    print(f"Target:   {d.get('target_label')}")
    print(f"Status:   {d.get('status')}")
    print(f"Progress: {d.get('progress')}%")
    print(f"Findings: {len(d.get('findings', []))}")
    print("Last 25 log lines:")
    for l in d.get('logs', [])[-25:]:
        print(l)
    print()
