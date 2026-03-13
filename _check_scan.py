#!/usr/bin/env python3
"""Check scan results for language detection and validation details."""

import json
import sys
from pathlib import Path

# Find the most recent scan
runs_dir = Path("/home/user/AutoPoV/results/runs")
json_files = sorted(runs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

if not json_files:
    print("No scan results found")
    sys.exit(1)

latest_scan = json_files[0]
print(f"Reading scan: {latest_scan.name}\n")

with open(latest_scan) as f:
    data = json.load(f)

print("=" * 60)
print("SCAN SUMMARY")
print("=" * 60)
print(f"Scan ID: {data.get('scan_id')}")
print(f"Status: {data.get('status')}")
print(f"Detected Language: {data.get('detected_language', 'NOT DETECTED')}")
print(f"Codebase Path: {data.get('codebase_path', 'N/A')}")
print(f"Total Findings: {len(data.get('findings', []))}")
print(f"Total Cost: ${data.get('total_cost_usd', 0):.4f}")
print(f"Total Tokens: {data.get('total_tokens', 0)}")

if data.get('tokens_by_model'):
    print("\nTokens by Model:")
    for model, tokens in data['tokens_by_model'].items():
        print(f"  {model}: {tokens}")

print("\n" + "=" * 60)
print("RECENT LOGS")
print("=" * 60)
for log in data.get('logs', [])[-30:]:
    print(log)

print("\n" + "=" * 60)
print("FINDINGS SUMMARY")
print("=" * 60)
for i, finding in enumerate(data.get('findings', [])[:5]):
    print(f"\nFinding #{i+1}:")
    print(f"  File: {finding.get('filepath')}")
    print(f"  CWE: {finding.get('cwe_type')}")
    print(f"  Verdict: {finding.get('llm_verdict')}")
    print(f"  Confidence: {finding.get('confidence', 0):.2f}")
    print(f"  Final Status: {finding.get('final_status')}")
    
    pov_result = finding.get('pov_result', {})
    if pov_result:
        print(f"  PoV Success: {pov_result.get('success')}")
        print(f"  PoV Triggered: {pov_result.get('triggered')}")
        if pov_result.get('issues'):
            print(f"  PoV Issues: {pov_result.get('issues')}")
    
    # Check for validation result
    validation = finding.get('validation_result', {})
    if validation:
        print(f"  Validation: {validation.get('validation_type', 'N/A')}")
        print(f"  Side Effects: {validation.get('side_effects', {})}")
