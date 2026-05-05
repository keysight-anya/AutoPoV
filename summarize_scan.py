import json

d = json.load(open("results/runs/7baa2ac1-5584-442f-92ea-50c3c5994bf0.json"))
print("Total findings:", d["total_findings"])
print("Confirmed:", d["confirmed_vulns"])
print("Failed:", d["failed"])
print("Duration:", d["duration_s"], "seconds")
print()
for i, f in enumerate(d["findings"], 1):
    pov = f.get("pov_result", {})
    print(f"{i}. [{f.get('cwe_type', '?')}] {f.get('filepath', '?')}:{f.get('line_number', '?')}")
    print(f"   verdict={pov.get('proof_verdict', '?')}")
    print(f"   triggered={pov.get('vulnerability_triggered', False)}")
    print(f"   confidence={f.get('confidence', 0)}")
    print()
