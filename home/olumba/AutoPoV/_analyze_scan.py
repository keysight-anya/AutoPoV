import json

scan_id = "6cf375f1-5d11-4571-bb81-81c188022225"
path = "/home/olumba/AutoPoV/results/runs/" + scan_id + ".json"

with open(path) as f:
    d = json.load(f)

print("=" * 60)
print("Scan ID   :", d.get("scan_id"))
print("Status    :", d.get("status"))
print("Error msg :", d.get("error_message", d.get("error", "N/A")))
print("Logs (last 10):")
for lg in (d.get("logs") or [])[-10:]:
    print("  ", lg)
print("Total findings :", d.get("total_findings"))
print("Confirmed vulns:", d.get("confirmed_vulns"))
print("False positives:", d.get("false_positives"))
print("Failed count   :", d.get("failed"))
print("Duration (s)   :", d.get("duration_s"))
print("Cost (USD)     :", d.get("total_cost_usd"))
print("=" * 60)

findings = d.get("findings", [])
print("\nTotal findings in list:", len(findings))

statuses = {}
for f_item in findings:
    s = f_item.get("final_status", "unknown")
    statuses[s] = statuses.get(s, 0) + 1
print("Status breakdown:", statuses)

print("\n--- FAILED FINDINGS ---")
for i, f_item in enumerate(findings):
    if f_item.get("final_status") == "failed":
        print("\n[" + str(i) + "] CWE:", f_item.get("cwe_type"), "| File:", f_item.get("filepath"), "| LLM verdict:", f_item.get("llm_verdict"))
        pr = f_item.get("pov_result") or {}
        print("     PoV success:", pr.get("success"), "| vuln triggered:", pr.get("vulnerability_triggered"))
        print("     failure_category:", pr.get("failure_category"), "| failure_reason:", pr.get("failure_reason"))
        print("     oracle_reason:", pr.get("oracle_reason"))
        print("     exit_code:", pr.get("exit_code"))
        stderr_snip = str(pr.get("stderr", ""))[:300]
        print("     stderr snippet:", stderr_snip)
        ref_hist = f_item.get("refinement_history", [])
        if ref_hist:
            last = ref_hist[-1]
            print("     Last refinement errors:", last.get("errors"))

print("\n--- SKIPPED FINDINGS (first 10) ---")
count = 0
for i, f_item in enumerate(findings):
    if "skipped" in str(f_item.get("final_status", "")):
        print("[" + str(i) + "]", f_item.get("cwe_type"), "|", f_item.get("filepath"), "| status=", f_item.get("final_status"))
        count += 1
        if count >= 10:
            break
