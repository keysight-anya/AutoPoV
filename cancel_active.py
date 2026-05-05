import urllib.request
import urllib.error
import os
import json

API_KEY = "apov_7ZcziTB7veZ2eUxSvmLdm1NHRlvGD0s9Js5ji6xI8PU"
BASE = "http://localhost:8000/api/scan"

SCANS = [
    "07bc7829-5549-4c99-a996-bed77ebf53c1",
    "3d48e877-8653-4aaf-b773-e99e8d3ed7a0",
    "4395e14f-dd9a-4562-b4e2-d6d420dd3b36",
    "7babd36f-a719-4577-bfff-35513f2f7865",
    "c508980c-b018-4fc9-8f6e-6b04ff47d740",
    "d4591b39-41a0-4c81-a0b0-716895ac76db",
    "f12835da-2712-4fbc-b3c8-24e73e940a99",
]

results = []
for scan_id in SCANS:
    url = f"{BASE}/{scan_id}/cancel"
    req = urllib.request.Request(url, method="POST", headers={"Authorization": f"Bearer {API_KEY}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            results.append(f"[{resp.status}] {scan_id}: {body}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        results.append(f"[{e.code}] {scan_id}: {body}")
    except Exception as e:
        results.append(f"[ERR] {scan_id}: {e}")

# Check remaining active scans
active_dir = "/home/olumba/AutoPoV/results/runs/active"
try:
    remaining = os.listdir(active_dir)
except Exception as e:
    remaining = [f"ERROR: {e}"]

output = "\n".join(results) + f"\n\nActive scans remaining: {len(remaining)}\n" + "\n".join(remaining)
print(output)

# Also write to file so we can read it
with open("/home/olumba/AutoPoV/cancel_results.txt", "w") as f:
    f.write(output)
