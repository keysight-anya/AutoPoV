"""Wait for backend to come up, then trigger a qwen3 scan on skeeto/enchive."""
import urllib.request
import urllib.error
import json
import time

API_KEY = "apov_7ZcziTB7veZ2eUxSvmLdm1NHRlvGD0s9Js5ji6xI8PU"
BASE    = "http://localhost:8000/api"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}

OUTPUT = "/home/olumba/AutoPoV/start_scan_result.txt"

def req(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(r, timeout=15) as resp:
        return resp.status, resp.read().decode()

lines = []

# 1. Wait for backend
lines.append("Waiting for backend health...")
for attempt in range(24):          # up to 2 minutes
    try:
        status, body = req("GET", "/health")
        if status == 200:
            lines.append(f"Backend healthy: {body[:120]}")
            break
    except Exception as e:
        lines.append(f"  attempt {attempt+1}: {e}")
    time.sleep(5)
else:
    lines.append("ERROR: backend did not come up in time")
    open(OUTPUT, "w").write("\n".join(lines))
    raise SystemExit(1)

# 2. Check for any active scans still running
try:
    status, body = req("GET", "/scans/active")
    lines.append(f"Active scans: {body[:300]}")
except Exception as e:
    lines.append(f"Could not list active scans: {e}")

# 3. Trigger new scan: qwen3 on skeeto/enchive
payload = {
    "url": "https://github.com/skeeto/enchive",
    "model": "qwen3",
}
try:
    status, body = req("POST", "/scan/git", payload)
    lines.append(f"Scan trigger [{status}]: {body[:400]}")
except urllib.error.HTTPError as e:
    lines.append(f"Scan trigger HTTP error [{e.code}]: {e.read().decode()[:400]}")
except Exception as e:
    lines.append(f"Scan trigger error: {e}")

with open(OUTPUT, "w") as f:
    f.write("\n".join(lines) + "\n")

print("Done. See", OUTPUT)
